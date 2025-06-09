#include "pch.h"

engine::engine()
{
	glb.e = this;
#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	loader ldr(this);

	if (!ldr.load_conf(glb.path_config))
	{
		exit_code = ldr.exit_code;
		glb.stop();
		return;
	}

	glb.path_config = FN();

	if (!glb.actual)
		return;

	ldr.iterate_p([&](const str::astr& name, const asts& lb) {

		if (name.empty())
		{
			LOG_W("proxy with no name skipped");
			return true;
		}

		proxy* p = proxy::build(ldr, name, lb);
		if (nullptr == p)
			return false;

		prox.emplace_back(p);
		return true;
	});

	if (ldr.exit_code != 0)
	{
		exit_code = ldr.exit_code;
		glb.stop();
		return;
	}

	ldr.iterate_l([&](const str::astr& name, const asts& lb) {

		if (name.empty())
		{
			if (glb.listeners_need_all)
			{
				ldr.exit_code = EXIT_FAIL_NEED_ALL_LISTENERS;
				return false;
			}

			LOG_W("listener with no name skipped");
			return true;
		}

		listener::build(listners, ldr, name, lb);
		if (ldr.exit_code != EXIT_OK)
			return false;

		return true;
	});

	if (ldr.exit_code != 0)
	{
		exit_code = ldr.exit_code;
		glb.stop();
		return;
	}

	if (listners.empty())
	{
		LOG_FATAL("empty (or not loaded) \"listeners\" block");
		exit_code = EXIT_FAIL_NOLISTENERS;
		glb.stop();
		return;
	}

    for (signed_t idpool = 1; auto & p : prox)
    {
        p->id = idpool++;
    }

	for (signed_t idpool = 1; auto &l : listners)
	{
		l->id = idpool++;
	}

	if (ldr.nameservers && glb.dns != nullptr)
	{
		glb.dns->load_serves(this, ldr.nameservers);
	}

	if (ldr.icpt)
	{
		if (!glb.icpt.load(this, ldr.icpt))
		{
			exit_code = ldr.exit_code;
            glb.stop();
            return;
		}
	}

	for (auto &l : listners)
		l->open();

}

engine::~engine()
{
	glb.stop();

    current_absorber = 0; // force remove absorber

	for (; num_acceptors > 0;)
	{
		cv.notify_all();
		spinlock::sleep(100);
	}

    spinlock::lock_read(lock_tcp_list); // << LOCK a
    if (tcps)
        tcps->close();
    spinlock::unlock_read(lock_tcp_list); // << UNLOCK a

    for (; tcps.get() != nullptr;)
        spinlock::sleep(100);

	glb.e = nullptr;

	std::array<netkit::pipe*,256> pipes2del;
	std::array<slot_statistics*, 256> stat2del;
	size_t p2dsz = 0, s2dsz = 0;
	while (newpipes.get([&](tcp_pipe_and_handler& h) {
		pipes2del[p2dsz++] = h.pipe;
	}));

    while (ready_bridges.get([&](bridge_ready& h) {
        pipes2del[p2dsz++] = h.pipe1;
		pipes2del[p2dsz++] = h.pipe2;
		stat2del[s2dsz++] = h.stat;
    }));

    for (size_t i = 0; i < p2dsz; ++i)
    {
        if (pipes2del[i]->is_ref_new())
        {
            delete pipes2del[i];
            continue;
        }

        netkit::pipe_ptr pp;
        pp._assign(pipes2del[i]);
    }

    for (size_t i = 0; i < s2dsz; ++i)
        delete stat2del[i];

#ifdef _WIN32
	WSACleanup();
#endif
}

void engine::acceptor()
{
    spinlock::atomic_increment(num_acceptors);
	ostools::set_current_thread_name(ASTR("acceptor"));

    auto process_pipes = [&](handler* h, netkit::tcp_pipe* p)->bool {

        spinlock::atomic_decrement(num_acceptors); // exclude current acceptor from available acceptors pool
        ostools::set_current_thread_name(h->desc());
        h->handle_pipe(p); // can take long time...
        if (glb.is_stop())
            return true;
        if (num_acceptors >= ENOUGH_ACCEPTORS_COUNT)
            return true; // no need more acceptors
        spinlock::atomic_increment(num_acceptors);
		return false;
	};

	handler* hg;
	netkit::tcp_pipe* pg;
	while (newpipes.get([&](tcp_pipe_and_handler& x) { hg = x.h; pg = x.pipe; }))
	{
		if (process_pipes(hg,pg))
			return;
	}

	// no more ready-to-work pipes
	// enter wait mode and... wait

	time_t last_use = chrono::now();

	for (;!glb.is_stop();)
    {
        ostools::set_current_thread_name(ASTR("acceptor"));

		pg = nullptr;
        std::unique_lock<std::mutex> m(mtx);
        cv.wait(m, [&] {
			return glb.is_stop() || check_acceptors > 0 || newpipes.get([&](tcp_pipe_and_handler& x) { hg = x.h; pg = x.pipe; });
        });
		m.unlock();

		if (glb.is_stop())
		{
            if (pg)
                delete pg;
			break;
		}
		if (pg == nullptr)
		{
			// just check last use
			time_t ct = chrono::now();
			if ((ct - last_use) > 600)
			{
				// thread unused more then 10 min - close
				break;
			}

			size_t cav = check_acceptors;
            if (cav > 0)
                spinlock::atomic_cas(check_acceptors, cav, cav - 1);
			continue;
		}

		if (process_pipes(hg, pg))
            return;

		while (newpipes.get([&](tcp_pipe_and_handler& x) { hg = x.h; pg = x.pipe; }))
        {
            if (process_pipes(hg, pg))
                return;
        }

		last_use = chrono::now();
	}

	spinlock::atomic_decrement(num_acceptors);
	size_t cav = check_acceptors;
    if (cav > num_acceptors)
        spinlock::atomic_cas(check_acceptors, cav, cav - 1);

}

void engine::new_tcp_pipe(handler* h, netkit::tcp_pipe* p)
{
    ASSERT(p->is_ref_new());

	for (size_t spinlockcount = 0;;++spinlockcount)
    {
        bool done = newpipes.put([&](tcp_pipe_and_handler& buck) {
            buck.h = h;
            buck.pipe = p;
        });
		if (done)
			break;

		spinlock::sleep(1);
		if (spinlockcount > 1000)
		{
			delete p;
			return;
		}
	}
	
	if (num_acceptors == 0)
    {
        std::thread th(&engine::acceptor, this);
        th.detach();
	}
	
	cv.notify_one();
}

void engine::release_tcp(tcp_processing_thread* tcp_wt)
{
    spinlock::auto_lock_write l(lock_tcp_list);

    std::unique_ptr<tcp_processing_thread>* ptr = &tcps;
    for (tcp_processing_thread* t = ptr->get(); t;)
    {
        if (t == tcp_wt)
        {
            t = t->get_next_and_forget();
            ptr->reset(t); // it now deletes previous t
            break;
        }
        ptr = t->get_next_ptr();
        t = t->get_next();
    }

}

engine::bridged::process_result engine::bridged::process(u8* data, netkit::pipe_waiter::mask& masks)
{
    process_result rv = masks.have_closed(mask1 | mask2) ? SLOT_DEAD : SLOT_SKIPPED;

    if (masks.have_read(mask1))
    {
        if (pipe2->send(nullptr, 0) == netkit::pipe::SEND_BUFFERFULL)
        {
        }
        else
        {
            signed_t sz = pipe1->recv(data, BRIDGE_BUFFER_SIZE, RECV_BRIDGE_MODE_TIMEOUT);

            if (sz < 0)
                rv = SLOT_DEAD;
            else if (sz > 0)
            {
                netkit::pipe::sendrslt r = pipe2->send(data, sz);
                if (r == netkit::pipe::SEND_FAIL)
                    return SLOT_DEAD;

                if (r == netkit::pipe::SEND_OK)
                    masks.remove_write(mask2);

#ifdef LOG_TRAFFIC
                loger.log12(data, sz);
#endif
            }
        }
        if (rv != SLOT_DEAD) rv = SLOT_PROCESSES;

    }
    if (masks.have_read(mask2))
    {
        if (pipe1->send(nullptr, 0) == netkit::pipe::SEND_BUFFERFULL)
        {
            // send buffer full
            // don't read pipe now because we can't send it
        }
        else
        {
            signed_t sz = pipe2->recv(data, BRIDGE_BUFFER_SIZE, RECV_BRIDGE_MODE_TIMEOUT);

            if (sz < 0)
                rv = SLOT_DEAD;
            else if (sz > 0)
            {
                netkit::pipe::sendrslt r = pipe1->send(data, sz);
                if (r == netkit::pipe::SEND_FAIL)
                    return SLOT_DEAD;

                if (r == netkit::pipe::SEND_OK)
                    masks.remove_write(mask1);

#ifdef LOG_TRAFFIC
                loger.log21(data, sz);
#endif

            }
        }
        if (rv != SLOT_DEAD) rv = SLOT_PROCESSES;

    }

    if (masks.have_write(mask1))
    {
        netkit::pipe::sendrslt r = pipe1->send(data, 0); // just send unsent buffer
        if (r == netkit::pipe::SEND_FAIL)
            return SLOT_DEAD;
        if (rv != SLOT_DEAD) rv = SLOT_PROCESSES;
    }
    if (masks.have_write(mask2))
    {
        netkit::pipe::sendrslt r = pipe2->send(data, 0); // just send unsent buffer
        if (r == netkit::pipe::SEND_FAIL)
            return SLOT_DEAD;
        if (rv != SLOT_DEAD) rv = SLOT_PROCESSES;
    }

    return rv;

}

bool engine::release_absorber_status(const tcp_processing_thread* th, bool full_reason)
{
    size_t thptr = reinterpret_cast<size_t>(th);
    if (spinlock::atomic_cas<size_t>(current_absorber, thptr, 0))
    {
        return full_reason ? true : ready_bridges.empty();
    }
    return true;
}


void engine::bridge(netkit::pipe_ptr&& pipe1, netkit::pipe_ptr&& pipe2)
{
    ASSERT(!pipe1->is_multi_ref() && !pipe2->is_multi_ref()); // avoid memory leak! bridge is now owner of pipe1 and pipe2

    ostools::set_current_thread_name(ASTR("bridge"));

#if 0
    if (g_single_core)
    {
        // do not merge connection threads if single core
        tcp_processing_thread pt;

        pt.try_add_bridge(pipe1, pipe2);
        bridge(&pt);

        pipe1 = nullptr;
        pipe2 = nullptr;
        return;
    }
#endif

	if (has_absorber() && bridge_alienation(pipe1, pipe2))
	{
		absorber_signal();

        // pipes is now in bridge-bucket, so no need to delete them now
        pipe1._assign(nullptr);
        pipe2._assign(nullptr);

        return;
	}

    tcp_processing_thread* npt = NEW tcp_processing_thread(pipe1, pipe2);
    pipe1 = nullptr;
    pipe2 = nullptr;

    spinlock::lock_write(lock_tcp_list); //<< LOCK b

    npt->get_next_ptr()->reset(tcps.get());
    tcps.release();
    tcps.reset(npt);

    spinlock::unlock_write(lock_tcp_list); //<< UNLOCK b

    bridge(npt);


    release_tcp(npt);

}

void engine::bridge(tcp_processing_thread* npt)
{
    u8 data[BRIDGE_BUFFER_SIZE];
    for (; !glb.is_stop();)
    {
        if (!npt->tick(data))
            break;
    }
}

engine::tcp_processing_thread::~tcp_processing_thread()
{
    ASSERT(!glb.e->is_absorber_status(this));
    spinlock::atomic_decrement(glb.numtcp);
}

void engine::tcp_processing_thread::close()
{
    for (signed_t i = 0; i < numslots; ++i)
    {
        slots[i].pipe1 = nullptr;
        slots[i].pipe2 = nullptr;
    }

    signal();

    if (next)
        next->close();
}



bool engine::tcp_processing_thread::tick(u8* data)
{
    bool absorber = glb.e->acquire_absorber_status(this);

rep_prep:
    waiter.prepare();
    for (signed_t i = 0; i < numslots;)
    {
        if (!slots[i].prepare_wait(waiter))
        {
            --numslots;
            moveslot(i, numslots);

            if (numslots == 0)
            {
                if (absorber && !glb.is_stop())
                {
                    if (glb.e->bridge_absorb(slots[0]))
                    {
                        slots[0].mask1 = 0;
                        slots[0].mask2 = 0;
                        numslots = 1;
                        goto rep_prep;
                    }

                    if (!glb.e->release_absorber_status(this, false))
                        break; // stay absorber
                }
                numslots = -1;
                return false;
            }
            continue;
        }
        ++i;
    }

    while (absorber)
    {
        if (numslots < MAXIMUM_SLOTS)
        {
            if (glb.e->bridge_absorb(slots[numslots]))
            {
                slots[numslots].mask1 = 0;
                slots[numslots].mask2 = 0;
                if (slots[numslots].prepare_wait(waiter))
                    ++numslots;
                continue;
            }
            break;
        }
        else
        {
            glb.e->release_absorber_status(this, true);
            absorber = false;
            break;
        }
    }

    if (numslots == 0)
    {
        if (absorber && !glb.is_stop())
        {
            if (!glb.e->release_absorber_status(this, false))
                goto rep_prep;
        }

        numslots = -1;
        return false;
    }

    if (name_wrk != numslots)
    {
        name_wrk = numslots;
        str::astr n;
        str::impl_build_string(n, absorber ? "tcp-abs [$]" : "tcp-wrk [$]", numslots);
        ostools::set_current_thread_name(n);
    }

    waiting = true;
    auto mask = waiter.wait(10 * 1000 /*10 sec*/);
    waiting = false;

    if (glb.is_stop())
        return false;

    signed_t cleanup = -1, curms = 0;
    auto getms = [&curms]() ->signed_t { if (curms == 0) curms = chrono::ms(); return curms; };

    auto allow_alienation = [&]()
        {
            if (absorber || glb.is_stop())
                return false;
            return glb.e->has_absorber();
        };

    auto process_inactive_slot = [&](bridged& slot, signed_t slot_i)
        {
            // inactive slot
            if (!slot.stat)
                slot.stat.reset(NEW slot_statistics(getms()));
            else if (slot.stat->inactive_start == 0)
            {
                slot.stat->inactive_start = getms();
                slot.stat->one_sec_inactive = false;
            }
            else {

                // check inactive timeout
                signed_t dt = getms() - slot.stat->inactive_start;
                if (dt > 60000 * 2)
                {
                    // kill inactive slot
                    slot.clear();
                    if (cleanup < 0)
                        cleanup = slot_i;
                    return;
                }
                slot.stat->one_sec_inactive = dt > 1000;
                if (dt > 1000 && cleanup < 0)
                    cleanup = slot_i;
            }
        };

    auto handle_cleanup = [&]() ->bool
        {
            bool alienation = false;
            if (cleanup >= 0)
            {
                bool aln = numslots < MAXIMUM_SLOTS / 2;

                for (signed_t i = cleanup; i < numslots; ++i)
                {
                    if (slots[i].is_empty())
                        continue;

                    if (aln && allow_alienation() && slots[i].stat && slots[i].stat->one_sec_inactive && glb.e->bridge_alienation(slots[i]))
                    {
                        alienation = true;
                        continue;
                    }

                    if (cleanup < i)
                    {
                        slots[cleanup] = std::move(slots[i]);
                    }

                    cleanup++;
                }
                numslots = cleanup;
                if (numslots <= 0)
                {
                    if (absorber && !glb.is_stop())
                    {
                        if (!glb.e->release_absorber_status(this, false))
                            return true; // stay absorber with 0 slots // will absorb new slots next iteration 
                    }
                    numslots = -1;
                    return false;
                }
            }

            if (alienation && !glb.is_stop())
            {
                glb.e->absorber_signal();
            }

            return numslots > 0;
        };

    if (mask.is_empty())
    {
        if (!absorber)
        {
            for (signed_t i = 0; i < numslots; ++i)
                process_inactive_slot(slots[i], i);
            return handle_cleanup();
        }
        return true;
    }

    bool some_processed = false;
    for (signed_t i = 0; i < numslots && !mask.is_empty();)
    {
        bridged::process_result pr = slots[i].process(data, mask);
        some_processed |= pr == bridged::SLOT_PROCESSES;

        if (bridged::SLOT_DEAD == pr)
        {
            slots[i].clear();
            if (cleanup < 0)
                cleanup = i;
            continue;
        }

        if (bridged::SLOT_SKIPPED == pr)
        {
            process_inactive_slot(slots[i], i);
        }
        else
        {
            if (slots[i].stat)
            {
                slots[i].stat->inactive_start = 0;
                slots[i].stat->one_sec_inactive = false;
            }
        }

        ++i;
    }

    return handle_cleanup();
}


bool engine::heartbeat()
{
	if (glb.is_stop())
	{
	    LOG_I("stoping...");
	    Print();
		for (std::unique_ptr<listener> & l : listners)
			l->stop();

		return true;
	}

	if (glb.numlisteners <= 0)
	{
		LOG_FATAL("there are no active listeners");
		Print();
		return true;
	}

	return false;
}
