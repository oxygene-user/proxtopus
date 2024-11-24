#include "pch.h"

#define BRIDGE_BUFFER_SIZE 65536

handler* handler::build(loader& ldr, listener *owner, const asts& bb, netkit::socket_type_e st)
{
	const str::astr &t = bb.get_string(ASTR("type"));
	if (t.empty())
	{
		ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
		LOG_E("{type} not defined for handler of listener [%s]; type {proxtopus help handler} for more information", str::printable(owner->get_name()));
		return nullptr;
	}

	handler* h = nullptr;
	if (ASTR("direct") == t)
	{
		h = NEW handler_direct(ldr, owner, bb, st);
	}
	else if (str::starts_with(t, ASTR("socks")))
	{
		if (st != netkit::ST_TCP)
        {
		//err:
			ldr.exit_code = EXIT_FAIL_SOCKET_TYPE;
            LOG_E("{%s} handler can only be used with TCP type of listener [%s]", t.c_str(), str::printable(owner->get_name()));
            return nullptr;
		}

		h = NEW handler_socks(ldr, owner, bb, str::view(t).substr(5));
	}
	else if (ASTR("shadowsocks") == t)
	{
		h = NEW handler_ss(ldr, owner, bb, st);
	}

	if (h != nullptr)
	{
		if (ldr.exit_code != 0)
		{
			delete h;
			return nullptr;
		}
		return h;
	}

	LOG_E("unknown {type} [%s] for handler of lisnener [%s]; type {proxtopus help handler} for more information", str::printable(t), str::printable(owner->get_name()));
	ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
	return nullptr;
}

handler::handler(loader& ldr, listener* owner, const asts& bb):owner(owner)
{
	const proxy* p = nullptr;
	str::astr pch = bb.get_string(ASTR("udp-proxy"));
    if (!pch.empty())
    {
        p = ldr.find_proxy(pch);
        if (p == nullptr)
        {
        per:
            LOG_E("unknown {proxy} [%s] for handler of lisnener [%s]", pch.c_str(), str::printable(owner->get_name()));
            ldr.exit_code = EXIT_FAIL_PROXY_NOTFOUND;
            return;
        }

        if (!p->support(netkit::ST_UDP))
        {
            ldr.exit_code = EXIT_FAIL_SOCKET_TYPE;
            LOG_E("upstream {proxy} [%s] does not support UDP protocol (listener: [%s])", pch.c_str(), str::printable(owner->get_name()));
            return;
        }

        udp_proxy = p;
    }

	pch = bb.get_string(ASTR("proxychain"));
	if (!pch.empty())
	{
		TFORa(tkn, pch, ',')
		{
			p = ldr.find_proxy(*tkn);
			if (p == nullptr)
			{
				pch = *tkn;
				goto per;
			}
            proxychain.push_back(p);
		}
	}
}

void handler::bridge(netkit::pipe_ptr &&pipe1, netkit::pipe_ptr&& pipe2)
{
	ASSERT(!pipe1->is_multi_ref()); // avoid memory leak! bridge is now owner of pipe1 and pipe2
	ASSERT(!pipe2->is_multi_ref());

	auto tcp = tcp_pth.lock_read();
	tcp_processing_thread* ptr = tcp().get();
	for (; ptr != nullptr; ptr = ptr->get_next())
	{
		signed_t x = ptr->try_add_bridge(/*ep,*/ pipe1, pipe2);
		if (x > 0)
		{
			tcp.unlock();
			ptr->signal();
			return;
		}
	}
	tcp.unlock();


	auto tcpw = tcp_pth.lock_write();
	tcp_processing_thread *npt = NEW tcp_processing_thread();
	npt->get_next_ptr()->reset(tcpw().get());
	tcpw().release();
	tcpw().reset(npt);
	tcpw.unlock();

	npt->try_add_bridge(pipe1, pipe2);
	bridge(npt);

	pipe1 = nullptr;
	pipe2 = nullptr;

	release_tcp(npt);

}

#ifdef LOG_TRAFFIC
static volatile spinlock::long3264 idpool = 1;
traffic_logger::traffic_logger()
{
}
traffic_logger::~traffic_logger()
{

}
void traffic_logger::prepare()
{
	if (id == 0)
	{
		id = spinlock::increment(idpool);
		fn = ASTR("t:\\trl\\");
		fn.append(std::to_string(GetCurrentProcessId()));
		fn.push_back('_');
		fn.append(std::to_string(id));
		fn.append(ASTR("_12.traf"));
	}

}
traffic_logger& traffic_logger::operator=(traffic_logger&&x)
{
	id = x.id;
	x.id = 0;
	fn = std::move(x.fn);
	tools::swap(f12, x.f12);
	tools::swap(f21, x.f21);
	x.clear();

	return *this;
}
void traffic_logger::clear()
{
	id = 0;
	if (f12)
	{
		CloseHandle(f12);
		f12 = nullptr;
	}
	if (f21)
	{
		CloseHandle(f21);
		f21 = nullptr;
	}
}

void traffic_logger::log12(u8* data, signed_t sz)
{
	if (f12 == nullptr)
	{
		prepare();
		fn[fn.length() - 7] = '1';
		fn[fn.length() - 6] = '2';
		f12 = CreateFileA(fn.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (f12 == INVALID_HANDLE_VALUE)
		{
			f12 = nullptr;
			return;
		}
	}

	DWORD w;
	WriteFile(f12, data, (DWORD)sz, &w, nullptr);

}
void traffic_logger::log21(u8* data, signed_t sz)
{
	if (f21 == nullptr)
	{
		prepare();
		fn[fn.length() - 7] = '2';
		fn[fn.length() - 6] = '1';
		f21 = CreateFileA(fn.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (f21 == INVALID_HANDLE_VALUE)
		{
			f21 = nullptr;
			return;
		}
	}

	DWORD w;
	WriteFile(f21, data, (DWORD)sz, &w, nullptr);
}
#endif


handler::bridged::process_result handler::bridged::process(u8* data, netkit::pipe_waiter::mask &masks)
{
	process_result rv = masks.have_closed(mask1 | mask2) ? SLOT_DEAD : SLOT_SKIPPED;

	if (masks.have_read(mask1))
	{
		if (pipe2->send(nullptr, 0) == netkit::pipe::SEND_BUFFERFULL)
		{

		}
		else
        {
            signed_t sz = pipe1->recv(data, BRIDGE_BUFFER_SIZE);
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
		}
		else
        {
            signed_t sz = pipe2->recv(data, BRIDGE_BUFFER_SIZE);
            if (sz < 0)
                rv =  SLOT_DEAD;
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

signed_t handler::tcp_processing_thread::tick(u8* data)
{
	auto ns = numslots.lock_write();

	for (signed_t i = 0; i < ns(); ++i)
	{
		if (!slots[i].prepare_wait(waiter))
		{
			--ns();
			moveslot(i, ns());
		}
	}

	if (ns() <= 0)
	{
		ns() = -1;
		return -1;
	}

	ns.unlock();

	auto mask = waiter.wait(10 * 1000 * 1000 /*10 sec*/);
	if (mask.is_empty())
		return 0;

	signed_t cur_numslots = numslots.lock_read()();
	signed_t rv = MAXIMUM_SLOTS + 1;

	signed_t was_del = -1;

	for (signed_t i = 0; i < cur_numslots && !mask.is_empty();)
	{
		bridged::process_result pr = slots[i].process(data, mask);

		if (bridged::SLOT_DEAD == pr)
		{
			slots[i].clear();
			if (was_del < 0)
				was_del = i;
			continue;
		}

		if (rv > MAXIMUM_SLOTS && bridged::SLOT_SKIPPED == pr)
			rv = i;

		++i;
	}

	ns = numslots.lock_write();

	ASSERT(cur_numslots <= ns());

	if (was_del >= 0)
	{
		for (signed_t i = was_del + 1; i < ns(); ++i)
		{
			if (slots[i].is_empty())
				continue;
			slots[was_del] = std::move(slots[i]);
			if (rv == i)
				rv = was_del;

			was_del++;
			ASSERT(slots[was_del].is_empty());
		}
		ns() = was_del;
	}

	bool cont_inue = ns() > 0;
	if (!cont_inue)
		ns() = -1; // lock this thread

	return cont_inue ? rv : -1;
}

void handler::bridge(tcp_processing_thread *npt)
{
	u8 data[BRIDGE_BUFFER_SIZE];
	netkit::pipe_waiter::mask mask;
	for (; !need_stop ;)
	{
		signed_t r = npt->tick(data);
		if (r < 0)
			break;

		if (glb.is_stop())
			break;

		if (r < MAXIMUM_SLOTS)
		{
			// transplant idle slots to end of thread list to free up the current thread faster

			auto tcp = tcp_pth.lock_read(); // why lock read? due we do not kill or change list-pointers here. we just expect no one kill them while this job in progress

			if (tcp_processing_thread * ptr = npt->get_next())
				npt->transplant(r, ptr);

			/*
			tcp_processing_thread *ptr = tcp().get();
			for (; ptr && ptr != npt; ptr = ptr->get_next())
			{
				if (npt->transplant(r, ptr))
					break;
			}
			*/
		}
	}
}

void handler::release_udps()
{
#ifdef _DEBUG
	ASSERT(spinlock::tid_self() == owner->accept_tid);
#endif // _DEBUG

	auto keys = std::move( finished.lock_write()() );

	for(const auto &k : keys)
		udp_pth.erase(k);
}

void handler::release_udp(udp_processing_thread* udp_wt)
{
	finished.lock_write()().push_back(udp_wt->key());
}

void handler::release_tcp(tcp_processing_thread* tcp_wt)
{
	auto tcp = tcp_pth.lock_write();
	std::unique_ptr<tcp_processing_thread>* ptr = &tcp();
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


netkit::pipe_ptr handler::connect( netkit::endpoint& addr, bool direct)
{
	static spinlock::long3264 tag = 1;

	if (direct || proxychain.size() == 0)
	{
		if (netkit::pipe* pipe = conn::connect(addr))
		{
			if (proxychain.size() == 0)
			{
				LOG_N("connected to (%s) via listener [%s]", addr.desc().c_str(), str::printable(owner->get_name()));
			}

			netkit::pipe_ptr pp(pipe);
			return pp;
		}

		if (proxychain.size() == 0)
		{
			LOG_N("not connected to (%s) via listener [%s]", addr.desc().c_str(), str::printable(owner->get_name()));
		}

		return netkit::pipe_ptr();
	}

	spinlock::long3264 t = spinlock::increment(tag);
	str::astr stag(ASTR("[")); stag.append(std::to_string(t)); stag.append(ASTR("] "));

	size_t tl = stag.size();

	auto ps = [&](const str::astr_view& s)
	{
		stag.resize(tl);
		stag.append(s);
	};

	//LOG_N("listener {%s} has been started (bind ip: %s, port: %i)", str::printable(name), bind2.to_string().c_str(), port);

	if (proxychain.size() == 1)
	{
		ps("connecting to upstream proxy (%s) via listener [%s]"); LOG_N(stag.c_str(), proxychain[0]->desc().c_str(), str::printable(owner->get_name()));
	}
	else
	{
		ps("connecting through proxy chain via listener [%s]"); LOG_N(stag.c_str(), str::printable(owner->get_name()));
		ps("connecting to proxy (%s)"); LOG_N(stag.c_str(), proxychain[0]->desc().c_str());
	}

	netkit::endpoint prx_ep;
	auto get_proxy_addr = [&](signed_t i) -> netkit::endpoint&
		{
			prx_ep = proxychain[i]->get_addr();
			return prx_ep;
		};

	netkit::pipe_ptr pp = connect(get_proxy_addr(0), true);

	for (signed_t i = 0; pp != nullptr && i < (signed_t)proxychain.size(); ++i)
	{
		bool finala = i + 1 >= (signed_t)proxychain.size();
		netkit::endpoint &na = finala ? addr : get_proxy_addr(i + 1);
		if (finala)
		{
			ps("connecting to address (%s)"); LOG_N(stag.c_str(), na.desc().c_str());
		}
		else
		{
			ps("connecting to proxy (%s)"); LOG_N(stag.c_str(), proxychain[i + 1]->desc().c_str());
		}

		pp = proxychain[i]->prepare(pp, na);
	}
	return pp;
}

bool handler::tcp_processing_thread::transplant(signed_t slot, tcp_processing_thread* n)
{
	auto ns = numslots.lock_write();

	ASSERT(slot < ns());
	bridged& br = slots[slot];

	if (n->try_add_bridge(br.pipe1, br.pipe2) > 0)
	{
		--ns();
		moveslot(slot, ns());
		if (ns() == 0)
		{
			ns() = -1;
			return true;
		}
	}

	return false;

}

void handler::tcp_processing_thread::close()
{
	signal();
	{
		std::array<netkit::pipe_ptr, MAXIMUM_SLOTS * 2> ptrs;
		signed_t n = 0;

		auto ns = numslots.lock_write();
		for (signed_t i = 0; i < ns(); ++i)
		{
			ptrs[n++] = std::move(slots[i].pipe1);
			ptrs[n++] = std::move(slots[i].pipe2);
		}
		ns() = 0;
	}

	if (next)
		next->close();
}

void handler::udp_processing_thread::udp_bridge(SOCKET initiator)
{
    u8 packet[65536];
	netkit::pgen pg(packet, 65535);
	if (auto to = h->udp_timeout(); to > 0)
		cutoff_time = chrono::ms() + to;

	netkit::udp_pipe* pipe = this;
    std::unique_ptr<netkit::udp_pipe> proxypipe;

	if (const proxy *prx = h->udp_proxy)
	{
		proxypipe = prx->prepare(this);
		pipe = proxypipe.get();
		if (!pipe)
			return;

		LOG_N("UDP connection from %s via proxy %s established", hashkey.to_string(true).c_str(), prx->desc().c_str());
	}

    for(;;)
    {
        auto x = sendb.lock_write();
        sdptr b;
        if (x().get(b))
        {
            if (b == nullptr)
                return; // stop due error
            x.unlock();
            netkit::pgen spg(b->data(), b->datasz, b->pre());
            pipe->send(b->tgt, spg);
		}
		else
		{
            if (!ts.data)
            {
                // wait for send and init thread storage for pipe
				spinlock::sleep(0);
                continue;
            }

			sendor = pipe;
			break;
		}
    }

	netkit::ipap from;
	for (;;)
	{
		pg.set_extra(32);
		auto ior = pipe->recv(from, pg, 65535-32);
		if (ior != netkit::ior_ok)
		{
			if (ior == netkit::ior_timeout && !is_timeout(chrono::ms()))
				continue;
			break;
		}
		if (!h->encode_packet(handler_state, from, pg))
			break;
		if (!hashkey.sendto(initiator, pg.to_span()))
			break;

        if (auto to = h->udp_timeout(); to > 0)
            cutoff_time = chrono::ms() + to;

	}

	sendor = nullptr;
}

/*virtual*/ netkit::io_result handler::udp_processing_thread::send(const netkit::endpoint& toaddr, const netkit::pgen& pg)
{
	return netkit::udp_send(ts, toaddr, pg);
}
/*virtual*/ netkit::io_result handler::udp_processing_thread::recv(netkit::ipap &from, netkit::pgen& pg, signed_t max_bufer_size)
{
	return netkit::udp_recv(ts, from, pg, max_bufer_size);
}


void handler::stop()
{
	if (need_stop)
		return;

#ifdef _DEBUG
	ASSERT(spinlock::tid_self() == owner->accept_tid);
#endif // _DEBUG

	need_stop = true;

	auto tcp = tcp_pth.lock_write();
	if (tcp())
		tcp()->close();
	tcp.unlock();

	for (auto &pp : udp_pth)
	{
		if (pp.second)
			pp.second->close();
	}

	for (; tcp_pth.lock_read()().get() != nullptr || !udp_pth.empty();)
	{
		spinlock::sleep(100);
		release_udps();
	}
}

void handler::on_udp(netkit::socket& lstnr, netkit::udp_packet& p)
{
    ptr::shared_ptr<udp_processing_thread> wt;

    release_udps();
    auto rslt = udp_pth.insert(std::pair(p.from, nullptr));

    if (!rslt.second)
    {
        wt = rslt.first->second; // already exist, return it

        if (wt != nullptr)
            wt->update_cutoff_time();
    }

    bool new_thread = false;
    //netkit::ipap tgtip;

	netkit::endpoint ep;
	netkit::pgen pg;
	netkit::thread_storage hss;
	netkit::thread_storage* hs = wt ? wt->geths() : &hss;
	if (!handle_packet(*hs, p, ep, pg))
		return;

    if (wt == nullptr)
    {
        wt = NEW udp_processing_thread(this, std::move(hss), p.from);
        rslt.first->second = wt;

        std::thread th(&handler::udp_worker, this, &lstnr, wt.get());
        th.detach();
        new_thread = true;
    }

    wt->convey(pg, ep);

	if (new_thread)
		log_new_udp_thread(p.from, ep);
}

void handler::udp_worker(netkit::socket* lstnr, udp_processing_thread* udp_wt)
{
    ptr::shared_ptr<udp_processing_thread> lock(udp_wt); // lock
    // handle answers
    udp_wt->udp_bridge(lstnr->s);
    release_udp(udp_wt);
}


//////////////////////////////////////////////////////////////////////////////////
//
// direct
//
//////////////////////////////////////////////////////////////////////////////////


handler_direct::handler_direct(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st):handler(ldr, owner,bb)
{
	to_addr = bb.get_string(ASTR("to"));
	if (!conn::is_valid_addr(to_addr))
	{
		ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
		LOG_E("{to} field of direct handler not defined or invalid (listener: [%s])", str::printable(owner->get_name()));
		return;
	}

	if (netkit::ST_UDP == st)
    {
        udp_timeout_ms = bb.get_int(ASTR("udp-timeout"), udp_timeout_ms);
	}
}

void handler_direct::on_pipe(netkit::pipe* pipe)
{
	std::thread th(&handler_direct::tcp_worker, this, pipe);
	th.detach();
}

/*virtual*/ void handler_direct::log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to)
{
    LOG_N("new UDP mapping (%s <-> %s) via listener [%s]", from.to_string(true).c_str(), to.desc().c_str(), str::printable(owner->get_name()));
}

/*virtual*/ bool handler_direct::handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg)
{
    if (ep.state() == netkit::EPS_EMPTY)
    {
        ep.preparse(to_addr);

        if (ep.state() == netkit::EPS_DOMAIN)
        {
            if (!proxychain.empty())
            {
                // keep unresolved, resolve via proxy
            }
            else
            {
                // try resolve
                ep.resolve_ip(glb.cfg.ipstack | conf::gip_log_it);
                if (ep.state() != netkit::EPS_RESLOVED)
                {
                cant:
                    ep = netkit::endpoint();
                    LOG_E("failed UDP mapping: can't use endpoint %s (listener [%s])", to_addr.c_str(), str::printable(owner->get_name()));
                    return false;
                }
            }
        }

        if (ep.port() == 0)
            goto cant;
    }

    epr = ep;
	pg.set(p, 0);

	return true;
}

void handler::udp_processing_thread::close()
{

}

void handler::udp_processing_thread::convey(netkit::pgen& p, const netkit::endpoint& tgt)
{
    if (sendor)
    {
        // send now
        sendor->send(tgt, p);
        return;
    }

    auto sb = sendb.lock_write();
    if (send_data* b = send_data::build(p.to_span(), tgt))
    {
        sb().emplace(b);
    }
    else {
        sb().emplace();
    }
}

void handler_direct::tcp_worker(netkit::pipe* pipe)
{
	// now try to connect to out

	netkit::pipe_ptr p(pipe);
	ep.preparse(to_addr);

	if (netkit::pipe_ptr outcon = connect(ep, false))
		bridge(std::move(p), std::move(outcon));
}


//////////////////////////////////////////////////////////////////////////////////
//
// socks
//
//////////////////////////////////////////////////////////////////////////////////

handler_socks::handler_socks(loader& ldr, listener* owner, const asts& bb, const str::astr_view& st) :handler(ldr, owner, bb)
{
	if (st == ASTR("4"))
		allow_5 = false;
	if (st == ASTR("5"))
		allow_4 = false;

	if (allow_4)
	{
        userid = bb.get_string(ASTR("userid"));
	}

    if (allow_5)
    {
        login = bb.get_string(ASTR("auth"));
        size_t dv = login.find(':');
        if (dv != login.npos)
        {
            pass = login.substr(dv + 1);
            login.resize(dv);
        }

        if (login.length() > 254 || pass.length() > 254)
        {
            login.clear();
            pass.clear();
        }

		if (login.empty() || bb.get_bool(ASTR("anon")))
			socks5_allow_anon = true;

		allow_udp_assoc = bb.get_bool(ASTR("udp-assoc"), true);

        str::astr bs = bb.get_string(ASTR("udp-bind"));
		udp_bind = netkit::ipap::parse(bs);
    }


}

void handler_socks::on_pipe(netkit::pipe* pipe)
{
	std::thread th(&handler_socks::handshake, this, pipe);
	th.detach();
}

void handler_socks::handshake(netkit::pipe* pipe)
{
	u8 packet[8];
	signed_t rb = pipe->recv(packet, -1);
	if (rb != 1)
		return;

	if (packet[0] == 4)
	{
		handshake4(pipe);
		return;
	}

	if (packet[0] == 5)
	{
		handshake5(pipe);
		return;
	}
}

void handler_socks::handshake4(netkit::pipe* pipe)
{
	if (!allow_4)
		return;

	u8 packet[8];
	signed_t rb = pipe->recv(packet, -7);
	if (rb != 7 || packet[0] != 1)
		return;

	u16 port = (((u16)packet[1]) << 8) | packet[2];
	netkit::ipap dst = netkit::ipap::build(packet + 3, 4, port);

	str::astr uid;
	for (;;)
	{
		rb = pipe->recv(packet, -1);
		if (rb != 1)
			return;
		if (packet[0] == 0 || uid.size() > 255)
			break;
		uid.push_back(packet[0]);
	}

	if (uid != userid)
	{
		packet[0] = 0;
		packet[1] = 93; // request rejected because the client program and identd report different user - ids
		packet[2] = 0; packet[3] = 0;
		packet[4] = 0; packet[5] = 0; packet[6] = 0; packet[7] = 0;

		pipe->send(packet, 8);
		return;
	}

	netkit::endpoint inf(dst);
	worker(pipe, inf, [port, dst](netkit::pipe* p, rslt ec) {

		u8 rp[8];

		rp[0] = 0;

		switch (ec)
		{
		case EC_GRANTED:
			rp[1] = 90;
			break;
		case EC_REMOTE_HOST_UNRCH:
			rp[1] = 92;
			break;
		default:
			rp[1] = 91;
			break;
		}

		rp[2] = (port>>8) & 0xff; rp[3] = port & 0xff;
		*(u32*)(rp + 4) = (u32)dst;

		p->send(rp, 8);
	});
}

namespace
{
	class udp_assoc_handler : public handler
	{
		netkit::ipap bind;
		netkit::pipe_ptr pipe;

		str::astr desc() const override { return str::astr(); }

		/*virtual*/ bool handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg) override
		{
			// udp assoc packet from initiator
            //  +-----+------+-------------
            //  | RSV | FRAG | ATYP...
            //  +-----+------+-------------
            //  |  2  |  1   | Variable...
            //  +-----+------+-------------

			netkit::pgen pgr(p.packet, p.sz);
			if (0 != pgr.read16()) // RSV, must be 0
				return false;

			if (0 != pgr.read8()) // FRAG, must be 0: fragmentation not supported yet
                return false;

			if (!proxy_socks5::read_atyp(pgr, epr))
				return false;

			pg.set(p, pgr.ptr);
			return true;
		}
        /*virtual*/ bool encode_packet(netkit::thread_storage& /*ctx*/, const netkit::ipap &from, netkit::pgen& pg) override
        {
            auto prepare_header = [](u8* packet, const netkit::endpoint& ep)
                {
                    netkit::pgen pgx(packet, 512);
                    pgx.push16(0); // RSV
                    pgx.push8(0); // FRAG

                    proxy_socks5::push_atyp(pgx, ep);
                };


			netkit::endpoint fep(from);
			signed_t presize = proxy_socks5::atyp_size(fep) + 3 /* 3 octets is: RSV and FRAG (see prepare_header) */;
			if (presize <= pg.extra)
			{
                netkit::pgen pgh(pg.get_data() - presize, pg.sz + presize);
				pgh.extra = tools::as_word(pg.extra - presize);
                prepare_header(pgh.get_data(), fep);
				pg = pgh;
				return true;
			}

			if (!pg.sz || pg.sz > 65535 - presize)
				return false;

			signed_t e = pg.extra;
			signed_t osz = pg.sz;
			pg.set_extra(0);
			memmove(pg.get_data() + presize, pg.get_data() + e, osz);
			prepare_header(pg.get_data(), netkit::ipap());
			return true;
        }
        /*virtual*/ signed_t udp_timeout() const override
        {
            return 0; // infinite because udp assoc keeps the connection until the tcp connection is disconnected
        }
        /*virtual*/ void on_listen_port(signed_t port) override
		{
            u8 rp[512];

            rp[0] = 5; // VER
            rp[1] = 0; // SUCCESS
            rp[2] = 0;

			netkit::pgen pg(rp + 3, 512 - 3);
			netkit::endpoint ep(bind);
			ep.set_port(port);
			proxy_socks5::push_atyp(pg, ep);
            pipe->send(rp, pg.ptr+3);
		}
	public:
        udp_assoc_handler(const netkit::ipap& bind, netkit::pipe* pipe) :bind(bind), pipe(pipe) {}
	};

	/*
    class udp_assoc_listener : public udp_listener
    {
	public:
		udp_assoc_listener(const netkit::ipap& bind, handler *h) :udp_listener(bind, h)
		{
		}
    };
	*/

}

void handler_socks::handshake5(netkit::pipe* pipe)
{
	if (!allow_5)
		return;

	u8 packet[512];
	signed_t rb = pipe->recv(packet, -1);
	if (rb != 1)
		return;

	signed_t numauth = packet[0];
	rb = pipe->recv(packet, -numauth);
	if (numauth != rb)
		return;

	u8 rauth = 0xff;

	for (signed_t i = 0; i < numauth && rauth != 0; ++i)
	{
		switch (packet[i])
		{
		case 0: // anonymous access request
			if (socks5_allow_anon && rauth > 0)
				rauth = 0;
			break;
		case 2:
			if (!login.empty() && rauth > 2)
				rauth = 2;
			break;
		}
	}

	packet[0] = 5;
	packet[1] = rauth;
	if (pipe->send(packet, 2) == netkit::pipe::SEND_FAIL || rauth == 0xff)
		return;

	if (rauth == 2)
	{
		// wait for auth packet
		rb = pipe->recv(packet, -2);
		if (rb != 2 || packet[0] != 1)
			return;
		signed_t loginlen = 1 + packet[1]; // and one byte - len of pass
		rb = pipe->recv(packet, -loginlen);
		if (rb != loginlen)
			return;
		str::astr rlogin, rpass;
		rlogin.append((const char *)packet, loginlen - 1);
		signed_t passlen = packet[loginlen - 1];
		rb = pipe->recv(packet, -passlen);
		if (rb != passlen)
			return;
		rpass.append((const char*)packet, passlen);

		if (rlogin != login || rpass != pass)
		{
			packet[0] = 1;
			packet[1] = 1;
			pipe->send(packet, 2);
			return;
		}
		packet[0] = 1;
		packet[1] = 0;
		pipe->send(packet, 2);
	}

	auto fail_answer = [&](u8 code)
	{
		packet[0] = 5; // VER
		packet[1] = code; // REP // FAILURE
		packet[2] = 0;
		packet[3] = 1; // ATYPE // ip4
		packet[4] = 0; packet[5] = 0; packet[6] = 0; packet[7] = 0;
		packet[8] = 0; packet[9] = 0;
		pipe->send(packet, 10);
	};

	rb = pipe->recv(packet, -5);
	if (rb != 5 || packet[0] != 5)
	{
		fail_answer(1); // FAILURE
		return;
	}

	if (allow_udp_assoc && packet[1] == 3 /* UDP ASSOC */)
	{
		// skip addr and port
		switch (packet[3])
		{
        case 1: // ip4
            rb = pipe->recv(packet + 5, -3-2);
            if (rb != 5)
                return;
            break;
        case 3: // domain name

            numauth = packet[4] + 2; // len of domain
            rb = pipe->recv(packet, -numauth);
            if (rb != numauth)
                return;
            break;

        case 4: // ipv6
            rb = pipe->recv(packet + 5, -15-2); // read 15 of 16 bytes of ipv6 address (1st byte already read) and 2 bytes port
            if (rb != 17)
                return;
            break;
		}

		udp_assoc_handler udph(udp_bind, pipe);
		udp_listener udpl(udp_bind, &udph);
		udpl.open();

		for (;;)
        {
			u8 garbage[512];
			auto rslt = netkit::wait(pipe->get_waitable(), -1);
			if (rslt == netkit::WR_CLOSED)
				break;
			if (rslt == netkit::WR_READY4READ)
				pipe->recv(garbage, sizeof(garbage));
		}

		udpl.stop();
		return;
	}

	if (packet[1] != 1 /* only CONNECT for now */)
	{
		fail_answer(7); // COMMAND NOT SUPPORTED
		return;
	}

	netkit::endpoint ep;

	switch (packet[3])
	{
	case 1: // ip4
		rb = pipe->recv(packet + 5, -3);
		if (rb != 3)
			return;
		ep.set_ipap(netkit::ipap::build(packet + 4, 4));
		break;
	case 3: // domain name

		numauth = packet[4]; // len of domain
		rb = pipe->recv(packet, -numauth);
		if (rb != numauth)
			return;
		ep.set_domain( str::astr((const char *)packet, numauth) );
		break;

	case 4: // ipv6
		rb = pipe->recv(packet + 5, -15); // read 15 of 16 bytes of ipv6 address (1st byte already read)
		if (rb != 15)
			return;
		ep.set_ipap(netkit::ipap::build(packet + 4, 16));
		break;
	}

	rb = pipe->recv(packet, -2);
	if (rb != 2)
		return;

	signed_t port = ((signed_t)packet[0]) << 8 | packet[1];
	ep.set_port(port);

	worker(pipe, ep, [port, &ep](netkit::pipe* p, rslt ec) {

		u8 rp[10];

		rp[0] = 5; // VER
		rp[2] = 0;
		rp[3] = 1; // ATYPE // ip4

		switch (ec)
		{
		case EC_GRANTED:
			rp[1] = 0; // SUCCESS
			break;
		case EC_REMOTE_HOST_UNRCH:
			rp[1] = 4;
			break;
		default:
			rp[1] = 1;
			break;
		}

		*(u32*)(rp + 4) = 0; // (u32)ep.get_ip(conf::gip_only4);
		rp[8] = (port >> 8) & 0xff;
		rp[9] = port & 0xff;
		p->send(rp, 10);
	});
}


void handler_socks::worker(netkit::pipe* pipe, netkit::endpoint &inf, sendanswer answ)
{
	// now try to connect to out

	netkit::pipe_ptr p(pipe);
	if (netkit::pipe_ptr outcon = connect(inf, false))
	{
		answ( pipe, EC_GRANTED );
		bridge(std::move(p), std::move(outcon));
	}
	else {
		answ(pipe, EC_REMOTE_HOST_UNRCH);
	}

}
