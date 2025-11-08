#include "pch.h"

void udp_processing_thread::update_cutoff_time()
{
    auto to = h->udp_timeout();
    cutoff_time = to == 0 ? chrono::mils() : chrono::ms(to);
}

void udp_processing_thread::close()
{

}

void udp_processing_thread::convey(netkit::pgen& p, const netkit::endpoint& tgt)
{
    if (sendor)
    {
        // send now
        sendor->send(tgt, p);
        return;
    }

    if (send_data* b = send_data::build(p.to_span(), tgt))
    {
        sendb.enqueue([b](sdptr& ptr) { ptr.reset(b); });
    }
    else {
        sendb.enqueue([](sdptr& ptr) { ptr.reset(); });
    }
}

/*virtual*/ netkit::io_result udp_processing_thread::send(const netkit::endpoint& toaddr, const netkit::pgen& pg)
{
    return netkit::udp_send(ts, toaddr, pg);
}
/*virtual*/ netkit::io_result udp_processing_thread::recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size)
{
    return netkit::udp_recv(ts, from, pg, max_bufer_size);
}


void udp_processing_thread::udp_bridge(netkit::datagram_socket* initiator)
{
    u8 packet[65536];
    netkit::pgen pg(packet, 65535);
    if (auto to = h->udp_timeout(); to > 0)
        cutoff_time = chrono::ms(to);

    netkit::udp_pipe* pipe = this;
    std::unique_ptr<netkit::udp_pipe> proxypipe;

    if (const proxy* prx = h->udp_proxy())
    {
        proxypipe = prx->prepare(this);
        pipe = proxypipe.get();
        if (!pipe)
            return;

        LOG_N("UDP connection from $ via proxy $ established", froma.to_string(), prx->desc());
    }

    for (auto loopstart = chrono::ms();;)
    {
        sdptr b;
        if (sendb.dequeue([&](sdptr& sb) { b = std::move(sb); }))
        {
            if (b == nullptr)
                return; // stop due error
            netkit::pgen spg(b->data(), b->datasz, b->pre());
            pipe->send(b->tgt, spg);
        }
        else
        {
            if (!ts.data)
            {
                // wait for send and init thread storage for pipe
                spinlock::sleep(0);

                auto ct = chrono::ms();
                if ((ct - loopstart) > 1000)
                {
                    // no data too long
                    return;
                }

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
        auto ior = pipe->recv(from, pg, 65535 - 32);
        if (ior != netkit::ior_ok)
        {
            if (ior == netkit::ior_timeout && !is_timeout(chrono::ms()))
                continue;
            break;
        }
        if (!h->encode_packet(handler_state, from, pg))
            break;
        if (!initiator->sendto(froma, pg.to_span()))
            break;

        if (auto to = h->udp_timeout(); to > 0)
            cutoff_time = chrono::ms(to);

    }
    sendor = nullptr;
}

void udp_dispatcher::release_udps()
{
#ifdef _DEBUG
    ASSERT(spinlock::current_thread_uid() == check_tid);
#endif // _DEBUG

    auto keys = std::move(finished.lock_write()());

    for (const auto& k : keys)
        udp_pth.erase(k);
}

void udp_dispatcher::release_udp(udp_processing_thread* udp_wt)
{
    finished.lock_write()().push_back(udp_wt->from());
}

void udp_dispatcher::stop()
{
#ifdef _DEBUG
    ASSERT(check_tid == 0 || spinlock::current_thread_uid() == check_tid);
#endif // _DEBUG


    for (auto& pp : udp_pth)
    {
        if (pp.second)
            pp.second->close();
    }

    for (; !udp_pth.empty();)
    {
        spinlock::sleep(100);
        release_udps();
    }
}

void udp_dispatcher::udp_dispatch(netkit::datagram_socket& lstnr, netkit::udp_packet& p)
{
    ptr::shared_ptr<udp_processing_thread> wt;

    release_udps();
    auto [it, inserted] = udp_pth.try_emplace(p.from, nullptr);

    if (!inserted)
    {
        wt = it->second; // already exist, return it

        if (wt != nullptr)
            wt->update_cutoff_time();
    }

    bool log_new_thread = false;

    netkit::endpoint ep;
    netkit::pgen pg;
    netkit::thread_storage hss;
    netkit::thread_storage* hs = wt ? wt->geths() : &hss;
    if (!handle_packet(*hs, p, ep, pg))
        return;

    if (wt == nullptr)
    {
        wt = NEW udp_processing_thread(this, std::move(hss), p.from);
        it->second = wt;
        glb.e->new_udp_pipe(this, wt.get(), &lstnr);
        log_new_thread = log_enabled();
    }

    wt->convey(pg, ep);

    if (log_new_thread)
        log_new_udp_thread(p.from, ep);

}

void udp_dispatcher::udp_worker(netkit::datagram_socket* lstnr, udp_processing_thread* udp_wt)
{
    ostools::set_current_thread_name(str::build_string("udp-wrk $", udp_wt->from().to_string()));

    // handle answers
    udp_wt->udp_bridge(lstnr);
    release_udp(udp_wt);

}

