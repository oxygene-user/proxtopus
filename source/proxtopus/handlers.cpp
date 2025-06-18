#include "pch.h"

handler* handler::new_handler(loader& ldr, listener *owner, const asts& bb, netkit::socket_type_e st)
{
    const str::astr &t = bb.get_string(ASTR("type"), glb.emptys);
    if (t.empty())
    {
        ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
        LOG_FATAL("{type} not defined for handler of listener [$]^", str::clean(owner->get_name()));
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
            LOG_FATAL("{$} handler can only be used with TCP type of listener [$]", t, str::clean(owner->get_name()));
            return nullptr;
        }

        h = NEW handler_socks(ldr, owner, bb, str::view(t).substr(5));
    }
    else if (ASTR("shadowsocks") == t)
    {
        h = NEW handler_ss(ldr, owner, bb, st);
    }
    else if (ASTR("http") == t)
    {
        h = NEW handler_http(ldr, owner, bb, st);
    }

#ifdef _DEBUG
    else if (ASTR("debug") == t)
    {
        h = NEW handler_debug(ldr, owner, bb, st);
    }
#endif

    if (h != nullptr)
    {
        if (ldr.exit_code != 0)
        {
            delete h;
            return nullptr;
        }
        return h;
    }

    LOG_FATAL("unknown {type} [$] for handler of listener [$]^", str::clean(t), str::clean(owner->get_name()));
    ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
    return nullptr;
}

handler::handler(loader& ldr, listener* owner, const asts& bb):owner(owner)
{
    const proxy* p = nullptr;
    str::astr_view pch = str::view(bb.get_string(ASTR("udp-proxy"), glb.emptys));
    if (!pch.empty())
    {
        p = ldr.find_proxy(pch);
        if (p == nullptr)
        {
        per:
            LOG_FATAL("unknown {proxy} [$] for handler of listener [$]", pch, str::clean(owner->get_name()));
            ldr.exit_code = EXIT_FAIL_PROXY_NOTFOUND;
            return;
        }

        if (!p->support(netkit::ST_UDP))
        {
            ldr.exit_code = EXIT_FAIL_SOCKET_TYPE;
            LOG_FATAL("upstream {proxy} [$] does not support UDP protocol (listener: [$])", pch, str::clean(owner->get_name()));
            return;
        }

        udp_proxy = p;
    }

    pch = str::view(bb.get_string(ASTR("proxychain"), glb.emptys));
    if (!pch.empty())
    {
        enum_tokens_a(tkn, pch, ',')
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

void handler::make_bridge(tools::circular_buffer_extdata& rcvd, const str::astr& epa, netkit::pipe* clientpipe, mbresult res)
{
    netkit::pipe_ptr p(clientpipe);
    netkit::endpoint ep;
    ep.preparse(epa);

    if (netkit::pipe_ptr outcon = connect(ep, false))
    {
        res(true);
        p->unrecv(rcvd);
        glb.e->bridge(std::move(p), std::move(outcon));
    }
    else
        res(false);
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


void handler::release_udps()
{
#ifdef _DEBUG
    ASSERT(spinlock::current_thread_uid() == owner->accept_tid);
#endif // _DEBUG

    auto keys = std::move( finished.lock_write()() );

    for(const auto &k : keys)
        udp_pth.erase(k);
}

void handler::release_udp(udp_processing_thread* udp_wt)
{
    finished.lock_write()().push_back(udp_wt->key());
}


netkit::pipe_ptr handler::connect(netkit::endpoint& addr, bool direct)
{
    static size_t tag = 1;

    if (direct || proxychain.size() == 0)
    {
        if (netkit::pipe* pipe = conn::connect(addr))
        {
            if (proxychain.size() == 0)
            {
                LOG_N("connected to ($) via listener [$]", addr.desc(), str::clean(owner->get_name()));
            }

            netkit::pipe_ptr pp(pipe);
            return pp;
        }

        if (proxychain.size() == 0)
        {
            LOG_N("not connected to ($) via listener [$]", addr.desc(), str::clean(owner->get_name()));
        }

        return netkit::pipe_ptr();
    }

    size_t t = spinlock::atomic_increment(tag);
    str::astr stag(ASTR("[")); str::append_num(stag,t,0); stag.append(ASTR("] "));

    size_t tl = stag.size();

    auto ps = [&](const str::astr_view& s)
    {
        stag.resize(tl);
        stag.append(s);
    };

    //LOG_N("listener {$} has been started (bind ip: $, port: $)", str::printable(name), bind2.to_string(), port);

    if (proxychain.size() == 1)
    {
        ps("connecting to upstream proxy ($) via listener [$]"); LOG_N(stag.c_str(), proxychain[0]->desc(), str::clean(owner->get_name()));
    }
    else
    {
        ps("connecting through proxy chain via listener [$]"); LOG_N(stag.c_str(), str::clean(owner->get_name()));
        ps("connecting to proxy ($)"); LOG_N(stag.c_str(), proxychain[0]->desc());
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
            ps("connecting to address ($)"); LOG_N(stag.c_str(), na.desc());
        }
        else
        {
            ps("connecting to proxy ($)"); LOG_N(stag.c_str(), proxychain[i + 1]->desc());
        }

        pp = proxychain[i]->prepare(pp, na);
    }
    return pp;
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

        LOG_N("UDP connection from $ via proxy $ established", hashkey.to_string(true), prx->desc());
    }

    for(auto loopstart = chrono::ms();;)
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

/*virtual*/ void handler::api(json_saver& j) const
{
    j.field(ASTR("type"), desc());
    if (proxychain.size() > 0)
    {
        j.arr(ASTR("proxychain"));
        for (const proxy* p : proxychain)
            j.num(p->get_id());
        j.arrclose();
    }
    if (udp_proxy)
        j.field(ASTR("udp-proxy"), udp_proxy->get_id());
}

void handler::stop()
{

    if (owner == nullptr)
        return;

#ifdef _DEBUG
    ASSERT(owner->accept_tid == 0 || spinlock::current_thread_uid() == owner->accept_tid);
#endif // _DEBUG

    for (auto &pp : udp_pth)
    {
        if (pp.second)
            pp.second->close();
    }

    for (; !udp_pth.empty();)
    {
        spinlock::sleep(100);
        release_udps();
    }

    owner = nullptr;
}

void handler::udp_dispatch(netkit::socket& lstnr, netkit::udp_packet& p)
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
    ostools::set_current_thread_name(str::build_string("udp-wrk $", udp_wt->key().to_string(true)));

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
    to_addr = bb.get_string(ASTR("to"), glb.emptys);
    if (!conn::is_valid_addr(to_addr))
    {
        ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
        LOG_FATAL("{to} field of direct handler not defined or invalid (listener: [$])", str::clean(owner->get_name()));
        return;
    }

    if (netkit::ST_UDP == st)
    {
        udp_timeout_ms = bb.get_int(ASTR("udp-timeout"), udp_timeout_ms);
    }
}

void handler_direct::handle_pipe(netkit::pipe* pipe)
{
    // now try to connect to out

    netkit::pipe_ptr p(pipe);
    ep.preparse(to_addr);

    if (netkit::pipe_ptr outcon = connect(ep, false))
    {
        glb.e->bridge(std::move(p), std::move(outcon));
    }
}


/*virtual*/ void handler_direct::log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to)
{
    LOG_N("new UDP mapping ($ <-> $) via listener [$]", from.to_string(true), to.desc(), str::clean(owner->get_name()));
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
                    LOG_E("failed UDP mapping: can't use endpoint $ (listener [$])", to_addr, str::clean(owner->get_name()));
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
        userid = bb.get_string(ASTR("userid"), glb.emptys);
    }

    if (allow_5)
    {
        login = bb.get_string(ASTR("auth"), glb.emptys);
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

        const str::astr &bs = bb.get_string(ASTR("udp-bind"), glb.emptys);
        udp_bind = netkit::ipap::parse(bs);

        allow_private = bb.get_bool(ASTR("allow-private"), true);

    }


}

void handler_socks::handle_pipe(netkit::pipe* pipe)
{
    u8 packet[512];
    tools::circular_buffer_extdata rcvb( std::span(packet, sizeof(packet)) );
    if (signed_t rb = pipe->recv(rcvb, 1, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 1)
        return;

    if (packet[0] == 4)
    {
        rcvb.skip(1);
        handshake4(rcvb, pipe);
        return;
    }

    if (packet[0] == 5)
    {
        rcvb.skip(1);
        handshake5(rcvb, pipe);
        return;
    }
}

void handler_socks::handshake4(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe)
{
    if (!allow_4)
        return;

    signed_t rb = pipe->recv(rcvd, 7, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
    const u8* packet = rcvd.data1st(7);
    if (rb != 7 || packet[0] != 1)
        return;

    u16 port = (((u16)packet[1]) << 8) | packet[2];
    netkit::ipap dst = netkit::ipap::build(packet + 3, 4, port);

    if (!allow_private && dst.is_private())
        return;

    rcvd.skip(7);

    str::astr uid;
    for (;;)
    {
        rb = pipe->recv(rcvd, 1, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
        if (rb != 1)
            return;
        u8 byt = rcvd.getle<u8>();
        if (byt == 0 || uid.size() > 255)
            break;
        uid.push_back(byt);
    }

    if (uid != userid)
    {
        u8 sb[8] = {0, 93, 0, 0, 0, 0, 0, 0}; // request rejected because the client program and identd report different user - ids
        pipe->send(sb, 8);
        return;
    }

    netkit::endpoint inf(dst);
    worker(rcvd, pipe, inf, [port, dst](netkit::pipe* p, rslt ec) {

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
        bool allow_private;

        str::astr_view desc() const override { return str::astr_view(); }

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

            if (!allow_private && epr.state() == netkit::EPS_RESLOVED && epr.get_ip().is_private())
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
        udp_assoc_handler(const netkit::ipap& bind, netkit::pipe* pipe, bool allow_private) :bind(bind), pipe(pipe), allow_private(allow_private) {}
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

void handler_socks::handshake5(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe)
{
    if (!allow_5)
        return;

    if (signed_t rb = pipe->recv(rcvd, 1, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 1)
        return;
    u8 numauth = rcvd.getle<u8>();
    if (signed_t rb = pipe->recv(rcvd, numauth, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); numauth != rb)
        return;

    u8 rauth = 0xff;
    const u8* packet = rcvd.data1st(numauth);
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
    rcvd.skip(numauth);

    u8 temp[16];
    temp[0] = 5;
    temp[1] = rauth;
    if (pipe->send(temp, 2) == netkit::pipe::SEND_FAIL || rauth == 0xff)
        return;

    if (rauth == 2)
    {
        // wait for auth packet
        signed_t rb = pipe->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
        packet = rcvd.data1st(2);
        if (rb != 2 || packet[0] != 1)
            return;
        signed_t loginlen = 1 + packet[1]; // and one byte - len of pass
        rcvd.skip(2);
        if (rb = pipe->recv(rcvd, loginlen, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != loginlen)
            return;
        str::astr rlogin, rpass;
        rcvd.peek(rlogin, loginlen-1);
        u8 passlen = rcvd.getle<u8>();
        if (rb = pipe->recv(rcvd, passlen, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != passlen)
            return;
        rcvd.peek(rpass, passlen);

        temp[0] = 1;
        if (rlogin != login || rpass != pass)
        {
            temp[1] = 1;
            pipe->send(temp, 2);
            return;
        }
        temp[1] = 0;
        pipe->send(temp, 2);
    }

    auto fail_answer = [&](u8 code)
    {
        temp[0] = 5; // VER
        temp[1] = code; // REP // FAILURE
        temp[2] = 0;
        temp[3] = 1; // ATYPE // ip4
        temp[4] = 0; temp[5] = 0; temp[6] = 0; temp[7] = 0;
        temp[8] = 0; temp[9] = 0;
        pipe->send(temp, 10);
    };

    if (signed_t rb = pipe->recv(rcvd, 5, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 5)
    {
        fail_answer(1); // FAILURE
        return;
    }

    packet = rcvd.data1st(5);
    if (packet[0] != 5)
    {
        fail_answer(1); // FAILURE
        return;
    }

    if (allow_udp_assoc && packet[1] == 3 /* UDP ASSOC */)
    {
        //rcvd have 5 bytes not skipped

        // skip addr and port
        switch (packet[3])
        {
        case 1: // ip4
            if (signed_t rb = pipe->recv(rcvd, 5 + 3 + 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 5 + 3 + 2)
                return;
            break;
        case 3: // domain name

            numauth = packet[4] + 5+2; // len of domain
            if (signed_t rb = pipe->recv(rcvd, numauth, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != numauth)
                return;
            break;

        case 4: // ipv6
            // read 15 of 16 bytes of ipv6 address (1st byte already read) and 2 bytes port
            if (signed_t rb = pipe->recv(rcvd, 15 + 2 + 5, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 15 + 2 + 5)
                return;
            break;
        }

        udp_assoc_handler udph(udp_bind, pipe, allow_private);
        udp_listener udpl(udp_bind, &udph);
        udpl.open();

        for (;!glb.is_stop();)
        {
            rcvd.clear();
            auto rslt = netkit::wait(pipe->get_waitable(), -1);
            if (rslt == netkit::WR_CLOSED)
                break;
            if (rslt == netkit::WR_READY4READ)
                pipe->recv(rcvd, 0, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
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

    // 5 is number of not skipped bytes in rcvd

    switch (packet[3])
    {
    case 1: // ip4
        if (signed_t rb = pipe->recv(rcvd, 5 + 3, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 5+3)
            return;
        ep.set_ipap(netkit::ipap::build(packet + 4, 4));
        rcvd.skip(5 + 3);
        break;
    case 3: // domain name

        numauth = packet[4] + 5; // len of domain
        if (signed_t rb = pipe->recv(rcvd, numauth, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != numauth)
            return;
        ep.set_domain( str::astr_view((const char *)packet+5, numauth-5) );
        rcvd.skip(numauth);
        break;

    case 4: // ipv6
        // read 15 of 16 bytes of ipv6 address (1st byte already read) (also 5 bytes already read)
        if (signed_t rb = pipe->recv(rcvd, 5 + 15, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 5+15)
            return;
        ep.set_ipap(netkit::ipap::build(packet + 4, 16));
        rcvd.skip(5 + 15);
        break;
    }

    if (!allow_private && ep.state() == netkit::EPS_RESLOVED && ep.get_ip().is_private())
        return;

    if (signed_t rb = pipe->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 2)
        return;

    const u8* port_ptr = rcvd.data1st(2);
    signed_t port = ((signed_t)port_ptr[0]) << 8 | port_ptr[1];
    ep.set_port(port);

    rcvd.skip(2);

    worker(rcvd, pipe, ep, [port, &ep](netkit::pipe* p, rslt ec) {

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


void handler_socks::worker(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe, netkit::endpoint &inf, sendanswer answ)
{
    // now try to connect to out

    netkit::pipe_ptr p(pipe);
    if (netkit::pipe_ptr outcon = connect(inf, false))
    {
        answ( pipe, EC_GRANTED );
        p->unrecv(rcvd);
        glb.e->bridge(std::move(p), std::move(outcon));
    }
    else {
        answ(pipe, EC_REMOTE_HOST_UNRCH);
    }

}
