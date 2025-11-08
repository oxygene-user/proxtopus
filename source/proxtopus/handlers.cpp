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
    else if (ASTR("dummy") == t)
    {
        h = NEW handler_dummy(ldr, owner, bb);
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
    auto lazyinfo = [owner]() -> str::astr
    {
        str::astr s(ASTR("listener: ["));
        str::clean(owner->get_name()).append_to(s);
        s.push_back(']');
        return s;
    };

    ups.load(ldr, bb, lazyinfo);
}

void handler::make_bridge(tools::circular_buffer_extdata& rcvd, const str::astr& epa, netkit::pipe* clientpipe, mbresult res)
{
    netkit::pipe_ptr pp(clientpipe); // just keep ref
    netkit::endpoint ep;
    ep.preparse(epa);

    ups_conn_log clogger(owner->get_name(), clientpipe, &ep);

    if (netkit::pipe_ptr outcon = ups.connect(clogger, ep, false))
    {
        res(true);
        clientpipe->unrecv(rcvd);
        glb.e->bridge(clientpipe, outcon.get());
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

/*virtual*/ void handler::api(json_saver& j) const
{
    j.field(ASTR("type"), desc());
    ups.api(j);
}

void handler::stop()
{
    if (owner == nullptr)
        return;

    udp_dispatcher::stop();

    owner = nullptr;
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
    ep.preparse(to_addr);

    ups_conn_log clogger(owner->get_name(), pipe, &ep);

    if (netkit::pipe_ptr outcon = ups.connect(clogger, ep, false))
    {
        glb.e->bridge(pipe, outcon.get());
    }
}


/*virtual*/ void handler_direct::log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to)
{
    LOG_N("new UDP mapping ($ <-> $) via listener [$]", from.to_string(), to.desc(), str::clean(owner->get_name()));
}

/*virtual*/ bool handler_direct::handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg)
{
    if (ep.state() == netkit::EPS_EMPTY)
    {
        ep.preparse(to_addr);

        if (ep.state() == netkit::EPS_DOMAIN)
        {
            if (!ups.is_proxychain_empty())
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


//////////////////////////////////////////////////////////////////////////////////
//
// socks
//
//////////////////////////////////////////////////////////////////////////////////

handler_socks::handler_socks(loader& ldr, listener* owner, const asts& bb, const str::astr_view& st) :handler(ldr, owner, bb)
{
    if (st == ASTR("4"))
        flags.unset<f_allow_5>();
    if (st == ASTR("5"))
        flags.unset<f_allow_4>();

    if (flags.is<f_allow_4>())
    {
        const str::astr& userid = bb.get_string(ASTR("userid"), glb.emptys);
        if (!userid.empty())
            authdata = std::make_unique<auth_data>();
    }

    if (flags.is<f_allow_5>())
    {
        const asts *authpar = bb.get(ASTR("auth"));
        const asts* obfs_authpar = bb.get(ASTR("obfs-auth"));

        str::astr login, pass;

        if (authpar != nullptr)
        {
            const str::astr &auths = authpar->as_string(glb.emptys);

            if (size_t dv = auths.find(':'); dv != login.npos)
            {
                pass = str::substr(auths, dv + 1);
                login = str::substr(auths, 0, dv);

                if (login.length() > 254 || pass.length() > 254)
                {
                    ldr.exit_code = EXIT_FAIL_AUTH_INVALID;
                    LOG_FATAL("auth too long (listener: $)", str::clean(owner->get_name()));
                    return;
                }

                if (!authdata)
                    authdata = std::make_unique<auth_data>();
                authdata->login = login;
                authdata->pass = pass;
                if (authpar->has_elements())
                {
                    const str::astr& allowrules = authpar->get_string(ASTR("allow"), glb.emptys);
                    if (!allowrules.empty())
                    {
                        macro_context ctx(&bb);
                        if (!authdata->parse(ctx, allowrules))
                        {
                            ldr.exit_code = EXIT_FAIL_EXPRESSION_INVALID;
                            LOG_FATAL("can't parse allow expression (auth, listener: $)", str::clean(owner->get_name()));
                            return;
                        }
                    }
                }
            }
            else
                login.clear();
        }

        if (obfs_authpar != nullptr)
        {
            str::astr_view pass1, login1;
            const str::astr& oauths = obfs_authpar->as_string(glb.emptys);
            if (size_t dv = oauths.find(':'); dv != login.npos)
            {
                pass1 = str::substr(oauths, dv + 1);
                login1 = str::substr(oauths, 0, dv);
            }
            if (login1.empty() || pass1.empty())
            {
                ldr.exit_code = EXIT_FAIL_AUTH_INVALID;
                LOG_FATAL("{obfs-auth} is invalid (must be {obfs-auth}=user:pass) (listener: $)", str::clean(owner->get_name()));
                return;
            }

            if (login.length() == 16 && pass.length() == 32)
            {
                LOG_FATAL("please change length of login or pass of {auth} param (not compatible with {obfs-auth}) (listener: $)", str::clean(owner->get_name()));
                ldr.exit_code = EXIT_FAIL_AUTH_INVALID;
                return;
            }

            obfsdata = std::make_unique<obfs_data>();
            ss::core::keyspace zeros(true);
            ss::core::keyspace ons(true); ons.space[1] = 1;
            hkdf< hmac<sha256> >::perform_kdf(std::span(obfsdata->masterkey), zeros.span(), ons.span(), str::span(oauths));

            if (obfs_authpar->has_elements())
            {
                const str::astr& allowrules = obfs_authpar->get_string(ASTR("allow"), glb.emptys);
                if (!allowrules.empty())
                {
                    macro_context ctx(&bb);
                    if (!obfsdata->parse(ctx, allowrules))
                    {
                        ldr.exit_code = EXIT_FAIL_EXPRESSION_INVALID;
                        LOG_FATAL("can't parse allow expression (obfs-auth, listener: $)", str::clean(owner->get_name()));
                        return;
                    }
                }
            }
        }

        if ((login.empty() && !obfsdata) || bb.get_bool(ASTR("anon")))
            flags.set<f_socks5_allow_anon>();

        flags.set<f_allow_udp_assoc>(bb.get_bool(ASTR("udp-assoc"), true));

        const str::astr& bs = bb.get_string(ASTR("udp-bind"), glb.emptys);
        udp_bind = netkit::ipap::parse(bs);

        if (!flags.is<f_socks5_allow_anon>() && flags.is<f_allow_4>() && (authdata == nullptr || authdata->userid.empty()))
        {
            LOG_FATAL("anonymous socks4 not allowed (listener: $)", str::clean(owner->get_name()));
            ldr.exit_code = EXIT_FAIL_AUTH_INVALID;
            return;
        }

        if (flags.is<f_socks5_allow_anon>() || flags.is<f_allow_4>())
        {
            macro_context ctx(&bb);
            const str::astr& allow = bb.get_string(ASTR("allow"), glb.emptys);
            if (allow.empty())
            {
                defexpr = std::make_unique<expression>();
                defexpr->parse(ctx, ASTR("!prvt()")); // means "disable private target"
                LOG_W("{allow} rule not defined for listener $; default rule has been applied (\"!prvt()\")", str::clean(owner->get_name()));
            } else
            {
                defexpr = std::make_unique<expression>();
                if (!defexpr->parse(ctx, allow))
                {
                    ldr.exit_code = EXIT_FAIL_EXPRESSION_INVALID;
                    LOG_FATAL("can't parse anon allow expression (listener: $)", str::clean(owner->get_name()));
                    return;
                }
            }
        }

    }

}

void handler_socks::handle_pipe(netkit::pipe* pipe)
{
    tools::circular_buffer_preallocated<2048> rcvb;
    if (signed_t rb = pipe->recv(rcvb, 1, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 1)
        return;

    u8 ver = rcvb.getle<u8>();
    if (ver == 4)
    {
        handshake4(rcvb, pipe);
        return;
    }

    if (ver == 5)
    {
        handshake5(rcvb, pipe);
        return;
    }

    pipe->close(false);
}

void handler_socks::handshake4(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe)
{
    if (!flags.is<f_allow_4>())
        return;

    signed_t rb = pipe->recv(rcvd, 7, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
    u8 temp[8];
    const u8* packet = rcvd.plain_data(temp, 7);
    if (rb != 7 || packet[0] != 1)
        return;

    u16 port = load_be<2>(packet + 1);
    netkit::ipap dst = netkit::ipap::build(packet + 3, 4, port);

    if (defexpr)
    {
        netkit::endpoint epsrc(pipe->get_remote_ipap()), eptgt(dst);
        econtext ctx(&epsrc, &eptgt, !ups.is_proxychain_empty()); // CONTEXT
        if (defexpr->calc(ctx) == 0)
            return;
    }

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

    if (authdata)
    {
        if (uid != authdata->userid)
        {
            u8 sb[8] = { 0, 93, 0, 0, 0, 0, 0, 0 }; // request rejected because the client program and identd report different user - ids
            pipe->send(sb, 8);
            return;
        }

    }
    else
    {
        // pass any userid if server not configured for auth
    }

    netkit::endpoint inf(dst);
    ups_conn_log clogger(owner->get_name(), pipe, &inf);
    if (netkit::pipe_ptr outcon = ups.connect(clogger, inf, false))
    {
        pipe->unrecv(rcvd);

        temp[0] = 0;
        temp[1] = 90;
        temp[2] = (port >> 8) & 0xff;
        temp[3] = port & 0xff;
        *(u32*)(temp + 4) = (u32)dst;
        pipe->send(temp, 8);

        glb.e->bridge(pipe, outcon.get());
    }
    else {

        temp[0] = 0;
        temp[1] = 92;
        temp[2] = (port >> 8) & 0xff;
        temp[3] = port & 0xff;
        *(u32*)(temp + 4) = (u32)dst;
        pipe->send(temp, 8);
    }
}

namespace
{
    class udp_assoc_handler : public handler
    {
        netkit::ipap bind;
        netkit::pipe_ptr pipe;
        const expression * allow_check;

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

            if (allow_check)
            {
                netkit::endpoint epsrc(pipe->get_remote_ipap());
                econtext ctx(&epsrc, &epr, !ups.is_proxychain_empty()); // CONTEXT
                if (allow_check->calc(ctx) == 0)
                {
                    LOG_W("{allow} rule rejects udp packet $ -> $ ($)", p.from.to_string(), epr.desc(), this->desc());
                    return false;
                }
            }

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
        /*virtual*/ void on_listen_port(size_t port) override
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
        udp_assoc_handler(const netkit::ipap& bind, netkit::pipe* pipe, const expression* allow) :bind(bind), pipe(pipe), allow_check(allow) {}
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

    struct decode_sni_socket : public netkit::replace_socket
    {
        chacha20 decoder;
        bool first_packet = true;
        decode_sni_socket(chacha20&& enc) :decoder(std::move(enc)) {}

        /*virtual*/ system_socket* update(std::unique_ptr<system_socket>& mp) override
        {
            if (!first_packet)
            {
                mp = std::move(sock);
            }
            return mp.get();
        }

        /*virtual*/ u8 setup_wait_slot(netkit::wait_slot* slot) override
        {
            return sock->setup_wait_slot(slot);
        }
        /*virtual*/ u8 get_event_info(netkit::wait_slot* slot) override
        {
            return sock->get_event_info(slot);
        }
        /*virtual*/ void readypipe(bool rp) override
        {
            sock->readypipe(rp);
        }
        /*virtual*/ u8 wait(size_t evts, signed_t timeout_ms) override
        {
            return sock->wait(evts, timeout_ms);
        }
        /*virtual*/ bool connect(const netkit::ipap& a, netkit::socket_info_func sif) override
        {
            return sock->connect(a, sif);
        }
        /*virtual*/ void sendfull(bool sff) override
        {
            sock->sendfull(sff);
        }
        /*virtual*/ signed_t send(std::span<const u8> data) override
        {
            return sock->send(data);
        }
        /*virtual*/ void close(bool flush_before_close) override
        {
            sock->close(flush_before_close);
        }
        /*virtual*/ signed_t recv(tools::memory_pair& mp) override
        {
            signed_t rv = sock->recv(mp);

            if (first_packet && rv > 0)
            {
                first_packet = false;
                size_t psz = rv;
                bool already_plain = psz <= mp.p0.size();
                u8* plainbuf = already_plain ? mp.p0.data() : ALLOCA(psz);
                if (!already_plain) mp.copy_out(plainbuf, psz);
                std::span<const u8> snin = extract_tls_clienthello_sni(plainbuf, psz);
                if (!snin.empty())
                {
                    str::astr sni = decoder.decode_host(str::view(snin));
                    size_t offs = snin.data() - plainbuf;
                    mp.copy_in(offs, (const u8 *)sni.c_str(), snin.size());
                }
            }

            return rv;
        }
    };
}

void handler_socks::handshake5(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe)
{
    if (!flags.is<f_allow_5>())
        return;

    if (signed_t rb = pipe->recv(rcvd, 1, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 1)
        return;
    signed_t numauth = rcvd.getle<u8>();
    if (signed_t rb = pipe->recv(rcvd, numauth, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); numauth != rb)
        return;

    u8 temp[512];
    u8 rauth = 0xff;

    const u8 *packet = rcvd.plain_data(temp, numauth);
    if (nullptr == packet)
        return;

    for (signed_t i = 0; i < numauth && rauth != 0; ++i)
    {
        switch (packet[i])
        {
        case 0: // anonymous access request
            if (flags.is<f_socks5_allow_anon>() && rauth > 0)
                rauth = 0;
            break;
        case 2:
            if (authdata && !authdata->login.empty() && rauth > 2)
                rauth = 2;
            break;
        }
    }
    rcvd.skip(numauth);

    temp[0] = 5;
    temp[1] = rauth;
    if (pipe->send(temp, 2) == netkit::pipe::SEND_FAIL || rauth == 0xff)
        return;

    const expression* checkexpr = defexpr.get();
    chacha20 decr;
    if (rauth == 2)
    {
        // wait for auth packet
        if (signed_t rb = pipe->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 2)
            return;
        packet = rcvd.plain_data(temp, 2);
        if (packet[0] != 1)
            return;
        signed_t loginlen = 1 + packet[1]; // and one byte - len of pass
        rcvd.skip(2);
        if (signed_t rb = pipe->recv(rcvd, loginlen, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != loginlen)
            return;
        str::astr rlogin, rpass;
        rcvd.peek(rlogin, loginlen-1);
        u8 passlen = rcvd.getle<u8>();
        if (signed_t rb = pipe->recv(rcvd, passlen, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != passlen)
            return;
        rcvd.peek(rpass, passlen);
        temp[0] = 1;

        bool rfc1929 = obfsdata == nullptr;
        if (!rfc1929 && (loginlen != 17 || passlen != 32))
            rfc1929 = true;

        if (rfc1929)
        {
            if (!authdata || rlogin != authdata->login || rpass != authdata->pass)
            {
                temp[1] = 1;
                pipe->send(temp, 2);

                LOG_W("auth failed from $ (listener: $)", pipe->get_info(netkit::pipe::I_REMOTE), str::clean(owner->get_name()));

                return;
            }
            checkexpr = authdata->initialized() ? authdata.get() : nullptr;
        }
        else
        {
            u8 calckey[sha256::output_bytes];

            hkdf< hmac<sha256> >::perform_kdf(
                std::span(calckey, 32),                             // output
                std::span(obfsdata->masterkey),                     // masterkey (kdf generated on proxy load)
                std::span<const u8>((const u8 *)rlogin.data(), 16), // salt
                str::span(ASTR("socks-obfs")));

            if (!secure::equals<32>(calckey, rpass.data()))
            {
                temp[1] = 1;
                pipe->send(temp, 2);

                LOG_W("obfs-auth failed from $ (listener: $)", pipe->get_info(netkit::pipe::I_REMOTE), str::clean(owner->get_name()));

                return;
            }

            if (!obfsdata->flt.test_and_add(std::span<const u8>((const u8*)rlogin.data(), 16)))
            {
                // not pass! Replay Attack detected! (or false positive)
                // 
                LOG_W("reply-attack-filter rejects packet from $ (listener: $)", pipe->get_info(netkit::pipe::I_REMOTE), str::clean(owner->get_name()));
                return;
            }

            decr.set_iv(std::span<const u8>((const u8*)rlogin.data(), 12));
            decr.set_key(obfsdata->masterkey);

            checkexpr = obfsdata->initialized() ? obfsdata.get() : nullptr;
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

    packet = rcvd.plain_data(temp, 5);
    if (packet[0] != 5)
    {
        fail_answer(1); // FAILURE
        return;
    }
    
    if (flags.is<f_allow_udp_assoc>() && packet[1] == 3 /* UDP ASSOC */)
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

        udp_assoc_handler udph(udp_bind, pipe, checkexpr);
        udp_listener udpl(udp_bind, &udph);
        udpl.open();

        for (;!glb.is_stop();)
        {
            rcvd.clear();

            u8 rslt = pipe->wait(netkit::SE_READ, -1);

            if (rslt & netkit::SE_CLOSED)
                break;
            if (rslt & netkit::SE_READ)
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

        if (const u8* plain = rcvd.plain_data(temp, 8))
        {
            if (decr.ready())
            {
                u8* deca = temp + 256;
                decr.cipher(plain + 4, deca, 4);
                ep.set_ipap(netkit::ipap::build(deca, 4));
            }
            else
                ep.set_ipap(netkit::ipap::build(plain + 4, 4));

            rcvd.skip(5 + 3);
        }
        else
            return;

        break;
    case 3: // domain name

        numauth = packet[4] + 5; // len of domain
        if (signed_t rb = pipe->recv(rcvd, numauth, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != numauth)
            return;

        if (const u8* plain = rcvd.plain_data(temp, numauth))
        {
            if (decr.ready())
            {
                size_t domlen = numauth - 5;
                u8* deca = temp + 256;
                decr.cipher(plain + 5, deca, domlen);
                ep.set_domain(str::astr_view((const char*)deca, domlen));
            }
            else
                ep.set_domain(str::astr_view((const char*)plain + 5, numauth - 5));
            rcvd.skip(numauth);
        }
        else
            return;

        break;

    case 4: // ipv6
        // read 15 of 16 bytes of ipv6 address (1st byte already read) (also 5 bytes already read)
        if (signed_t rb = pipe->recv(rcvd, 5 + 15, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 5+15)
            return;
        if (const u8* plain = rcvd.plain_data(temp, 20))
        {
            if (decr.ready())
            {
                u8* deca = temp + 256;
                decr.cipher(plain + 4, deca, 16);
                ep.set_ipap(netkit::ipap::build(deca, 16));
            }
            else
                ep.set_ipap(netkit::ipap::build(plain + 4, 16));
            rcvd.skip(5 + 15);
        }
        else
            return;
        break;
    }

    if (signed_t rb = pipe->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 2)
        return;

    const u8* port_ptr = rcvd.plain_data(temp, 2);
    size_t port;
    if (decr.ready())
    {
        u8 deca[2];
        decr.cipher(port_ptr, deca, 2);
        port = load_be<2>(deca);
    }
    else
    {
        port = load_be<2>(port_ptr);
    }
    ep.set_port(port);

    rcvd.skip(2);

    if (checkexpr)
    {
        netkit::endpoint epsrc(pipe->get_remote_ipap());
        econtext ctx(&epsrc, &ep, !ups.is_proxychain_empty()); // CONTEXT
        if (checkexpr->calc(ctx) == 0)
        {
            LOG_W("{allow} rule rejects connection $ -> $ ($)", pipe->get_info(netkit::pipe::I_REMOTE), ep.desc(), str::clean(owner->get_name()));
            return;
        }
    }

    str::astr_view ent = owner->get_name();
    str::astr tmps;
    if (decr.ready())
    {
        tmps = ent;
        tmps.append(ASTR("/obfs"));
        ent = tmps;
    }
    ups_conn_log clogger(ent, pipe, &ep);
    if (netkit::pipe_ptr outcon = ups.connect(clogger, ep, false))
    {
#ifdef _DEBUG
        if (ep.domain() == "wikipedia.org")
        {
            outcon->tag = 1;
        }
        pipe->calc_entropy = 0;
#endif

        pipe->unrecv(rcvd);

        temp[0] = 5; // VER
        temp[1] = 0; // SUCCESS
        temp[2] = 0;
        temp[3] = 1; // ATYPE // ip4

        *(u32*)(temp + 4) = 0; // (u32)ep.get_ip(conf::gip_only4);
        temp[8] = (port >> 8) & 0xff;
        temp[9] = port & 0xff;

        pipe->send(temp, 10);

        if (decr.ready())
            pipe->replace(NEW decode_sni_socket(std::move(decr)));

        glb.e->bridge(pipe, outcon.get());
    }
    else {

        temp[0] = 5; // VER
        temp[1] = 4; // HOST_UNRCH
        temp[2] = 0;
        temp[3] = 1; // ATYPE // ip4

        *(u32*)(temp + 4) = 0; // (u32)ep.get_ip(conf::gip_only4);
        temp[8] = (port >> 8) & 0xff;
        temp[9] = port & 0xff;

        pipe->send(temp, 10);
    }
}

//////////////////////////////////////////////////////////////////////////////////
//
// dummy
//
//////////////////////////////////////////////////////////////////////////////////

handler_dummy::handler_dummy(loader& ldr, listener* /*owner*/, const asts& bb):handler(ldr,nullptr,bb)
{
    echo = bb.get_bool(ASTR("echo"), false);
}
/*virtual*/ void handler_dummy::handle_pipe(netkit::pipe* pipe)
{
    ostools::set_current_thread_name(ASTR("dummy"));

    u8 packet[65536], temp[65536];
    tools::circular_buffer_extdata rcvb(std::span(packet, sizeof(packet)));

    for (; !glb.is_stop();)
    {
        rcvb.clear();

        u8 wr = pipe->wait(netkit::SE_READ, 1000);
        if (wr & netkit::SE_CLOSED)
            break;
        if (wr & netkit::SE_TIMEOUT)
        {
            if (glb.is_stop())
                break;
            continue;
        }

        signed_t r = pipe->recv(rcvb,0,1000);
        if (r < 0)
            break;

        if (echo && rcvb.datasize() > 0)
            pipe->send( rcvb.plain_data(temp, rcvb.datasize()), rcvb.datasize() );
    }

}
