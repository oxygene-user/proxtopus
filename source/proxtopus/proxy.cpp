#include "pch.h"

proxy* proxy::build(loader& ldr, const str::astr& name, const asts& bb)
{

    const str::astr &t = bb.get_string(ASTR("type"), glb.emptys);
    if (t.empty())
    {
        ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
        LOG_FATAL("{type} not defined for proxy [$]^", str::clean(name));
        return nullptr;
    }

    if (ASTR("socks4") == t)
    {
        proxy_socks4* p = NEW proxy_socks4(ldr, name, bb);
        if (ldr.exit_code != 0)
        {
            delete p;
            return nullptr;
        }
        return p;
    }

    if (ASTR("socks5") == t)
    {
        proxy_socks5* p = NEW proxy_socks5(ldr, name, bb);
        if (ldr.exit_code != 0)
        {
            delete p;
            return nullptr;
        }
        return p;
    }

    if (ASTR("shadowsocks") == t)
    {
        proxy_shadowsocks* p = NEW proxy_shadowsocks(ldr, name, bb);
        if (ldr.exit_code != 0)
        {
            delete p;
            return nullptr;
        }
        return p;
    }

    if (ASTR("ssp") == t)
    {
        proxy_ssp* p = NEW proxy_ssp(ldr, name, bb);
        if (ldr.exit_code != 0)
        {
            delete p;
            return nullptr;
        }
        return p;
    }

    if (ASTR("http") == t)
    {
        proxy_http* p = NEW proxy_http(ldr, name, bb);
        if (ldr.exit_code != 0)
        {
            delete p;
            return nullptr;
        }
        return p;
    }


    LOG_FATAL("unknown {type} [$] for proxy [$]^", t, str::clean(name));
    ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;

    return nullptr;
}

proxy::proxy(loader& ldr, const str::astr& name, const asts& bb, bool addr_required):name(name)
{
    const str::astr &a = bb.get_string(ASTR("addr"), glb.emptys);
    if (a.empty())
    {
        if (addr_required)
        {
            ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
            LOG_FATAL("addr not defined for proxy [$]", str::clean(name));
            return;
        }
    } else
        addr.preparse(a);
}

/*virtual*/ void proxy::api(json_saver& j) const
{
    j.field(ASTR("id"), get_id());
    j.field(ASTR("name"), get_name());
    j.field(ASTR("endpoint"), addr.to_string());

}

str::astr proxy::desc() const
{
    return name + "@" + addr.desc();
}

proxy_socks4::proxy_socks4(loader& ldr, const str::astr& name, const asts& bb):proxy(ldr, name, bb)
{
    userid = bb.get_string(ASTR("userid"), glb.emptys);
    if (userid.length() > 255)
        userid.resize(255);
}

namespace {

#pragma pack(push,1)
    struct connect_packet_socks4
    {
        u8 vn;
        u8 cd;
        u16be destport;
        u32be destip;
    };
    struct connect_answr_socks4
    {
        u8 vn;
        u8 cd;
        u8 dummy[6];
    };
#pragma pack(pop)

}

/*virtual*/ void proxy_socks4::api(json_saver& j) const
{
    proxy::api(j);
    j.field(ASTR("type"), ASTR("socks4"));
}

netkit::pipe_ptr proxy_socks4::prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr2) const
{
    addr2.resolve_ip(conf::gip_only4);
    if (addr2.state() != netkit::EPS_RESLOVED || addr2.port() == 0)
    {
        return netkit::pipe_ptr();
    }

    signed_t dsz = sizeof(connect_packet_socks4) + 1 + userid.length();
    connect_packet_socks4* pd = (connect_packet_socks4 *)ALLOCA(dsz);
    pd->vn = 4; pd->cd = 1;
    pd->destport = addr2.port();
    pd->destip = (u32be)addr2.get_ip();
    memcpy(reinterpret_cast<u8 *>(pd + 1), userid.c_str(), userid.length());
    ((u8*)pd)[dsz - 1] = 0;

    if (pipe_to_proxy->send((u8*)pd, dsz) == netkit::pipe::SEND_FAIL)
        return netkit::pipe_ptr();

    tools::circular_buffer_preallocated<sizeof(connect_answr_socks4)> rcvd;
    signed_t rb = pipe_to_proxy->recv(rcvd, sizeof(connect_answr_socks4), RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
    const connect_answr_socks4 *answ = reinterpret_cast<const connect_answr_socks4 *>(rcvd.data1st(sizeof(connect_answr_socks4)));
    if (rb != sizeof(connect_answr_socks4) || answ->vn != 0 || answ->cd != 90)
        return netkit::pipe_ptr();

    return pipe_to_proxy;
}

proxy_socks5::proxy_socks5(loader& ldr, const str::astr& name, const asts& bb) :proxy(ldr, name, bb)
{

    str::astr_view pwd, user;
    const str::astr& auth = bb.get_string(ASTR("auth"), glb.emptys);
    if (size_t dv = auth.find(':'); dv != auth.npos)
    {
        pwd = str::view(auth).substr(dv + 1);
        user = str::view(auth).substr(0, dv);
    }

    if (user.length() > 254 || pwd.length() > 254)
        user = str::view(glb.emptys);

    if (!user.empty())
    {
        // make auth packet
        // username/pwd (https://datatracker.ietf.org/doc/html/rfc1929)
        authpacket.resize(user.length() + pwd.length() + 3);

        netkit::pgen pg(authpacket.data(), authpacket.size());
        pg.push8(1);
        pg.pushs(user);
        pg.pushs(pwd);

    }
}

/*virtual*/ void proxy_socks5::api(json_saver& j) const
{
    proxy::api(j);
    j.field(ASTR("type"), ASTR("socks5"));
}


bool proxy_socks5::initial_setup(tools::circular_buffer_extdata& rcvd, netkit::pipe* p2p) const
{
    u8 sd[3] = { 5, 1, static_cast<u8>(authpacket.empty() ? 0 : 2) };

    if (p2p->send(sd, 3) == netkit::pipe::SEND_FAIL)
        return false;

    signed_t rb = p2p->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
    const u8* packet = rcvd.data1st(2);
    if (rb != 2 || packet[0] != 5 || packet[1] != sd[2])
        return false;
    rcvd.skip(2);
    if (!authpacket.empty())
    {
        if (p2p->send(authpacket.data(), authpacket.size()) == netkit::pipe::SEND_FAIL)
            return false;

        signed_t rb1 = p2p->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
        packet = rcvd.data1st(2);
        if (rb1 != 2 || packet[1] != 0)
            return false;
        rcvd.skip(2);
    }
    return true;
}

bool proxy_socks5::recv_rep(tools::circular_buffer_extdata& rcvd, netkit::pipe* p2p, netkit::endpoint* ep, const str::astr_view *addr2domain) const
{
    signed_t rb = p2p->recv(rcvd, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
    if (rb != 2)
        return false;
    const u8* packet = rcvd.data1st(2);
    if (packet[0] != 5 || packet[1] != 0)
    {
        if (addr2domain)
        {
            str::astr ers;
            auto proxyfail = [&](signed_t code) -> str::astr_view
                {
                    switch (code)
                    {
                    case 1: return ASTR("general SOCKS server failure");
                    case 2: return ASTR("connection not allowed by ruleset");
                    case 3: return ASTR("Network unreachable");
                    case 4:
                        ers = ASTR("host unreachable (");
                        ers.append(*addr2domain);
                        ers.push_back(')');
                        return str::view(ers);
                    case 5: return ASTR("connection refused");
                    case 6: return ASTR("TTL expired");
                    case 7: return ASTR("command not supported");
                    case 8: return ASTR("address type not supported");
                    }

                    ers = ASTR("unknown error code (");
                    str::append_num(ers, code, 0);
                    ers.push_back(')');
                    return str::view(ers);

                };

            LOG_N("proxy [$] fail: $", str::clean(name), proxyfail(packet[1]));

        }
        return false;
    }

    if (rb = p2p->recv(rcvd, 2 + 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 4) // read next 2 bytes
        return false;
    u8 atyp = rcvd.data1st(4)[3];
    rcvd.skip(4);

    switch (atyp)
    {
    case 1:
        // read ip4 and port
        if (rb = p2p->recv(rcvd, 6, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 6)
            return false;

        if (ep)
            ep->read(rcvd.data1st(6), 6);
        rcvd.skip(6);
        break;
    case 3:
        if (signed_t n = p2p->recv(rcvd, 1, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); n != 1) // read domain len
            return false;

        if (signed_t n = rcvd.getle<u8>() + 2; n == p2p->recv(rcvd, n, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr))) // read domain and port
        {
            const u8* d = rcvd.data1st(n);
            ep->set_domain(str::astr_view((const char*)d, n-2));
            ep->set_port(((u16)d[n-2] << 8) | d[n-1]);
            rcvd.skip(n);
            break;
        }
        return false;

    case 4:
        // read ip6 and port
        if (rb = p2p->recv(rcvd, 18, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 18)
            return false;

        if (ep)
            ep->read(rcvd.data1st(18), 18);
        rcvd.skip(18);
        break;

    default:
        return false;
    }

    return true;
}

netkit::pipe_ptr proxy_socks5::prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr2) const
{
    if (addr2.state() == netkit::EPS_EMPTY || addr2.port() == 0)
        return netkit::pipe_ptr();

    tools::circular_buffer_preallocated<512> rcvd;
    if (!initial_setup(rcvd, pipe_to_proxy.get()))
        return netkit::pipe_ptr();

    u8 packet[512];
    netkit::pgen pg(packet, sizeof(packet));

    pg.push8(5); // socks 5
    pg.push8(1); // connect
    pg.push8(0);

    push_atyp(pg, addr2);

    if (pipe_to_proxy->send(packet, pg.ptr) == netkit::pipe::SEND_FAIL)
        return netkit::pipe_ptr();

    if (!recv_rep(rcvd, pipe_to_proxy.get(), nullptr, makeptr(str::view(addr2.domain()))))
        return netkit::pipe_ptr();

    pipe_to_proxy->unrecv(rcvd);

    return pipe_to_proxy;
}

namespace
{
    class udp_via_socks5 : public netkit::udp_pipe
    {
        const proxy_socks5* basedon;
        netkit::udp_pipe* transport;
        netkit::endpoint udpassoc;
        netkit::pipe_ptr pipe2s;
    public:

        udp_via_socks5(const proxy_socks5* basedon, netkit::udp_pipe* transport, const netkit::endpoint& udpassoc, netkit::pipe_ptr pipe2s) :basedon(basedon), transport(transport), udpassoc(udpassoc), pipe2s(pipe2s)
        {
        }

        netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg) override
        {
            if (!pipe2s->alive())
            {
                if (!basedon->prepare_udp_assoc(udpassoc, pipe2s, false))
                    return netkit::ior_timeout;
            }

            auto prepare_header = [](u8* packet, const netkit::endpoint& ep)
                {
                    netkit::pgen pgx(packet, 512);
                    pgx.push16(0); // RSV
                    pgx.push8(0); // FRAG

                    proxy_socks5::push_atyp(pgx, ep);
                };

#ifdef _DEBUG
            LOG_I("udp via proxy request ($)", toaddr.desc());
#endif
            signed_t presize = proxy_socks5::atyp_size(toaddr) + 3 /* 3 octets is: RSV and FRAG (see prepare_header) */;
            if (presize <= pg.extra)
            {
                // pg has extra space before packet! so, we can use it for udp header for socks server
                netkit::endpoint epc = toaddr;
                netkit::pgen pgh(const_cast<u8*>(pg.get_data()) - presize, pg.sz + presize);
                prepare_header(pgh.get_data(), epc);
                return transport->send(udpassoc, pgh);
            }

            u8* packet = ALLOCA(presize + pg.sz);
            prepare_header(packet, toaddr);
            memcpy(packet + presize, pg.to_span().data(), pg.sz);
            return transport->send(udpassoc, netkit::pgen(packet, presize + pg.sz));
        }
        netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size) override
        {
            pg.set_extra(0);
            netkit::io_result r = transport->recv(from, pg, max_bufer_size);
            if (netkit::ior_ok == r)
            {
                pg.ptr = 2; // skip RSV(2)

                u8 frag = pg.read8();
                if (frag != 0)
                    return netkit::ior_proxy_fail; // fragmentation not supported yet

                netkit::endpoint ep;
                if (!proxy_socks5::read_atyp(pg, ep))
                    return netkit::ior_proxy_fail;
                from = ep.resolve_ip(glb.cfg.ipstack | conf::gip_any);
                pg.set_extra(pg.ptr);
            }
            return r;
        }
    };
}

bool proxy_socks5::read_atyp(netkit::pgen& pg, netkit::endpoint& addr)
{
    switch (pg.read8())
    {
    case 1:
        if (const u8* p = pg.read(6))
        {
            addr.read(p, 6);
        }
        else
            return false;
        break;
    case 3:
        if (u8 sl = pg.read8(); const u8* p = pg.read(sl))
        {
            addr.set_domain(str::astr_view((const char*)p, sl));
            addr.set_port(pg.read16());
        } else
            return false;
        break;

    case 4:
        if (const u8* p = pg.read(18))
        {
            addr.read(p, 18);
        }
        else
            return false;
        break;
    }

    return true;

}

void proxy_socks5::push_atyp(netkit::pgen& pg, const netkit::endpoint& addr2)
{
    //  +------+----------+----------+
    //  | ATYP | DST.ADDR | DST.PORT |
    //  +------+----------+----------+
    //  |   1  | Variable |    2     |
    //  +------+----------+----------+
    //  o  ATYP address type of following addresses:
    //    o  IP V4 address : X'01'
    //    o  DOMAINNAME : X'03'
    //    o  IP V6 address : X'04'

    if (addr2.domain().empty())
    {
        const netkit::ipap &ip = addr2.get_ip();

        pg.push8(ip.v4 ? 1 : 4);
        pg.push(ip, true);
    }
    else
    {
        pg.push8(3); // atyp: domain name
        pg.pushs(addr2.domain());
        pg.push16(addr2.port());
    }
}

signed_t proxy_socks5::atyp_size(const netkit::endpoint& addr)
{
    if (addr.domain().empty())
    {
        const netkit::ipap& ip = addr.get_ip();
        return ip.v4 ? 7 : 19;
    }

    return 1 + 2 + 1 + addr.domain().length(); // ATYP(1) + port(2) + size_of_domain(1) + size_of_domain
}

bool proxy_socks5::prepare_udp_assoc(netkit::endpoint& udp_assoc_ep, netkit::pipe_ptr& pip_out, bool log_fails) const
{
#ifdef _DEBUG
    LOG_I("udp assoc prepare to $", addr.desc());
#endif
    netkit::endpoint addrr(addr);
    netkit::pipe* pip = conn::connect(addrr);
    if (!pip)
    {
    not_success:
        if (log_fails)
            LOG_W("not connected to proxy ($)", desc());
        return false;
    }
    netkit::pipe_ptr p2p(pip);
    tools::circular_buffer_preallocated<512> rcvd;
    if (!initial_setup(rcvd, pip))
        goto not_success;

    u8 sd[10];
    netkit::pgen pg(sd, 10);

    pg.push8(5); // socks 5
    pg.push8(3); // UDP ASSOCIATE
    pg.push8(0);

    pg.push8(1); // ipv4
    pg.pushz(6); // zero ipv4 addr and zero port

    if (p2p->send(sd, pg.sz) == netkit::pipe::SEND_FAIL)
        goto not_success;

    if (!recv_rep(rcvd, pip, &udp_assoc_ep, log_fails ? makeptr(ASTR("udp")) : nullptr))
        goto not_success;

    if (udp_assoc_ep.get_ip().is_wildcard() && udp_assoc_ep.domain().empty())
        udp_assoc_ep.set_addr(addrr.get_ip());

    pip_out = p2p;

    return true;
}

/*virtual*/ std::unique_ptr<netkit::udp_pipe> proxy_socks5::prepare(netkit::udp_pipe* transport) const
{
    netkit::endpoint ep;
    netkit::pipe_ptr p2p;
    if (prepare_udp_assoc(ep, p2p, true))
        return std::make_unique<udp_via_socks5>(this, transport, ep, p2p);
    return std::unique_ptr<netkit::udp_pipe>();
}



proxy_http::proxy_http(loader& ldr, const str::astr& name, const asts& bb) :proxy(ldr, name, bb)
{
    host = ASTR("$(v)"); // by default : variable[0] means request string
    host = bb.get_string(ASTR("host"), host);
    if (const auto* f = bb.get(ASTR("fields")))
    {
        for (auto it = f->begin(); it; ++it)
            fields.emplace_back( it.name(), it->as_string() );
    }
}

netkit::pipe_ptr proxy_http::prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr2) const
{
    if (addr2.state() == netkit::EPS_EMPTY || addr2.port() == 0)
        return netkit::pipe_ptr();

    netkit::pipe_tools pt(pipe_to_proxy.get());

    buffer b;
    str::astr eps = addr2.to_string();
    str::__append(b, ASTR("CONNECT "));
    str::__append(b, eps);
    str::__append(b, ASTR(" HTTP/1.1\r\nHost: "));

    macro_context mc(eps);
    eps = host;
    macro_expand(&mc, eps);

    str::__append(b, eps);

    for (const auto& f : fields)
    {
        str::__append(b, ASTR("\r\n"));
        str::__append(b, f.first);
        str::__append(b, ASTR(": "));

        eps = f.second;
        macro_expand(&mc, eps);
        str::__append(b, eps);

    }

    str::__append(b, ASTR("\r\n\r\n"));

    if (pt.send(b) == netkit::pipe::SEND_FAIL)
    {
        return netkit::pipe_ptr();
    }

    str::astr answ;
    pt.read_line(&answ);
    pt.read_line(nullptr);

    if (!answ.starts_with(ASTR("HTTP/1.1 200")) && !answ.starts_with(ASTR("HTTP/1.0 200")))
        return netkit::pipe_ptr();

    pt.unrecv();

    return pipe_to_proxy;

}

void proxy_http::api(json_saver& j) const
{
    proxy::api(j);
    j.field(ASTR("type"), ASTR("http"));
}

