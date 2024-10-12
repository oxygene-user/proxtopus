#include "pch.h"

proxy* proxy::build(loader& ldr, const str::astr& name, const asts& bb)
{

	str::astr t = bb.get_string(ASTR("type"));
	if (t.empty())
	{
		ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
		LOG_E("{type} not defined for proxy [%s]; type {imconee help proxy} for more information", str::printable(name));
		return nullptr;
	}

	if (ASTR("socks4") == t)
	{
		proxy_socks4* p = new proxy_socks4(ldr, name, bb);
		if (ldr.exit_code != 0)
		{
			delete p;
			return nullptr;
		}
		return p;
	}

	if (ASTR("socks5") == t)
	{
		proxy_socks5* p = new proxy_socks5(ldr, name, bb);
		if (ldr.exit_code != 0)
		{
			delete p;
			return nullptr;
		}
		return p;
	}

	if (ASTR("shadowsocks") == t)
	{
		proxy_shadowsocks* p = new proxy_shadowsocks(ldr, name, bb);
		if (ldr.exit_code != 0)
		{
			delete p;
			return nullptr;
		}
		return p;
	}

	LOG_E("unknown {type} [%s] for proxy [%s]; type {imconee help proxy} for more information", str::printable(t), str::printable(name));
	ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;

	return nullptr;



}

proxy::proxy(loader& ldr, const str::astr& name, const asts& bb, bool addr_required):name(name)
{
	str::astr a = bb.get_string(ASTR("addr"));
	if (a.empty())
	{
		if (addr_required)
		{
			ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
			LOG_E("addr not defined for proxy [%s]", str::printable(name));
			return;
		}
	} else
		addr.preparse(a);
}

str::astr proxy::desc() const
{
	return name + "@" + addr.desc();
}

proxy_socks4::proxy_socks4(loader& ldr, const str::astr& name, const asts& bb):proxy(ldr, name, bb)
{
	userid = bb.get_string(ASTR("userid"));
	if (userid.length() > 255)
		userid.resize(255);
}

namespace {

#pragma pack(push,1)
	struct connect_packet_socks4
	{
		u8 vn = 4;
		u8 cd = 1;
		u16 destport;
		u32 destip;
	};
	struct connect_answr_socks4
	{
		u8 vn;
		u8 cd;
		u8 dummy[6];
	};
#pragma pack(pop)

}

#ifdef __GNUC__
#define _alloca alloca
#endif

netkit::pipe_ptr proxy_socks4::prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr2) const
{
	addr2.resolve_ip(conf::gip_only4);
	if (addr2.state() != netkit::EPS_RESLOVED || addr2.port() == 0)
	{
		return netkit::pipe_ptr();
	}

	signed_t dsz = sizeof(connect_packet_socks4) + 1 + userid.length();
	connect_packet_socks4* pd = (connect_packet_socks4 *)_alloca(dsz);
	pd->vn = 4; pd->cd = 1;
	pd->destport = netkit::to_ne((u16)addr2.port());
	pd->destip = addr2.get_ip();
	memcpy(pd + 1, userid.c_str(), userid.length());
	((u8*)pd)[dsz - 1] = 0;

	if (pipe_to_proxy->send((u8*)pd, dsz) == netkit::pipe::SEND_FAIL)
	{
		return netkit::pipe_ptr();
	}

	connect_answr_socks4 answ;
	signed_t rb = pipe_to_proxy->recv((u8*)&answ, -(signed_t)sizeof(connect_answr_socks4));

	if (rb != sizeof(connect_answr_socks4) || answ.vn != 0 || answ.cd != 90)
		return netkit::pipe_ptr();


	return pipe_to_proxy;
}

proxy_socks5::proxy_socks5(loader& ldr, const str::astr& name, const asts& bb) :proxy(ldr, name, bb)
{

	str::astr pwd, user = bb.get_string(ASTR("auth"));
	size_t dv = user.find(':');
	if (dv != user.npos)
	{
		pwd = user.substr(dv + 1);
		user.resize(dv);
	}

	if (user.length() > 254 || pwd.length() > 254)
		user.clear();

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

bool proxy_socks5::initial_setup(u8* packet, netkit::pipe* p2p) const
{
	packet[0] = 5;
	packet[1] = 1;
	packet[2] = authpacket.empty() ? 0 : 2;

	if (p2p->send(packet, 3) == netkit::pipe::SEND_FAIL)
		return false;

	signed_t rb = p2p->recv(packet, -2);

	if (rb != 2 || packet[0] != 5 || packet[1] != packet[2])
		return false;

	if (!authpacket.empty())
	{
		if (p2p->send(authpacket.data(), authpacket.size()) == netkit::pipe::SEND_FAIL)
			return false;

		signed_t rb1 = p2p->recv(packet, -2);
		if (rb1 != 2 || packet[1] != 0)
			return false;
	}
	return true;
}

bool proxy_socks5::recv_rep(u8* packet, netkit::pipe* p2p, netkit::endpoint* ep, const str::astr_view *addr2domain) const
{
	signed_t rb = p2p->recv(packet, -2);

	if (rb != 2 || packet[0] != 5 || packet[1] != 0)
	{
		if (addr2domain)
		{
            str::astr ers;
            auto proxyfail = [&](signed_t code) -> const char*
                {
                    switch (code)
                    {
                    case 1: return "general SOCKS server failure";
                    case 2: return "connection not allowed by ruleset";
                    case 3: return "Network unreachable";
                    case 4:
                        ers = ASTR("host unreachable (");
                        ers.append(*addr2domain);
                        ers.push_back(')');
                        return ers.c_str();
                    case 5: return "connection refused";
                    case 6: return "TTL expired";
                    case 7: return "command not supported";
                    case 8: return "address type not supported";
                    }

                    ers = ASTR("unknown error code (");
                    ers.append(std::to_string(code));
                    ers.push_back(')');
                    return ers.c_str();

                };

            LOG_N("proxy [%s] fail: %s", str::printable(name), proxyfail(packet[1]));

		}
		return false;
	}


	rb = p2p->recv(packet, -2); // read next 2 bytes

	if (rb != 2)
		return false;

	switch (packet[1])
	{
	case 1:
		rb = p2p->recv(packet, -6); // read ip4 and port
		if (rb != 6)
			return false;

		if (ep)
			ep->read(packet, 6);

		break;
	case 3:
		rb = p2p->recv(packet, -1); // read domain len
		if (rb != 1)
			return false;

		rb = packet[0] + 2;
		rb = p2p->recv(packet+1, rb); // read domain and port
		if (rb != rb)
			return false;

		ep->set_domain( str::astr_view((const char *)packet + 1, packet[0]));
		ep->set_port(((u16)packet[packet[0]+1] << 8) | packet[packet[0] + 2]);

		break;
	case 4:
		rb = p2p->recv(packet, -18); // read ip6 and port
		if (rb != 18)
			return false;

		if (ep)
			ep->read(packet, 18);

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

	u8 packet[512];
	if (!initial_setup(packet, pipe_to_proxy.get()))
		return netkit::pipe_ptr();

	netkit::pgen pg(packet, 512);

    pg.push8(5); // socks 5
    pg.push8(1); // connect
    pg.push8(0);

	push_atyp(pg, addr2);
    if (pipe_to_proxy->send(packet, pg.ptr) == netkit::pipe::SEND_FAIL)
        return netkit::pipe_ptr();

	if (!recv_rep(packet, pipe_to_proxy.get(), nullptr, makeptr(str::view(addr2.domain()))))
		return netkit::pipe_ptr();

	return pipe_to_proxy;
}

class udp_via_socks5 : public netkit::udp_pipe
{
	const proxy_socks5* basedon;
	netkit::udp_pipe* transport;
	netkit::endpoint udpassoc;
	netkit::pipe_ptr pipe2s;
public:

	udp_via_socks5(const proxy_socks5* basedon, netkit::udp_pipe* transport, const netkit::endpoint &udpassoc, netkit::pipe_ptr pipe2s):basedon(basedon), transport(transport), udpassoc(udpassoc), pipe2s(pipe2s)
	{
	}

	// Inherited via udp_pipe
	netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg) override
	{
		if (!pipe2s->alive())
		{
			if (!basedon->prepare_udp_assoc(udpassoc, pipe2s, false))
				return netkit::ior_timeout;
		}

		auto prepare_header = [](u8* packet, const netkit::endpoint &ep)
			{
				netkit::pgen pgx(packet, 512);
				pgx.push16(0); // RSV
				pgx.push8(0); // FRAG

				proxy_socks5::push_atyp(pgx, ep);
			};

#ifdef _DEBUG
		LOG_I("udp via proxy request (%s)", toaddr.desc().c_str());
#endif
		signed_t presize = proxy_socks5::atyp_size(toaddr) + 3 /* 3 octets is: RSV and FRAG (see prepare_header) */;
		if (presize <= pg.pre)
		{
			// pg has extra space before packet! so, we can use it for udp header for socks server
			netkit::endpoint epc = toaddr;
			netkit::pgen pgh(const_cast<u8 *>(pg.to_span().data()) - presize, pg.sz + presize);
			prepare_header(pgh.get_data(), epc);
			return transport->send(udpassoc, pgh);
		}

		u8 *packet = (u8*)_alloca(presize + pg.sz);
		prepare_header(packet, toaddr);
		memcpy(packet + presize, pg.to_span().data(), pg.sz);
		return transport->send(udpassoc, netkit::pgen(packet, presize + pg.sz));
	}
	netkit::io_result recv(netkit::pgen& pg, signed_t max_bufer_size) override
	{
		pg.set_pre(0);
		netkit::io_result r = transport->recv(pg, max_bufer_size);
		if (netkit::ior_ok == r)
		{
			switch (pg.get_data()[3])
			{
			case 1:
				pg.set_pre(10);
				break;
			case 4:
				pg.set_pre(22);
				break;
			default:
				return netkit::ior_proxy_fail;
			}
		}
		return r;
	}
};

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
	LOG_I("udp assoc prepare to %s", addr.desc().c_str());
#endif
	netkit::endpoint addrr(addr);
	netkit::pipe* pip = conn::connect(addrr);
	if (!pip)
	{
	not_success:
		if (log_fails)
			LOG_W("not connected to proxy (%s)", desc().c_str());
		return false;
	}
	netkit::pipe_ptr p2p(pip);
	u8 packet[512];
	if (!initial_setup(packet, pip))
		goto not_success;

	netkit::pgen pg(packet, 10);

	pg.push8(5); // socks 5
	pg.push8(3); // UDP ASSOCIATE
	pg.push8(0);

	pg.push8(1); // ipv4
	pg.pushz(6); // zero ipv4 addr and zero port

	if (p2p->send(packet, pg.sz) == netkit::pipe::SEND_FAIL)
		goto not_success;

	if (!recv_rep(packet, pip, &udp_assoc_ep, log_fails ? makeptr(ASTR("udp")) : nullptr))
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

