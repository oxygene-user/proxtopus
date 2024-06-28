#include "pch.h"

proxy* proxy::build(loader& ldr, const std::string& name, const asts& bb)
{

	std::string t = bb.get_string(ASTR("type"));
	if (t.empty())
	{
		ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
		LOG_W("{type} not defined for proxy [%s]. Type {imconee help proxy} for more information.", str::printable(name));
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

	LOG_E("unknown {type} [%s] for proxy [%s]. Type {imconee help proxy} for more information.", str::printable(t), str::printable(name));
	ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;

	return nullptr;


	
}

proxy::proxy(loader& ldr, const std::string& name, const asts& bb):name(name)
{
	std::string a = bb.get_string(ASTR("addr"));
	if (a.empty())
	{
		ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
		LOG_W("addr not defined for proxy [%s]", str::printable(name));
		return;
	}

	addr.preparse(a);
}

std::string proxy::desc() const
{
	return name + "@" + addr.desc();
}

proxy_socks4::proxy_socks4(loader& ldr, const std::string& name, const asts& bb):proxy(ldr, name, bb)
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

netkit::pipe_ptr proxy_socks4::prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr2) const
{
	addr2.get_ip4(false);
	if (addr2.type() != netkit::AT_TCP_RESLOVED || addr2.port() == 0)
	{
		return netkit::pipe_ptr();
	}

	signed_t dsz = sizeof(connect_packet_socks4) + 1 + userid.length();
	connect_packet_socks4* pd = (connect_packet_socks4 *)_alloca(dsz);
	pd->connect_packet_socks4::connect_packet_socks4();
	pd->destport = netkit::to_ne((u16)addr2.port());
	pd->destip = addr2.get_ip4(false);
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

proxy_socks5::proxy_socks5(loader& ldr, const std::string& name, const asts& bb) :proxy(ldr, name, bb)
{

	std::string pwd, user = bb.get_string(ASTR("auth"));
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


netkit::pipe_ptr proxy_socks5::prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr2) const
{
	if (addr2.type() == netkit::AT_ERROR || addr2.port() == 0)
		return netkit::pipe_ptr();

	u8 packet[512];
	packet[0] = 5;
	packet[1] = 1;
	packet[2] = authpacket.empty() ? 0 : 2;

	if (pipe_to_proxy->send(packet, 3) == netkit::pipe::SEND_FAIL)
		return netkit::pipe_ptr();

	signed_t rb = pipe_to_proxy->recv(packet, -2);

	if (rb != 2 || packet[0] != 5 || packet[1] != packet[2])
		return netkit::pipe_ptr();

	if (!authpacket.empty())
	{
		if (pipe_to_proxy->send(authpacket.data(), authpacket.size()) == netkit::pipe::SEND_FAIL)
			return netkit::pipe_ptr();

		signed_t rb1 = pipe_to_proxy->recv(packet, -2);
		if (rb1 != 2 || packet[1] != 0)
			return netkit::pipe_ptr();
	}

	if (addr2.domain().empty())
	{
		netkit::pgen pg(packet, 10);

		pg.push8(5); // socks 5
		pg.push8(1); // connect
		pg.push8(0);
		pg.push8(1); // ip4
		pg.push(addr2.get_ip4(false));
		pg.push16(addr2.port());

		if (pipe_to_proxy->send(packet, pg.sz) == netkit::pipe::SEND_FAIL)
			return netkit::pipe_ptr();
	}
	else
	{
		netkit::pgen pg(packet, addr2.domain().length() + 7);

		pg.push8(5); // socks 5
		pg.push8(1); // connect
		pg.push8(0);
		pg.push8(3); // domain name
		pg.pushs(addr2.domain());
		pg.push16(addr2.port());

		if (pipe_to_proxy->send(packet, pg.sz) == netkit::pipe::SEND_FAIL)
			return netkit::pipe_ptr();
	}


	signed_t rb2 = pipe_to_proxy->recv(packet, -2);

	if (rb != 2 || packet[0] != 5 || packet[1] != 0)
	{
		std::string ers;
		auto proxyfail = [&](signed_t code) -> const char*
		{
			switch (code)
			{
			case 1: return "general SOCKS server failure";
			case 2: return "connection not allowed by ruleset";
			case 3: return "Network unreachable";
			case 4: 
				ers = ASTR("Host unreachable (");
				ers.append(addr2.domain());
				ers.push_back(')');
				return ers.c_str();
			case 5: return "Connection refused";
			case 6: return "TTL expired";
			case 7: return "Command not supported";
			case 8: return "Address type not supported";
			}

			ers = ASTR("unknown error code (");
			ers.append(std::to_string(code));
			ers.push_back(')');
			return ers.c_str();

		};

		LOG_N("Proxy [%s] fail: %s", str::printable(name), proxyfail(packet[1]));

		return netkit::pipe_ptr();
	}


	rb2 = pipe_to_proxy->recv(packet, -2); // read next 2 bytes

	if (rb != 2)
		return netkit::pipe_ptr();

	switch (packet[1])
	{
	case 1:
		rb2 = pipe_to_proxy->recv(packet, -6); // read ip4 and port
		if (rb2 != 6)
			return netkit::pipe_ptr();
		break;
	case 3:
		rb2 = pipe_to_proxy->recv(packet, -1); // read domain len
		if (rb2 != 1)
			return netkit::pipe_ptr();
		rb = packet[0] + 2;
		rb2 = pipe_to_proxy->recv(packet, rb); // read domain and port
		if (rb2 != rb)
			return netkit::pipe_ptr();

		break;
	case 4:
		rb2 = pipe_to_proxy->recv(packet, -18); // read ip6 and port
		if (rb2 != 18)
			return netkit::pipe_ptr();
		break;

	default:
		return netkit::pipe_ptr();
	}


	return pipe_to_proxy;
}

