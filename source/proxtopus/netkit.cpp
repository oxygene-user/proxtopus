#include "pch.h"
#ifdef _WIN32
#include <Ws2tcpip.h>
#endif
#ifdef _NIX
#include <sys/ioctl.h>
#include <linux/sockios.h> // SIOCOUTQ
#endif

namespace netkit
{
    static signed_t send_buffer_size = 128 * 1024; // 128k

#ifdef _NIX
        const int SD_SEND = SHUT_WR;
#endif

    void ipap::clear()
    {
        v4 = glb.cfg.ipstack == conf::gip_only4 || glb.cfg.ipstack == conf::gip_prior4;
        if (v4) ipv4.s_addr = 0; else memset(&ipv6, 0, sizeof(ipv6));
    }

	ipap ipap::parse6(const str::astr_view& s, bool parse_port)
	{
		bool colon = false;
		bool fillright = false;
		signed_t somedigits = 0;

		signed_t cntl = 0, cntr = 0;
		std::array<u16, 8> left;
		std::array<u16, 8> rite;

		u16 current = 0;

		auto pushdig = [&]() -> bool
		{
			if (fillright)
			{
				rite[cntr++] = netkit::to_ne(current);
				if (cntl + cntr == 7)
					return true;
			}
			else {
				left[cntl++] = netkit::to_ne(current);
				if (cntl == 8)
					return true;
			}
			return false;
		};

		auto hexdig = [](char c) -> u8
		{
			if (c >= '0' && c <= '9')
				return c - 48;
			if (c >= 'a' && c <= 'f')
				return c - 'a' + 10;
			if (c >= 'A' && c <= 'F')
				return c - 'A' + 10;
			return 255;
		};

		signed_t check_port = -1;
		bool clexpected = s[0] == '[';
		for (signed_t i = clexpected ? 1 : 0, sl = s.length(); i<sl; ++i )
		{
			char c = s[i];
			if (c == '[')
			{
				return ipap();
			}
			if (c == ']')
			{
				if (!clexpected)
					return ipap();
				if (parse_port)
					check_port = i + 1;
				clexpected = false;
				break;
			}

			if (c == ':')
			{
				if (somedigits > 0 && pushdig())
					break;

				if (colon)
				{
					// double colon
					fillright = true;
				}

				colon = true;
				current = 0;
				somedigits = 0;
				continue;
			}
			colon = false;
			u8 hd = hexdig(c);
			if (hd == 255)
				return ipap();
			current = (current << 4) + hd;
			++somedigits;
			if (somedigits == 5)
				return ipap();
		}

		if (clexpected)
			return ipap();

		if (somedigits)
			pushdig();

		ipap rv(false);
		u16 *w = rv.words();
		signed_t i = 0;
		for (; i < cntl; ++i)
			w[i] = left[i];

		signed_t i2 = 8 - cntr;

		for (; i < i2; ++i)
			w[i] = 0;

		for (signed_t j = 0;i < 8; ++i, ++j)
			w[i] = rite[j];

		if (check_port > 0 && s[check_port] == ':')
		{
			rv.port = tools::as_word(str::parse_int(s.substr(check_port + 1), 65535, 0));
		}

		return rv;
	}

	ipap ipap::parse(const str::astr_view& s, bool parse_port)
	{
		if (s.empty())
			return ipap();

		if (s[0] == '[')
			return parse6(s, parse_port);

		signed_t numd = 0;
		for( char c : s )
			if (c == ':')
			{
				++numd;
				if (numd == 2)
					return parse6(s, false);
			}

		ipap rv;

		u8* dst = rv.octets();
		signed_t index = 0;
		for (str::token<char, str::sep_onechar<char, '.'>> tkn(s); tkn; tkn(), ++index, ++dst)
		{
			if (index >= 4)
			{
				rv.ipv4.s_addr = 0;
				return rv;
			}

			if (index == 3)
			{
				size_t d = tkn->find(':');
				if (d != str::astr::npos)
				{
					if (parse_port)
						rv.port = tools::as_word(str::parse_int(tkn->substr(d + 1), 65535, 0));
					tkn.trim(d);
				}
			}

			signed_t oktet = str::parse_int(*tkn, 255, 256);
			if (oktet > 255)
			{
				rv.ipv4.s_addr = 0;
				return rv;
			}
			*dst = tools::as_byte(oktet);

		}

		return rv;
	}

	signed_t ipap::bind(SOCKET s) const
	{
		if (v4)
		{
			sockaddr_in addr;

			addr.sin_family = AF_INET;
			addr.sin_addr = ipv4;
			addr.sin_port = netkit::to_ne((u16)port);

			bool ok = SOCKET_ERROR != ::bind(s, (const sockaddr*)&addr, sizeof(addr));
			if (!ok)
				return -1;

			signed_t rp = port;
			if (rp == 0)
			{
//#ifdef _WIN32
				socklen_t x = sizeof(addr);
				getsockname(s, (sockaddr*)&addr, &x);
				rp = netkit::to_ne(addr.sin_port);
//#endif

			}
			return rp;
		}

		sockaddr_in6 addr = {};

		addr.sin6_family = AF_INET6;
		memcpy(&addr.sin6_addr, &ipv6, sizeof(ipv6));
		addr.sin6_port = netkit::to_ne((u16)port);

		bool ok = SOCKET_ERROR != ::bind(s, (const sockaddr*)&addr, sizeof(addr));

        if (!ok)
            return -1;

        signed_t rp = port;
        if (rp == 0)
        {
            socklen_t x = sizeof(addr);
            getsockname(s, (sockaddr*)&addr, &x);
            rp = netkit::to_ne(addr.sin6_port);
        }
        return rp;
	}

	bool ipap::connect(SOCKET s) const
	{
		if (v4)
		{
			sockaddr_in addr = {};
			addr.sin_family = AF_INET;
			addr.sin_addr = ipv4;
			addr.sin_port = netkit::to_ne((u16)port);
			return SOCKET_ERROR != ::connect(s, (const sockaddr*)&addr, sizeof(addr));
		}

		sockaddr_in6 addr = {};
		addr.sin6_family = AF_INET6;
		memcpy(&addr.sin6_addr, &ipv6, sizeof(ipv6));
		addr.sin6_port = netkit::to_ne((u16)port);
		return SOCKET_ERROR != ::connect(s, (const sockaddr*)&addr, sizeof(addr));

	}

	bool ipap::sendto(SOCKET s, const std::span<const u8>& p) const
	{
		if (v4)
		{
			sockaddr_in addr = {};
			addr.sin_family = AF_INET;
			addr.sin_addr = ipv4;
			addr.sin_port = netkit::to_ne((u16)port);
			return SOCKET_ERROR != ::sendto(s, (const char*)p.data(), (int)p.size(), 0, (const sockaddr*)&addr, sizeof(addr));
		}

		sockaddr_in6 addr = {};
		addr.sin6_family = AF_INET6;
		memcpy(&addr.sin6_addr, &ipv6, sizeof(ipv6));
		addr.sin6_port = netkit::to_ne((u16)port);
		return SOCKET_ERROR != ::sendto(s, (const char *)p.data(), (int)p.size(), 0, (const sockaddr*)&addr, sizeof(addr));
	}

	void waitable_socket::close(bool flush_before_close)
	{
#ifdef _WIN32
		if (_socket.wsaevent)
		{
			WSACloseEvent(_socket.wsaevent);
			_socket.wsaevent = nullptr;
		}
#endif
		if (sock() != INVALID_SOCKET)
		{
			if (flush_before_close)
				/*int errm =*/ shutdown(sock(), SD_SEND);
			closesocket(sock());
			_socket = INVALID_SOCKET;
		}
	}

	bool waitable_socket::listen(const str::astr& name, const ipap& bind2)
	{
		if (glb.cfg.ipstack == conf::gip_only6 && bind2.v4)
		{
			LOG_W("bind failed for listener [%s] due ipv4 addresses are disabled in config", str::printable(name));
			return false;
		}
		if (glb.cfg.ipstack == conf::gip_only4 && !bind2.v4)
		{
			LOG_W("bind failed for listener [%s] due ipv6 addresses are disabled in config", str::printable(name));
			return false;
		}

		_socket = ::socket(bind2.v4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (INVALID_SOCKET == sock())
			return false;

		if (bind2.bind(sock()) < 0)
		{
			LOG_W("bind failed for listener [%s]; check binding (%s)", str::printable(name), bind2.to_string(true).c_str());
			close(false);
			return false;
		}

		if (SOCKET_ERROR == ::listen(sock(), SOMAXCONN))
		{
			LOG_W("listen failed for listener [%s]", str::printable(name));
			close(false);
			return false;
		}

		return true;
	}

	void socket::close(bool flush_before_close)
	{
		if (s != INVALID_SOCKET)
		{
			if (flush_before_close)
				/*int errm =*/ shutdown(s, SD_SEND);
			closesocket(s);
			s = INVALID_SOCKET;
		}
	}

	bool socket::init(signed_t timeout, bool v4)
	{
		if (glb.cfg.ipstack == conf::gip_only6 && v4)
		{
			return false;
		}
		if (glb.cfg.ipstack == conf::gip_only4 && !v4)
		{
			return false;
		}

		if (INVALID_SOCKET != s)
			close(false);

		s = ::socket(v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (INVALID_SOCKET == s)
			return false;

		if (timeout > 0)
		{
#ifdef _WIN32
			DWORD ms = tools::as_dword(timeout);
			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) & ms, sizeof(ms));
#endif
#ifdef _NIX
			struct timeval to = { timeout / 1000, 0 }; // seconds, microseconds
			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
#endif
		}

		return true;
	}

	signed_t socket::listen_udp(const str::astr& name, const ipap& bind2)
	{
		if (glb.cfg.ipstack == conf::gip_only6 && bind2.v4)
		{
			LOG_W("bind failed for listener [%s] due ipv4 addresses are disabled in config", str::printable(name));
			return -1;
		}
		if (glb.cfg.ipstack == conf::gip_only4 && !bind2.v4)
		{
			LOG_W("bind failed for listener [%s] due ipv6 addresses are disabled in config", str::printable(name));
			return -1;
		}

		s = ::socket(bind2.v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (INVALID_SOCKET == s)
			return -1;

		signed_t bport = bind2.bind(s);
		if (bport < 0)
		{
			LOG_W("bind failed for listener [%s]; check binding (%s)", str::printable(name), bind2.to_string(true).c_str());
			close(false);
			return -1;
		}

		return bport;
	}

	tcp_pipe* waitable_socket::tcp_accept(const str::astr &name)
	{
		if (glb.is_stop())
			return nullptr;


#ifdef _NIX
		int dom = -1;
		socklen_t doml = sizeof(dom);
		getsockopt(sock(), SOL_SOCKET, SO_DOMAIN, (char*)&dom, &doml);
		bool v4 = dom == AF_INET;
#endif
#ifdef _WIN32
		WSAPROTOCOL_INFO pi = {};
		int pil = sizeof(pi);
		getsockopt(sock(), SOL_SOCKET, SO_PROTOCOL_INFO, (char*)&pi, &pil);
		bool v4 = pi.iAddressFamily == AF_INET;
#endif

		union
		{
			sockaddr_in addr4;
			sockaddr_in6 addr6;
		} aaaa;
		socklen_t addrlen = v4 ? sizeof(aaaa.addr4) : sizeof(aaaa.addr6);
		SOCKET s = accept(sock(), (sockaddr*)&aaaa, &addrlen);
		if (INVALID_SOCKET == s)
			return nullptr;

		if (glb.is_stop())
        {
            closesocket(s);
            LOG_I("listener %s has been terminated", name.c_str());
            Print();
            return nullptr;
        }

		return NEW tcp_pipe(s, ipap(&aaaa, addrlen));
	}

	bool socket::recv(udp_packet& p)
	{
		sockaddr_in addr4 = {};
		sockaddr_in6 addr6 = {};
		socklen_t sz = p.from.v4 ? sizeof(addr4) : sizeof(addr6);
		int recvsz = recvfrom(s, (char *)p.packet, sizeof(p.packet), 0, p.from.v4 ? (sockaddr *)&addr4 : (sockaddr*)&addr6, &sz);
		if (recvsz <= 0)
			return false;
		if (p.from.v4)
			p.from.set(&addr4, true);
		else
			p.from.set(&addr6, true);
		p.sz = tools::as_word(recvsz);
		return true;
	}
	bool socket::send(const std::span<const u8>& p, const ipap& tgt_ip)
	{
		return tgt_ip.sendto(s, p);
	}

    void tcp_pipe::set_address(endpoint& ainf)
    {
        set_address(ainf.resolve_ip(glb.cfg.ipstack | conf::gip_any));
    }

	bool tcp_pipe::connect()
	{
		if (connected())
			close(false);

		_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (INVALID_SOCKET == sock())
			return false;

		// LOG socket created

		int val = 0;
		socklen_t optl = sizeof(val);
		if (SOCKET_ERROR == getsockopt(sock(), SOL_SOCKET, SO_RCVBUF, (char*)&val, &optl))
		{
			close(false);
			return false;
		}
		if (val < 128 * 1024)
		{
			val = 128 * 1024;
			if (SOCKET_ERROR == setsockopt(sock(), SOL_SOCKET, SO_RCVBUF, (char*)&val, sizeof(val)))
			{
				close(false);
				return false;
			}
		}

		if (SOCKET_ERROR == getsockopt(sock(), SOL_SOCKET, SO_SNDBUF, (char*)&val, &optl))
		{
			close(false);
			return false;
		}
		if (val < 128 * 1024)
		{
			val = 128 * 1024;
			if (SOCKET_ERROR == setsockopt(sock(), SOL_SOCKET, SO_SNDBUF, (char*)&val, sizeof(val)))
			{
				close(false);
				return false;
			}
		}
		else if (val > send_buffer_size)
			send_buffer_size = val;

		if (!addr.connect(sock()))
		{
			close(false);
			return false;
		}

		#ifdef _WIN32
		// non-blocking mode
		u_long one(1);
		ioctlsocket(sock(), FIONBIO, (u_long*)&one);
		#endif
		#ifdef _NIX
        fcntl(sock(), F_SETFL, O_NONBLOCK | fcntl(sock(),F_GETFL));
		#endif

		// LOG connected

		return true;
	}

#ifdef _WIN32
#define CHECK_IF_NOT_NOW (WSAGetLastError() == WSAEWOULDBLOCK)
#endif
#ifdef _NIX
#define CHECK_IF_NOT_NOW (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

	/*virtual*/ bool tcp_pipe::alive()
	{
		if (connected())
			return wait(get_waitable(), 0) != WR_CLOSED;
		return false;
	}

	pipe::sendrslt tcp_pipe::send(const u8* data, signed_t datasize)
	{
		if (data == nullptr)
			return outbuf.is_empty() ? SEND_OK : SEND_BUFFERFULL;

		if (!outbuf.is_empty())
		{
			if (datasize > 0)
			{
				auto d = std::span<const u8>(data, datasize);
				outbuf.append(d);
			}
			auto d2s = outbuf.get_1st_chunk();

			int iRetVal = ::send(sock(), (const char*)d2s.data(), int(d2s.size()), 0);
			if (iRetVal == SOCKET_ERROR)
			{
				if (CHECK_IF_NOT_NOW)
					return SEND_BUFFERFULL;
				return SEND_FAIL;
			}

			outbuf.skip(iRetVal);
			if (outbuf.is_empty())
			{

#ifdef _WIN32
				WSAEventSelect(sock(), get_waitable()->wsaevent, FD_READ|FD_CLOSE);
#endif
#ifdef _NIX
                get_waitable()->bufferfull = 0;
#endif // _NIX
				return SEND_OK;
			}

			return SEND_BUFFERFULL;
		}

		if (datasize == 0)
			return SEND_OK;

		int iRetVal = ::send(sock(), (const char*)data, int(datasize), 0);

		if (iRetVal == SOCKET_ERROR)
		{
			if (!CHECK_IF_NOT_NOW)
			{
				return SEND_FAIL;
			}
			iRetVal = 0;
		}

		if (iRetVal < datasize)
		{
#ifdef _WIN32
			WSAEventSelect(sock(), get_waitable()->wsaevent, FD_READ|FD_WRITE|FD_CLOSE);
#endif
#ifdef _NIX
            // mark this pipe as bufferfull
            get_waitable()->bufferfull = 1;
#endif // _NIX
			auto d = std::span<const u8>(data+iRetVal, datasize-iRetVal);
			outbuf.append(d);
			return SEND_BUFFERFULL;
		}

		return SEND_OK;
	}

	/*virtual*/ signed_t tcp_pipe::recv(u8* data, signed_t maxdatasz)
	{
		if (maxdatasz < 0)
		{
			try
			{
				// need exactly -maxdatasz bytes
				maxdatasz = -maxdatasz;
				for (; rcvbuf.datasize() < maxdatasz;)
				{
					if (!rcv_all())
						return -1;
					if (rcvbuf.datasize() < maxdatasz)
					{
						wrslt rslt = wait(get_waitable(), LOOP_PERIOD);
						if (rslt == WR_CLOSED)
							return -1;
					}
				}
				rcvbuf.peek(data, maxdatasz);
				return maxdatasz;
			}
			catch (const std::exception&) {}
			return -1;
		}

		if (rcvbuf.datasize() < maxdatasz)
			if (!rcv_all())
				return -1;
		if (rcvbuf.datasize() > 0)
			return rcvbuf.peek(data, maxdatasz);
		return 0;
	}

	/*virtual*/ WAITABLE tcp_pipe::get_waitable()
	{
		return waitable_socket::get_waitable();
	}

	bool tcp_pipe::rcv_all()
	{
		if (rcvbuf.is_full())
			return true;

		for (;;)
		{
			u_long rb = 0;
			#ifdef _WIN32
			int er = ioctlsocket(sock(), FIONREAD, &rb);
			#endif
			#ifdef _NIX
			int er = ioctl (sock(), FIONREAD, &rb);
			#endif
			if (er == SOCKET_ERROR)
			{
				close(false);
				return false;
			}

			if (rb == 0 && is_ready(get_waitable())) // check ready bit for complex pipes (like crypto pipe)
				rb = 1;

			if (rb > 0)
			{
				if (rcvbuf.get_free_size() > 1300)
				{
					auto tank = rcvbuf.get_1st_free();

					signed_t _bytes = ::recv(sock(), (char*)tank.data(), (int)(math::minv(tank.size(), 16384)), 0);
					if (_bytes == SOCKET_ERROR)
					{
						if (CHECK_IF_NOT_NOW)
						{
							// nothing to read for now
							break;
						}
						close(false);
						return false;
					}
					if (_bytes == 0)
					{
						// connection closed
						close(false);
						return false;
					}

					clear_ready(get_waitable(), READY_SYSTEM);
					rcvbuf.confirm(_bytes);
					if (rcvbuf.get_free_size() < 1300)
						break;
					continue;
				}
			}

			break;
		}
		return true;
	}

#ifdef _WIN32
	bool dnsresolve_sys(const str::astr& host, ipap& addr)
	{
		ADDRINFOEXA* result = nullptr;

		ADDRINFOEXA hints = {};
		hints.ai_family = AF_UNSPEC;

		if (glb.cfg.ipstack == conf::gip_only4)
			hints.ai_family = AF_INET;
		else if (glb.cfg.ipstack == conf::gip_only6)
			hints.ai_family = AF_INET6;

		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		DWORD dwRetval = GetAddrInfoExA(host.c_str(), nullptr, NS_ALL, nullptr, &hints, &result, nullptr, nullptr, nullptr, nullptr);

		if (dwRetval != NO_ERROR) {

			str::astr message = "getaddrinfo() for [" + host + "] failed. WSAGetLastError: " + std::to_string(::WSAGetLastError());
			LOG_W(message.c_str());
			return false;
		}

		sockaddr_in* a4 = nullptr;
		sockaddr_in6* a6 = nullptr;

		for (ADDRINFOEXA* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
		{
			switch (ptr->ai_family)
			{
			case AF_INET:
				a4 = (sockaddr_in*)ptr->ai_addr;
				continue;
			case AF_INET6:
				a6 = (sockaddr_in6*)ptr->ai_addr;
				continue;
			}
		}

		if (a4 != nullptr && a6 == nullptr && glb.cfg.ipstack != conf::gip_only6)
			addr.set(a4, false);
		else if (a6 != nullptr && a4 == nullptr && glb.cfg.ipstack != conf::gip_only4)
			addr.set(a6, false);
		else if (a4 != nullptr && a6 != nullptr)
		{
			if (glb.cfg.ipstack == conf::gip_prior4 || glb.cfg.ipstack == conf::gip_only4)
				addr.set(a4, false);
			else if (glb.cfg.ipstack == conf::gip_prior6 || glb.cfg.ipstack == conf::gip_only6)
				addr.set(a6, false);
		}


#undef FreeAddrInfoEx
		FreeAddrInfoEx(result);

		return a4 != nullptr || a6 != nullptr;

	}
#endif
#ifdef _NIX
	bool dnsresolve_sys(const str::astr& host, ipap& addr)
	{
		addrinfo hints;
		addrinfo* res;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;

		if (glb.cfg.ipstack == conf::gip_only4)
			hints.ai_family = AF_INET;
		else if (glb.cfg.ipstack == conf::gip_only6)
			hints.ai_family = AF_INET6;

		hints.ai_socktype = SOCK_STREAM;
		//hints.ai_flags = AI_PASSIVE;
		int status = getaddrinfo(host.c_str(), nullptr, &hints, &res);
		if (status != 0)
		{
			str::astr message = "getaddrinfo() for [" + host + "] failed. "+ strerror(status) + " (errno: " + std::to_string(errno) + ")";
			LOG_W(message.c_str());
			return false;
		}

		sockaddr_in* a4 = nullptr;
		sockaddr_in6* a6 = nullptr;

		for (addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {

			switch (rp->ai_family)
			{
			case AF_INET:
				a4 = (sockaddr_in*)rp->ai_addr;
				continue;
			case AF_INET6:
				a6 = (sockaddr_in6*)rp->ai_addr;
				continue;
			}
		}

		if (a4 != nullptr && a6 == nullptr && glb.cfg.ipstack != conf::gip_only6)
			addr.set(a4, false);
		else if (a6 != nullptr && a4 == nullptr && glb.cfg.ipstack != conf::gip_only4)
			addr.set(a6, false);
		else if (a4 != nullptr && a6 != nullptr)
		{
			if (glb.cfg.ipstack == conf::gip_prior4 || glb.cfg.ipstack == conf::gip_only4)
				addr.set(a4, false);
			else if (glb.cfg.ipstack == conf::gip_prior6 || glb.cfg.ipstack == conf::gip_only6)
				addr.set(a6, false);
		}
		else
			return false;

		return true;

	}
#endif

	bool dnsresolve(const str::astr& host, ipap& addr, bool log_it)
	{
		auto int_resolve = [&]()
			{
				netkit::ipap ip = glb.dns->resolve(host, log_it);
				if (!ip.is_wildcard())
				{
					addr.set(ip, false);
					return true;
				}
				return false;
			};

		if ((glb.cfg.dnso & conf::dnso_mask) == conf::dnso_internal)
		{
			if (int_resolve())
				return true;
			if (0 == (glb.cfg.dnso & conf::dnso_bit_use_system))
				return false;
		}
		if (dnsresolve_sys(host, addr))
			return true;

		if (log_it)
		{
			LOG_E("dns: name resolve failed: [%s]", host.c_str());
		}

		return false;
	}

	netkit::endpoint::endpoint(const str::astr& a_raw)
	{
		preparse(a_raw);
	}

	void netkit::endpoint::check_domain_or_ip()
	{
		state_ = EPS_DOMAIN;

		if (domain_ == ASTR("localhost"))
		{
			ip.set(ipap::localhost(true), false);
			state_ = EPS_RESLOVED;
			return;
		}

		ip.set(ipap::parse(domain_,false), false);
		if (!ip.is_wildcard())
		{
			domain_.clear();
			state_ = EPS_RESLOVED;
		}

	}

	void netkit::endpoint::preparse(const str::astr& a_raw)
	{
		// TODO : test with [::1]:999 or [::1]

		str::astr_view a = a_raw;
		if (str::starts_with(a, ASTR("tcp://")))
		{
			sockt = ST_TCP;
			a = a.substr(6);
		}
		else if (str::starts_with(a, ASTR("udp://")))
		{
			sockt = ST_UDP;
			a = a.substr(6);
		}

		if (a.find(ASTR("://")) != str::astr::npos)
			return;

		size_t dv = a.find(':');
		if (dv == str::astr::npos)
		{
			domain_ = a;
			check_domain_or_ip();
			return;
		}

		// may be ipv6

		size_t porti = dv + 1;

		if (a[0] == '[')
		{
			dv = a.find(ASTR("]:"));
			if (dv == str::astr::npos)
			{
				if (a[a.length() - 1] != ']')
					return;
			}
			else
			{
				a = a.substr(1);
				dv = dv - 1;
				porti = dv + 2;
			}
		}


		domain_ = a.substr(0, dv);
		auto ports = a.substr(porti);
		std::from_chars(ports.data(), ports.data() + ports.length(), ip.port);
		check_domain_or_ip();
	}

	ipap netkit::endpoint::resolve_ip(size_t options)
	{
		if (state_ == EPS_RESLOVED)
		{
			if ((options & conf::gip_any) != 0)
				return ip;

			if (ip.v4 && ((options & 0xff) == conf::gip_only4 || (options & 0xff) == conf::gip_prior4))
				return ip;

			if (!ip.v4 && ((options & 0xff) == conf::gip_only6 || (options & 0xff) == conf::gip_prior6))
				return ip;

		}

		if (state_ == EPS_EMPTY)
			return ipap();

		if (netkit::dnsresolve(domain_, ip, (0 != (options & conf::gip_log_it))))
		{
			state_ = EPS_RESLOVED;
			return ip;
		}
		return ipap();
	}

	wrslt wait(WAITABLE s, long microsec)
	{
		if (is_ready(s))
			return WR_READY4READ;

#ifdef _WIN32
		if (microsec == 0)
		{
			WSANETWORKEVENTS e;
			WSAEnumNetworkEvents(s->s, s->wsaevent, &e);
			if (0 != (e.lNetworkEvents & FD_CLOSE))
				return WR_CLOSED;

			if (0 != (e.lNetworkEvents & FD_READ))
			{
				s->ready |= READY_SYSTEM;
				return WR_READY4READ;
			}

			return WR_TIMEOUT;
		}

		u32 rslt = WSAWaitForMultipleEvents(1, &s->wsaevent, TRUE, microsec < 0 ? WSA_INFINITE : (microsec / 1000), FALSE);
		if (WSA_WAIT_TIMEOUT == rslt)
			return WR_TIMEOUT;

		if (rslt == WSA_WAIT_EVENT_0)
		{
			WSANETWORKEVENTS e;
			WSAEnumNetworkEvents(s->s, s->wsaevent, &e);
			if (0 != (e.lNetworkEvents & FD_CLOSE))
				return WR_CLOSED;

			if (0 != (e.lNetworkEvents & FD_READ))
			{
				s->ready |= READY_SYSTEM;
				return WR_READY4READ;
			}

			return WR_CLOSED;
		}
		return WR_READY4READ;
#endif
#ifdef _NIX

        pollfd p = { s->s, POLLIN };
        int pr = poll(&p, 1, microsec * 1000);
        if (pr == 0)
            return WR_TIMEOUT;
        if (pr < 0)
            return WR_CLOSED;
        if (p.revents & POLLIN)
        {
            s->ready |= READY_SYSTEM;
            return WR_READY4READ;
        }

        return WR_TIMEOUT;
#endif
	}

	u64 pipe_waiter::reg(pipe* p)
	{
		u64 mask = 1ull << numw;
		pipes[numw] = p;

		auto x = p->get_waitable();
		if (x == NULL_WAITABLE)
			return 0;

#ifdef _WIN32
		soks[numw] = x->s;
		www[numw] = x->wsaevent;
#endif
#ifdef _NIX
        polls[numw].fd = x->s;
        polls[numw].events = POLLIN;
#endif // _NIX
		if (is_ready(x))
			readymask |= mask;

		++numw;
		return mask;
	}

	void pipe_waiter::unreg_last()
	{
		--numw;
		u64 mask = 1ull << numw;
		readymask &= ~mask;
	}

#ifdef _NIX
	pipe_waiter::mask pipe_waiter::checkall()
	{
        mask m(readymask);

        for (int i = 0; i < numw; ++i)
        {
            WAITABLE w = pipes[i]->get_waitable();
            u_long rb = 0;
            int er = ioctl (w->s, FIONREAD, &rb);
            if (er < 0)
            {
                m.add_close(1ull << i);
            } else if (rb > 0)
            {
                m.add_read(1ull << i);
                make_ready(w, READY_SYSTEM);
            }
            if (w->bufferfull)
            {
                rb = 0;
                int er = ioctl (w->s, SIOCOUTQ, &rb);
                if (er < 0)
                    m.add_close(1ull << i);
                else if ((send_buffer_size-rb) > 0)
                    m.add_write(1ull << i);
            }

        }

        readymask = 0;
        numw = 0;
        return m;

	}
#endif // _NIX

	pipe_waiter::mask pipe_waiter::wait(long microsec)
	{
#ifdef _WIN32
		if (readymask != 0)
		{
			u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw), www, FALSE, 0, FALSE);

			if (rslt >= WSA_WAIT_EVENT_0 && (rslt - WSA_WAIT_EVENT_0) < numw)
			{
				signed_t i = (rslt - WSA_WAIT_EVENT_0);

				mask m(readymask);

				WSANETWORKEVENTS e;
				for (; i < numw; ++i)
				{
					WSAEnumNetworkEvents(soks[i], www[i], &e);
					if (0 != (e.lNetworkEvents & FD_CLOSE))
					{
						m.add_close(1ull << i);
					}
					if (0 != (e.lNetworkEvents & FD_READ))
					{
						m.add_read(1ull << i);
						make_ready(pipes[i]->get_waitable(), READY_SYSTEM);
					}
					if (0 != (e.lNetworkEvents & FD_WRITE))
					{
						m.add_write(1ull << i);
					}
				}

				readymask = 0;
				numw = 0;
				return m;
			}

			u64 rm = readymask;
			readymask = 0;
			numw = 0;
			return mask(rm);
		}

		if (numw == 0)
			return mask();

		if (sig == NULL_WAITABLE)
		{
			sig = WSACreateEvent();
		}

		www[numw] = sig;
		u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw + 1), www, FALSE, microsec < 0 ? WSA_INFINITE : (microsec / 1000), FALSE);
		if (WSA_WAIT_TIMEOUT == rslt)
		{
			readymask = 0;
			numw = 0;
			return mask();
		}

		if (rslt == WSA_WAIT_EVENT_0 + numw)
		{
			// signal
			WSAResetEvent(sig);
			readymask = 0;
			numw = 0;
			return mask();
		}

		if (rslt >= WSA_WAIT_EVENT_0 && (rslt-WSA_WAIT_EVENT_0) < numw)
		{
			signed_t i = (rslt - WSA_WAIT_EVENT_0);

			mask m;
			WSANETWORKEVENTS e;
			for (; i < numw; ++i)
			{
				WSAEnumNetworkEvents(soks[i], www[i], &e);
				if (0 != (e.lNetworkEvents & FD_CLOSE))
				{
					m.add_close(1ull << i);
				}
				if (0 != (e.lNetworkEvents & FD_READ))
				{
					m.add_read(1ull << i);
					make_ready(pipes[i]->get_waitable(), READY_SYSTEM);
				}
				if (0 != (e.lNetworkEvents & FD_WRITE))
				{
					m.add_write(1ull << i);
				}
			}

			readymask = 0;
			numw = 0;
			return m;
		}

#endif
#ifdef _NIX
		if (readymask != 0)
		{
		    return checkall();
        }

		if (numw == 0)
			return mask();

		if (evt[0] < 0)
		{
			socketpair(PF_LOCAL, SOCK_STREAM, 0, evt);
		}

		polls[numw].fd = evt[0];
		polls[numw].events = POLLIN;

		for (signed_t i = 0; i < numw; ++i)
        {
            WAITABLE w = pipes[i]->get_waitable();
            if (w->bufferfull)
            {
                polls[i].events = POLLIN | POLLOUT;
            } else {
                polls[i].events = POLLIN;
            }
        }

        int er = poll(polls, numw+1, microsec >= 0 ? (microsec/1000) : -1);
		if (er < 0)
            return checkall();

        mask m;
        for (signed_t i = 0; i < numw; ++i)
        {
            ;
            if (0 != (polls[i].revents & (POLLHUP|POLLERR|POLLNVAL)))
            {
                m.add_close(1ull << i);
            }
            if (0 != (polls[i].revents & POLLIN))
            {
                m.add_read(1ull << i);
                make_ready(pipes[i]->get_waitable(), READY_SYSTEM);
            }
            if (0 != (polls[i].revents & POLLOUT))
            {
                m.add_write(1ull << i);
            }
        }

        if (0 != (polls[numw].revents & POLLIN))
        {
            u8 temp[64];
            ::recv(evt[0], temp, sizeof(temp), 0); // just clear buf of socketpair
        }

        readymask = 0;
        numw = 0;
        return m;
#endif

		readymask = 0;
		numw = 0;
        return mask();
	}

	void pipe_waiter::signal()
	{
#ifdef _WIN32
		if (sig)
			WSASetEvent(sig);
#endif
#ifdef _NIX

        u8 fakedata = 1;
		::send(evt[1], &fakedata, 1, 0);
#endif
	}

	namespace {
		struct udpss : thread_storage_data
		{
			netkit::socket s;
			bool v4;
			udpss(bool v4) :v4(v4)
			{
				s.init(1000, v4);
			}
			~udpss()
			{

			}
		};
	}

	/*
	void udp_prepare(thread_storage& ts, bool v4)
	{
		if (ts.data == nullptr || static_cast<udpss*>(ts.data.get())->v4 != v4)
			ts.data.reset(NEW udpss(v4));
	}
	*/

    io_result udp_send(thread_storage& ts, const endpoint& toaddr, const pgen& pg /* in/out */)
    {
        udpss* s = static_cast<udpss*>(ts.data.get());
		const netkit::endpoint* ep = &toaddr;
        netkit::endpoint epl;
        if (toaddr.state() != netkit::EPS_RESLOVED)
        {
			epl = toaddr;
            epl.resolve_ip(glb.cfg.ipstack | conf::gip_log_it);
			if (epl.state() != netkit::EPS_RESLOVED)
				return io_result::ior_notresolved;
			ep = &epl;
        }


		if (s == nullptr || s->v4 != ep->get_ip().v4)
		{
			s = NEW udpss(ep->get_ip().v4);
		}

        if (!s->s.send(pg.to_span(), ep->get_ip()))
            return ior_send_failed;

		// IMPORTANT! thread_storage ts MUST be initialized just after send, not before
		if (ts.data.get() != s)
			ts.data.reset(s);

        return ior_ok;
    }

	io_result udp_recv(thread_storage& ts, netkit::ipap& from, pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/)
	{
		if (!ts.data)
			return ior_general_fail; // it is forbidden to do recv before send; send will initialize ts

		udpss* s = static_cast<udpss*>(ts.data.get());

		udp_packet p(s->v4);
		if (s->s.recv(p))
		{
			if (p.sz > max_bufer_size)
				return ior_general_fail;

			from = p.from;
			pg.copy_from(p);

			return ior_ok;
		}

		return ior_timeout;

	}

} // netkit

