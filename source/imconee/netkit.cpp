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

	ip4 ip4::parse(const str::astr_view& s)
	{
		ip4 rv = {};
		u8* dst = (u8*)&rv;
		u8* end = dst + 4;

		for (str::token<char> tkn(s, '.'); tkn; ++tkn)
		{
			*dst = (u8)std::stoi(str::astr(*tkn));
			++dst;
			if (dst > end)
			{
				rv.s_addr = 0;
				break;
			}
		}
		return rv;
	}

	void socket::close(bool flush_before_close)
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

	bool socket::tcp_listen(const ip4& bind2, int port)
	{
		_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (INVALID_SOCKET == sock())
			return false;

		sockaddr_in addr;

		addr.sin_family = AF_INET;
		addr.sin_addr = bind2;
		addr.sin_port = netkit::to_ne((u16)port);

		if (SOCKET_ERROR == bind(sock(), (const sockaddr *)&addr, sizeof(addr)))
		{
			LOG_W("bind failed for listener [%s]", str::printable(name));
			close(false);
			return false;
		};

		if (SOCKET_ERROR == listen(sock(), SOMAXCONN))
		{
			LOG_W("listen failed for listener [%s]", str::printable(name));
			close(false);
			return false;
		}

		return true;
	}

	tcp_pipe* socket::tcp_accept()
	{
		if (engine::is_stop())
			return nullptr;

		sockaddr_in addr;
		socklen_t AddrLen = sizeof(addr);
		SOCKET s = accept(sock(), (sockaddr*)&addr, &AddrLen);
		if (INVALID_SOCKET == s)
			return nullptr;

		if (engine::is_stop())
        {
            closesocket(s);
            LOG_I("Listener %s has been terminated", name.c_str());
            return nullptr;
        }

		return new tcp_pipe(s, addr);
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

		while (SOCKET_ERROR == ::connect(sock(), (const sockaddr *)&addr, sizeof(addr)))
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
						wait(get_waitable(), LOOP_PERIOD);
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
		return socket::get_waitable();
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
	bool dnsresolve(const str::astr& host, ip4& addr)
	{
		ADDRINFOEXA* result = nullptr;

		ADDRINFOEXA hints = {};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		DWORD dwRetval = GetAddrInfoExA(host.c_str(), nullptr, NS_ALL, nullptr, &hints, &result, nullptr, nullptr, nullptr, nullptr);

		if (dwRetval != NO_ERROR) {

			str::astr message = "getaddrinfo() for [" + host + "] failed. WSAGetLastError: " + std::to_string(::WSAGetLastError());
			LOG_W(message.c_str());
			return false;
		}

		for (ADDRINFOEXA* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
		{

			switch (ptr->ai_family)
			{
			case AF_UNSPEC:
				continue;
			case AF_INET:
				addr = (struct sockaddr_in*)ptr->ai_addr;
				break;
			case AF_INET6:
				continue;
			}
		}

#undef FreeAddrInfoEx
		FreeAddrInfoEx(result);

		return true;

	}
#endif
#ifdef _NIX
	bool dnsresolve(const str::astr& host, ip4& addr)
	{
		struct addrinfo hints;
		struct addrinfo* res;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		//hints.ai_flags = AI_PASSIVE;
		int status = getaddrinfo(host.c_str(), nullptr, &hints, &res);
		if (status != 0)
		{
			str::astr message = "getaddrinfo() for [" + host + "] failed. "+ strerror(status) + " (errno: " + std::to_string(errno) + ")";
			LOG_W(message.c_str());
			return false;
		}

		addr = res;
		return true;

	}
#endif

	netkit::endpoint::endpoint(const str::astr& a_raw)
	{
		preparse(a_raw);
	}

	void netkit::endpoint::preparse(const str::astr& a_raw)
	{
		str::astr_view a = a_raw;
		if (str::starts_with(a, ASTR("tcp://")))
			a = a.substr(6);

		if (a.find(ASTR("://")) != str::astr::npos)
			return;

		size_t dv = a.find(':');
		if (dv == str::astr::npos)
		{
			domain_ = a;
			type_ = AT_TCP_DOMAIN;
			return;
		}
		domain_ = a.substr(0, dv);
		auto ports = a.substr(dv + 1);
		std::from_chars(ports.data(), ports.data() + ports.length(), port_);
		type_ = AT_TCP_DOMAIN;
	}

	ip4 netkit::endpoint::get_ip4(bool log_enable) const
	{
		if (type_ == AT_TCP_RESLOVED)
			return ip;

		if (type_ == AT_ERROR)
			return ip4();

		if (netkit::dnsresolve(domain_, ip))
		{
			type_ = AT_TCP_RESLOVED;
			return ip;
		}
		else if (log_enable)
		{
			LOG_E("domain name resolve failed: [%s]", domain_.c_str());
		}
		return ip4();
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

}

