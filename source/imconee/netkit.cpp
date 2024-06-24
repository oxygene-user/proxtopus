#include "pch.h"
#include "Ws2tcpip.h"

namespace netkit
{
	ip4 ip4::parse(const std::string_view& s)
	{
		ip4 rv = {};
		u8* dst = (u8*)&rv;
		u8* end = dst + 4;

		for (str::token<char> tkn(s, '.'); tkn; ++tkn)
		{
			*dst = (u8)std::stoi(std::string(*tkn));
			++dst;
			if (dst > end)
			{
				rv.S_un.S_addr = 0;
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

		if (SOCKET_ERROR == bind(sock(), (SOCKADDR*)&addr, sizeof(addr)))
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
		int AddrLen = sizeof(addr);
		SOCKET s = accept(sock(), (sockaddr*)&addr, &AddrLen);
		if (INVALID_SOCKET == s)
			return nullptr;

		if (engine::is_stop())
			return nullptr;

		return new tcp_pipe(s, addr);
	}


	bool tcp_pipe::connect()
	{
		if (connected())
			closesocket(sock());

		_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (INVALID_SOCKET == sock())
			return false;

		// LOG socket created

		int val = 1024 * 128;
		if (SOCKET_ERROR == setsockopt(sock(), SOL_SOCKET, SO_RCVBUF, (char*)&val, sizeof(val)))
		{
			close(false);
			return false;
		}
		if (SOCKET_ERROR == setsockopt(sock(), SOL_SOCKET, SO_SNDBUF, (char*)&val, sizeof(val)))
		{
			close(false);
			return false;
		}

		if (SOCKET_ERROR == ::connect(sock(), (LPSOCKADDR)&addr, sizeof(addr)))
		{
			close(false);
			//error_ = WSAGetLastError();
			//if (WSAEWOULDBLOCK != error_)
			return false;
		}

		// LOG connected

		return true;
	}

	bool tcp_pipe::send(const u8* data, signed_t datasize)
	{
		const u8* d2s = data;
		signed_t sent = 0;

		do
		{
			int iRetVal = ::send(sock(), (const char*)(d2s + sent), int(datasize - sent), 0);
			if (iRetVal == SOCKET_ERROR)
			{
				return false;
			}
			if (iRetVal == 0)
				__debugbreak();
			sent += iRetVal;
		} while (sent < datasize);

		return true;
	}

	/*virtual*/ signed_t tcp_pipe::recv(u8* data, signed_t maxdatasz)
	{
		if (maxdatasz < 0)
		{
			try
			{
				// need exactly -maxdatasz bytes
				maxdatasz = -maxdatasz;
				for (; rcvbuf_sz < maxdatasz;)
				{
					if (!rcv_all())
						return -1;
					if (rcvbuf_sz < maxdatasz)
						wait(get_waitable(), LOOP_PERIOD);
				}
				memcpy(data, rcvbuf, maxdatasz);
				cpdone(maxdatasz);
				return maxdatasz;
			}
			catch (const std::exception&) {}
			return -1;
		}

		if (rcvbuf_sz < maxdatasz)
			if (!rcv_all())
				return -1;
		if (rcvbuf_sz > 0)
		{
			signed_t mds = math::minv(rcvbuf_sz, maxdatasz);
			memcpy(data, rcvbuf, mds);
			cpdone(mds);
			return mds;
		}
		return 0;
	}

	/*virtual*/ WAITABLE tcp_pipe::get_waitable()
	{
#ifdef _WIN32
		return socket::get_waitable();
#endif
	}

	bool tcp_pipe::rcv_all()
	{
		if (rcvbuf_sz >= sizeof(rcvbuf))
			return true;

		for (;;)
		{
			wrslt r = wait(get_waitable(), 0);
			if (WR_READY4READ == r)
			{
				signed_t buf_free_space = sizeof(rcvbuf) - rcvbuf_sz;
				if (buf_free_space > 1300)
				{
					signed_t reqread = 65536;
					if (buf_free_space < reqread)
						reqread = buf_free_space;

					signed_t _bytes = ::recv(sock(), (char*)rcvbuf + rcvbuf_sz, (int)reqread, 0);
					if (_bytes == 0 || _bytes == SOCKET_ERROR)
					{
						// connection closed
						close(false);
						return false;
					}

					clear_ready(get_waitable(), 1);

					rcvbuf_sz += _bytes;
					if ((sizeof(rcvbuf) - rcvbuf_sz) < 1300)
						break;
					continue;
				}
			}
			else if (WR_CLOSED == r)
			{
				close(false);
				return false;
			}

			break;
		}
		return true;
	}



	bool dnsresolve(const std::string& host, ip4& addr)
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
			std::string message = "getaddrinfo() for [" + host + "] failed. "
#if defined( _WIN32 ) && !defined( __SYMBIAN32__ )
				"WSAGetLastError: " + std::to_string(::WSAGetLastError());
#else
				+ strerror(err) + " (errno: " + std::to_string(errno) + ")";
#endif

			LOG_W(message.c_str());
			return false;
		}

		addr = res;
		return true;

	}


	netkit::endpoint::endpoint(const std::string& a_raw)
	{
		preparse(a_raw);
	}

	void netkit::endpoint::preparse(const std::string& a_raw)
	{
		std::string_view a = a_raw;
		if (str::starts_with(a, ASTR("tcp://")))
			a = a.substr(6);

		if (a.find(ASTR("://")) != std::string::npos)
			return;

		size_t dv = a.find(':');
		if (dv == std::string::npos)
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
#ifdef _WIN32

		if (is_ready(s))
			return WR_READY4READ;

		if (microsec == 0)
		{
			WSANETWORKEVENTS e;
			WSAEnumNetworkEvents(s->s, s->wsaevent, &e);
			if (0 != (e.lNetworkEvents & FD_CLOSE))
				return WR_CLOSED;

			if (0 != (e.lNetworkEvents & FD_READ))
			{
				s->ready |= 1;
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
				s->ready |= 1;
				return WR_READY4READ;
			}

			return WR_CLOSED;
		}
#endif
#ifdef _NIX

		fd_set rs = {};
		rs.fd_array[0] = s;
		rs.fd_count = 1;

		TIMEVAL tv;
		tv.tv_sec = 0;
		tv.tv_usec = microsec;

		signed_t n = ::select((int)(s + 1), &rs, nullptr, nullptr, microsec >= 0 ? &tv : nullptr);
		if (n == SOCKET_ERROR)
			return WR_CLOSED;
#endif
		return WR_READY4READ;
	}

	u64 pipe_waiter::reg(pipe* p)
	{
		u64 mask = 1ull << numw;
		pipes[numw] = p;

		auto x = p->get_waitable();
		if (x == NULL_WAITABLE)
			return 0;

#ifdef _WIN32
		www[numw] = x->wsaevent;
		soks[numw] = x->s;
#else
		todo
#endif
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


	std::tuple<u64, u64> pipe_waiter::wait(long microsec)
	{
		if (readymask != 0)
		{
			u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw), www, FALSE, 0, FALSE);

			if (rslt >= WSA_WAIT_EVENT_0 && (rslt - WSA_WAIT_EVENT_0) < numw)
			{
				signed_t i = (rslt - WSA_WAIT_EVENT_0);

				u64 mask_read = readymask;
				u64 mask_close = 0;
				WSANETWORKEVENTS e;
				for (; i < numw; ++i)
				{
					WSAEnumNetworkEvents(soks[i], www[i], &e);
					if (0 != (e.lNetworkEvents & FD_CLOSE))
					{
						mask_close |= 1ull << i;
					}
					if (0 != (e.lNetworkEvents & FD_READ))
					{
						mask_read |= 1ull << i;
						make_ready(pipes[i]->get_waitable(), 1);
					}
				}

				readymask = 0;
				numw = 0;
				return { mask_read, mask_close };
			}

			u64 rm = readymask;
			readymask = 0;
			numw = 0;
			return { rm, 0 };
		}

		if (numw == 0)
			return { 0, 0 };

		if (sig == NULL_WAITABLE)
		{
#ifdef _WIN32
			sig = WSACreateEvent();
#endif
		}

		www[numw] = sig;
		u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw + 1), www, FALSE, microsec < 0 ? WSA_INFINITE : (microsec / 1000), FALSE);
		if (WSA_WAIT_TIMEOUT == rslt)
		{
			readymask = 0;
			numw = 0;
			return { 0, 0 };
		}

		if (rslt == WSA_WAIT_EVENT_0 + numw)
		{
			// signal
			WSAResetEvent(sig);
			readymask = 0;
			numw = 0;
			return { 0, 0 };
		}

		if (rslt >= WSA_WAIT_EVENT_0 && (rslt-WSA_WAIT_EVENT_0) < numw)
		{
			signed_t i = (rslt - WSA_WAIT_EVENT_0);

			u64 mask_read = 0;
			u64 mask_close = 0;
			WSANETWORKEVENTS e;
			for (; i < numw; ++i)
			{
				WSAEnumNetworkEvents(soks[i], www[i], &e);
				if (0 != (e.lNetworkEvents & FD_CLOSE))
				{
					mask_close |= 1ull << i;
				}
				if (0 != (e.lNetworkEvents & FD_READ))
				{
					mask_read |= 1ull << i;
					make_ready(pipes[i]->get_waitable(), 1);
				}
			}

			readymask = 0;
			numw = 0;
			return { mask_read, mask_close };
		}

		readymask = 0;
		numw = 0;
		return { 0, 0 };
	}

	void pipe_waiter::signal()
	{
		if (sig)
			WSASetEvent(sig);
	}

}

