#include "pch.h"
#ifdef _WIN32
#include <Ws2tcpip.h>
#endif
#ifdef _NIX
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/sockios.h> // SIOCOUTQ
#endif

#ifdef _WIN32
#define CHECK_IF_NOT_NOW (WSAGetLastError() == WSAEWOULDBLOCK)
#endif
#ifdef _NIX
#define CHECK_IF_NOT_NOW (errno == EAGAIN || errno == EWOULDBLOCK)
#endif


namespace {

    str::astr_view err2str(signed_t error_code)
    {
        switch (error_code) {
#ifdef _WIN32
            // Windows error messages
        case WSAEACCES: return ASTR("Permission denied");
        case WSAEADDRINUSE: return ASTR("Address already in use");
        case WSAEADDRNOTAVAIL: return ASTR("Cannot assign requested address");
        case WSAEFAULT: return ASTR("Invalid pointer address");
        case WSAEINVAL: return ASTR("Socket already bound to an address or invalid family");
        case WSAENOBUFS: return ASTR("No buffer space available");
        case WSAENOTSOCK: return ASTR("Descriptor is not a socket");
        default: return ASTR("Unknown Windows socket error");
#else
            // Linux/Unix error messages
        case EACCES: return ASTR("Permission denied");
        case EADDRINUSE: return ASTR("Address already in use");
        case EBADF: return ASTR("Invalid socket descriptor");
        case EINVAL: return ASTR("Socket already bound to an address");
        case ENOTSOCK: return ASTR("Descriptor is not a socket");
        case EADDRNOTAVAIL: return ASTR("Cannot assign requested address");
        case EFAULT: return ASTR("Invalid pointer address");
        case ELOOP: return ASTR("Too many symbolic links encountered");
        case ENAMETOOLONG: return ASTR("Path name too long");
        case ENOENT: return ASTR("Path name does not exist");
        case ENOMEM: return ASTR("Insufficient kernel memory");
        case ENOTDIR: return ASTR("Component of path not a directory");
        case EROFS: return ASTR("Socket inode would reside on read-only filesystem");
        default: return ASTR("Unknown Unix socket error");
#endif
        }
    }
}

namespace netkit
{
    static signed_t send_buffer_size = 128 * 1024; // 128k

    void ipap::clear()
    {
        flags.set<f_v4>(glb.cfg.ipstack == conf::gip_only4 || glb.cfg.ipstack == conf::gip_prior4);
        if (flags.is<f_v4>()) ipv4.s_addr = 0; else memset(&ipv6, 0, sizeof(ipv6));
        flags.set<f_empty>();
    }

    ipap ipap::parse6(const str::astr_view& s, size_t parse_options)
    {
        bool colon = false;
        bool fillright = false;
        signed_t somedigits = 0;

        signed_t cntl = 0, cntr = 0;
        std::array<u16be, 8> left;
        std::array<u16be, 8> rite;

        u16 current = 0;

        auto pushdig = [&]() -> bool
        {
            if (fillright)
            {
                rite[cntr++] = current;
                if (cntl + cntr == 7)
                    return true;
            }
            else {
                left[cntl++] = current;
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

        signed_t check_port_or_prefix = -1;
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
                if (0 != (parse_options & (f_port|f_prefix)))
                    check_port_or_prefix = i + 1;
                clexpected = false;
                break;
            }
            if (0 != (parse_options & (f_prefix)) && c == '/')
            {
                check_port_or_prefix = i;
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
        u16be *w = rv.words();
        signed_t i = 0;
        for (; i < cntl; ++i)
            w[i] = left[i];

        signed_t i2 = 8 - cntr;

        for (; i < i2; ++i)
            w[i] = 0;

        for (signed_t j = 0;i < 8; ++i, ++j)
            w[i] = rite[j];

        rv.flags.unset<f_empty>();

        if (check_port_or_prefix > 0)
        {
            if ((parse_options & f_port) && s[check_port_or_prefix] == ':')
            {
                rv.port = tools::as_word(str::parse_int(s.substr(check_port_or_prefix + 1), 65535, 0));
                rv.flags.set<f_port>( rv.port != 0 );

            } else if (parse_options & f_prefix)
            {
                if (s[check_port_or_prefix] == '/')
                {
                    rv.port = tools::as_word(str::parse_int(s.substr(check_port_or_prefix + 1), 128, 129));
                    if (rv.port == 129)
                    {
                        rv.flags.unset<f_prefix>();
                        rv.port = 0;
                    } else
                        rv.flags.set<f_prefix>();
                }
                else if (parse_options & f_prefix_default)
                {
                    rv.port = 128;
                    rv.flags.set<f_prefix>();
                }
            }
        }

        return rv;
    }

    ipap ipap::parse(const str::astr_view& s, size_t parse_options)
    {
        if (s.empty())
            return ipap();

        if (s[0] == '[')
            return parse6(s, parse_options);

        signed_t numd = 0;
        for( char c : s )
            if (c == ':')
            {
                ++numd;
                if (numd == 2)
                    return parse6(s, parse_options);
            }

        ipap rv;

        u8* dst = reinterpret_cast<u8 *>(&rv.ipv4.s_addr); // from low to high on little endian cpu because ipv4.s_addr is in big endian
        signed_t index = 0;
        for (str::token<char, str::sep_onechar<char, '.'>> tkn(s); tkn; tkn(), ++index, ++dst)
        {
            if (index >= 4)
            {
                rv.clear();
                return rv;
            }

            if (index == 3)
            {
                size_t i = 0;
                char ndc = 0;
                for (; i < tkn->size(); ++i)
                {
                    if (char ndc1 = tkn->at(i); !is_digit(ndc1))
                    {
                        ndc = ndc1;
                        break;
                    }
                }
                rv.flags.unset<f_empty>();
                if ((parse_options & f_port) && ndc == ':')
                {
                    rv.port = tools::as_word(str::parse_int(tkn->substr(i + 1), 65535, 0));
                    rv.flags.set<f_port>(rv.port != 0);
                }
                else if (parse_options & f_prefix)
                {
                    if (ndc == '/')
                    {
                        rv.port = tools::as_word(str::parse_int(tkn->substr(i + 1), 32, 33));
                        if (rv.port == 33)
                        {
                            rv.flags.unset<f_prefix>();
                            rv.port = 0;
                        } else
                            rv.flags.set<f_prefix>();
                    }
                    else if (parse_options & f_prefix_default)
                    {
                        rv.port = 32;
                        rv.flags.set<f_prefix>();
                    }
                }

                tkn.trim(i);
            }

            signed_t oktet = str::parse_int(*tkn, 255, 256);
            if (oktet > 255)
            {
                rv.clear();
                return rv;
            }
            *dst = tools::as_byte(oktet);

        }

        return rv;
    }

    bool ipap::connect(system_socket_type s) const
    {
        ASSERT(!is_empty());
        // non-blocking mode
#ifdef _WIN32
        u_long one(1);
        ioctlsocket(s, FIONBIO, (u_long*)&one);
#else
        fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL));
        using SOCKET = int;
#endif
        auto call_connect = [this](SOCKET s) -> auto
        {
            ASSERT(has_port());
            if (v4())
            {
                sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_addr = ipv4;
                ref_cast<u16be>(addr.sin_port) = port;
                return ::connect(s, (const sockaddr*)&addr, sizeof(addr));
            }

            sockaddr_in6 addr = {};
            addr.sin6_family = AF_INET6;
            tools::memcopy<sizeof(ipv6)>(&addr.sin6_addr, &ipv6);
            ref_cast<u16be>(addr.sin6_port) = port;
            return ::connect(s, (const sockaddr*)&addr, sizeof(addr));
        };

        auto result = call_connect(s);
        if (result == 0)
            return true;

#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK)
            return false;

        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);

        TIMEVAL tv;
        tv.tv_sec = glb.cfg.connect_timeout/1000;
        tv.tv_usec = (glb.cfg.connect_timeout % 1000) * 1000;

        return select(0, nullptr, &writefds, nullptr, &tv) > 0;
#else
        if (errno != EINPROGRESS)
            return false;

        pollfd pfd;

        pfd.fd = s;
        pfd.events = POLLOUT;

        return poll(&pfd, 1, glb.cfg.connect_timeout) > 0;
#endif
    }

    str::astr endpoint::desc() const
    {
        ASSERT(ip.has_port());

        str::astr d(domain_);
        if (!d.empty())
        {
            d.push_back(':');
            str::append_num(d, ip.port, 0);
        }
        switch (state_)
        {
        case netkit::EPS_DOMAIN:
            break;
        case netkit::EPS_RESLOVED:
            if (d.empty())
            {
                d = ip.to_string();
            }
            else
            {
                str::astr ipa = ip.addr_to_string();
                if (d.find(ipa) == d.npos)
                {
                    d.append(ASTR(" ("));
                    d.append(ipa);
                    d.push_back(')');
                }
            }
            break;
        default:
            if (!d.empty()) d.push_back(' ');
            d.append(ASTR("(unresolved)"));
            break;
        }
        return d;
    }

    str::astr endpoint::to_string(endpoint_string eps) const
    {
        str::astr d;
        switch (state_)
        {
        case netkit::EPS_RESLOVED:
            if (d.empty())
            {
                d = ip.to_string();
                break;
            }
            else if (eps == EPS_GET_IP_IF_RESOLVED)
            {
                d = ip.to_string();
                break;
            }
            [[fallthrough]];
        case netkit::EPS_DOMAIN:
            d = domain_;
            d.push_back(':');
            str::append_num(d, ip.port, 0);
            break;
        default:
            break;
        }
        return d;
    }

    /*virtual*/ bool SYSTEM_DATAGRAM_SOCKET::sendto(const ipap& a, const std::span<const u8>& p) const
    {
        ASSERT(a.has_port());

        if (a.v4())
        {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr = a.ipv4;
            ref_cast<u16be>(addr.sin_port) = a.port;
            return SOCKET_ERROR != ::sendto(s, (const char*)p.data(), (int)p.size(), 0, (const sockaddr*)&addr, sizeof(addr));
        }

        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        tools::memcopy<sizeof(a.ipv6)>(&addr.sin6_addr, &a.ipv6);
        ref_cast<u16be>(addr.sin6_port) = a.port;
        return SOCKET_ERROR != ::sendto(s, (const char*)p.data(), (int)p.size(), 0, (const sockaddr*)&addr, sizeof(addr));
    }

#ifdef _WIN32
    /*virtual*/ u8 win32_stream_socket::wait(size_t reqevts, signed_t timeout_ms)
    {
        ASSERT(reqevts != 0);

        if (s == INVALID_SOCKET)
            return SE_CLOSED;

        ASSERT(wsaevent);

        u8 evts = tools::as_byte(flags.getn<f_events>());
        if (flags.is<f_pipeready>())
            evts |= SE_READ;

        if (reqevts == evts)
        {
            flags.setn<f_events>(evts & (~reqevts)); // reset all requested bits
            return evts;
        }

        for (;;)
        {
            chrono::mils wst = timeout_ms > 0 ? chrono::ms() : chrono::mils();

            u32 rslt = WSA_WAIT_FAILED;
            if (timeout_ms != 0)
            {
                rslt = WSAWaitForMultipleEvents(1, &wsaevent, TRUE, timeout_ms < 0 ? WSA_INFINITE : (DWORD)timeout_ms, FALSE);
                if (WSA_WAIT_TIMEOUT == rslt)
                    return SE_TIMEOUT;
            }

            if (timeout_ms == 0 || rslt == WSA_WAIT_EVENT_0)
            {
                WSANETWORKEVENTS e;
                WSAEnumNetworkEvents(s, wsaevent, &e);
                if (e.lNetworkEvents & FD_CLOSE)
                {
                    close(true);
                    return SE_CLOSED;
                }

                if (e.lNetworkEvents & FD_READ)
                    evts |= SE_READ;
                if (e.lNetworkEvents & FD_WRITE)
                    evts |= SE_WRITE;

                u8 ret = evts & reqevts;
                if (ret == 0)
                {
                    flags.setn<f_events>(evts);

                    if (timeout_ms == 0)
                        break;

                    if (timeout_ms > 0)
                    {
                        signed_t delta = chrono::ms() - wst;
                        timeout_ms -= delta;
                        if (timeout_ms <= 0)
                            return netkit::SE_TIMEOUT;
                    }

                    continue;
                }

                flags.setn<f_events>(evts & (~reqevts)); // reset all requested bits

                return ret;
            }
            else
                break;
        }
        return SE_TIMEOUT;
    }

#else

    /*virtual*/ u8 nix_stream_socket::wait(size_t reqevts, signed_t timeout_ms)
    {
        if (s < 0)
            return SE_CLOSED;

        u8 evts = tools::as_byte(flags.getn<f_events>());
        if (flags.is<f_pipeready>())
            evts |= SE_READ;

        if (reqevts == evts)
        {
            flags.setn<f_events>(evts & (~reqevts)); // reset all requested bits
            return evts;
        }

        pollfd p = { s, (short int)(((reqevts & SE_READ) ? POLLIN : 0) | ((reqevts & SE_WRITE) ? POLLOUT : 0)) };
        int pr = poll(&p, 1, timeout_ms);
        if (pr == 0)
            return SE_TIMEOUT;
        if (pr < 0)
        {
            close(true);
            return SE_CLOSED;
        }
        if (p.revents & POLLIN)
            evts |= SE_READ;
        if (p.revents & POLLOUT)
            evts |= SE_WRITE;

        flags.setn<f_events>(evts & (~reqevts)); // reset all requested bits

        return evts & reqevts;

    }
#endif

    signed_t bind(system_socket_type s, const ipap& a)
    {
#ifdef _NIX
        static const constexpr int SOCKET_ERROR = -1;
#endif

        if (a.v4())
        {
            sockaddr_in addr;

            addr.sin_family = AF_INET;
            addr.sin_addr = a.ipv4;

            signed_t rp = a.has_port() ? a.port : 0;
            ref_cast<u16be>(addr.sin_port) = rp;

            bool ok = SOCKET_ERROR != ::bind(s, (const sockaddr*)&addr, sizeof(addr));
            if (!ok)
                return -1;

            if (rp == 0)
            {
                //#ifdef _WIN32
                socklen_t x = sizeof(addr);
                getsockname(s, (sockaddr*)&addr, &x);
                rp = u16be::from_be(addr.sin_port);
                //#endif
            }
            return rp;
        }

        sockaddr_in6 addr = {};

        addr.sin6_family = AF_INET6;
        tools::memcopy<sizeof(a.ipv6)>(&addr.sin6_addr, &a.ipv6);
        signed_t rp = a.has_port() ? a.port : 0;
        ref_cast<u16be>(addr.sin6_port) = rp;

        bool ok = SOCKET_ERROR != ::bind(s, (const sockaddr*)&addr, sizeof(addr));

        if (!ok)
            return -1;

        if (rp == 0)
        {
            socklen_t x = sizeof(addr);
            getsockname(s, (sockaddr*)&addr, &x);
            rp = u16be::from_be(addr.sin6_port);
        }
        return rp;
    }

    signed_t SYSTEM_STREAM_ACCEPTOR_SOCKET::bind(const ipap &a)
    {
        for (signed_t btc = glb.bind_try_count; btc > 0; --btc)
        {
            //LOG_D("try bind ($/$): $", glb.bind_try_count-btc+1, glb.bind_try_count, this->to_string(true));
            signed_t x = netkit::bind(s, a);
            if (x >= 0)
                return x;
            if (btc > 1) spinlock::sleep(1000);
        }
        return -1;
    }
    static bool log_socket_error(int error, const str::astr& name, [[maybe_unused]] const ipap& bind2)
    {
        switch (error) {
#ifdef _WIN32
        case WSAENOBUFS:
            LOG_E("socket creation failed for listener [$]: no buffer space is available", str::clean(name));
            break;
#else
        case EPERM:
        case EACCES:
            LOG_E("socket creation failed for listener [$]: operation not permitted", str::clean(name));
            break;
        case EAFNOSUPPORT:
            LOG_E("socket creation failed for listener [$]: unsupported address ($)", str::clean(name), bind2.to_string());
            break;
#endif
        default:
            LOG_E("socket creation failed for listener [$]: undescribed error ($)", str::clean(name), error);
            break;
        }
        return false;
    }



    bool SYSTEM_STREAM_ACCEPTOR_SOCKET::listen(const str::astr& name, const ipap& bind2)
    {
#ifdef _NIX
        static const constexpr int SOCKET_ERROR = -1;
#endif

        if (glb.cfg.ipstack == conf::gip_only6 && bind2.v4())
        {
            LOG_W("bind failed for listener [$] due ipv4 addresses are disabled in config", str::clean(name));
            return false;
        }
        if (glb.cfg.ipstack == conf::gip_only4 && !bind2.v4())
        {
            LOG_W("bind failed for listener [$] due ipv6 addresses are disabled in config", str::clean(name));
            return false;
        }

        s = ::socket(bind2.v4() ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
        if (INVALID_SOCKET == s)
            return log_socket_error(WSAGetLastError(), name, bind2);
#else
        if (s < 0)
            return log_socket_error(errno, name, bind2);

        int yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(s, F_GETFD);
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);
#endif

        if (bind(bind2) < 0)
        {
#ifdef _WIN32
            signed_t error_code = WSAGetLastError();
#else
            signed_t error_code = errno;
#endif

            LOG_W("bind failed for listener [$]; reason: $", str::clean(name), err2str(error_code));
            close();
            return false;
        }

        if (SOCKET_ERROR == ::listen(s, SOMAXCONN))
        {
            LOG_W("listen failed for listener [$]", str::clean(name));
            close();
            return false;
        }

        return true;
    }

    tcp_pipe* SYSTEM_STREAM_ACCEPTOR_SOCKET::tcp_accept(const str::astr& name)
    {
        if (glb.is_stop())
            return nullptr;

#ifdef _WIN32
        WSAPROTOCOL_INFO pi = {};
        int pil = sizeof(pi);
        getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFO, (char*)&pi, &pil);
        bool v4 = pi.iAddressFamily == AF_INET;
#else
        int dom = -1;
        socklen_t doml = sizeof(dom);
        getsockopt(s, SOL_SOCKET, SO_DOMAIN, (char*)&dom, &doml);
        bool v4 = dom == AF_INET;

        // to keep windows code unchanged
        using SOCKET = int;
        static const constexpr int INVALID_SOCKET = -1;
        auto closesocket = [](int s) { ::close(s); };
#endif
        union
        {
            sockaddr_in addr4;
            sockaddr_in6 addr6;
        } aaaa;
        socklen_t addrlen = v4 ? sizeof(aaaa.addr4) : sizeof(aaaa.addr6);
        SOCKET acpts = accept(s, (sockaddr*)&aaaa, &addrlen);
        if (INVALID_SOCKET == acpts)
            return nullptr;

        if (glb.is_stop())
        {
            closesocket(acpts);
            LOG_I("listener $ has been terminated", name);
            Print();
            return nullptr;
        }

        // non-blocking mode
#ifdef _WIN32
        u_long one(1);
        ioctlsocket(acpts, FIONBIO, (u_long*)&one);
#endif
#ifdef _NIX
        fcntl(acpts, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL));
#endif

        return NEW tcp_pipe(NEW SYSTEM_STREAM_SOCKET(acpts), ipap(&aaaa, addrlen));
    }

    /*virtual*/ bool SYSTEM_STREAM_SOCKET::connect(const ipap &addr, socket_info_func pif)
    {
        close(false);

        s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
        if (INVALID_SOCKET == s)
            return false;
#endif

#ifdef _NIX
        if (s < 0)
            return false;

        int yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(s, F_GETFD);
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);

        static const constexpr int SOCKET_ERROR = -1;
#endif

        // LOG socket created

        int val = 0;
        socklen_t optl = sizeof(val);
        if (SOCKET_ERROR == getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&val, &optl))
        {
            close(false);
            return false;
        }
        if (val < 128 * 1024)
        {
            val = 128 * 1024;
            if (SOCKET_ERROR == setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&val, sizeof(val)))
            {
                close(false);
                return false;
            }
        }

        if (SOCKET_ERROR == getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&val, &optl))
        {
            close(false);
            return false;
        }
        if (val < 128 * 1024)
        {
            val = 128 * 1024;
            if (SOCKET_ERROR == setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&val, sizeof(val)))
            {
                close(false);
                return false;
            }
        }
        else if (val > send_buffer_size)
            send_buffer_size = val;

        if (pif)
        {
            // hard way
            // it's need to obtain local address and port before any packet will send
            ipap la = bind4addr(addr);
            if (la.port == addr.port)
            {
                la.port = 0; // auto
                la.port = tools::as_word(netkit::bind(s, la));
                if (la.port > 0)
                    pif(la, addr);
            }
        }

        if (!addr.connect(s))
        {
            close(false);
            if (!addr.is_private())
                glb.e->ban(addr);
            return false;
        }

        prepare();

        return true;

    }

    signed_t SYSTEM_STREAM_SOCKET::send(std::span<const u8> data)
    {
#ifdef _NIX
        static const constexpr int SOCKET_ERROR = -1;
#endif

        flags.setn<f_events>(flags.getn<f_events>() & ~(SE_WRITE));

        signed_t sr = ::send(s, (const char*)data.data(), int(data.size()), NIXONLY(MSG_NOSIGNAL) WINONLY(0));
        if (sr == SOCKET_ERROR)
        {
            if (CHECK_IF_NOT_NOW)
            {
                sendfull(true);
                return 0;
            }
            return -1;
        }

        sendfull(sr < SIGNED % data.size());
        return sr;
    }


#ifdef _WIN32
    signed_t win32_stream_socket::recv(tools::memory_pair& mp)
    {
        flags.setn<f_events>(flags.getn<f_events>() & ~(SE_READ));

        WSABUF bufs[2];
        DWORD received = 0;
        DWORD buf_count = 0;

        if (!mp.p0.empty()) {
            bufs[buf_count].buf = reinterpret_cast<char*>(mp.p0.data());
            bufs[buf_count].len = static_cast<ULONG>(mp.p0.size());
            ++buf_count;
        }

        if (!mp.p1.empty()) {
            bufs[buf_count].buf = reinterpret_cast<char*>(mp.p1.data());
            bufs[buf_count].len = static_cast<ULONG>(mp.p1.size());
            ++buf_count;
        }

        DWORD rflags = 0;
        int ret = WSARecv(s, bufs, buf_count, &received, &rflags, nullptr, nullptr);
        if (ret < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK)
                return 0;
            return -1;
        }
        if (ret == 0 && received == 0)
            return -1;

        return static_cast<signed_t>(received);
    }
#else
    signed_t nix_stream_socket::recv(tools::memory_pair & mp)
    {
        flags.setn<f_events>(flags.getn<f_events>() & ~(SE_READ));

        struct iovec iov[2];
        int iovcnt = 0;

        if (!mp.p0.empty()) {
            iov[iovcnt].iov_base = mp.p0.data();
            iov[iovcnt].iov_len = mp.p0.size();
            ++iovcnt;
        }

        if (!mp.p1.empty()) {
            iov[iovcnt].iov_base = mp.p1.data();
            iov[iovcnt].iov_len = mp.p1.size();
            ++iovcnt;
        }

        auto ret = readv(s, iov, iovcnt);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            return -1;
        }
        if (ret == 0)
            return -1;
        return static_cast<signed_t>(ret);
    }
#endif

    signed_t SYSTEM_DATAGRAM_SOCKET::listen_udp(const str::astr& name, const ipap& bind2)
    {
        if (glb.cfg.ipstack == conf::gip_only6 && bind2.v4())
        {
            LOG_W("bind failed for listener [$] due ipv4 addresses are disabled in config", str::clean(name));
            return -1;
        }
        if (glb.cfg.ipstack == conf::gip_only4 && !bind2.v4())
        {
            LOG_W("bind failed for listener [$] due ipv6 addresses are disabled in config", str::clean(name));
            return -1;
        }

        s = ::socket(bind2.v4() ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
        if (INVALID_SOCKET == s)
            return -1;
#else
        if (s < 0)
            return -1;

        int yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(s, F_GETFD);
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);
#endif

        signed_t bport = netkit::bind(s, bind2);
        if (bport < 0)
        {
            LOG_W("bind failed for listener [$]; check binding ($)", str::clean(name), bind2.to_string());
            close();
            return -1;
        }

        return bport;
    }


    bool SYSTEM_DATAGRAM_SOCKET::init(signed_t timeout, bool v4)
    {
        if (glb.cfg.ipstack == conf::gip_only6 && v4)
        {
            return false;
        }
        if (glb.cfg.ipstack == conf::gip_only4 && !v4)
        {
            return false;
        }

        close();

        s = ::socket(v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        WINONLY (if (INVALID_SOCKET == s) )
        NIXONLY (if (s < 0))
            return false;

#ifdef _NIX
        int yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(s, F_GETFD);
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);
#endif

        if (timeout > 0)
        {
#ifdef _WIN32
            DWORD ms = tools::as_dword(timeout);
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) & ms, sizeof(ms));
#else
            struct timeval to = { timeout / 1000, 0 }; // seconds, microseconds
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
#endif
        }

        return true;
    }

    bool SYSTEM_DATAGRAM_SOCKET::recv(udp_packet& p)
    {
        sockaddr_in addr4 = {};
        sockaddr_in6 addr6 = {};
        socklen_t sz = p.from.v4() ? sizeof(addr4) : sizeof(addr6);
        int recvsz = recvfrom(s, (char *)p.packet, sizeof(p.packet), 0, p.from.v4() ? (sockaddr*)&addr4 : (sockaddr*)&addr6, &sz);
        if (recvsz <= 0)
            return false;
        if (p.from.v4())
            p.from.set(&addr4, true);
        else
            p.from.set(&addr6, true);
        p.sz = tools::as_word(recvsz);
        return true;
    }

    void tcp_pipe::set_address(endpoint& ainf)
    {
        set_address(ainf.resolve_ip(glb.cfg.ipstack | conf::gip_any));
    }


    /*virtual*/ bool tcp_pipe::alive()
    {
        if (connected())
            return (wait(SE_CLOSED, 0) & SE_CLOSED) == 0;
        return false;
    }

    pipe::sendrslt tcp_pipe::trysend()
    {
        if (outbuf.is_empty())
            return SEND_OK;

        auto d2s = outbuf.get_1st_chunk();

        signed_t success_send = sock->send(d2s);
        if (success_send < 0)
            return SEND_FAIL;

        outbuf.skip(success_send);

        if (outbuf.is_empty())
        {
            sock->sendfull(false);
            return SEND_OK;
        }
        sock->sendfull();
        return SEND_BUFFERFULL;
    }

    pipe::sendrslt tcp_pipe::send(const u8* data, signed_t datasize)
    {
        if (!sock)
            return SEND_FAIL;

        if (data == nullptr)
            return trysend();

        if (!outbuf.is_empty())
        {
            if (datasize > 0)
            {
                auto d = std::span<const u8>(data, datasize);
                outbuf.append(d);
            }

            return trysend();
        }

        if (datasize == 0)
            return SEND_OK;

#ifdef _DEBUG
        if (tag)
        {
            LOG_D("tagged $ send", tag);
        }
#endif

        signed_t success_send = sock->send( std::span(data, datasize) );

#ifdef _DEBUG
        if (tag)
        {
            LOG_D("tagged $ send $", tag, success_send);
        }
#endif

        if (success_send < 0)
            return SEND_FAIL;

        if (success_send < datasize)
        {
            auto d = std::span<const u8>(data + success_send, datasize - success_send);
            outbuf.append(d);
            return SEND_BUFFERFULL;
        }

        return SEND_OK;
    }

    /*virtual*/ signed_t tcp_pipe::recv(tools::circular_buffer_extdata& data, signed_t required, signed_t timeout DST(, deep_tracer* tracer))
    {
        DST( if (tracer) tracer->log("tcprecv $/$/$/$", data.datasize(), data.get_free_size(), required, timeout));

        if (unrcv)
        {
            ASSERT(data.datasize() == 0);
            data += unrcv->span();
            ma::mf(unrcv);
            unrcv = nullptr;
        }

        if (required > 0 && data.datasize() >= UNSIGNED % required)
        {
            DST(if (tracer) tracer->log("tcprecv alrd"));
            return required;
        }

        for (chrono::mils deadtime = required > 0 ? chrono::ms(timeout) : chrono::mils();;)
        {
            auto mp = data.get_free();

#ifdef _DEBUG
            if (tag)
            {
                LOG_D("tagged $ recv", tag);
            }
#endif

            DST(if (tracer) tracer->log("tcprecv tank $", tank.size()));
            signed_t _bytes = sock->recv(mp);
            DST(if (tracer) tracer->log("tcprecv rcvd $", _bytes));

#ifdef _DEBUG
            if (calc_entropy > 0 && calc_entropy <= _bytes)
            {
                LOG_D("enropy of 1st $ bytes from client: $", calc_entropy, tools::calculate_entropy(std::span(mp.p0.data(), calc_entropy)));
                calc_entropy = 0;
            }

            if (tag)
            {
                LOG_D("tagged $ recv $", tag, _bytes);
            }
#endif

            if (glb.is_stop())
                return -1;

            if (_bytes < 0)
            {
                // connection closed
                close(false);
                return -1;
            }

            if (_bytes == 0)
            {
                DST(if (tracer) tracer->log("tcprecv no data"));
                // nothing to read for now
                if (required == 0)
                    return 0;

                if (!deadtime.is_empty() && chrono::ms() > deadtime)
                    return -1;

                u8 wr = sock->wait(SE_READ, LOOP_PERIOD);
                if (wr & SE_CLOSED || glb.is_stop())
                    return -1;

                continue;
            }

            data.confirm(_bytes);
            if (required == 0)
                return _bytes;
            if (data.datasize() >= UNSIGNED % required)
                return required;

            if (chrono::ms() > deadtime)
                return -1;

            u8 wr = sock->wait(SE_READ, LOOP_PERIOD);
            if (wr & SE_CLOSED || glb.is_stop())
                return -1;
        }
        UNREACHABLE();
    }

    /*virtual*/ str::astr tcp_pipe::get_info(info i) const
    {
        if (i == I_REMOTE_RAW)
        {
            str::astr s; s.resize(sizeof(netkit::ipap));
            tools::memcopy<sizeof(netkit::ipap)>(s.data(), &addr);
            return s;
        }

        if (i == I_REMOTE || i == I_SUMMARY)
            return addr.to_string();
        return glb.emptys;
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
                ipap ip = glb.e->dns()->resolve(host, log_it);
                if (!ip.is_empty())
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
            LOG_E("dns: name resolve failed: [$]", host);
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

        ip.set(ipap::parse(domain_,false), 0);
        if (!ip.is_empty())
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

        ip.port = tools::as_word(str::parse_int(ports, 65535, 0));
        ip.flags.set<ipap::f_port>(ip.port != 0);
        check_domain_or_ip();
    }

    ipap netkit::endpoint::resolve_ip(size_t options)
    {
        if (state_ == EPS_RESLOVED)
        {
            if ((options & conf::gip_any) != 0)
                return ip;

            if (ip.v4() && ((options & 0xff) == conf::gip_only4 || (options & 0xff) == conf::gip_prior4))
                return ip;

            if (!ip.v4() && ((options & 0xff) == conf::gip_only6 || (options & 0xff) == conf::gip_prior6))
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

    u64 pipe_waiter::reg(pipe* p)
    {
        u64 mask = 1ull << numw;

        auto s = p->get_socket();
        if (nullptr == s)
            return 0;

        u8 evts = s->setup_wait_slot(slots + numw);
        
        if (evts & SE_CLOSED)
            return 0;

        sockets[numw] = s;

        if (evts & SE_READ)
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

    pipe_waiter::mask pipe_waiter::wait(signed_t ms_timeout)
    {
        if (numw == 0)
        {
            spinlock::sleep(1);
            return mask();
        }

#ifdef _WIN32
        if (readymask != 0)
        {
            u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw), slots, FALSE, 0, FALSE);

            if (rslt >= WSA_WAIT_EVENT_0 && (rslt - WSA_WAIT_EVENT_0) < numw)
            {
                size_t i = (rslt - WSA_WAIT_EVENT_0);

                mask m(readymask);

                for (; i < numw; ++i)
                {
                    u8 evts = sockets[i]->get_event_info(nullptr);

                    if (0 != (evts & SE_CLOSED))
                        m.add_close(1ull << i);
                    if (0 != (evts & SE_READ))
                        m.add_read(1ull << i);
                    if (0 != (evts & SE_WRITE))
                        m.add_write(1ull << i);
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

        if (sig == nullptr)
            sig = WSACreateEvent();

        slots[numw] = sig;
        u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw + 1), slots, FALSE, ms_timeout < 0 ? WSA_INFINITE : (DWORD)ms_timeout, FALSE);
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
            return mask(true);
        }

        if (rslt >= WSA_WAIT_EVENT_0 && (rslt-WSA_WAIT_EVENT_0) < numw)
        {
            size_t i = (rslt - WSA_WAIT_EVENT_0);

            mask m;
            for (; i < numw; ++i)
            {
                u8 evts = sockets[i]->get_event_info(nullptr);

                if (0 != (evts & SE_CLOSED))
                    m.add_close(1ull << i);
                if (0 != (evts & SE_READ))
                    m.add_read(1ull << i);
                if (0 != (evts & SE_WRITE))
                    m.add_write(1ull << i);
            }

            readymask = 0;
            numw = 0;
            return m;
        }

        readymask = 0;
        numw = 0;
        return mask();

#endif

#ifdef _NIX

        if (efd < 0)
        {
            efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        }

        slots[numw].fd = efd;
        slots[numw].events = POLLIN;

        if (readymask != 0)
            ms_timeout = 1;

        int er = poll(slots, numw+1, ms_timeout >= 0 ? ms_timeout : -1);
        if (er < 0)
        {
            readymask = 0;
            numw = 0;
            return mask();
        }

        mask m(readymask);
        for (size_t i = 0; i < numw; ++i)
        {
            u8 evts = sockets[i]->get_event_info(slots + i);

            if (0 != (evts & SE_CLOSED))
                m.add_close(1ull << i);
            if (0 != (evts & SE_READ))
                m.add_read(1ull << i);
            if (0 != (evts & SE_WRITE))
                m.add_write(1ull << i);

        }

        if (0 != (slots[numw].revents & POLLIN))
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
            uint64_t cnt;
            read(efd, &cnt, sizeof(cnt));
#pragma GCC diagnostic pop

            m.set_by_signal();
        }

        readymask = 0;
        numw = 0;
        return m;
#endif

    }

    void pipe_waiter::signal()
    {
#ifdef _WIN32
        if (sig)
            WSASetEvent(sig);
#else
        if (efd >= 0)
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"

            uint64_t one = 1;
            write(efd, &one, sizeof(one));
#pragma GCC diagnostic pop
        }
#endif
    }

    namespace {
        struct udpss : thread_storage_data
        {
            SYSTEM_DATAGRAM_SOCKET s;
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


        if (s == nullptr || s->v4 != ep->get_ip().v4())
        {
            s = NEW udpss(ep->get_ip().v4());
        }

        if (!s->s.sendto(ep->get_ip(), pg.to_span()))
            return ior_send_failed;

        // IMPORTANT! thread_storage ts MUST be initialized just after send, not before
        if (ts.data.get() != s)
            ts.data.reset(s);

        return ior_ok;
    }

    io_result udp_recv(thread_storage& ts, ipap& from, pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/)
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

    netkit::pipe::sendrslt pipe_tools::send(const std::span<const u8>& d)
    {
        for (const u8* data = d.data();; data = nullptr)
        {
            auto r = pp->send(data, d.size());
            if (r != pipe::SEND_BUFFERFULL)
                return r;

            pp->wait(SE_WRITE, 1000);
        }

        UNREACHABLE();
    }


    bool pipe_tools::read_line(str::astr* s)
    {
        for (; rcvd.get_free_size() > 0;)
        {
            if (rcvd.datasize() > 0)
            {
                tools::memory_pair mp = rcvd.data(rcvd.datasize());
                str::astr_view rs(mp.view1st());
                size_t nlp = rs.find(ASTR("\r\n"));
                if (nlp != rs.npos)
                {
                    if (s) *s = rs.substr(0, nlp);
                    rcvd.skip(nlp + 2);
                    return true;
                }
                str::astr_view rs2(mp.view2nd());
                nlp = rs2.find(ASTR("\r\n"));
                if (nlp != rs2.npos)
                {
                    if (s) s->assign(rs).append(rs2.substr(0, nlp));
                    rcvd.skip(rs.size() + nlp + 2);
                    return true;
                }

            }

            signed_t rcv = pp->recv(rcvd, 0, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr));
            if (rcv < 0 || glb.is_stop())
                return false;
            if (rcv == 0)
            {
                if (u8 re = pp->wait(SE_READ, LOOP_PERIOD); 0 != (re & netkit::SE_CLOSED) || glb.is_stop())
                    return false;
            }
        }
        return false;
    }

    ipap bind4addr(const ipap& tgt)
    {
        sockaddr_in v4a;
        sockaddr_in6 v6a;

        if (tgt.v4())
        {
            v4a.sin_family = AF_INET;
            v4a.sin_addr.s_addr = tgt.ipv4.s_addr;
            ref_cast<u16be>(v4a.sin_port) = 53; // no matter which port
        }
        else
        {
            v6a.sin6_family = AF_INET6;
            tools::memcopy<sizeof(tgt.ipv6)>(&v6a.sin6_addr, &tgt.ipv6);
            ref_cast<u16be>(v6a.sin6_port) = 53; // no matter which port
        }

        auto s = ::socket(tgt.v4() ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (connect(s, tgt.v4() ? (const sockaddr*)&v4a : (const sockaddr*)&v6a, (socklen_t)(tgt.v4() ? sizeof(sockaddr_in) : sizeof(sockaddr_in6))) != 0) {
#ifdef _WIN32
            closesocket(s);
#else
            close(s);
#endif
            return ipap();
        }

        struct sockaddr_storage locala;
        socklen_t local_len = sizeof(locala);
        if (getsockname(s, (struct sockaddr*)&locala, &local_len) != 0) {
#ifdef _WIN32
            closesocket(s);
#else
            close(s);
#endif
            return ipap();
        }

        ipap r;

        if (locala.ss_family == AF_INET) {
            sockaddr_in* sin = (sockaddr_in*)&locala;
            r.set(sin, false);
        }
        else if (locala.ss_family == AF_INET6) {
            sockaddr_in6* sin6 = (sockaddr_in6*)&locala;
            r.set(sin6, false);
        }
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif

        r.set_port(tgt.port); // just copy port to indicate success

        return r;
    }

} // netkit

