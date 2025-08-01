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
        u16be *w = rv.words();
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

        u8* dst = reinterpret_cast<u8 *>(&rv.ipv4.s_addr); // from low to high on little endian cpu because ipv4.s_addr is in big endian
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

    signed_t ipap::bind_once(SOCKET s) const
    {
        if (v4)
        {
            sockaddr_in addr;

            addr.sin_family = AF_INET;
            addr.sin_addr = ipv4;
            ref_cast<u16be>(addr.sin_port) = port;

            bool ok = SOCKET_ERROR != ::bind(s, (const sockaddr*)&addr, sizeof(addr));
            if (!ok)
                return -1;

            signed_t rp = port;
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
        tools::memcopy<sizeof(ipv6)>(&addr.sin6_addr, &ipv6);
        ref_cast<u16be>(addr.sin6_port) = port;

        bool ok = SOCKET_ERROR != ::bind(s, (const sockaddr*)&addr, sizeof(addr));

        if (!ok)
            return -1;

        signed_t rp = port;
        if (rp == 0)
        {
            socklen_t x = sizeof(addr);
            getsockname(s, (sockaddr*)&addr, &x);
            rp = u16be::from_be(addr.sin6_port);
        }
        return rp;
    }

    signed_t ipap::bind(SOCKET s) const
    {
        for(signed_t btc = glb.bind_try_count;btc > 0; --btc)
        {
            //LOG_D("try bind ($/$): $", glb.bind_try_count-btc+1, glb.bind_try_count, this->to_string(true));
            signed_t x = bind_once(s);
            if (x >= 0)
                return x;
            if (btc > 1) spinlock::sleep(1000);
        }
        return -1;
    }

    bool ipap::connect(SOCKET s) const
    {
        // non-blocking mode
#ifdef _WIN32
        u_long one(1);
        ioctlsocket(s, FIONBIO, (u_long*)&one);
#else
        fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL));
#endif
        auto call_connect = [this](SOCKET s) -> auto
        {
            if (v4)
            {
                sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_addr = ipv4;
                ref_cast<u16be&>(addr.sin_port) = port;
                return ::connect(s, (const sockaddr*)&addr, sizeof(addr));
            }

            sockaddr_in6 addr = {};
            addr.sin6_family = AF_INET6;
            tools::memcopy<sizeof(ipv6)>(&addr.sin6_addr, &ipv6);
            ref_cast<u16be&>(addr.sin6_port) = port;
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
        tv.tv_sec = CONNECT_TIMEOUT/1000;
        tv.tv_usec = (CONNECT_TIMEOUT%1000) * 1000;

        return select(0, nullptr, &writefds, nullptr, &tv) > 0;
#else
        if (errno != EINPROGRESS)
            return false;

        pollfd pfd;

        pfd.fd = s;
        pfd.events = POLLOUT;

        return poll(&pfd, 1, CONNECT_TIMEOUT) > 0;
#endif
    }

    bool ipap::sendto(SOCKET s, const std::span<const u8>& p) const
    {
        if (v4)
        {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr = ipv4;
            ref_cast<u16be&>(addr.sin_port) = port;
            return SOCKET_ERROR != ::sendto(s, (const char*)p.data(), (int)p.size(), 0, (const sockaddr*)&addr, sizeof(addr));
        }

        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        tools::memcopy<sizeof(ipv6)>(&addr.sin6_addr, &ipv6);
        ref_cast<u16be&>(addr.sin6_port) = port;
        return SOCKET_ERROR != ::sendto(s, (const char *)p.data(), (int)p.size(), 0, (const sockaddr*)&addr, sizeof(addr));
    }

    str::astr endpoint::desc() const
    {
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
                d = ip.to_string(true);
            }
            else
            {
                str::astr ipa = ip.to_string(false);
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
                d = ip.to_string(true);
                break;
            }
            else if (eps == EPS_GET_IP_IF_RESOLVED)
            {
                d = ip.to_string(true);
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

    signed_t waitable_socket::recv(tools::memory_pair& mp)
    {
#ifdef _WIN32
        WSABUF bufs[2];
        DWORD flags = 0;
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

        int ret = WSARecv(sock(), bufs, buf_count, &received, &flags, nullptr, nullptr);
        if (ret < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK)
                return 0;
            return -1;
        }
        if (ret == 0 && received == 0)
            return -1;

        return static_cast<signed_t>(received);
#else
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

        auto ret = readv(sock(), iov, iovcnt);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            return -1;
        }
        if (ret == 0)
            return -1;
        return static_cast<signed_t>(ret);
#endif
    }


    bool waitable_socket::listen(const str::astr& name, const ipap& bind2)
    {
        if (glb.cfg.ipstack == conf::gip_only6 && bind2.v4)
        {
            LOG_W("bind failed for listener [$] due ipv4 addresses are disabled in config", str::clean(name));
            return false;
        }
        if (glb.cfg.ipstack == conf::gip_only4 && !bind2.v4)
        {
            LOG_W("bind failed for listener [$] due ipv6 addresses are disabled in config", str::clean(name));
            return false;
        }

        _socket = ::socket(bind2.v4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (INVALID_SOCKET == sock())
            return false;

#ifdef _NIX
        int yes = 1;
        setsockopt(sock(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(sock(), F_GETFD);
        fcntl(sock(), F_SETFD, flags | FD_CLOEXEC);
#endif

        if (bind2.bind(sock()) < 0)
        {
#ifdef _WIN32
            signed_t error_code = WSAGetLastError();
#else
            signed_t error_code = errno;
#endif

            LOG_W("bind failed for listener [$]; reason: $", str::clean(name), err2str(error_code));
            close(false);
            return false;
        }

        if (SOCKET_ERROR == ::listen(sock(), SOMAXCONN))
        {
            LOG_W("listen failed for listener [$]", str::clean(name));
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

    signed_t socket::listen_udp(const str::astr& name, const ipap& bind2)
    {
        if (glb.cfg.ipstack == conf::gip_only6 && bind2.v4)
        {
            LOG_W("bind failed for listener [$] due ipv4 addresses are disabled in config", str::clean(name));
            return -1;
        }
        if (glb.cfg.ipstack == conf::gip_only4 && !bind2.v4)
        {
            LOG_W("bind failed for listener [$] due ipv6 addresses are disabled in config", str::clean(name));
            return -1;
        }

        s = ::socket(bind2.v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (INVALID_SOCKET == s)
            return -1;

#ifdef _NIX
        int yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(s, F_GETFD);
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);
#endif

        signed_t bport = bind2.bind(s);
        if (bport < 0)
        {
            LOG_W("bind failed for listener [$]; check binding ($)", str::clean(name), bind2.to_string(true));
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
            LOG_I("listener $ has been terminated", name);
            Print();
            return nullptr;
        }

        // non-blocking mode
#ifdef _WIN32
        u_long one(1);
        ioctlsocket(s, FIONBIO, (u_long*)&one);
#endif
#ifdef _NIX
        fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL));
#endif

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

#ifdef _NIX
        int yes = 1;
        setsockopt(sock(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        int flags = fcntl(sock(), F_GETFD);
        fcntl(sock(), F_SETFD, flags | FD_CLOEXEC);
#endif

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
            glb.e->ban(addr);
            return false;
        }

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
            //return connection_still_alive();
        return false;
    }

    pipe::sendrslt tcp_pipe::trysend()
    {
        if (outbuf.is_empty())
            return SEND_OK;

        auto d2s = outbuf.get_1st_chunk();

        signed_t sendrv = ::send(sock(), (const char*)d2s.data(), int(d2s.size()), NIXONLY(MSG_NOSIGNAL) WINONLY(0));
        if (sendrv == SOCKET_ERROR)
        {
            if (CHECK_IF_NOT_NOW)
            {
                sendfull();
                return SEND_BUFFERFULL;
            }
            return SEND_FAIL;
        }
        outbuf.skip(sendrv);

        if (outbuf.is_empty())
        {

#ifdef _WIN32
            if (get_waitable()->bufferfull)
            {
                WSAEventSelect(sock(), get_waitable()->wsaevent, FD_READ | FD_CLOSE);
                get_waitable()->bufferfull = 0;
            }
#endif
#ifdef _NIX
            get_waitable()->bufferfull = 0;
#endif // _NIX
            return SEND_OK;
        }
        sendfull();
        return SEND_BUFFERFULL;
    }

    pipe::sendrslt tcp_pipe::send(const u8* data, signed_t datasize)
    {
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

        signed_t sendrv = ::send(sock(), (const char*)data, int(datasize), NIXONLY(MSG_NOSIGNAL) WINONLY(0));

#ifdef _DEBUG
        if (tag)
        {
            LOG_D("tagged $ send $", tag, sendrv);
        }
#endif

        if (sendrv == SOCKET_ERROR)
        {
            if (!CHECK_IF_NOT_NOW)
            {
                return SEND_FAIL;
            }
            sendrv = 0;
        }

        if (sendrv < datasize)
        {
            sendfull();
            auto d = std::span<const u8>(data + sendrv, datasize - sendrv);
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

        if (required > 0 && data.datasize() >= required)
        {
            DST(if (tracer) tracer->log("tcprecv alrd"));
            return required;
        }

        for (signed_t deadtime = required > 0 ? (timeout+chrono::ms()) : 0;;)
        {
            auto mp = data.get_free();

#ifdef _DEBUG
            if (tag)
            {
                LOG_D("tagged $ recv", tag);
            }
#endif

            DST(if (tracer) tracer->log("tcprecv tank $", tank.size()));
            signed_t _bytes = waitable_socket::recv(mp);
            DST(if (tracer) tracer->log("tcprecv rcvd $", _bytes));

#ifdef _DEBUG
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

                if (chrono::ms() > deadtime)
                    return -1;

                auto w = get_waitable();
                clear_ready(w, READY_PIPE|READY_SYSTEM);
                wrslt rslt = wait(w, LOOP_PERIOD);
                if (rslt == WR_CLOSED || glb.is_stop())
                    return -1;
                continue;
            }

            clear_ready(get_waitable(), READY_SYSTEM);
            data.confirm(_bytes);
            if (required == 0)
                return _bytes;
            if (data.datasize() >= required)
                return required;

            if (chrono::ms() > deadtime)
                return -1;

            auto w = get_waitable();
            clear_ready(w, READY_PIPE | READY_SYSTEM);
            wrslt rslt = wait(w, LOOP_PERIOD);
            if (rslt == WR_CLOSED || glb.is_stop())
                return -1;
        }
        UNREACHABLE();
    }

    /*virtual*/ WAITABLE tcp_pipe::get_waitable()
    {
        return waitable_socket::get_waitable();
    }

    /*virtual*/ str::astr tcp_pipe::get_info(info i) const
    {
        if (i == I_REMOTE || i == I_SUMMARY)
            return addr.to_string(true);
        return glb.emptys;
    }

#if 0
    bool tcp_pipe::connection_still_alive()
    {
        if (lastcheckalive == 0)
        {
            // do not check for now
            lastcheckalive = chrono::ms();
            return true;
        }

        signed_t ct = chrono::ms();
        if ((ct - lastcheckalive) > 5000)
        {
            // check no more than once per second
            lastcheckalive = ct;

            // check connections still alive
            char temp;
            int result = ::recv(sock(), &temp, 1, MSG_PEEK);
            if (result == 0)
            {
                close(false);
                return false;
            }
            if (result == SOCKET_ERROR)
            {
                if (CHECK_IF_NOT_NOW)
                {
                }
                else {
                    close(false);
                    return false;
                }
            }

        }

        return true;
    }
#endif

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

    wrslt wait(WAITABLE s, signed_t ms_timeout)
    {
        if (ms_timeout != 0 && is_recv_ready(s))
            return WR_READY4READ;

#ifdef _WIN32
        if (ms_timeout == 0)
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

        u32 rslt = WSAWaitForMultipleEvents(1, &s->wsaevent, TRUE, ms_timeout < 0 ? WSA_INFINITE : (DWORD)ms_timeout, FALSE);
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
        int pr = poll(&p, 1, ms_timeout);
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

    wrslt wait_write(WAITABLE s, signed_t ms_timeout)
    {
#ifdef _WIN32
        if (ms_timeout == 0)
        {
            WSANETWORKEVENTS e;
            WSAEnumNetworkEvents(s->s, s->wsaevent, &e);
            if (0 != (e.lNetworkEvents & FD_CLOSE))
                return WR_CLOSED;

            if (0 != (e.lNetworkEvents & FD_WRITE))
            {
                return WR_READY4WRITE;
            }

            return WR_TIMEOUT;
        }

        u32 rslt = WSAWaitForMultipleEvents(1, &s->wsaevent, TRUE, ms_timeout < 0 ? WSA_INFINITE : (DWORD)ms_timeout, FALSE);
        if (WSA_WAIT_TIMEOUT == rslt)
            return WR_TIMEOUT;

        if (rslt == WSA_WAIT_EVENT_0)
        {
            WSANETWORKEVENTS e;
            WSAEnumNetworkEvents(s->s, s->wsaevent, &e);
            if (0 != (e.lNetworkEvents & FD_CLOSE))
                return WR_CLOSED;

            if (0 != (e.lNetworkEvents & FD_WRITE))
            {
                return WR_READY4WRITE;
            }

        }
        return WR_TIMEOUT;
#endif
#ifdef _NIX

        pollfd p = { s->s, POLLOUT };
        int pr = poll(&p, 1, ms_timeout);
        if (pr == 0)
            return WR_TIMEOUT;
        if (pr < 0)
            return WR_CLOSED;
        if (p.revents & POLLOUT)
        {
            return WR_READY4WRITE;
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
        if (is_recv_ready(x))
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

        for (size_t i = 0; i < numw; ++i)
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

    pipe_waiter::mask pipe_waiter::wait(signed_t ms_timeout)
    {
#ifdef _WIN32
        if (readymask != 0)
        {
            u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw), www, FALSE, 0, FALSE);

            if (rslt >= WSA_WAIT_EVENT_0 && (rslt - WSA_WAIT_EVENT_0) < numw)
            {
                size_t i = (rslt - WSA_WAIT_EVENT_0);

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
        u32 rslt = WSAWaitForMultipleEvents(tools::as_dword(numw + 1), www, FALSE, ms_timeout < 0 ? WSA_INFINITE : (DWORD)ms_timeout, FALSE);
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
        //if (readymask != 0)
        //{
        //    return checkall();
        //}

        if (numw == 0)
        {
            spinlock::sleep(1);
            return mask();
        }

        if (efd < 0)
        {
            efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        }

        polls[numw].fd = efd;
        polls[numw].events = POLLIN;

        for (size_t i = 0; i < numw; ++i)
        {
            WAITABLE w = pipes[i]->get_waitable();
            if (w->bufferfull)
            {
                polls[i].events = POLLIN | POLLOUT;
            } else {
                polls[i].events = POLLIN;
            }
        }

        if (readymask != 0)
            ms_timeout = 1;

        int er = poll(polls, numw+1, ms_timeout >= 0 ? ms_timeout : -1);
        if (er < 0)
            return checkall();

        mask m(readymask);
        for (size_t i = 0; i < numw; ++i)
        {
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
#ifdef _NIX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif // _NIX
            uint64_t cnt;
            read(efd, &cnt, sizeof(cnt));
#ifdef _NIX
#pragma GCC diagnostic pop
#endif // _NIX

            m.set_by_signal();
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
#else
        if (efd >= 0)
        {
#ifdef _NIX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif // _NIX

            uint64_t one = 1;
            write(efd, &one, sizeof(one));
#ifdef _NIX
#pragma GCC diagnostic pop
#endif // _NIX

        }
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

    netkit::pipe::sendrslt pipe_tools::send(const std::span<const u8>& d)
    {
        for (const u8* data = d.data();; data = nullptr)
        {
            auto r = pp->send(data, d.size());
            if (r != pipe::SEND_BUFFERFULL)
                return r;
            wait_write(pp->get_waitable(), 1000);
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
                auto w = pp->get_waitable();
                clear_ready(w, READY_PIPE | READY_SYSTEM);
                netkit::wrslt rslt = wait(w, LOOP_PERIOD);
                if (rslt == netkit::WR_CLOSED || glb.is_stop())
                    return false;
            }
        }
        return false;
    }


} // netkit

