#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <Mmsystem.h>
#endif

#define LOOP_PERIOD 500 // 0.5 sec
#define DEFAULT_CONNECT_TIMEOUT 10 // 10 sec

#ifdef _WIN32
#define MAXIMUM_WAITABLES (MAXIMUM_WAIT_OBJECTS - 2)
using system_socket_type = SOCKET;
#endif
#ifdef _NIX
#define MAXIMUM_WAITABLES 64
using system_socket_type = int;
#endif

#define DEEP_SLOT_TRACE 0

#if DEEP_SLOT_TRACE
struct deep_tracer;
#define DST(...) __VA_ARGS__
#else
#define DST(...)
#endif

struct thread_storage;

template<size_t sz> struct greater_power_of_2;
template<> struct greater_power_of_2<1> { static const constexpr size_t value = 1; };
template<> struct greater_power_of_2<2> { static const constexpr size_t value = 2; };
template<> struct greater_power_of_2<3> { static const constexpr size_t value = 4; };
template<> struct greater_power_of_2<4> { static const constexpr size_t value = 4; };
template<> struct greater_power_of_2<5> { static const constexpr size_t value = 8; };
template<> struct greater_power_of_2<6> { static const constexpr size_t value = 8; };
template<> struct greater_power_of_2<7> { static const constexpr size_t value = 8; };

template<size_t sz> inline typename sztype<sz>::type halfswap(typename sztype<sz>::type input)
{
    return ((input >> (sz * 4)) | (input << (sz * 4))) & math::maximum<typename sztype<sz>::type>::value;
}

template<size_t sz> inline typename sztype<sz>::type swapbytes(typename sztype<sz>::type input)
{
    if constexpr (sz > 1)
    {
        static_assert(sz <= 8);
        if constexpr (sz == 2)
        {
            return halfswap<sz>(input);
        }
        else if constexpr (sz >= 4)
        {
            auto lv = swapbytes<sz / 2>(uints::low(input));
            auto hv = swapbytes<sz / 2>(uints::high(input));

            return ((decltype(input))lv << (sz*4)) | hv;
        }
    } else
        return input;
}

template<size_t sz> inline typename sztype<sz>::type hton(typename sztype<sz>::type input)
{
    if constexpr (Endian::little && sz > 1)
    {
        return swapbytes<sz>(input);
    }
    else {
        return input;
    }
}

template<size_t sz> inline typename xtype<sz>::type load_be(const u8 *input)
{
    if constexpr (sz < greater_power_of_2<sz>::value)
    {
        using rt = typename xtype<sz>::type;
        return (((rt)(*input)) << (8 * (sz-1))) | load_be<sz-1>(input+1);
    } else
        return hton<sz>(*reinterpret_cast<const xtype<sz>::type*>(input));
}

template<size_t sz> inline typename sztype<sz>::type load_le(const u8* input)
{
    if constexpr (Endian::little || sz == 1)
    {
        return *reinterpret_cast<const sztype<sz>::type*>(input);
    }
    else {
        return swapbytes<sz>(*reinterpret_cast<const sztype<sz>::type*>(input));
    }
}

struct u16be
{
    u16 beval = 0;

    u16be() {}
    u16be(const u16be& val) :beval(val.beval)
    {
    }

    template <typename N> u16be(N nval)
    {
        if constexpr (Endian::little)
        {
            beval = ((nval & 0xff) << 8) | ((nval >> 8) & 0xff);
        }
        else {
            beval = (u16)(nval & 0xffff);
        }
    }

    u16be& operator=(u16be val)
    {
        beval = val.beval;
        return *this;
    }

    template <std::unsigned_integral N> u16be& operator=(N nval)
    {
        if constexpr (Endian::little)
        {
            beval = ((nval & 0xff) << 8) | ((nval >> 8) & 0xff);
        }
        else {
            beval = (u16)(nval & 0xffff);
        }
        return *this;
    }

    operator u16() const
    {
        if constexpr (Endian::little)
        {
            return ((beval & 0xff) << 8) | ((beval >> 8) & 0xff);
        }
        else {
            return beval;
        }
    };

    static u16be from_be(u16 beval)
    {
        u16be x;
        x.beval = beval;
        return x;
    }

};

struct u32be
{
    u32 beval = 0;

    u32be() {}
    u32be(const u32be& val) :beval(val.beval)
    {
    }
    u32be(u32 nval)
    {
        if constexpr (Endian::little)
        {
            beval = ((nval & 0xff) << 24) | ((nval & 0xff00) << 8) | ((nval & 0xff0000) >> 8) | ((nval & 0xff000000) >> 24);
        }
        else {
            beval = nval;
        }
    }
    u32be& operator=(u32be val)
    {
        beval = val.beval;
        return *this;
    }

    u32be& operator =(u32 nval)
    {
        if constexpr (Endian::little)
        {
            beval = ((nval & 0xff) << 24) | ((nval & 0xff00) << 8) | ((nval & 0xff0000) >> 8) | ((nval & 0xff000000) >> 24);
        }
        else {
            beval = nval;
        }
        return *this;
    }

    operator u32() const
    {
        if constexpr (Endian::little)
        {
            return ((beval & 0xff) << 24) | ((beval & 0xff00) << 8) | ((beval & 0xff0000) >> 8) | ((beval & 0xff000000) >> 24);
        }
        else {
            return beval;
        }
    };

    static u32be from_be(u32 beval)
    {
        u32be x;
        x.beval = beval;
        return x;
    }
};

namespace netkit
{
    enum sevents : u8 // socket events
    {
        SE_READ = 1,
        SE_WRITE = 2,
        SE_CLOSED = 4,
        SE_TIMEOUT = 8, // only return flag
    };

#ifdef _WIN32
    using wait_slot = WSAEVENT;
#endif
#ifdef _NIX
    using wait_slot = pollfd;
#endif

    struct ipap;
    struct tcp_pipe;
    struct udp_packet;
    using socket_info_func = std::function< void(const ipap& lcl, const ipap& rmt) >;

    signed_t bind(system_socket_type s, const ipap& a);

    inline u32 prefix_to_mask_4(size_t prefix_length) {
        if (prefix_length == 0 || prefix_length > 32)
            return 0;
        return hton<4>(0xffffffff << (32 - prefix_length));
    }
    inline u32 makeip4(u8 a1, u8 a2, u8 a3, u8 a4) {

        union
        {
            struct { u8 x1, x2, x3, x4; };
            u32 u;
        } tmp;

        tmp.x1 = a1; tmp.x2 = a2; tmp.x3 = a3; tmp.x4 = a4;

        return tmp.u;
    }

    class system_socket
    {
    public:
        virtual ~system_socket() {}

        virtual u8 setup_wait_slot(wait_slot* slot) = 0;
        virtual u8 get_event_info(wait_slot* slot) = 0;

        virtual void readypipe(bool rp) = 0;

        virtual u8 wait(size_t evts, signed_t timeout_ms) = 0; // wait exactly evts events
        virtual bool connect(const ipap&, socket_info_func sif) = 0;

        virtual void sendfull(bool sff = true) = 0;
        virtual signed_t send(std::span<const u8> data) = 0;
        virtual void close(bool flush_before_close) = 0;

        virtual signed_t recv(tools::memory_pair& mp) = 0;

        virtual system_socket* update(std::unique_ptr<system_socket>& mp)
        {
            return mp.get();
        }
    };

    struct replace_socket : public system_socket
    {
        std::unique_ptr<system_socket> sock;
    };

    class datagram_socket
    {
    public:
        virtual ~datagram_socket() {}
        virtual bool sendto(const ipap& a, const std::span<const u8>& p) const = 0;
        virtual void lock() {}
        virtual void unlock() {}
    };

#ifdef _WIN32
    class win32_stream_socket final : public system_socket
    {
        WSAEVENT wsaevent = nullptr;
        system_socket_type s = INVALID_SOCKET;

        tools::flags<1> flags;

        constexpr const static size_t f_events = 3;
        constexpr const static size_t f_pipeready = 32;
        constexpr const static size_t f_bufferfull = 64;

        void prepare()
        {
            if (!wsaevent && s != INVALID_SOCKET)
            {
                wsaevent = WSACreateEvent();
                WSAEventSelect(s, wsaevent, FD_READ | FD_WRITE | FD_CLOSE);
            }
        }

    public:
        win32_stream_socket() {}
        win32_stream_socket(system_socket_type s) :s(s) { prepare(); }
        virtual ~win32_stream_socket() {}

        /*virtual*/ u8 setup_wait_slot(wait_slot* slot) override
        {
            ASSERT(wsaevent);
            *slot = wsaevent;
            return tools::as_byte(flags.getn<f_events>() | (flags.is<f_pipeready>() ? SE_READ : 0));
        }

        /*virtual*/ u8 get_event_info(wait_slot* /*slot*/) override
        {
            WSANETWORKEVENTS e;
            WSAEnumNetworkEvents(s, wsaevent, &e);
            if (0 != (e.lNetworkEvents & FD_CLOSE))
            {
                close(true);
                return SE_CLOSED;
            }

            u8 evts = tools::as_byte(flags.getn<f_events>());
            if (flags.is<f_pipeready>())
                evts |= SE_READ;

            if (e.lNetworkEvents & FD_READ)
                evts |= SE_READ;
            if (e.lNetworkEvents & FD_WRITE)
                evts |= SE_WRITE;

            flags.setn<f_events>(evts);

            return evts;
        }

        /*virtual*/ void readypipe(bool rp) override
        {
            if (rp)
                flags.set<f_pipeready>();
            else
                flags.unset<f_pipeready>();
        }

        /*virtual*/ void sendfull(bool sff) override
        {
            if (sff)
                flags.set<f_bufferfull>();
            else
                flags.unset<f_bufferfull>();
        };
        /*virtual*/ signed_t send(std::span<const u8> data) override;
        /*virtual*/ void close(bool flush_before_close) override
        {
            if (wsaevent)
            {
                WSACloseEvent(wsaevent);
                wsaevent = nullptr;
            }
            if (s != INVALID_SOCKET)
            {
                if (flush_before_close)
                    /*int errm =*/ shutdown(s, SD_SEND);
                closesocket(s);
                s = INVALID_SOCKET;
            }
        }
        /*virtual*/ u8 wait(size_t evts, signed_t timeout_ms) override;
        /*virtual*/ bool connect(const ipap& addr, socket_info_func sif) override;
        /*virtual*/ signed_t recv(tools::memory_pair& mp) override;

    };

    class win32_simple_socket final : public datagram_socket
    {
        system_socket_type s = INVALID_SOCKET;
    public:
        virtual ~win32_simple_socket() { close(); }

        bool listen(const str::astr& name, const ipap& bind2);
        tcp_pipe* tcp_accept(const str::astr& name);

        bool init(signed_t timeout, bool v4); // udp
        signed_t listen_udp(const str::astr& name, const ipap& bind2);
        /*virtual*/ bool sendto(const ipap& a, const std::span<const u8>& p) const override;
        bool recv(udp_packet& p);

        signed_t bind(const ipap& a);
        void close()
        {
            if (s != INVALID_SOCKET)
            {
                closesocket(s);
                s = INVALID_SOCKET;
            }
        }

    };

#define SYSTEM_STREAM_SOCKET win32_stream_socket
#define SYSTEM_DATAGRAM_SOCKET win32_simple_socket
#define SYSTEM_STREAM_ACCEPTOR_SOCKET win32_simple_socket
#endif
#ifdef _NIX
    class nix_stream_socket final : public system_socket
    {
        system_socket_type s = -1;

        tools::flags<1> flags;

        constexpr const static size_t f_events = 3;
        constexpr const static size_t f_bufferfull = 32;
        constexpr const static size_t f_pipeready = 64;

        void prepare() {}

    public:
        nix_stream_socket() {}
        nix_stream_socket(system_socket_type s) :s(s) { }
        virtual ~nix_stream_socket() {}

        /*virtual*/ u8 setup_wait_slot(wait_slot* slot) override
        {
            slot->fd = s;
            slot->events = POLLIN;
            if (flags.is<f_bufferfull>())
                slot->events |= POLLOUT;
            return tools::as_byte(flags.getn<f_events>() | (flags.is<f_pipeready>() ? SE_READ : 0));
        }

        /*virtual*/ u8 get_event_info(wait_slot* slot) override
        {
            if (0 != (slot->revents & (POLLHUP | POLLERR | POLLNVAL)))
            {
                close(true);
                return SE_CLOSED;
            }

            u8 evts = tools::as_byte(flags.getn<f_events>());
            if (flags.is<f_pipeready>())
                evts |= SE_READ;

            if (0 != (slot->revents & POLLIN))
                evts |= SE_READ;
            if (0 != (slot->revents & POLLOUT))
                evts |= SE_WRITE;

            flags.setn<f_events>(evts);

            return evts;
        }

        /*virtual*/ void readypipe(bool rp) override
        {
            if (rp)
                flags.set<f_pipeready>();
            else
                flags.unset<f_pipeready>();
        }

        /*virtual*/ void sendfull(bool sff) override
        {
            if (sff)
                flags.set<f_bufferfull>();
            else
                flags.unset<f_bufferfull>();
        };
        /*virtual*/ signed_t send(std::span<const u8> data) override;

        /*virtual*/ void close(bool flush_before_close) override
        {
            if (s != -1)
            {
                if (flush_before_close)
                    /*int errm =*/ shutdown(s, SHUT_WR);
                ::close(s);
                s = -1;
            }
        }
        /*virtual*/ u8 wait(size_t evts, signed_t timeout_ms) override;
        /*virtual*/ bool connect(const ipap& addr, socket_info_func sif) override;
        /*virtual*/ signed_t recv(tools::memory_pair& mp) override;

    };
    class nix_simple_socket final : public datagram_socket
    {
        system_socket_type s = -1;
        static const constexpr int SOCKET_ERROR = -1;
    public:
        virtual ~nix_simple_socket() { close(); }

        bool listen(const str::astr& name, const ipap& bind2);
        tcp_pipe* tcp_accept(const str::astr& name);

        bool init(signed_t timeout, bool v4); // udp
        signed_t listen_udp(const str::astr& name, const ipap& bind2);
        /*virtual*/ bool sendto(const ipap& a, const std::span<const u8>& p) const override;
        bool recv(udp_packet& p);

        signed_t bind(const ipap& a);
        void close()
        {
            if (s >= 0)
            {
                ::close(s);
                s = -1;
            }
        }

    };
#define SYSTEM_STREAM_SOCKET nix_stream_socket
#define SYSTEM_DATAGRAM_SOCKET nix_simple_socket
#define SYSTEM_STREAM_ACCEPTOR_SOCKET nix_simple_socket
#endif

    enum socket_type_e : u8
    {
        ST_UNDEFINED,
        ST_TCP,
        ST_UDP,
    };

    struct udp_packet;
    struct ipap // ip address and port
    {
        static ipap parse6(const str::astr_view& s, size_t parse_options = f_port|f_prefix); // assume s is ipv6 address
        static ipap parse(const str::astr_view& s, size_t parse_options = f_port|f_prefix);
        static void build(ipap* r, const u8* packet, signed_t plen, u16 port = 0)
        {
            bool readport = false;
            if (port == 0 && (plen == 6 || plen == 18))
            {
                plen -= 2;
                readport = true;
            }

            if (plen == 4)
            {
                r->ipv4 = *(in_addr*)packet;
                r->flags = f_v4;
            }
            else if (plen == 16) {
                tools::memcopy<16>(&r->ipv6, packet);
                r->flags = 0;
            }
            if (readport)
                r->port = load_be<2>(packet + plen);
            else
                r->port = port;

            if (r->port)
                r->flags.set<f_port>();
        }
        static ipap build(const u8* packet, signed_t plen, u16 port = 0)
        {
            ipap r;
            build(&r, packet, plen, port);
            return r;
        }

        static ipap localhost(bool v4)
        {
            return ipap(v4).init_localhost();
        }

        union
        {
            in_addr ipv4; // network (big endian) byte order : 0x04030201 (x86) == 1.2.3.4
            in6_addr ipv6;
        };

        u16 port = 0; // in native order (will be converted to network order directly while filling sockaddr_in or sockaddr_in6 structures)
        tools::flags<2> flags;
        
        enum
        {
            f_v4 = 1,       // is ipv4 addr
            f_port = 2,     // port is set
            f_prefix = 4,   // port member is not port - it's network prefix (example: 192.168.0.0/16 - port member == 16)
            f_empty = 8,

            f_prefix_default = 16 // parse option: set prefix to 32 (for ipv4) or 128 (for ipv6) if not present in string
        };

        void clear();

        std::size_t calc_hash() const
        {
            u64 h1 = flags.is<f_v4>() ? 1 : 2;
            u64 h2 = port;

            if (flags.is<f_v4>())
            {
                spooky::hash_short(&ipv4, 4, &h1, &h2);
            }
            else
            {
                spooky::hash_short(&ipv6, 16, &h1, &h2);
            }

            return tools::as_sizet(h1);

        }

        ipap& init_wildcard()
        {
            if (flags.is<f_v4>()) ipv4.s_addr = 0; else memset(&ipv6, 0, sizeof(ipv6));
            flags.unset<f_empty>();
            return *this;
        }

        ipap &init_localhost()
        {
            if (flags.is<f_v4>())
            {
                u8* octs = reinterpret_cast<u8*>(&ipv4.s_addr); // ipv4.s_addr in big endian

                octs[0] = 127;
                octs[1] = 0;
                octs[2] = 0;
                octs[3] = 1;
            } else {
                u16be* w = reinterpret_cast<u16be*>(&ipv6);
                w[0] = 0;
                w[1] = 0;
                w[2] = 0;
                w[3] = 0;
                w[4] = 0;
                w[5] = 0;
                w[6] = 0;
                w[7] = 1;
            }
            return *this;
        }

        bool match4(u8 a1, u8 a2, u8 a3, u8 a4, u8 m) const
        {
            if (!flags.is<f_v4>())
                return false;
            u32 ipt = makeip4(a1, a2, a3, a4);
            u32 msk = prefix_to_mask_4(m);
            return (ipv4.s_addr & msk) == ipt;
        }
        bool match(const ipap& subnet) const
        {
            ASSERT(subnet.flags.is<f_prefix>() );
            
            if (subnet.port == 0)
                return true;

            if (flags.is<f_v4>())
            {
                u32 msk = prefix_to_mask_4(subnet.port);
                return 0 == ((ipv4.s_addr ^ subnet.ipv4.s_addr) & msk);
            }

            if (subnet.port > 128) {
                return false;
            }
            const size_t* addr_words = reinterpret_cast<const size_t*>(&ipv6);
            const size_t* subnet_words = reinterpret_cast<const size_t*>(&subnet.ipv6);

            const constexpr size_t wordbits = sizeof(size_t) * 8;

            size_t full_words = subnet.port / wordbits;
            for (size_t i = 0; i < full_words; ++i)
                if (addr_words[i] != subnet_words[i])
                    return false;
            
            if (size_t remaining_bits = subnet.port & (wordbits - 1); remaining_bits > 0)
            {
                size_t mask = hton<sizeof(size_t)>(math::maximum<size_t>::value << (wordbits - remaining_bits));
                if ((addr_words[full_words] & mask) != (subnet_words[full_words] & mask))
                    return false;
            }

            return true;
        }

        bool v4() const
        {
            return flags.is<f_v4>();
        }
        bool has_port() const
        {
            return flags.is<f_port>() && port != 0;
        }
        bool has_prefix() const
        {
            return flags.is<f_prefix>();
        }

        bool is_empty() const
        {
            return flags.is<f_empty>();
        }

        bool inrange4(u8 a1, u8 a2, u8 a3, u8 a4, u8 b1, u8 b2, u8 b3, u8 b4) const
        {
            u32 hoa = hton<4>(ipv4.s_addr);
            u32 r0 = ((u32)a1 << 24) | ((u32)a2 << 16) | ((u32)a3 << 8) | a4;
            u32 r1 = ((u32)b1 << 24) | ((u32)b2 << 16) | ((u32)b3 << 8) | b4;
            return hoa >= r0 && hoa <= r1;
        }

        bool is_private() const
        {
            if (flags.is<f_v4>())
            {
                return match4(10, 0, 0, 0, 8) ||
                    match4(172, 16, 0, 0, 12) ||
                    match4(192, 168, 0, 0, 16) ||
                    match4(100, 64, 0, 0, 10) ||
                    match4(169, 254, 0, 0, 16) ||
                    match4(127, 0, 0, 0, 8);
            }

            //fd00::/8

            return *reinterpret_cast<const u8*>(&ipv6) == 0xfd;

        }

        bool is_multicast() const
        {
            if (flags.is<f_v4>())
            {
                return inrange4(224, 0, 0, 0, 239, 255, 255, 255);
            }

            return false;

        }

        bool is_wildcard_address() const
        {
            if (flags.is<f_v4>()) return ipv4.s_addr == 0;
            const u64 * d = reinterpret_cast<const u64*>(&ipv6);
            return d[0] == 0 && d[1] == 0;

        }

        ipap()
        {
            clear();
        }
        explicit ipap(bool v4)
        {
            flags.set<f_v4>(v4);
            flags.set<f_empty>();
        }

        explicit ipap(u32 addr4, u16 port) :port(port), flags(f_v4|f_port)
        {
            ipv4.s_addr = addr4;
        }

        ipap(const ipap &ip2) :port(ip2.port), flags(ip2.flags.all())
        {
            if (flags.is<f_v4>())
            {
                ipv4.s_addr = ip2.ipv4.s_addr;
            }
            else {
                tools::memcopy<sizeof(ipv6)>(&ipv6, &ip2.ipv6);
            }
        }

        explicit ipap(const void *aaaa, signed_t aaaa_size) {
            if (aaaa_size == sizeof(sockaddr_in))
            {
                const sockaddr_in* a = (const sockaddr_in*)aaaa;
                ipv4.s_addr = a->sin_addr.s_addr;
                port = u16be::from_be(a->sin_port);
                flags = f_v4|f_port;
            }
            else
            {
                const sockaddr_in6* a = (const sockaddr_in6*)aaaa;
                tools::memcopy<sizeof(a->sin6_addr)>(&ipv6, &a->sin6_addr);
                port = u16be::from_be(a->sin6_port);
                flags = f_port;
            }
        };

        ipap& operator=(const ipap& ip)
        {
            flags = ip.flags.all();
            if (ip.flags.is<f_v4>())
            {
                ipv4.s_addr = ip.ipv4.s_addr;
            }
            else {
                tools::memcopy<sizeof(ipv6)>(&ipv6, &ip.ipv6);
            }
#ifdef _DEBUG
            if (port == 53 && ip.port == 0)
                DEBUGBREAK();
#endif
            port = ip.port;
            return *this;
        }

        void set(const ipap& ip, bool useport)
        {
            if (ip.is_empty())
            {
                clear();
                return;
            }

            if (ip.flags.is<f_v4>())
            {
                ipv4.s_addr = ip.ipv4.s_addr;
                flags.set<f_v4>();
                flags.unset<f_empty>();
            }
            else
            {
                tools::memcopy<sizeof(ipv6)>(&ipv6, &ip.ipv6);
                flags.unset<f_v4>();
                flags.unset<f_empty>();
            }
            if (useport && ip.has_port())
            {
                port = ip.port;
                flags.set<f_port>();
            }
        }
        void set(const sockaddr_in* ip4, bool useport)
        {
            flags = f_v4;
            ipv4.s_addr = ip4->sin_addr.s_addr;
            if (useport)
            {
                port = u16be::from_be(ip4->sin_port);
                flags.set<f_port>();
            }
        }
        void set(const sockaddr_in6* ip6, bool useport)
        {
            flags = 0;
            memcpy(&ipv6, &ip6->sin6_addr, sizeof(ip6->sin6_addr));
            if (useport)
            {
                port = u16be::from_be(ip6->sin6_port);
                flags.set<f_port>();
            }
        }

        void operator=(const addrinfo *addr)
        {
            clear();

            for (; addr != nullptr; addr = addr->ai_next) {

                if (addr->ai_family == AF_INET) { // IPv4
                    set((sockaddr_in*)addr->ai_addr, true);
                    break;
                }
                else if (addr->ai_family == AF_INET6) { // IPv6
                    set((sockaddr_in6*)addr->ai_addr, true);
                    break;
                }
            }
        }

        ipap& set_port(size_t p)
        {
            this->port = tools::as_word(p);
            flags.set<f_port>();
            flags.unset<f_prefix>();
            flags.unset<f_empty>();
            return *this;
        }

        ipap& set_prefix(signed_t p)
        {
            this->port = tools::as_word(p);
            flags.unset<f_port>();
            flags.unset<f_empty>();
            flags.set<f_prefix>();
            return *this;
        }

        u16be* words()
        {
            return !flags.is<f_v4>() ? reinterpret_cast<u16be*>(&ipv6) : nullptr;
        }
        const u16be* words() const
        {
            ASSERT(!is_empty());
            return !flags.is<f_v4>() ? reinterpret_cast<const u16be*>(&ipv6) : nullptr;
        }

        str::astr to_string() const
        {
            return to_string_impl(has_port() ? port : 0);
        }

        str::astr addr_to_string() const
        {
            return to_string_impl(0);
        }

        str::astr to_string_impl(signed_t override_port) const
        {
            if (is_empty())
                return str::astr(ASTR("empty"));
            if (flags.is<f_v4>())
            {
                const u8* octs = reinterpret_cast<const u8*>(&ipv4.s_addr); // this is valid because ipv4.s_addr already in big endian and should be filled with in-mem byte order

                str::astr s;
                str::append_num(s, octs[0], 0);
                s.push_back('.'); str::append_num(s, octs[1], 0);
                s.push_back('.'); str::append_num(s, octs[2], 0);
                s.push_back('.'); str::append_num(s, octs[3], 0);

                if (override_port > 0)
                {
                    ASSERT(has_port());
                    s.push_back(':');
                    str::append_num(s, override_port, 0);
                }
                return s;
            }
            if (const u16be* ww = words())
            {
                str::astr s; if (override_port > 0) s.push_back('[');

                bool col = false, clp = false;
                bool needz = false;
                for (signed_t i = 0; i < 8; ++i)
                {
                    u16be w = ww[i];
                    if (w == 0 && !needz)
                    {
                        if (!col)
                        {
                            if (clp)
                                s.push_back(':');
                            else
                                s.append(ASTR("::"));
                        }
                        col = true;
                    }
                    else
                    {
                        if (col)
                            needz = true;
                        str::append_hex(s, (u16)w);
                        if (i < 7)
                        {
                            clp = true;
                            s.push_back(':');
                        }
                    }


                }

                if (override_port > 0)
                {
                    s.append(ASTR("]:"));
                    str::append_num(s, override_port, 0);
                }
                return s;
            }

            UNREACHABLE();
        }

        bool operator<(const ipap& other) const {
            
            if (flags.is<f_v4>() && !other.flags.is<f_v4>())
                return true; // v4 always less then v6
            if (!flags.is<f_v4>() && other.flags.is<f_v4>())
                return false;

            // Note: port is compared first for performance reasons,
            // even though this affects overall sort order

            if (port < other.port)
                return true;
            if (port > other.port)
                return false;

            if (flags.is<f_v4>())
                return ipv4.s_addr < other.ipv4.s_addr;
            
            return std::memcmp(&ipv6, &other.ipv6, 16) < 0;
        }

        bool copmpare(const ipap& a) const // compare address and port
        {
            if (is_empty())
                return a.is_empty();
            if (a.is_empty())
                return false;

            if (flags.is<f_v4>() && a.flags.is<f_v4>())
                return port == a.port && ipv4.s_addr == a.ipv4.s_addr;
            if (!flags.is<f_v4>() && !a.flags.is<f_v4>())
                return port == a.port && memcmp(&ipv6, &a.ipv6, sizeof(ipv6)) == 0;
            return false;
        }
        bool copmpare_a(const ipap& a) const // compare only address (not port)
        {
            if (is_empty())
                return a.is_empty();
            if (a.is_empty())
                return false;

            if (flags.is<f_v4>() && a.flags.is<f_v4>())
                return ipv4.s_addr == a.ipv4.s_addr;
            if (!flags.is<f_v4>() && !a.flags.is<f_v4>())
                return memcmp(&ipv6, &a.ipv6, sizeof(ipv6)) == 0;
            return false;
        }
        bool copmpare_a(const u8 *data, signed_t dsz) const // compare only address
        {
            if (is_empty())
                return false;

            if (flags.is<f_v4>() && dsz == 4)
                return ipv4.s_addr == *(const u32 *)data;
            if (!flags.is<f_v4>() && dsz == 16)
                return memcmp(&ipv6, data, sizeof(ipv6)) == 0;
            return false;
        }

        bool operator==(const ipap& a) const // compare address and port
        {
            return copmpare(a);
        }

        operator u32be() const { // ACHTING!!! returns BIG-ENDIAN value of ipv4 address (on little-endian cpus lower octet contains high ip value (eg: 127 for "127.0.0.1"))
            ASSERT(!is_empty() && v4());
            return u32be::from_be(ipv4.s_addr);
        }

        operator bool() const
        {
            return !is_empty();
        }

        /*
        operator u128() const {
            return !v4 ? *(u128 *)&ipv6 : 0;
        }
        */

        bool connect(system_socket_type s) const; // tcp connect to addr
    };

    enum endpoint_state : u8
    {
        EPS_EMPTY,
        EPS_DOMAIN,
        EPS_RESLOVED,
    };
    enum endpoint_string : u8
    {
        EPS_DEFAUL,
        EPS_GET_IP_IF_RESOLVED,
    };

    struct pipe;
    class pipe_waiter
    {
        using psock = system_socket*;
        u64 readymask = 0;
        psock sockets[MAXIMUM_WAITABLES];
        wait_slot slots[MAXIMUM_WAITABLES + 2];
#ifdef _WIN32
        WSAEVENT sig = nullptr;
#endif
#ifdef _NIX
        int efd = -1;
#endif // _NIX
        size_t numw = 0;

        static_assert(MAXIMUM_WAITABLES <= 64);

    public:

        void prepare()
        {
            numw = 0;
            readymask = 0;
        }

        class mask
        {
            u64 readm = 0;
            u64 closem = 0;
            u64 writem = 0;
            bool by_signal = false;

        public:
            mask(u64 readmask):readm(readmask)
            {
            }
            mask(bool bsgn = false) :by_signal(bsgn)
            {
            }

            void set_by_signal()
            {
                by_signal = true;
            }

#ifdef _DEBUG
            u64 rm() const { return readm; };
            u64 cm() const { return closem; };
            u64 wm() const { return writem; };
#endif

            bool have_read(u64 m)
            {
                if ((readm & m) != 0)
                {
                    readm &= ~m;
                    return true;
                }
                return false;
            }
            bool have_closed(u64 m)
            {
                if ((closem & m) != 0)
                {
                    closem &= ~m;
                    return true;
                }
                return false;
            }
            bool have_write(u64 m)
            {
                if ((writem & m) != 0)
                {
                    writem &= ~m;
                    return true;
                }
                return false;
            }

            void add_read(u64 m) { readm |= m; }
            void add_close(u64 m) { closem |= m; }
            void add_write(u64 m) { writem |= m; }

            void remove_read(u64 m) { readm &= ~m; }
            void remove_close(u64 m) { closem &= ~m; }
            void remove_write(u64 m) { writem &= ~m; }

            bool is_empty() const { return readm == 0 && closem == 0 && writem == 0; }
            bool is_bysignal() const { return by_signal; }
        };

        ~pipe_waiter()
        {
#ifdef _WIN32
            if (sig)
                WSACloseEvent(sig);
#else
            if (efd >= 0)
                ::close(efd);
#endif // _NIX
        }

        u64 reg(pipe* p);
        void unreg_last();

        mask wait(signed_t ms_timeout); // after wait return, waiter is in empty state
        void signal();
    };

    class endpoint
    {
        str::astr domain_;
        ipap ip;
        endpoint_state state_ = EPS_EMPTY;
        socket_type_e sockt = ST_UNDEFINED;

        void check_domain_or_ip();

    public:

        endpoint() {}
        explicit endpoint(const str::astr& addr);
        endpoint(const ipap &ip):ip(ip), state_(EPS_RESLOVED) {}

        static consteval signed_t plain_tail_start()
        {
            return sizeof(domain_);
        }

        bool operator==(const endpoint& ep)
        {
            switch (state_)
            {
            case EPS_DOMAIN:

                if (ep.state_ == EPS_DOMAIN)
                    return domain_ == ep.domain_;

                if (ep.state_ == EPS_RESLOVED)
                    return ip.copmpare(ep.ip);

                return false;
            case netkit::EPS_RESLOVED:
                return ip.copmpare(ep.ip);
            }
            return false;
        }

        void preparse(const str::astr& addr);

        void read(const u8* packet, signed_t plen)
        {
            ipap::build(&ip, packet, plen);
            state_ = EPS_RESLOVED;
        }

        void set_addr(const ipap& ip_)
        {
            this->ip.set(ip_, false);
            state_ = EPS_RESLOVED;
        }

        void set_ipap(const ipap &ip_)
        {
            this->ip = ip_;
            state_ = EPS_RESLOVED;
        }

        void set_port(size_t p)
        {
            this->ip.set_port(p);
        }

        void set_domain(const str::astr& dom)
        {
            this->domain_ = dom;
            state_ = EPS_DOMAIN;
            check_domain_or_ip();
        }
        void set_domain(const str::astr_view& dom)
        {
            this->domain_ = dom;
            state_ = EPS_DOMAIN;
            check_domain_or_ip();
        }

        ipap resolve_ip(size_t options);
        const ipap& get_ip() const
        {
            ASSERT(state_ == EPS_RESLOVED);
            return ip;
        }

        signed_t port() const
        {
            ASSERT(ip.has_port());
            return ip.port;
        }
        bool has_port() const
        {
            return ip.has_port();
        }
        endpoint_state state() const
        {
            return state_;
        }
        socket_type_e socket_type() const
        {
            return sockt;
        }
        str::astr domain() const
        {
            return domain_;
        }
        str::astr desc() const; // human readable string
        str::astr to_string(endpoint_string eps = EPS_DEFAUL) const; // machine readable string
    };

    struct udp_packet
    {
        u8    packet[65536];
        ipap from;
        u16 sz = 0;
        explicit udp_packet(bool v4)
        {
            from.flags.set<netkit::ipap::f_v4>(v4);
        }

        std::span<const u8> to_span() const
        {
            return std::span<const u8>(packet, sz);
        }
    };

    struct tcp_pipe;

    struct pipe : public ptr::sync_shared_object
    {
        enum sendrslt
        {
            SEND_OK,
            SEND_FAIL,
            SEND_BUFFERFULL,

            SEND_UNDEFINED,
        };

        enum info
        {
            I_REMOTE,       // remote addr
            I_REMOTE_RAW,   // ipap itself
            I_USERNANE,     // for crypto server
            I_SUMMARY
        };

#ifdef _DEBUG
        signed_t tag = 0;
        signed_t calc_entropy = 0;
#endif

        pipe() {}
        virtual ~pipe() {}

        pipe(const tcp_pipe&) = delete;
        pipe(tcp_pipe&&) = delete;

        virtual void replace(replace_socket* rsock) = 0; // rsock will be owned by pipe

        u8 wait(size_t evts, signed_t timeout_ms)
        {
            if (auto* s = get_socket())
                return s->wait(evts, timeout_ms);
            return netkit::SE_CLOSED;
        }

        /*
        * send always consumes whole datasize amount of data (even if buffer is full)
        * call with data == nullptr to check send out buffer (full or not)
        * call with datasize == 0 and data != nullptr to send unsent data (if buffer is full)
        */

        virtual sendrslt send(const u8* data, signed_t datasize) = 0;
        
        /*
        * recv should always receive as much data as possible, so it should fill whole available free space in data buffer
        * the required parameter ensures that at least the required number of bytes is placed in the output buffer.
        * the return value is equal to the required parameter if it is greater than zero and equal to the increment of the output buffer,
        * is equal to zero. -1 in case of error
        */
        virtual signed_t recv(tools::circular_buffer_extdata &data, signed_t required, signed_t timeout DST(, deep_tracer*)) = 0;
        virtual void unrecv(tools::circular_buffer_extdata& data) = 0; // just back data to recv buf
        virtual system_socket *get_socket() = 0;
        virtual void close(bool flush_before_close) = 0;
        virtual bool alive() = 0;
        virtual str::astr get_info(info i) const = 0;

        ipap get_remote_ipap() const
        {
            str::astr src = this->get_info(netkit::pipe::I_REMOTE_RAW);
            if (src.length() == sizeof(netkit::ipap))
                return *reinterpret_cast<const netkit::ipap*>(src.c_str());
            return ipap();
        }
    };

    using pipe_ptr = ptr::shared_ptr<pipe>;

    struct tcp_pipe : public pipe
    {
        std::unique_ptr<system_socket> sock;
        ipap addr;

        struct unrecv_data
        {
            u32 size = 0;
            u8* data()
            {
                return reinterpret_cast<u8*>(this + 1);
            }
            std::span<const u8> span() const
            {
                return std::span(reinterpret_cast<const u8*>(this + 1), size);
            }
        };
        unrecv_data* unrcv = nullptr;
        
        tools::chunk_buffer<16384> outbuf;

        pipe::sendrslt trysend(); // just try to send outbuf

        tcp_pipe() {}
        tcp_pipe(system_socket *s, const ipap& addr) :addr(addr) { sock.reset(s); }
        tcp_pipe(const tcp_pipe&) = delete;
        tcp_pipe(tcp_pipe&&) = delete;

        /*virtual*/ ~tcp_pipe()
        {
            close(true);
            ma::mf(unrcv);
        }

        /*virtual*/ void replace(replace_socket* rsock) override
        {
            rsock->sock.reset(sock.release());
            sock.reset(rsock);
        }

        /*virtual*/ void close(bool flush_before_close) override
        {
            if (sock)
            {
#ifdef _DEBUG
                if (tag)
                {
                    LOG_D("tagged $ close", tag);
                }
#endif
                sock->close(flush_before_close);
                sock.reset();
            }
        }

        void set_address(const ipap &ipp)
        {
            addr = ipp;
        }
        void set_address(endpoint& ainf);

        bool connect(socket_info_func sif)
        {
            if (!sock)
                sock.reset( NEW SYSTEM_STREAM_SOCKET() );
            return sock->connect(addr, sif);
        }


        tcp_pipe& operator=(tcp_pipe&& p)
        {
            if (connected())
                close(false);

            sock = std::move(p.sock);
            addr = p.addr;
            return *this;
        }

        bool connected() const { return sock != nullptr; }

        /*virtual*/ bool alive() override;
        /*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;
        /*virtual*/ signed_t recv(tools::circular_buffer_extdata& data, signed_t required, signed_t timeout DST(, deep_tracer*)) override;
        /*virtual*/ void unrecv(tools::circular_buffer_extdata& data) override
        {
            ASSERT(unrcv == nullptr);
            if (size_t dsz = data.datasize(); dsz > 0)
            {
                unrcv = (unrecv_data*)MA(sizeof(unrecv_data) + dsz);
                tools::memory_pair mp = data.data(dsz);
                unrcv->size = static_cast<u32>(dsz);
                mp.copy_out(unrcv->data(), dsz);
                data.clear();
            }
        }

        /*virtual*/ system_socket* get_socket() override {
            if (sock)
                return sock->update(sock);
            return nullptr;
        }

        /*
        void cpdone(signed_t psz) // current packet done
        {
            if (rcvbuf_sz == psz)
                rcvbuf_sz = 0;
            else if (rcvbuf_sz > psz)
            {
                rcvbuf_sz -= psz;
                memcpy(rcvbuf, rcvbuf + psz, rcvbuf_sz);
            }
        }
        */

        /*virtual*/ str::astr get_info(info i) const override;
    };

    static_assert(sizeof(tcp_pipe) <= 65536);


    bool dnsresolve(const str::astr& host, ipap& addr, bool log_it);


    /*
    *   pgen is a wrapper for a byte array
    *   does not own the array
    *
    *   ptr - pointer to current write position; used for pushing data to array
    *   sz - array size; maximum vaule for ptr;
    *   extra - extra space before an array; can be used to insert some data before existing data
    */
    class pgen
    {
        u8* data;

        inline void shrink_extra(signed_t res) // positive res - shrink extra; negative res - expand extra
        {
            ASSERT(res > 0 ? extra >= res : (extra - res) <= sz);
            extra = tools::as_word(extra - res);
            data = data - res;
            sz = tools::as_word(sz + res);
            ptr = (res+ptr) < 0 ? 0 : tools::as_word(ptr + res);
        }

    public:
        u16 ptr = 0;
        u16 sz, extra = 0; // "extra" is extra space before data
        pgen(u8* data, signed_t sz, signed_t extra = 0) :data(data), sz(tools::as_word(sz)), extra(tools::as_word(extra)) {}
        pgen():data(nullptr), sz(0) {}

        inline void change_extra(signed_t res) // positive res - expand; negative res - shrink
        {
            shrink_extra(-res);
        }

        void set_extra(u16 req_extra)
        {
            if (req_extra == extra)
                return;
            signed_t delta = SIGNED % req_extra - SIGNED % extra;
            change_extra(delta);
        }

        void set(udp_packet& p, signed_t offst)
        {
            data = p.packet + offst;
            sz = ptr = tools::as_word(p.sz - offst);
            extra = tools::as_word(offst);
        }

        void copy_from(const udp_packet& p)
        {
            memcpy(data, p.packet, p.sz);
            sz = ptr = p.sz;
        }

        std::span<const u8> to_span() const
        {
            return std::span<const u8>(data, sz);
        }

        void start()
        {
            ptr = 0;
        }

        const u8* raw() const
        {
            return data + ptr;
        }
        u8* get_data()
        {
            return data;
        }
        const u8* get_data() const
        {
            return data;
        }

        str::astr_view str_view(signed_t ssz)
        {
            for (char* c = (char*)data + ptr, *e = (char*)data + ptr + ssz; c < e; ++c)
            {
                char ch = *c;
                if (ch >= 'A' && ch <= 'Z')
                {
                    *c = ch + 32;
                }
            }

            return str::astr_view( (const char *)data + ptr, ssz);
        }

        bool skipn(signed_t n)
        {
            ptr += tools::as_word(n);
            return ptr <= sz;
        }

        bool enough(signed_t numb) const
        {
            return ptr + numb <= sz;
        }

        u8 read8()
        {
            ASSERT(enough(1));
            return data[ptr++];
        }

        u16 read16()
        {
            ASSERT(enough(2));
            u16 rv = load_be<2>(data + ptr);
            ptr += 2;
            return rv;
        }
        u32 read32()
        {
            ASSERT(enough(4));
            u32 rv = load_be<4>(data + ptr);
            ptr += 4;
            return rv;
        }
        const u8* read(signed_t rsz)
        {
            if (!enough(rsz))
                return nullptr;
            signed_t p = ptr;
            ptr = tools::as_word(ptr + rsz);
            return data + p;
        }

        template<typename T> const T* readstruct()
        {
            if (!enough(sizeof(T)))
                return nullptr;
            T* t = (T *)(data + ptr);
            ptr += sizeof(T);
            return t;
        }
        template<typename T> T get()
        {
            if (!enough(sizeof(T)))
                return (T)0;
            T* t = (T*)(data + ptr);
            ptr += sizeof(T);
            return *t;
        }

        template<typename S> S & pushstruct()
        {
            ASSERT(enough(sizeof(S)));
            memset(data + ptr, 0, sizeof(S));
            S& s = *(S*)(data + ptr);
            ptr += sizeof(S);
            return s;
        }

        void pusha(const u8* a, signed_t asz)
        {
            ASSERT(enough(asz));
            memcpy(data + ptr, a, asz);
            ptr += tools::as_word(asz);
        }
        void pushz(signed_t zsz)
        {
            ASSERT(enough(zsz));
            memset(data + ptr, 0, zsz);
            ptr += tools::as_word(zsz);
        }

        void push8(signed_t b)
        {
            ASSERT(enough(1));
            data[ptr++] = (u8)b;
        }
        void push16(signed_t b) // push in big endiang order
        {
            ASSERT(enough(2));
            data[ptr++] = (u8)((b >> 8) & 0xff); // high first
            data[ptr++] = (u8)((b) & 0xff); // low second
        }
        void pushs(const str::astr_view& s)
        {
            data[ptr++] = (u8)s.length();
            memcpy(data + ptr, s.data(), s.length());
            ptr += tools::as_word(s.length());
        }
        void push(const netkit::ipap &ip, bool push_port) // push ip
        {
            if (ip.v4())
            {
                tools::memcopy<4>(data + ptr, &ip.ipv4);
                ptr += 4;
            }
            else {
                tools::memcopy<16>(data + ptr, &ip.ipv6);
                ptr += 16;
            }
            if (push_port)
            {
                ASSERT(ip.has_port());
                push16(ip.port);
            }
        }
    };

    struct thread_storage_data
    {
        virtual ~thread_storage_data() {}
    };

    struct thread_storage
    {
        std::unique_ptr<thread_storage_data> data;
    };

    enum io_result
    {
        ior_ok,
        ior_general_fail,
        ior_proxy_fail,
        ior_decrypt_fail,
        ior_send_failed,
        ior_notresolved,
        ior_timeout,
    };

    class udp_pipe
    {
    public:
        virtual ~udp_pipe() {}

        virtual io_result send(const endpoint &toaddr, const pgen& pg /* in */) = 0;
        virtual io_result recv(netkit::ipap &from, pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/) = 0;
    };

    void udp_prepare(thread_storage& ts, bool v4);
    io_result udp_send(thread_storage& ts, const endpoint& toaddr, const pgen& pg /* in */);
    io_result udp_recv(thread_storage& ts, netkit::ipap& from, pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/);

    class pipe_tools
    {
    protected:
        tools::circular_buffer_preallocated<16384> rcvd;
        netkit::pipe_ptr pp;

        netkit::pipe::sendrslt send(const std::span<const u8>& d);

    public:
        pipe_tools(netkit::pipe* p) :pp(p) {}
        ~pipe_tools() {}

        bool empty_recv() const { return rcvd.datasize() == 0; }

        bool read_line(str::astr* s);
        netkit::pipe::sendrslt send(const str::astr_view& d)
        {
            return this->send(str::span(d));
        }
        netkit::pipe::sendrslt send(const buffer& d)
        {
            return this->send(d.span());
        }
        void unrecv() // return rcvd unused data to pipe
        {
            pp->unrecv(rcvd);
        }
    };

    ipap bind4addr(const ipap& tgt);

} // namespace netkit

template <> struct std::hash<netkit::ipap>
{
    std::size_t operator()(const netkit::ipap& k) const
    {
        return k.calc_hash();
    }
};

