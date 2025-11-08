#include "pch.h"


template <typename HUB, typename PTR> bool classify(HUB& hub, PTR* p, size_t sz)
{
    if (sz < sizeof(ip4_header))
        return false;

    using ip4hdr = std::conditional_t<std::is_const_v<PTR>, const ip4_header, ip4_header>;
    using ip6hdr = std::conditional_t<std::is_const_v<PTR>, const ip6_header, ip6_header>;
    using tcphdr = std::conditional_t<std::is_const_v<PTR>, const tcp_header, tcp_header>;
    using udphdr = std::conditional_t<std::is_const_v<PTR>, const udp_header, udp_header>;

    ip4hdr* h4 = reinterpret_cast<ip4hdr*>(p);
    if (4 == h4->version)
    {
        if constexpr (HUB::check_total_len)
        {
            if (sz != h4->tot_len)
                return false;
        }

        size_t ipsz = h4->ihl * 4;

        // ipv4
        switch (h4->protocol)
        {
        case P_TCP: // tcp

            if ((ipsz + sizeof(tcp_header)) > sz)
                return false;
            else
            {
                tcphdr* tcph = reinterpret_cast<tcphdr*>(p + ipsz);
                size_t tcphsz = tcph->doff.template getn<tcp_doff>() * 4;
                if ((ipsz + tcphsz) > sz)
                    return false;

                hub(h4, tcph, sz);
            }

            break;
        case P_UDP: // udp

            hub(h4, reinterpret_cast<udphdr*>(p + h4->ihl * 4), sz);
            break;
        }
    }
    else if (6 == h4->version)
    {
        if (sz < sizeof(ip6_header))
            return false;

        ip6hdr* h6 = reinterpret_cast<ip6hdr*>(p);
        switch (h6->next_header)
        {
        case P_TCP: // tcp
            hub(h6, reinterpret_cast<tcphdr*>(p + 40), sz);
            break;
        case P_UDP: // udp
            hub(h6, reinterpret_cast<udphdr*>(p + 40), sz);
            break;
        }

    }

    return true;
}

namespace
{
    static u16 calculate_checksum_smallblock(const u8* data, size_t datalen, size_t sum = 0)
    {
        for (; datalen > 1; datalen -= 2, data += 2)
            sum += *(u16*)data;

        if (datalen & 1)
            sum += *data;

#ifdef ARCH_64BIT
        if (sum >> 32)
        {
            sum = (sum & 0xffffffff) + (sum >> 32);
            sum += (sum >> 32);
            sum &= 0xffffffff;
        }
#endif

        sum = (sum & 0xffff) + (sum >> 16);
        sum += (sum >> 16);

        return (~sum) & 0xffff;
    }

    static u16 calculate_checksum(const u8* data, size_t datalen, size_t sum = 0)
    {
        for (; datalen >= sizeof(size_t); datalen -= sizeof(size_t), data += sizeof(size_t))
        {
#ifdef ARCH_64BIT
            static_assert(sizeof(size_t) == sizeof(u64));
            u64* suma = reinterpret_cast<u64*>(&sum);
            sum += uints::carryop_add::op64(0, sum, *(u64*)data, suma);
#else
            u64 s = (u64)sum + *(size_t*)data;
            sum = (s & 0xffffffff) + (s >> 32);
#endif
        }

        if (datalen & (sizeof(size_t) - 1))
            return calculate_checksum_smallblock(data, datalen, sum);

#ifdef ARCH_64BIT
        sum = (sum & 0xffffffff) + (sum >> 32);
        sum += (sum >> 32);
        sum &= 0xffffffff;
#endif

        sum = (sum & 0xffff) + (sum >> 16);
        sum += (sum >> 16);

        return (~sum) & 0xffff;
    }

#if 0
    static void calculate_ip_checksum(ip4_header* hdr)
    {
        size_t header_length = hdr->ihl * 4;

        hdr->check = 0;

        if (header_length < 20)
            return;

        hdr->check = calculate_checksum((const u8*)hdr, header_length);
    }
#endif

    static tcp_header* build_tcp_packet(netkit::pgen& pg, const netkit::ipap& src, const netkit::ipap& dst)
    {
        if (src.v4())
        {
            ip4_header* iph = reinterpret_cast<ip4_header*>(pg.get_data());
            iph->version = 4;
            iph->ihl = 5;

            iph->tos = 0;
            iph->tot_len = sizeof(ip4_header) + sizeof(tcp_header);
            iph->id = 0;
            iph->fof = 0x4000;  // DF
            iph->ttl = 128;
            iph->protocol = P_TCP;  // TCP
            iph->check = 0;
            iph->saddr = src.ipv4.s_addr;
            iph->daddr = dst.ipv4.s_addr;

            tcp_header* tcph = reinterpret_cast<tcp_header*>(pg.get_data() + sizeof(ip4_header));
            tcph->sport = src.port;
            tcph->dport = dst.port;
            tcph->doff = 5 << 4; // 5 * 4 == 20 - no options
            tcph->flags = 0;
            tcph->window = 65535;
            tcph->urg_ptr = 0;

            pg.ptr = sizeof(ip4_header) + sizeof(tcp_header);

            return tcph;
        }
        else
        {
            // TODO
            DEBUGBREAK();
        }

        return nullptr;
    }

    static udp_header * build_udp_packet(netkit::pgen& pg, const netkit::ipap& src, const netkit::ipap& dst)
    {
        if (src.v4())
        {
            ip4_header* iph = reinterpret_cast<ip4_header*>(pg.get_data());
            iph->version = 4;
            iph->ihl = 5;

            iph->tos = 0;
            iph->tot_len = sizeof(ip4_header) + sizeof(udp_header);
            iph->id = 0;
            iph->fof = 0x4000;  // DF
            iph->ttl = 128;
            iph->protocol = P_UDP;  // UDP
            iph->check = 0;
            iph->saddr = src.ipv4.s_addr;
            iph->daddr = dst.ipv4.s_addr;

            udp_header* udph = reinterpret_cast<udp_header*>(pg.get_data() + sizeof(ip4_header));
            udph->sport = src.port;
            udph->dport = dst.port;
            udph->len = sizeof(udp_header);
            udph->check = 0;

            pg.ptr = sizeof(ip4_header) + sizeof(udp_header);
            return udph;
        }
        else
        {
            // TODO
            DEBUGBREAK();
        }

        return nullptr;
    }

    struct checksumcaldispatcher
    {
        static constexpr bool check_total_len = false;

        void operator ()(ip4_header* iph, tcp_header* tcph, size_t sz)
        {
            iph->tot_len = tools::as_word(sz); // update total len
            size_t iplen = iph->ihl * 4;
            iph->check = 0;
            iph->check = calculate_checksum(reinterpret_cast<const u8*>(iph), iplen, 0);

            size_t tcp_size = sz - iplen;
            // pseudo header pre-sum
            u32 sum = (iph->saddr >> 16) + (iph->saddr & 0xffff) + (iph->daddr >> 16) + (iph->daddr & 0xffff) + (P_TCP << 8) + htons(tools::as_word(tcp_size));
            tcph->check = 0;
            tcph->check = calculate_checksum(reinterpret_cast<const u8*>(tcph), tcp_size, sum);
        }
        void operator ()(ip4_header* iph, [[maybe_unused]] udp_header* udph, [[maybe_unused]] size_t sz)
        {
            iph->tot_len = tools::as_word(sz); // update total len

            size_t iplen = iph->ihl * 4;
            iph->check = 0;
            iph->check = calculate_checksum(reinterpret_cast<const u8*>(iph), iplen, 0);
            udph->check = 0; // optional; set to zero
        }
        void operator ()([[maybe_unused]] ip6_header* iph, [[maybe_unused]] tcp_header* tcph, [[maybe_unused]] size_t sz) {

            DEBUGBREAK();
        }
        void operator ()([[maybe_unused]] ip6_header* iph, [[maybe_unused]] udp_header* udph, [[maybe_unused]] size_t sz) {

            DEBUGBREAK();
        }
    };

    void add_options(netkit::pgen& pg, tcp_header* tcp) {
        // finalize

        ASSERT(tcp->doff.getn<tcp_doff>() == 5); // sure no options yet added
        ASSERT( (u8 *)tcp > pg.get_data() && (u8*)tcp < pg.raw());

        size_t current_hsz = pg.raw() - (u8*)tcp;
        for (;current_hsz & 3; ++current_hsz)
            pg.push8(TO_EOL);

        tcp->doff.setn<tcp_doff>(current_hsz/4);
    }


    template <typename... Ts> void add_options(netkit::pgen&, tcp_header*, size_t, const Ts&...)
    {
        ASSERT(false);
    }
    template <typename... Ts> void add_option_error(netkit::pgen&, tcp_header*, const Ts&...)
    {
        ASSERT(false);
    }

    void add_options(netkit::pgen& pg, tcp_header* tcp, tcp_options o);
    template <typename... Ts> void add_options(netkit::pgen& pg, tcp_header* tcp, tcp_options o, const Ts&... rest);
    template <typename... Ts> void add_option_mss(netkit::pgen& pg, tcp_header* tcp, size_t mss, const Ts&... rest) {
        ASSERT(mss < 65536);
        pg.push8(TO_MSS);
        pg.push8(4);
        pg.push16(tools::as_word(mss));
        add_options(pg, tcp, rest...);
    }
    template <typename... Ts> void add_option_ws(netkit::pgen& pg, tcp_header* tcp, size_t ws, const Ts&... rest) {
        ASSERT(ws <= 14);
        pg.push8(TO_WS);
        pg.push8(3);
        pg.push8(tools::as_byte(ws));
        add_options(pg, tcp, rest...);
    }

    void add_options(netkit::pgen& pg, tcp_header* tcp, tcp_options o) {
        ASSERT(o != TO_EOL && o != TO_NOP);
        switch (o)
        {
        case TO_SACK_PERM:
            pg.push8(TO_SACK_PERM);
            pg.push8(2);
            add_options(pg, tcp);
            return;
        }
        add_option_error(pg, tcp, 0);
    }


    template <typename... Ts> void add_options(netkit::pgen& pg, tcp_header* tcp, tcp_options o, const Ts&... rest) {
        ASSERT(o != TO_EOL && o != TO_NOP);
        switch (o)
        {
        case TO_MSS:
            add_option_mss(pg, tcp, rest...);
            return;
        case TO_WS:
            add_option_ws(pg, tcp, rest...);
            return;
        case TO_SACK_PERM:
            pg.push8(TO_SACK_PERM);
            pg.push8(2);
            add_options(pg, tcp, rest...);
            return;
        case TO_SACK:
            add_option_error(pg, tcp, rest...);
            return;
        case TO_TIMESTAMPS:
            add_option_error(pg, tcp, rest...);
            return;
        case TO_TFO:
            add_option_error(pg, tcp, rest...);
            return;
        }
        add_option_error(pg, tcp, rest...);
    }

    /*
    * fake socket only need for waiting events (SE_READ, SE_WRITE, SE_CLOSE)
    */
    struct fake_socket final : public netkit::system_socket
    {
#ifdef _WIN32
        WSAEVENT wsaevent = nullptr;
#endif
        volatile bool read_ready = false;
        volatile bool write_ready = false;
        volatile bool closed = false;

        fake_socket()
        {
#ifdef _WIN32
            wsaevent = WSACreateEvent();
#endif
        }
        ~fake_socket()
        {
#ifdef _WIN32
            if (wsaevent) WSACloseEvent(wsaevent);
#endif
        }

        void signal()
        {
#ifdef _WIN32
            WSASetEvent(wsaevent);
#else
            // TODO
#endif
        }

        u8 setup_wait_slot(netkit::wait_slot* slot) override
        {
            if (closed)
                return netkit::SE_CLOSED;
#ifdef _WIN32

            ASSERT(wsaevent);
            *slot = wsaevent;
#endif
            return (read_ready ? netkit::SE_READ : 0) | (write_ready ? netkit::SE_WRITE : 0);

        }
        u8 get_event_info(netkit::wait_slot* /*slot*/) override
        {
            if (closed)
                return netkit::SE_CLOSED;

#ifdef _WIN32
            WSAResetEvent(wsaevent);
#endif

            return (read_ready ? netkit::SE_READ : 0) | (write_ready ? netkit::SE_WRITE : 0);

        }
        void readypipe(bool rp) override
        {
            if (read_ready != rp)
            {
                read_ready = rp;
                signal();
            }
        }
        void readywrite(bool rw)
        {
            if (write_ready != rw)
            {
                write_ready = rw;
                signal();
            }
        }
        void closesignal()
        {
            if (!closed)
            {
                closed = true;
                signal();
            }
        }
        u8 wait(size_t reqevts, signed_t timeout_ms) override
        {
            if (closed)
                return netkit::SE_CLOSED;

            u8 curevts = (read_ready ? netkit::SE_READ : 0) | (write_ready ? netkit::SE_WRITE : 0);
            if (reqevts == curevts)
            {
                if (reqevts & netkit::SE_READ) read_ready = false;
                if (reqevts & netkit::SE_WRITE) write_ready = false;
                return curevts;
            }

            if (timeout_ms == 0 || (reqevts & curevts) != 0)
            {
                if (reqevts & netkit::SE_READ) read_ready = false;
                if (reqevts & netkit::SE_WRITE) write_ready = false;
                return curevts & reqevts;
            }

            for (;;)
            {
                chrono::mils wst = timeout_ms < 0 ? chrono::mils() : chrono::ms();

    #ifdef _WIN32
                if (WAIT_TIMEOUT == WaitForSingleObject(wsaevent, timeout_ms < 0 ? INFINITE : tools::as_dword(timeout_ms)))
                    return netkit::SE_TIMEOUT;
                WSAResetEvent(wsaevent);
    #endif
                curevts = (read_ready ? netkit::SE_READ : 0) | (write_ready ? netkit::SE_WRITE : 0);

                u8 ret = curevts & reqevts;
                if (ret == 0)
                {
                    if (timeout_ms > 0)
                    {
                        signed_t delta = chrono::ms() - wst;
                        timeout_ms -= delta;
                        if (timeout_ms <= 0)
                            return netkit::SE_TIMEOUT;
                    }

                    continue;
                }

                if (reqevts & netkit::SE_READ) read_ready = false;
                if (reqevts & netkit::SE_WRITE) write_ready = false;

                return ret;
            }

        }
        bool connect(const netkit::ipap&, netkit::socket_info_func ) override
        {
            DEBUGBREAK(); // inapplicable
            return false;
        }
        void sendfull(bool /*sff*/) override { DEBUGBREAK(); /*unused*/ }
        signed_t send(std::span<const u8> /*data*/) override { DEBUGBREAK(); return signed_t(); /*unused*/ }
        void close(bool /*flush_before_close*/) override
        {
            if (!closed)
            {
                closesignal();
#ifdef _WIN32
                HANDLE x = wsaevent;
                wsaevent = nullptr;
                WSACloseEvent(x);
#endif
            }
        }
        signed_t recv(tools::memory_pair& /*mp*/) override { DEBUGBREAK(); return signed_t(); /*unused*/ }
    };

    struct dispatcher
    {
        static constexpr bool check_total_len = true;
        ip_machine* ipm;
        void operator ()(const ip4_header* iph, const tcp_header* tcph, size_t sz) { ipm->handle_tcp_packet(iph, tcph, sz); }
        void operator ()(const ip4_header* iph, const udp_header* udph, size_t sz) { ipm->handle_udp_packet(iph, udph, sz); }
        void operator ()([[maybe_unused]] const ip6_header* iph, [[maybe_unused]] const tcp_header* tcph, [[maybe_unused]] size_t sz) {}
        void operator ()([[maybe_unused]] const ip6_header* iph, [[maybe_unused]] const udp_header* udph, [[maybe_unused]] size_t sz) {}
    };

}


void calculate_packet_checksums(u8* packet, size_t len) // it also updates total len of ip4 packet
{
    //auto ch1 = calculate_checksum(packet, len, 0);
    //auto ch2 = calculate_checksum_smallblock(packet, len, 0);
    //if (ch1 != ch2)
    //    __debugbreak();

    checksumcaldispatcher d;
    classify(d, packet, len);
}

void ip_machine::ipm_handle_packet(const u8* p, size_t sz)
{
#ifdef _DEBUG
    // packet handler is always executed in single thread
    size_t ctid = spinlock::current_thread_uid();
    if (handler_threadid == 0)
        handler_threadid = ctid;
    else {
        ASSERT(handler_threadid == ctid);
    }
#endif

    dispatcher d = { this };
    classify(d, p, sz);
}

ip_machine::ip_machine():acker_thread(&ip_machine::acker, this)
{
}
ip_machine::~ip_machine()
{
    stop_acker = true;
    auto w = streams.lock_write();
    for (auto& sp : w())
    {
        sp.second->owner = nullptr;
    }
    acker_thread.join();
    w.unlock();

    auto u = udfss.lock_write();
    for (auto& up : u())
    {
        up->owner = nullptr;
    }
}

void ip_machine::acker()
{
    ostools::set_current_thread_name(ASTR("acker"));

    pending_ack almost;
    for (; !glb.is_stop() && !stop_acker;)
    {

        if (almost.s)
        {
            if (!almost.s->alive())
            {
                // actually kill closed stream
                kill_stream(*almost.s, true);
                almost.s = nullptr;

            } else if (!almost.s->ack_time.is_empty())
            {
                auto ct = chrono::ms();

                if (ct >= almost.s->ack_time)
                {
                    send_simple_packet(*almost.s, 0); // ack
                }
                else
                {
                    spinlock::sleep(almost.s->ack_time - ct);
                    continue;
                }
            }
        }

        if (pending_acks.dequeue([&](pending_ack& a) {
            almost = a;
        }))
            continue;

        std::unique_lock<std::mutex> m(mtx);
        cv.wait(m, [&] {
            return glb.is_stop() || ack_signal || stop_acker;
        });
        m.unlock();
        ack_signal = false;

    }
}

void ip_machine::kill_stream(tcp_stream& s, bool force_now)
{
    if (s.flags.is<tcp_stream::F_ERASED>())
        return;

    if (force_now)
    {
        // F_ERASED can be set from non-handler thread, so it does not matter if other bits are damaged during multi-threaded races because this is the final bit, after which the values of other bits do not matter
        s.flags.set<tcp_stream::F_ERASED>();
        auto w = streams.lock_write();
        w().erase(s.key);
        w.unlock();

    }
    else
    {
        ref_cast<fake_socket>(s.sockspace).close(false);

        // just enqueue closed stream to acker - it will actually erase it
        s.ack_time = chrono::ms();
        pending_acks.enqueue([&](pending_ack& pa) {
            pa.s = &s;
            ack_signal = true;
            cv.notify_one();
        });

    }
}


bool ip_machine::send(u8* p, size_t sz)
{
    calculate_packet_checksums(p, sz);
    return inject(p, sz);
}

bool ip_machine::send_synack_packet(tcp_stream& s, bool retransmit)
{
    // send syn+ack packet

    u8 buf[sizeof(tcp_header) + sizeof(ip6_header)]; static_assert(sizeof(ip6_header) > sizeof(ip4_header));
    netkit::pgen pg(buf, sizeof(buf));
    tcp_header* h = build_tcp_packet(pg, s.dst, s.src);

    if (retransmit)
    {
        h->seq = s.server_seq - 1; // incremented, so we need to send previous value
        h->ack_seq = s.client_seq; // already incremented, no need to increment
    }
    else
    {
        h->seq = s.server_seq++; // syn increments seq
        h->ack_seq = ++s.client_seq; // increment due it answer to syn packet
    }
    h->flags = tcp_syn | tcp_ack;

    add_options(pg, h, TO_MSS, 65536 - 8, TO_WS, 2, TO_SACK_PERM);
    s.established = false;

    return send(pg.get_data(), pg.ptr);
}

bool ip_machine::ipm_stream_accept(tcp_stream& s)
{
    if (!send_synack_packet(s, false))
    {
        kill_stream(s, true);
        return false;
    }

    chrono::mils end_of_wait = chrono::ms(1000);

    for (; !s.established;)
    {
        spinlock::sleep(50);
        if (chrono::ms() > end_of_wait)
        {
            kill_stream(s, true);
            return false;
        }
    }

    return true;
}

void ip_machine::ipm_stream_reject(tcp_stream& s)
{
    send_simple_packet(s, tcp_rst);
    kill_stream(s, true);
}

bool ip_machine::send_simple_packet(tcp_stream& s, u8 tcpflags, u32 custom_ack)
{
    if (s.client_seq == s.client_seq_ack && tcpflags == 0)
        return true;

    s.client_seq_ack = s.client_seq;
    s.ack_time.empty(); // clear ack_time to allow tcp handler schedule new ack

    u8 buf[sizeof(tcp_header) + sizeof(ip6_header)]; static_assert(sizeof(ip6_header) > sizeof(ip4_header));
    netkit::pgen pg(buf, sizeof(buf));
    tcp_header* h = build_tcp_packet(pg, s.dst, s.src);

    h->seq = s.server_seq;
    h->ack_seq = (tcpflags & tcp_ack) ? custom_ack : s.client_seq;
    h->flags = tcpflags | tcp_ack;

    if (h->flags.is<tcp_fin|tcp_syn>())
        ++s.server_seq;

    return send(pg.get_data(), pg.ptr);

}

tcp_stream& ip_machine::create_tcp_stream(u64 key, const netkit::ipap& src, const netkit::ipap& dst)
{
    tcp_stream* stream = NEW tcp_stream(this, key, src, dst); // allocate before lock to minimize lock time
    auto w = streams.lock_write();

    auto [it, inserted] = w().emplace(key, ptr::shared_ptr<tcp_stream>());
    if (!inserted)
    {
        // stream already exists
        if (tcp_stream* stream_exist = it->second)
        {
            stream_exist->add_ref();
            w.unlock();
            delete stream; // delete after lock to minimize lock time
            return *stream_exist;
        }
    }

    it->second = stream;
    stream->add_ref();
    return *stream;
}

/*virtual*/ bool ip_machine::handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& p, netkit::endpoint& ep, netkit::pgen& pg)
{
    pg.set( p, 64 );
    ep.set_ipap( ref_cast<netkit::ipap>(p.packet) );
    return true;
}

void ip_machine::handle_tcp_packet(const ip4_header* h4, const tcp_header* tcph, size_t sz)
{
    netkit::ipap dst(h4->daddr, tcph->dport);
    if (!allow_tcp(dst))
        return;

    auto keepcheck1 = h4->check;
    auto keepcheck2 = tcph->check;
    calculate_packet_checksums((u8 *)h4, sz);
    if (keepcheck1 != h4->check || keepcheck2 != tcph->check)
        return;

    netkit::ipap src(h4->saddr, tcph->sport);

    if (h4->fof & 0x2000)
        DEBUGBREAK(); // MF flag / not supported yet

    u64 key = hash(src, dst);

    if (tcph->flags.all() == tcp_syn)
    {
        tcp_stream &s = create_tcp_stream(key, src, dst);
        if (!s.is_new())
        {
            if (!s.established && (tcph->seq + 1 == s.client_seq))
            {
                // retransmit
                send_synack_packet(s, true); // no matter it injected or not
                return;
            }

            send_simple_packet(s, tcp_rst|tcp_ack, tcph->seq + 1);
            return;
        }

        s.not_new();

        s.client_seq = tcph->seq;

        if (!s.parse_tcp_options(tcph))
        {
            ipm_stream_reject(s);
            tcp_stream::release(&s);
            return;
        }

        on_new_stream(s);
        tcp_stream::release(&s);
        return;
    }

    if (tcp_stream* s = lock_stream(key))
    {
        ASSERT(s->src == src && s->dst == dst);
        if (!s->established)
        {
            if (tcph->flags.all() == tcp_ack && s->client_seq == tcph->seq && s->server_seq == tcph->ack_seq)
            {
                s->established = true;
            }
            else
            {
                send_simple_packet(*s, tcp_rst | tcp_ack, tcph->seq + 1);
            }
        }
        else
        {
            const u8* eop = reinterpret_cast<const u8*>(h4) + sz;
            if (s->process_data_packet(tcph, eop))
            {
                pending_acks.enqueue([&](pending_ack& pa) {
                    pa.s = s;
                    ack_signal = true;
                    cv.notify_one();
                });
            }

        }
        tcp_stream::release(s); // unlock
    }

}


/*virtual*/ bool udp_fake_socket::sendto(const netkit::ipap& a, const std::span<const u8>& p) const
{
    if (!owner)
        return false;

    if (a.v4())
    {
        size_t psz = sizeof(ip4_header) + sizeof(udp_header) + p.size();
        u8* data = ALLOCA(psz);
        netkit::pgen pg(data, psz);
        udp_header *udph = build_udp_packet(pg, tgt, a);
        pg.pusha(p.data(), p.size());
        udph->len = tools::as_word(p.size() + sizeof(udp_header));
        owner->send(data, psz);
    }



    return false;
}

/*virtual*/ void udp_fake_socket::lock()
{
    add_ref();
}
/*virtual*/ void udp_fake_socket::unlock()
{
    if (dec_ref(1))
    {
        // fake socket has one ref - means it only in udfss set
        // so it is possible to delete it safely
        auto w = owner->udfss.lock_write();
        if (!is_multi_ref()) // addition check
        {
            owner = nullptr;
            w().erase(fsptr(this));
        }
    }
}


void ip_machine::handle_udp_packet([[maybe_unused]] const ip4_header* h4, [[maybe_unused]] const udp_header* udph, [[maybe_unused]] size_t sz)
{
    if (sz > 65536 - 64 || !allow_udp(netkit::ipap(h4->daddr, 0)))
        return;

    auto keepcheck1 = h4->check;
    calculate_packet_checksums((u8*)h4, sz);
    if (keepcheck1 != h4->check)
        return;

    size_t iplen = h4->ihl * 4 + sizeof(udp_header);
    if (sz - iplen != udph->len - sizeof(udp_header))
        return;

#ifdef _DEBUG
    udp_dispatcher::init_tid();
#endif // _DEBUG


    
    netkit::udp_packet pkt(true);
    pkt.sz = tools::as_word(sz - iplen + 64);
    new (&pkt.from) netkit::ipap(h4->saddr, udph->sport);
    new ((netkit::ipap *) & pkt.packet) netkit::ipap(h4->daddr, udph->dport);
    memcpy(pkt.packet + 64, reinterpret_cast<const u8*>(h4) + iplen, sz - iplen);

    udp_fake_socket* fs = NEW udp_fake_socket(this, *((netkit::ipap*)&pkt.packet));

    auto w = udfss.lock_write();
    auto [it, inserted] = w().insert(fsptr(fs));
    if (!inserted)
    {
        // socket already exists
        (*it)->lock(); // prevent instant free from other thread

        w.unlock();
        fs = *it;
        udp_dispatch(*fs, pkt);
        fs->unlock();
        return;
    }

    fs->lock();
    w.unlock();
    udp_dispatch( *fs, pkt );
    fs->unlock();
}



tcp_stream::tcp_stream(ip_machine* owner, u64 key, const netkit::ipap src, const netkit::ipap dst):key(key), src(src), dst(dst), owner(owner)
{
    server_seq = randomgen::get().rnd<u32>();

    static_assert(sizeof(fake_socket) <= sizeof(sockspace));
    new (sockspace) fake_socket();
}

tcp_stream::~tcp_stream()
{
    ASSERT(flags.is<F_ERASED>());
    ref_cast<fake_socket>(sockspace).~fake_socket();
}

bool tcp_stream::parse_tcp_options(const tcp_header* hdr)
{
    windowsize = hdr->window;

    size_t options_size = (hdr->doff.getn<tcp_doff>() - 5) * 4;
    const u8* optr = reinterpret_cast<const u8*>(hdr + 1);
    for (size_t oi = 0; oi < options_size;)
    {
        tcp_options kind = (tcp_options)optr[oi];
        switch (kind)
        {
        case TO_EOL:
            return true;
        case TO_NOP:
            ++oi;
            continue;
        case TO_MSS:
            if ((oi+1) >= options_size) return false;
            else {
                size_t len = optr[oi+1];
                if (len != 4 || (oi + 4) > options_size) return false;
                mss = load_be<2>(optr + oi + 2);
                oi += 4;
            }
            continue;
        case TO_WS:
            if ((oi + 1) >= options_size) return false;
            else {
                size_t len = optr[oi + 1];
                if (len != 3 || (oi + 3) > options_size) return false;
                ws = optr[oi + 2];
                oi += 3;
            }
            continue;
        case TO_SACK_PERM:
            if ((oi + 1) >= options_size) return false;
            else {
                size_t len = optr[oi + 1];
                if (len != 2 || (oi + 2) > options_size) return false;
                oi += 2;
                flags.set<F_SACK>();
            }
            continue;
        case TO_SACK:
            if ((oi + 1) >= options_size) return false;
            else {
                size_t len = optr[oi + 1];
                if ((oi + len) > options_size) return false;

                DEBUGBREAK(); // TODO : implement sack
            }
            continue;
        case TO_TIMESTAMPS:
            if ((oi + 1) >= options_size) return false;
            else {
                size_t len = optr[oi + 1];
                if (len != 10 || (oi + 10) > options_size) return false;

                DEBUGBREAK(); // TODO : implement timestamps
            }
            continue;
        case TO_TFO:
            if ((oi + 1) >= options_size) return false;
            else {
                size_t len = optr[oi + 1];
                if (len != 2 || (oi + 2) > options_size) return false;

                DEBUGBREAK(); // TODO : implement tfo
            }
            continue;
        default:
            break;
        }
    }
    return true;
}

bool tcp_stream::process_data_packet(const tcp_header* h, const u8* eop)
{
    if (flags.is<F_ERASED>())
        return false;

    if (client_seq == h->seq && parse_tcp_options(h))
    {
        if (h->flags.is<tcp_rst>())
        {
            if (h->flags.all() != (tcp_rst|tcp_ack) || h->ack_seq != server_seq)
                return false;

            owner->kill_stream(*this, false);
            return false;
        }

        size_t fin = 0;
        if (h->flags.is<tcp_fin>())
            fin = 1;
        const u8* payload = reinterpret_cast<const u8*>(h) + h->doff.getn<tcp_doff>() * 4;
        size_t payload_size = eop - payload;
        ready_data.lock_write()().append(std::span(payload, payload_size));
        ref_cast<fake_socket>(sockspace).readypipe(true);
        client_seq = tools::as_dword(client_seq + payload_size + fin);
        if (ack_time.is_empty() && fin == 0)
        {
            ack_time = chrono::ms(200);
            return true;
        }
        if (fin)
        {
            flags.set<F_FIN>();
            owner->send_simple_packet(*this, tcp_fin);
        }

    }
    return false;
}

netkit::pipe::sendrslt tcp_stream::send(const u8* data, signed_t datasize)
{
    if (ref_cast<fake_socket>(sockspace).closed)
    {
        unsent.clear();
        return SEND_FAIL;
    }

    if (flags.is<F_FIN>() && datasize)
        return SEND_FAIL;

    if (data == nullptr && unsent.is_empty())
        return SEND_OK;

    signed_t hdrsz = sizeof(tcp_header) + (src.v4() ? sizeof(ip4_header) : sizeof(ip6_header));
    signed_t send_size = 0;

    u8 *buf = (u8*)alloca( mss );
    netkit::pgen pg(buf, mss);

    bool trysend = false;

    if (datasize == 0)
    {
        trysend = true;
    rep_send:

        if (unsent.is_empty())
            return SEND_OK;

        auto sb = unsent.get_1st_chunk();
        data = sb.data();
        datasize = sb.size();
    }

    for(;;)
    {
        signed_t payload_size = datasize;
        if (payload_size > static_cast<signed_t>(mss) - hdrsz)
            payload_size = mss - hdrsz;

        new (&pg) netkit::pgen(buf, hdrsz + payload_size); // it is safe to call constructor without destructor (pgen is trivial destructible)

        tcp_header* h = build_tcp_packet(pg, dst, src);

        h->seq = server_seq;
        server_seq = static_cast<u32>((server_seq + payload_size) & 0xffffffff); // no need to make this op atomic because this is only place incrementing server_seq
        client_seq_ack = client_seq;
        h->ack_seq = client_seq;
        h->flags = tcp_psh | tcp_ack;

        pg.pusha(data, payload_size);

        if (owner->send(pg.get_data(), pg.ptr))
        {
            send_size += payload_size;

            if (datasize == send_size)
            {
                if (trysend)
                {
                    unsent.skip(send_size);
                    goto rep_send;
                }
                return SEND_OK;
            }
            continue;
        }

        if (trysend)
        {
            if (send_size > 0)
                unsent.skip(send_size);
        }
        else
        {
            unsent.append( std::span(data + send_size, datasize - send_size) );
        }

        return unsent.is_empty() ? SEND_OK : SEND_BUFFERFULL;
    }
    UNREACHABLE();
}
signed_t tcp_stream::recv(tools::circular_buffer_extdata& data, signed_t required, signed_t timeout DST(, deep_tracer*))
{
    if (ref_cast<fake_socket>(sockspace).closed)
        return -1;

    ref_cast<fake_socket>(sockspace).read_ready = false; // reset on recv

    auto rdr = ready_data.lock_read();

    for (chrono::mils deadtime = required > 0 && timeout > 0 ? chrono::ms(timeout) : chrono::mils(); required > 0;)
    {
        if (rdr().enough(required - data.datasize()))
        {
            rdr.unlock();
            auto rdw = ready_data.lock_write();
            rdw().peek(data);
            ASSERT(data.datasize() >= UNSIGNED % required);
            ref_cast<fake_socket>(sockspace).read_ready = !rdw().is_empty();

            return required;
        }

        rdr.unlock();

        if (flags.is<F_FIN>())
            return -1; // no more data

        ref_cast<fake_socket>(sockspace).wait(netkit::SE_READ, LOOP_PERIOD);

        if (!deadtime.is_empty() && chrono::ms() > deadtime)
            return -1;

        rdr = ready_data.lock_read();
    }

    if (!rdr().is_empty())
    {
        rdr.unlock();
        auto rdw = ready_data.lock_write();

        signed_t rv = rdw().peek(data);
        ref_cast<fake_socket>(sockspace).read_ready = !rdw().is_empty();

        return rv;
    }

    return 0;
}
void tcp_stream::unrecv(tools::circular_buffer_extdata& data)
{
    if (ref_cast<fake_socket>(sockspace).closed)
        return;

    if (size_t dsz = data.datasize(); dsz > 0)
    {
        tools::memory_pair mp = data.data(dsz);

        auto w = ready_data.lock_write();
        if (mp.p1.size())
            w().insert(mp.p1);
        w().insert(mp.p0);
        w.unlock();

        data.clear();
        ref_cast<fake_socket>(sockspace).readypipe(true);
    }

}
netkit::system_socket* tcp_stream::get_socket()
{
    return &ref_cast<fake_socket>(sockspace);
}
void tcp_stream::close(bool flush_before_close)
{
    if (ref_cast<fake_socket>(sockspace).closed)
        return;

    if (flush_before_close)
    {
        chrono::mils deadtime = chrono::ms(5000);
        for (; !unsent.is_empty();)
        {
            u8 dummy = 0;
            if (SEND_FAIL == send(&dummy, 0)) // try send
                break;
            if (chrono::ms() > deadtime)
                break;
        }
    }
    owner->send_simple_packet(*this, tcp_fin);
    owner->kill_stream(*this, false);
}
bool tcp_stream::alive()
{
    return !ref_cast<fake_socket>(sockspace).closed;
}
str::astr tcp_stream::get_info(info i) const
{
    if (i == I_REMOTE_RAW)
    {
        str::astr s; s.resize(sizeof(netkit::ipap));
        tools::memcopy<sizeof(netkit::ipap)>(s.data(), &dst);
        return s;
    }

    if (i == I_REMOTE || i == I_SUMMARY)
        return dst.to_string();

    return glb.emptys;
}
