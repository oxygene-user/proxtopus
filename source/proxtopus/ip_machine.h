#pragma once

#include <unordered_set>

#pragma pack(push, 1)

struct ip4_header
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u8  ihl : 4;        // header len with 32-bit words
    u8  version : 4;    // IP ver (4)
#else
    u8  version : 4;
    u8  ihl : 4;
#endif
    u8      tos;            // type of service
    u16be   tot_len;        // total len (header + payload)
    u16     id;
    u16be   fof;            // frag offset and flags
    u8      ttl;
    u8      protocol;       // protocol (TCP=6, UDP=17, ICMP=1)
    u16     check;          // checksum of header
    u32     saddr;          // source addr
    u32     daddr;          // target addr
    // options, if ihl > 5

};

struct ip6_header
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u32 flow_label : 20;
    u32 traffic_class : 8; // tos
    u32 version : 4;       // version (6)
#else
    u32 version : 4;
    u32 traffic_class : 8;
    u32 flow_label : 20;
#endif
    u16 payload_len;
    u8  next_header;    // next header (TCP=6, UDP=17, ICMPv6=58 etc...)
    u8  hop_limit;      // TTL
    u8  saddr[16];      // source addr
    u8  daddr[16];      // target addr
};

enum tcp_bits
{
    tcp_doff = 15 << 4,

    tcp_fin = 1,
    tcp_syn = 2,
    tcp_rst = 4,
    tcp_psh = 8,
    tcp_ack = 16,
    tcp_urg = 32,
    tcp_ece = 64,
    tcp_cwr = 128,
};

enum protocols
{
    P_ICMP = IPPROTO_ICMP,
    P_TCP = IPPROTO_TCP,
    P_UDP = IPPROTO_UDP,
};

enum tcp_options : u8
{
    TO_EOL,
    TO_NOP,
    TO_MSS,
    TO_WS,
    TO_SACK_PERM,
    TO_SACK,
    TO_TIMESTAMPS = 8,
    TO_TFO = 28,
};

struct tcp_header
{
    u16be sport;      // source port
    u16be dport;      // dst port
    u32be seq;        // seq num
    u32be ack_seq;    // confirm num

    tools::flags<1> doff;
    tools::flags<1> flags;

#if 0
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u16 res1 : 4;
    u16 hlen : 4;   // header len with 32-bit words (min 5)
    u16 fin : 1;
    u16 syn : 1;
    u16 rst : 1;
    u16 psh : 1;
    u16 ack : 1;
    u16 urg : 1;
    u16 ece : 1;
    u16 cwr : 1;
#else
    u16 doff : 4;
    u16 res1 : 4;
    u16 cwr : 1;
    u16 ece : 1;
    u16 urg : 1;
    u16 ack : 1;
    u16 psh : 1;
    u16 rst : 1;
    u16 syn : 1;
    u16 fin : 1;
#endif
#endif

    u16be window;       // windows size
    u16   check;        // checksum (not big endian)
    u16be urg_ptr;      // ptr to urgent data
    // options if hlen > 5

};

struct udp_header
{
    u16be sport;      // source port
    u16be dport;      // dst port
    u16be len;
    u16   check;        // checksum (not big endian)
};

#pragma pack(pop)

inline u64 hash(const netkit::ipap& src, const netkit::ipap& dst)
{
    u64 h1 = (src.v4() ? (1ull << 32) : (1ull << 33)) | (dst.v4() ? (1ull << 34) : (1ull << 35)) | (src.port) | (((u32)dst.port) << 16);
    u64 h2 = 0;

    if (src.v4() && dst.v4())
    {
        h2 = src.ipv4.s_addr;
        spooky::hash_short(&dst.ipv4, 4, &h1, &h2);
    }
    else
    {
        if (src.v4())
        {
            h2 = src.ipv4.s_addr;
            spooky::hash_short(&dst.ipv6, 16, &h1, &h2);
        }
        else if (dst.v4())
        {
            h2 = dst.ipv4.s_addr;
            spooky::hash_short(&src.ipv6, 16, &h1, &h2);
        }
        else {

            u8 buf[32];
            tools::memcopy<16>(buf, &src.ipv6);
            tools::memcopy<16>(buf + 32, &dst.ipv6);

            spooky::hash_short(buf, 32, &h1, &h2);
        }
    }

    return tools::as_sizet(h1);
}

class ip_machine;
struct tcp_stream final : public netkit::pipe
{
    enum flags_bits
    {
        F_SACK = 1,
        F_NOT_NEW = 2, // empty on just created
        F_FIN = 4, // client fin received, no more data expected
        F_ERASED = 8,
    };

    u64 key;
    netkit::ipap src;
    netkit::ipap dst;

    u32 client_seq_ack = 0; // value of client seq was send to client (confirmed)
    u32 client_seq = 0;
    u32 server_seq = 0; // randomgen::get().rnd<u32>();
    u32 windowsize = 0;
    u16 mss = 1500;
    u8  ws = 0;
    tools::flags<1> flags;

    ip_machine* owner = nullptr;

    u8 sockspace[sizeof(size_t) * 3];
    chrono::mils ack_time;

    tools::chunk_buffer<16384> unsent;
    spinlock::syncvar<tools::chunk_buffer<16384>> ready_data; // for recv

    volatile bool established = false;

    tcp_stream(ip_machine* owner, u64 key, const netkit::ipap src, const netkit::ipap dst);
    ~tcp_stream();

    /*virtual*/ void replace(netkit::replace_socket* rsock) override
    {
        delete rsock;
    }

    bool parse_tcp_options(const tcp_header* hdr);
    bool is_new() const { return !flags.is<F_NOT_NEW>(); }
    void not_new() { flags.set<F_NOT_NEW>(); }

    bool process_data_packet(const tcp_header *h, const u8* eop);

    /*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;
    /*virtual*/ signed_t recv(tools::circular_buffer_extdata& data, signed_t required, signed_t timeout DST(, deep_tracer*)) override;
    /*virtual*/ void unrecv(tools::circular_buffer_extdata& data) override;
    /*virtual*/ netkit::system_socket* get_socket() override;
    /*virtual*/ void close(bool flush_before_close) override;
    /*virtual*/ bool alive() override;
    /*virtual*/ str::astr get_info(info i) const override;

};

struct pending_ack
{
    ptr::shared_ptr<tcp_stream> s;
};

template<> struct is_relocatable<pending_ack> { static constexpr bool value = true; };

struct udp_fake_socket : netkit::datagram_socket, ptr::sync_shared_object
{
    ip_machine* owner;
    netkit::ipap tgt;
    udp_fake_socket(ip_machine* owner, const netkit::ipap& tgt) :owner(owner), tgt(tgt) {}
    /*virtual*/ bool sendto(const netkit::ipap& a, const std::span<const u8>& p) const;
    /*virtual*/ void lock();
    /*virtual*/ void unlock();

    bool operator<(const udp_fake_socket& other) const {
        return tgt < other.tgt;
    }
    bool operator==(const udp_fake_socket& other) const {
        return tgt == other.tgt;
    }
};

struct fsptr : public ptr::shared_ptr<udp_fake_socket>
{
    fsptr(udp_fake_socket* fs)
    {
        fs->add_ref();
        _assign(fs);
    }

    bool operator==(const fsptr& other) const {
        return *this->get() == *other.get();
    }

};

template<> struct std::hash<fsptr> {
    size_t operator()(const fsptr& p) const {
        return hash<netkit::ipap>{}(p->tgt);
    }
};

class ip_machine : public udp_dispatcher
{
    friend struct tcp_stream;
    friend struct udp_fake_socket;
    std::thread acker_thread;
    spinlock::syncvar< std::unordered_map< u64, ptr::shared_ptr<tcp_stream> > > streams;
    spinlock::syncvar< std::unordered_set< fsptr > > udfss;
#ifdef _DEBUG
    size_t handler_threadid = 0;
#endif

    tools::sync_fifo_shrinkable<pending_ack> pending_acks;

    std::mutex mtx;
    std::condition_variable cv;

    volatile bool ack_signal = false;
    volatile bool stop_acker = false;

    void acker();
    bool send_simple_packet(tcp_stream& s, u8 tcpflags, u32 custom_ack = 0);
    bool send_synack_packet(tcp_stream& s, bool retransmit);
    tcp_stream& create_tcp_stream(u64 key, const netkit::ipap& srv, const netkit::ipap& to); // it also locks stream
    tcp_stream* lock_stream(u64 key)
    {
        auto r = streams.lock_read();
        auto it = r().find(key);
        if (it == r().end())
            return nullptr;
        it->second->add_ref();
        return it->second;
    }

    void kill_stream(tcp_stream& s, bool force_now);

    bool send(u8* p, size_t sz); // calc checksum and inject

    ///*virtual*/ bool sendto(const netkit::ipap& a, const std::span<const u8>& p) const override;
    /*virtual*/ bool handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& /*p*/, netkit::endpoint& /*ep*/, netkit::pgen& /*pg*/);

public:
    void handle_tcp_packet(const ip4_header* h4, const tcp_header* tcph, size_t sz);
    void handle_udp_packet(const ip4_header* h4, const udp_header* tcph, size_t sz);

protected:
    virtual void on_new_stream(tcp_stream& s) = 0;
    virtual bool inject(const u8 *p, size_t sz) = 0;
    virtual bool allow_tcp(const netkit::ipap& tgt) = 0;
    virtual bool allow_udp(const netkit::ipap& tgt) = 0;

    bool ipm_stream_accept(tcp_stream& s); // can take long time // will wait for ACK
    void ipm_stream_reject(tcp_stream& s);

public:
    ip_machine();
    virtual ~ip_machine();

    void ipm_handle_packet( const u8 *p, size_t sz );

};