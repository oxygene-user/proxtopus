#pragma once

#define MAXIMUM_SLOTS 30 // only 30 due each slot - two sockets, but maximum sockets per thread are 64

class listener;

#ifdef LOG_TRAFFIC
class traffic_logger
{
    signed_t id;
    HANDLE f21 = nullptr;
    HANDLE f12 = nullptr;
    str::astr fn;

    traffic_logger(traffic_logger&) = delete;
    traffic_logger& operator=(traffic_logger&) = delete;
    void prepare();
public:
    traffic_logger();
    ~traffic_logger();
    traffic_logger& operator=(traffic_logger&&);
    void clear();
    void log12(u8* data, signed_t sz);
    void log21(u8* data, signed_t sz);
};
#endif


class apiobj
{
    friend class engine;
    signed_t id = 0;
public:
    signed_t get_id() const { return id; }
    virtual ~apiobj() {}
    virtual void api(json_saver& j) const
    {
        if (id != 0)
            j.field(ASTR("id"), id);
    }
};

class handler : public apiobj
{
    friend class listener;
    friend class engine;
protected:

    struct send_data
    {
        netkit::endpoint tgt;
        signed_t datasz;

        static consteval signed_t plain_tail_start() // get size of plain tail of this structure
        {
            return netkit::endpoint::plain_tail_start(); /* + offsetof(send_data, tgt) */
        }

        u8* data()
        {
            return ((u8 *)(this+1));
        }
        const u8* data() const
        {
            return ((const u8*)(this+1));
        }

        static u16 pre()
        {
            return tools::as_word(sizeof(send_data) - plain_tail_start());
        }

        static send_data* build(std::span<const u8> data, const netkit::endpoint& tgt)
        {
            if (send_data* sd = (send_data*)malloc(sizeof(send_data) + data.size()))
            {
                new (sd) send_data(tgt, data.size());
                memcpy(sd->data(), data.data(), data.size());
                return sd;
            }
            return nullptr;
        }

    private:
        send_data(const netkit::endpoint &tgt, signed_t datasz):tgt(tgt), datasz(datasz) {} // do not allow direct creation

    };

    struct mfrees
    {
        void operator()(send_data* p)
        {
            p->~send_data();
            free(p);
        }
    };

    using sdptr = std::unique_ptr<send_data, mfrees>;

    class udp_processing_thread : public netkit::udp_pipe, public ptr::sync_shared_object
    {
        handler* h = nullptr;
        netkit::thread_storage ts; // for udp connection to 2nd peer
        netkit::thread_storage handler_state; // internal per-thread handler's state
        netkit::ipap hashkey;
        signed_t cutoff_time = 0;
        spinlock::syncvar<tools::fifo<sdptr>> sendb;
        netkit::udp_pipe *sendor = nullptr;

    public:

        udp_processing_thread(handler *h, netkit::thread_storage &&hs, const netkit::ipap & k):h(h), handler_state(std::move(hs)), hashkey(k)
        {
            spinlock::atomic_increment(glb.numudp);
            update_cutoff_time();
        }
        ~udp_processing_thread()
        {
            spinlock::atomic_decrement(glb.numudp);
        }

        const netkit::ipap& key() const
        {
            return hashkey;
        }

        netkit::thread_storage* geths()
        {
            return &handler_state;
        }

        void update_cutoff_time()
        {
            auto to = h->udp_timeout();
            cutoff_time = to == 0 ? 0 : chrono::ms() + to;
        }
        void close();

        void convey(netkit::pgen &p, const netkit::endpoint& tgt);

        /*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg) override;
        /*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size) override;

        bool is_timeout( signed_t curtime ) const
        {
            return cutoff_time != 0 && curtime >= cutoff_time;
        }

        void udp_bridge(SOCKET initiator);

    };

    std::unordered_map<netkit::ipap, ptr::shared_ptr<udp_processing_thread>> udp_pth; // only accept thread can modify this map
    spinlock::syncvar<std::vector<netkit::ipap>> finished; // keys of finished threads

    listener* owner;
    std::vector<const proxy*> proxychain;
    const proxy* udp_proxy = nullptr;

    void release_udps(); // must be called from listener thread
    void release_udp(udp_processing_thread *udp_wt);
    void udp_worker(netkit::socket* lstnr, udp_processing_thread* udp_wt);

    /*
    *
    *   handle udp request: initiator -> handler -> remote
    *
    *   p (in/modif) - packet from initiator, can be modified
    *   ep (out) - address of remote
    *   pg (out) - packet to send to remote (refs to p.packet)
    *
    */
    virtual bool handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& /*p*/, netkit::endpoint& /*ep*/, netkit::pgen& /*pg*/)
    {
        return false;
    }

    /*
    *
    *   handle udp answer: initiator <- handler <- remote
    *
    *   ctx (in) - context of handler per thread (created in handle_packet)
    *   from (in) - packet source
    *   pg (in/out) - packet, received from remote; modified (or not modified) one will be send to initiator
    *
    *   return false to stop bridging of current udp stream
    */
    virtual bool encode_packet(netkit::thread_storage& /*ctx*/, const netkit::ipap& /*from*/, netkit::pgen& /*pg*/)
    {
        return true;
    }

    virtual signed_t udp_timeout() const // ms
    {
        return 10000;
    }
    virtual void log_new_udp_thread(const netkit::ipap& /*from*/, const netkit::endpoint& /*to*/) {}


public:
    handler(loader& ldr, listener* owner, const asts& bb);
    handler() {}
    virtual ~handler() { stop(); }

    void stop();
    netkit::pipe_ptr connect(str::astr_view loginfo, netkit::endpoint& addr, bool direct); // connect to remote host using current handler's proxy settings

    using mbresult = std::function< void(bool connection_established) >;
    void make_bridge(tools::circular_buffer_extdata &rcvd, const str::astr& epa, netkit::pipe* clientpipe, mbresult res);

    /*virtual*/ void api(json_saver&) const override;

    virtual str::astr_view desc() const = 0;
    virtual bool compatible(netkit::socket_type_e /*st*/) const
    {
        return false;
    }

    virtual void handle_pipe(netkit::pipe* pipe)  // will be called in new thread, so can work as long as need
    {
        // this func is owner of pipe now
        // delete it
        // (override this to handle pipe)
        delete pipe;
    }

    void udp_dispatch(netkit::socket&, netkit::udp_packet&);
    virtual void on_listen_port(signed_t /*port*/) {} // callback on listen port

    static handler* new_handler(loader& ldr, listener *owner, const asts& bb, netkit::socket_type_e st);
};


class handler_direct : public handler // just port mapper
{
    str::astr to_addr; // in format like: tcp://domain_or_ip:port
    netkit::endpoint ep; // only accessed from listener thread

    signed_t udp_timeout_ms = 10000;

protected:
    /*virtual*/ bool handle_packet(netkit::thread_storage& ctx, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg) override;
    /*virtual*/ signed_t udp_timeout() const override
    {
        return udp_timeout_ms;
    }
    /*virtual*/ void log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to) override;


public:
    handler_direct( loader &ldr, listener* owner, const asts& bb, netkit::socket_type_e st );
    virtual ~handler_direct() { stop(); }

    /*virtual*/ str::astr_view desc() const { return ASTR("direct"); }
    /*virtual*/ bool compatible(netkit::socket_type_e /*st*/) const
    {
        return true; // compatible with both tcp and udp
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

class handler_socks : public handler // socks4 and socks5
{
    enum rslt
    {
        EC_GRANTED,
        EC_FAILED,
        EC_REMOTE_HOST_UNRCH,
    };

    str::astr userid; // for socks4
    str::astr login, pass; // for socks5
    netkit::ipap udp_bind;

    bool socks5_allow_anon = false;

    bool allow_4 = true;
    bool allow_5 = true;
    bool allow_udp_assoc = true;
    bool allow_private = false;

    void handshake4(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe);
    void handshake5(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe);

    using sendanswer = std::function< void(netkit::pipe* pipe, rslt ecode) >;

    void worker(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe, netkit::endpoint& inf, sendanswer answ);

public:
    handler_socks(loader& ldr, listener* owner, const asts& bb, const str::astr_view &st);
    virtual ~handler_socks() { stop(); }

    /*virtual*/ str::astr_view desc() const { return ASTR("socks"); }
    /*virtual*/ bool compatible(netkit::socket_type_e st) const
    {
        return st == netkit::ST_TCP;
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

#include "handler_ss.h"
#include "handler_http.h"
#ifdef _DEBUG
#include "debug/handler_dbg.h"
#endif // _DEBUG
