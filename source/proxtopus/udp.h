#pragma once


// udp packet-to-send buffer item
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
        return ((u8*)(this + 1));
    }
    const u8* data() const
    {
        return ((const u8*)(this + 1));
    }

    static u16 pre()
    {
        return tools::as_word(sizeof(send_data) - plain_tail_start());
    }

    static send_data* build(std::span<const u8> data, const netkit::endpoint& tgt)
    {
        if (send_data* sd = (send_data*)MA(sizeof(send_data) + data.size()))
        {
            new (sd) send_data(tgt, data.size());
            memcpy(sd->data(), data.data(), data.size());
            return sd;
        }
        return nullptr;
    }

private:
    send_data(const netkit::endpoint& tgt, signed_t datasz) :tgt(tgt), datasz(datasz) {} // do not allow direct creation

};

struct mfrees
{
    void operator()(send_data* p)
    {
        p->~send_data();
        ma::mf(p);
    }
};

using sdptr = std::unique_ptr<send_data, mfrees>;

class udp_dispatcher;

class udp_processing_thread : public netkit::udp_pipe, public ptr::sync_shared_object
{
    udp_dispatcher* h = nullptr;
    netkit::thread_storage ts; // for udp connection to 2nd peer
    netkit::thread_storage handler_state; // internal per-thread handler's state
    netkit::ipap froma;
    chrono::mils cutoff_time;
    tools::sync_fifo_shrinkable<sdptr> sendb;
    netkit::udp_pipe* sendor = nullptr;

public:

    udp_processing_thread(udp_dispatcher* h, netkit::thread_storage&& hs, const netkit::ipap& froma) :h(h), handler_state(std::move(hs)), froma(froma)
    {
        spinlock::atomic_increment(glb.numudp);
        update_cutoff_time();
    }
    ~udp_processing_thread()
    {
        spinlock::atomic_decrement(glb.numudp);
    }

    const netkit::ipap& from() const
    {
        return froma;
    }

    netkit::thread_storage* geths()
    {
        return &handler_state;
    }

    void update_cutoff_time();
    void close();

    void convey(netkit::pgen& p, const netkit::endpoint& tgt);

    /*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg) override;
    /*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size) override;

    bool is_timeout(chrono::mils curtime) const
    {
        return !cutoff_time.is_empty() && curtime >= cutoff_time;
    }

    void udp_bridge(netkit::datagram_socket* initiator);

};

class udp_dispatcher
{
    friend class udp_processing_thread;

#ifdef _DEBUG
    size_t check_tid = 0;
#endif // _DEBUG

    std::unordered_map<netkit::ipap, ptr::shared_ptr<udp_processing_thread>> udp_pth; // only lstnr thread can modify this map
    spinlock::syncvar<std::vector<netkit::ipap>> finished; // keys of finished threads

protected:

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

public:

#ifdef _DEBUG
    void init_tid()
    {
        if (check_tid == 0)
            check_tid = spinlock::current_thread_uid();
    }
#endif // _DEBUG


    void stop();

    void release_udps(); // must be called from listener thread
    void release_udp(udp_processing_thread* udp_wt);
    void udp_worker(netkit::datagram_socket* lstnr, udp_processing_thread* udp_wt);

    void udp_dispatch(netkit::datagram_socket& lstnr, netkit::udp_packet& p);

    virtual const proxy* udp_proxy() const = 0;
    virtual signed_t udp_timeout() const // ms
    {
        return 10000;
    }
    virtual void log_new_udp_thread(const netkit::ipap& /*from*/, const netkit::endpoint& /*to*/) {}

};
