#pragma once

#include "udp.h"

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



class handler : public udp_dispatcher, apiobj
{
    friend class listener;
    friend class engine;

protected:

    upstream ups;
    listener* owner;

public:
    handler(loader& ldr, listener* owner, const asts& bb);
    handler() {}
    virtual ~handler() { stop(); }

    void stop();

    using mbresult = std::function< void(bool connection_established) >;
    void make_bridge(tools::circular_buffer_extdata &rcvd, const str::astr& epa, netkit::pipe* clientpipe, mbresult res);

    /*virtual*/ void api(json_saver&) const override;
    /*virtual*/ const proxy* udp_proxy() const override
    {
        return ups.get_udp_proxy();
    }

    virtual str::astr_view desc() const = 0;
    virtual bool compatible(netkit::socket_type_e /*st*/) const
    {
        return false;
    }

    virtual void handle_pipe(netkit::pipe* /*pipe*/)  // will be called in new thread, so can work as long as need !!!! handle_pipe will release pipe !!!!
    {
    }

    virtual void on_listen_port(size_t /*port*/) {} // callback on listen port
    static handler* new_handler(loader& ldr, listener *owner, const asts& bb, netkit::socket_type_e st);
};


class handler_direct final : public handler // just port mapper
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

    /*virtual*/ str::astr_view desc() const override { return ASTR("direct"); }
    /*virtual*/ bool compatible(netkit::socket_type_e /*st*/) const override
    {
        return true; // compatible with both tcp and udp
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

class handler_socks final : public handler // socks4 and socks5
{
    struct obfs_data : public expression
    {
        u8 masterkey[sha256::output_bytes];
        tools::bloom_filter_set<8192, 5> flt;
    };

    struct auth_data : public expression
    {
        str::astr userid; // for socks4
        str::astr login, pass; // for socks5
    };

    std::unique_ptr<obfs_data> obfsdata;
    std::unique_ptr<auth_data> authdata;
    std::unique_ptr<expression> defexpr;

    netkit::ipap udp_bind;

    tools::flags<1> flags = f_allow_4|f_allow_5|f_allow_udp_assoc;

    enum
    {
        f_socks5_allow_anon = 4,
        f_allow_4 = 8,
        f_allow_5 = 16,
        f_allow_udp_assoc = 32,
    };


    void handshake4(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe);
    void handshake5(tools::circular_buffer_extdata& rcvd, netkit::pipe* pipe);

public:
    handler_socks(loader& ldr, listener* owner, const asts& bb, const str::astr_view &st);
    virtual ~handler_socks() { stop(); }

    /*virtual*/ str::astr_view desc() const override { return ASTR("socks"); }
    /*virtual*/ bool compatible(netkit::socket_type_e st) const override
    {
        return st == netkit::ST_TCP;
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

class handler_dummy final : public handler
{
    bool echo = false;
public:
    handler_dummy(loader& ldr, listener* owner, const asts& bb);
    virtual ~handler_dummy() { stop(); }

    /*virtual*/ str::astr_view desc() const override { return ASTR("dummy"); }
    /*virtual*/ bool compatible(netkit::socket_type_e st) const override
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
