#pragma once

#include "handlers.h"
#include "transport.h"

#define RECV_BRIDGE_MODE_TIMEOUT 60000 // 1 min
#define RECV_PREPARE_MODE_TIMEOUT 5000 // 1 sec

class loader;
class proxy;
class listener;
using lcoll = api_collection_uptr<listener>;

class listener : public apiobj
{
protected:
    str::astr name;
    std::unique_ptr<handler> hand;
public:

    listener(loader& /*ldr*/, const str::astr& name, const asts& /*bb*/) :name(name) {}
    listener(handler* h) { hand.reset(h); h->owner = this; }
    virtual ~listener() {}

    const str::astr& get_name() const
    {
        return name;
    }

    /*virtual*/ void api(json_saver &) const override;

    virtual void open() = 0;
    virtual void stop() = 0;
    virtual void close() = 0;

    static void build(lcoll &arr, loader& ldr, const str::astr& name, const asts& bb);
};

class socket_listener : public listener
{
    enum state_stage : size_t
    {
        IDLE,
        ACCEPTOR_START,
        ACCEPTOR_WORKS,
    };


protected:
    volatile state_stage stage = IDLE;
    netkit::ipap bind;
    void acceptor();
    virtual void accept_impl() = 0;
    NIXONLY(virtual void kick_socket()=0);
public:

    socket_listener(loader& ldr, const str::astr& name, const asts& bb, netkit::socket_type_e st);
    socket_listener(const netkit::ipap &bind, handler *h);
    /*virtual*/ ~socket_listener() {}

    /*virtual*/ void api(json_saver&) const override;

    /*virtual*/ void open() override;
    /*virtual*/ void stop() override;

};


class tcp_listener final : public socket_listener
{
    netkit::SYSTEM_STREAM_ACCEPTOR_SOCKET sock;

protected:
    /*virtual*/ void accept_impl() override;
    NIXONLY(virtual void kick_socket() override);

public:

    tcp_listener(loader& ldr, const str::astr& name, const asts& bb);
    /*virtual*/ ~tcp_listener() {}

    /*virtual*/ void api(json_saver&) const override;

    /*virtual*/ void close() override
    {
        sock.close();
    }
};


class udp_listener final : public socket_listener
{
    netkit::SYSTEM_DATAGRAM_SOCKET sock;

protected:
    /*virtual*/ void accept_impl() override;
    NIXONLY(virtual void kick_socket() override);
public:

    udp_listener(loader& ldr, const str::astr& name, const asts& bb);
    udp_listener(const netkit::ipap& bind, handler* h);
    /*virtual*/ ~udp_listener() {}

    /*virtual*/ void api(json_saver&) const override;

    /*virtual*/ void close() override
    {
        sock.close();
    }

};
