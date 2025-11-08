#pragma once

#if FEATURE_ADAPTER

class proxy;
class engine;

#if 0
class icpt_rule
{
    enum act_e : u8
    {
        act_allow,
        act_deny,
    };
    enum proto_e : u8
    {
        proto_any,
        proto_tcp,
        proto_udp,
    };


    str::astr name, proc;
    const proxy* prx = nullptr;
    proto_e proto = proto_any;
    act_e act = act_allow;
public:
    explicit icpt_rule(engine* eng, const str::astr& name, const str::astr& s);
};
#endif

struct common_adapter_data
{
    u8 data[128];
};

class adapter : public ip_machine, public apiobj
{
protected:
    str::astr name;
    upstream ups;
    netkit::ipap ipaddr;
    std::vector<netkit::ipap> upsips; // upstream ip addrs (add them to route as direct)

    /*virtual*/ void on_new_stream(tcp_stream& s) override;
    /*virtual*/ const proxy* udp_proxy() const override
    {
        return ups.get_udp_proxy();
    }

    /*virtual*/ bool allow_tcp(const netkit::ipap& tgt) override
    {
        return !tgt.is_multicast() && !tgt.match(ipaddr);
    }
    /*virtual*/ bool allow_udp(const netkit::ipap& tgt) override
    {
        return allow_tcp(tgt);
    }

public:
    adapter(const str::astr_view& name) :name(name) {}
    virtual ~adapter() {}

    virtual void close() = 0;
    virtual bool load(common_adapter_data& d, loader& ldr, const asts* s);

    const str::astr &desc() const
    {
        return name;
    }

    
    void handle_pipe( netkit::pipe *p ); // called from acceptor's thread and can take long time
};

class adapters : public api_collection_uptr<adapter>
{
    common_adapter_data cad;

public:
    adapters();
    ~adapters()
    {
        close();
    }

    void close();
    bool load(loader& ldr);
};


#ifdef _WIN32
#include <iphlpapi.h>
class wintun_adapter : public adapter
{
    common_adapter_data* cad = nullptr;
    HANDLE adpt_handler = nullptr;
    HANDLE adpt_session = nullptr;
    volatile HANDLE newsb = nullptr;

    tools::sync_fifo_shrinkable<u8*> sendbufs;
    //std::vector<MIB_IPFORWARDROW> routes;

    void receiver();
    void sender();

protected:
    /*virtual*/ bool inject(const u8* p, size_t sz) override;

public:

    wintun_adapter(const str::astr_view& name) :adapter(name) {}
    /*virtual*/ ~wintun_adapter();

    /*virtual*/ void close();
    /*virtual*/ bool load(common_adapter_data &d, loader& ldr, const asts* s);

};
#else
class nix_adapter : public adapter
{
protected:
    /*virtual*/ bool inject(const u8* p, size_t sz) override { return false; }

public:

    nix_adapter(const str::astr_view& name) :adapter(name) {}
    /*virtual*/ ~nix_adapter() {}

    /*virtual*/ void close() override {}
    /*virtual*/ bool load(common_adapter_data& d, loader& ldr, const asts* s) override { return false; }

};
#endif

#endif