#pragma once

class proxy;
class listener;

struct ups_conn_log : public conn_logger
{
    static volatile size_t tag;

    std::span<proxychain_item> proxychain;
    str::astr stag;
    size_t tl = 0;

    str::lazy_cleanup_string entity;
    const netkit::pipe* pipe;
    const netkit::endpoint *addr, *final_addr = nullptr;
    ups_conn_log(str::astr_view entity, netkit::pipe* pipe, netkit::endpoint* addr) :entity(str::clean(entity, ASTR("{}[]`\"\'\\"))), pipe(pipe), addr(addr) {}

    void ps(const str::astr_view& s)
    {
        stag.resize(tl);
        stag.append(s);
    };

    /*virtual*/ void log_connect() const override;
    /*virtual*/ void log_not_connect() const override;
    /*virtual*/ void log_proxy_connect(std::span<proxychain_item> proxychain) override;
    /*virtual*/ void log_proxy_prepare(size_t i) override;
};

class upstream
{
    std::vector<const proxy*> proxychain;
    const proxy* udp_proxy = nullptr;

public:

    const proxy* get_udp_proxy() const { return udp_proxy; }

    bool is_proxychain_empty() const { return proxychain.empty(); }
    bool load(loader& ldr, const asts& bb, std::function<str::astr()> lazycontextinfo);

    void api(json_saver& j) const;
    netkit::pipe_ptr connect(conn_logger& clogger, netkit::endpoint& addr, bool direct); // connect to remote host using proxy

    void iterate_ips( std::function< void (const netkit::ipap &) >) const;

};
