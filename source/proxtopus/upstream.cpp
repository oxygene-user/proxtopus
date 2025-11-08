#include "pch.h"

volatile size_t ups_conn_log::tag = 1;

/*virtual*/ void ups_conn_log::log_connect() const
{
    LOG_N("[$@$] connected to ($)", entity, pipe->get_info(netkit::pipe::I_SUMMARY), addr->desc());
}
/*virtual*/ void ups_conn_log::log_not_connect() const
{
    LOG_N("[$@$] not connected to ($)", entity, pipe->get_info(netkit::pipe::I_SUMMARY), addr->desc());
}
void ups_conn_log::log_proxy_connect(std::span<proxychain_item> pch)
{
    if (!log_enabled())
        return;

    proxychain = pch;
    final_addr = addr;
    addr = &pch[0]->get_addr();

    size_t t = spinlock::atomic_increment(tag);
    stag = ASTR("[");
    str::append_num(stag, t, 0);
    stag.append(ASTR("] "));

    tl = stag.size();

    if (proxychain.size() == 1)
    {
        ps("[$@$] connecting to upstream proxy ($)"); LOG_N(stag.c_str(), entity, pipe->get_info(netkit::pipe::I_SUMMARY), proxychain[0]->desc());
    }
    else
    {
        ps("[$@$] connecting through proxy chain"); LOG_N(stag.c_str(), entity, pipe->get_info(netkit::pipe::I_SUMMARY));
        ps("connecting to proxy ($)"); LOG_N(stag.c_str(), proxychain[0]->desc());
    }

}

/*virtual*/ void ups_conn_log::log_proxy_prepare(size_t i)
{
    ASSERT(tl > 0 && tl <= stag.length() && proxychain.size() > 0);

    if (i >= proxychain.size())
    {
        ps("connecting to address ($)"); LOG_N(stag.c_str(), final_addr->desc());
    }
    else
    {
        ps("connecting to proxy ($)"); LOG_N(stag.c_str(), proxychain[i]->desc());
    }

}


void upstream::iterate_ips(std::function< void(const netkit::ipap&) > itr) const
{
    if (proxychain.size() > 0)
    {
        netkit::endpoint ep = proxychain[0]->get_addr();
        itr(ep.resolve_ip(glb.cfg.ipstack | conf::gip_any));
    }
    if (udp_proxy)
    {
        netkit::endpoint ep = udp_proxy->get_addr();
        itr(ep.resolve_ip(glb.cfg.ipstack | conf::gip_any));
    }
}

void upstream::api(json_saver& j) const
{
    if (proxychain.size() > 0)
    {
        j.arr(ASTR("proxychain"));
        for (const proxy* p : proxychain)
            j.num(p->get_id());
        j.arrclose();
    }
    if (udp_proxy)
        j.field(ASTR("udp-proxy"), udp_proxy->get_id());
}

bool upstream::load(loader& ldr, const asts& bb, std::function<str::astr()> lazycontextinfo)
{
    const proxy* p = nullptr;
    str::astr_view pch = str::view(bb.get_string(ASTR("udp-proxy"), glb.emptys));
    if (!pch.empty())
    {
        p = ldr.find_proxy(pch);
        if (p == nullptr)
        {
        per:
            LOG_FATAL("unknown {proxy} [$] ($)", pch, lazycontextinfo());
            ldr.exit_code = EXIT_FAIL_PROXY_NOTFOUND;
            return false;
        }

        if (!p->support(netkit::ST_UDP))
        {
            ldr.exit_code = EXIT_FAIL_SOCKET_TYPE;
            LOG_FATAL("upstream {proxy} [$] does not support UDP protocol ($)", pch, lazycontextinfo());
            return false;
        }

        udp_proxy = p;
    }

    pch = str::view(bb.get_string(ASTR("proxychain"), glb.emptys));
    if (!pch.empty())
    {
        enum_tokens_a(tkn, pch, ',')
        {
            p = ldr.find_proxy(*tkn);
            if (p == nullptr)
            {
                pch = *tkn;
                goto per;
            }
            proxychain.push_back(p);
        }
    }
    return true;
}

netkit::pipe_ptr upstream::connect(conn_logger &clogger, netkit::endpoint& addr, bool direct)
{
    if (direct || proxychain.size() == 0)
    {
        if (netkit::pipe* pipe = conn::connect(addr, nullptr))
        {
            if (proxychain.size() == 0)
                clogger.log_connect();

            netkit::pipe_ptr pp(pipe);
            return pp;
        }

        if (proxychain.size() == 0)
            clogger.log_not_connect();

        return netkit::pipe_ptr();
    }

    netkit::endpoint prx_ep;
    auto get_proxy_addr = [&](size_t i) -> netkit::endpoint&
    {
        prx_ep = proxychain[i]->get_addr();
        return prx_ep;
    };

    clogger.log_proxy_connect(proxychain);

    netkit::pipe_ptr pp = connect(clogger, get_proxy_addr(0), true);

    for (size_t i = 0; pp != nullptr && i < proxychain.size(); ++i)
    {
        clogger.log_proxy_prepare(i + 1);

        bool finala = i + 1 >= proxychain.size();
        netkit::endpoint& na = finala ? addr : get_proxy_addr(i + 1);
        
        pp = proxychain[i]->prepare(pp, na);
    }

    return pp;
}
