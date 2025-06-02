#include "pch.h"


#ifdef _WIN32
#pragma warning (push)
#pragma warning (disable:5033) // 'register' is no longer a supported storage class
#pragma warning (disable:4100) // unreferenced formal parameter
#pragma warning (disable:4244) // possible loss of data
#pragma warning (disable:4267) // possible loss of data
#pragma warning (disable:4702) // unreachable code

#define not notnot
#define and andand


#define module glb.module

#define TlsGetValue(x) glb.icpt.event
#define TlsSetValue(x,y) glb.icpt.event = y;

extern "C" {
#include "windivert/windivert.c"
}

#undef not
#undef and
#undef TlsGetValue
#undef TlsSetValue

#pragma warning (pop)
#endif

icpt_rule::icpt_rule(engine *eng, const str::astr& name,  const str::astr& s):name(name)
{
    enum_tokens_a(tkn, s, '/')
    {
        auto dv = tkn->find(':');
        if (dv == tkn->npos)
            continue;

        if (ASTR("proc") == tkn->substr(0,dv))
        {
            proc = tkn->substr(dv + 1);
            if (proc == ASTR("*"))
                proc.clear();
        } else if (ASTR("proto") == tkn->substr(0, dv))
        {
            if (ASTR("udp") == tkn->substr(dv + 1))
                proto = proto_udp;
            else if (ASTR("tcp") == tkn->substr(dv + 1))
                proto = proto_tcp;
            else
                proto = proto_any;
        } else if (ASTR("proxy") == tkn->substr(0, dv))
        {
            prx = eng->find_proxy(tkn->substr(dv + 1));
            if (prx == nullptr)
            {
                LOG_FATAL("unknown {proxy} [$] for icpt-rule [$]", tkn->substr(dv + 1), str::clean(name));
                eng->exit_code = EXIT_FAIL_PROXY_NOTFOUND;
                return;
            }

        } else if (ASTR("act") == tkn->substr(0, dv))
        {
            if (ASTR("allow") == tkn->substr(dv + 1))
                act = act_allow;
            else if (ASTR("deny") == tkn->substr(dv + 1))
                act = act_deny;
        }

    }

    if (prx)
    {
        if (proto == proto_any || proto == proto_udp)
        {
            if (!prx->support(netkit::ST_UDP))
            {
                eng->exit_code = EXIT_FAIL_SOCKET_TYPE;
                LOG_FATAL("upstream {proxy} [$] does not support UDP protocol (icpt-rule: [$])", prx->get_name(), str::clean(name));
                return;
            }
        }
        if (proto == proto_any || proto == proto_tcp)
        {
            if (!prx->support(netkit::ST_TCP))
            {
                eng->exit_code = EXIT_FAIL_SOCKET_TYPE;
                LOG_FATAL("upstream {proxy} [$] does not support TCP protocol (icpt-rule: [$])", prx->get_name(), str::clean(name));
                return;
            }
        }

    }

}

#ifdef _WIN32
bool interceptor::hand_pair::open()
{
    close();

    network = WinDivertOpen("outbound && udp", WINDIVERT_LAYER_NETWORK, 1001, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (network == INVALID_HANDLE_VALUE)
    {
        network = nullptr;
        return false;
    }
    flow = WinDivertOpen("outbound && udp", WINDIVERT_LAYER_FLOW, 1002, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (flow == INVALID_HANDLE_VALUE)
    {
        WinDivertClose(network);
        network = nullptr;
        flow = nullptr;
        return false;
    }

    std::thread th1(&hand_pair::nthread, this);
    th1.detach();

    std::thread th2(&hand_pair::fthread, this);
    th2.detach();

    return true;
}
void interceptor::hand_pair::close()
{
    if (network)
    {
        stop = true;
        while (!stoped1 || !stoped2)
            spinlock::sleep(100);

        WinDivertShutdown(network, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertShutdown(flow, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(network);
        WinDivertClose(flow);
        network = nullptr;
        flow = nullptr;
        stop = false;
        stoped1 = false;
        stoped2 = false;
    }

    for (flow_desc * fd = flows; fd;)
    {
        flow_desc* n = fd->next;
        delete fd;
        fd = n;
    }
}

void interceptor::hand_pair::nthread()
{
    u8 packet[WINDIVERT_MTU_MAX];
    UINT packet_len;

    WINDIVERT_PACKET info;
    WINDIVERT_ADDRESS addr;

    auto cmpa = [&](const netkit::ipap& a)
        {
            [[unlikely]] if (info.IPv6Header)
                return a.copmpare_a((const u8*)&info.IPv6Header->SrcAddr, 16);
            return a.copmpare_a((const u8*)&info.IPHeader->SrcAddr, 4);
        };

    for (;!stop && !glb.is_stop();)
    {
        if (!WinDivertRecv(network, packet, sizeof(packet), &packet_len, &addr))
            continue;

        if (!WinDivertHelperParsePacketEx(packet, packet_len, &info))
            continue;
        if (info.Truncated)
            continue;

        u32 pid = 0;
        if (info.UDPHeader)
        {
            loop_again:
            for (flow_desc* fd = flows; fd; fd = fd->next)
            {
                if (fd->processid == 0)
                    goto loop_again; // race

                if (fd->src.port == info.UDPHeader->SrcPort && cmpa(fd->src))
                {
                    pid = fd->processid;
                    if (pid == 0)
                        goto loop_again; // race
                    break;
                }
            }

            LOG_I("src $ : $", info.UDPHeader->SrcPort, pid);
        }


    }

    stoped1 = true;
}
void interceptor::hand_pair::fthread()
{
    WINDIVERT_ADDRESS addr;
    for (; !stop && !glb.is_stop();)
    {
        if (!WinDivertRecv(flow, nullptr, 0, nullptr, &addr))
            continue;

        bool add = false;
        switch (addr.Event)
        {
        case WINDIVERT_EVENT_FLOW_ESTABLISHED:

            for (flow_desc *fd = flows; fd; fd = fd->next)
            {
                if (fd->src.port == addr.Flow.LocalPort && fd->src.copmpare_a((const u8*)&addr.Flow.LocalAddr, addr.IPv6 ? 16 : 4))
                {
                    fd->processid = addr.Flow.ProcessId;
                    add = true;
                    break;
                }
            }
            if (!add)
            {
                flow_desc* nfd = get_flow_desc(addr.Flow.ProcessId);
                netkit::ipap::build(&nfd->src, (const u8*)&addr.Flow.LocalAddr, addr.IPv6 ? 16 : 4, addr.Flow.LocalPort);
                nfd->next = flows;
                flows = nfd;
            }
            break;

        case WINDIVERT_EVENT_FLOW_DELETED:
            for (flow_desc *fd = flows, *pfd = nullptr; fd; fd = fd->next)
            {
                if (fd->processid == addr.Flow.ProcessId && fd->src.port == addr.Flow.LocalPort && fd->src.copmpare_a((const u8*)&addr.Flow.LocalAddr, addr.IPv6 ? 16 : 4))
                {
                    fd->processid = 0;

                    if (pfd)
                        pfd->next = fd->next;
                    else
                        flows = fd->next;
                    fd->next = nullptr;
                    sump.emplace_back(fd); // due multithread access to queue, it is forbidden to delete fd now, so put it to sump
                    break;
                }
                pfd = fd;
            }
        }


    }

    stoped2 = true;
}



#endif // _WIN32

interceptor::~interceptor()
{
#ifdef _WIN32
    udp.close();
    if (event)
    {
        CloseHandle(event);
        event = nullptr;
    }
#endif // _WIN32
}

bool interceptor::load(engine* e, const asts* s)
{
    for (auto it = s->begin(); it; ++it)
    {
        rules.emplace_back(e, it.name(), it->as_string());
        if (e->exit_code != 0)
            return false;
    }

    if (!rules.empty())
    {
#ifdef _WIN32

        if (!udp.open())
        {
            HRESULT err = GetLastError();
            LOG_FATAL("packet interception driver load error: $", (u32)err);
            e->exit_code = EXIT_FAIL_ICPT_INIT_ERROR;
            return false;
        }


        return true;
#endif
#ifdef _NIX
        LOG_FATAL("packet interception not yet supported in current system");
        e->exit_code = EXIT_FAIL_ICPT_NOT_SUPPORTED;
#endif
    }

    return false;
}