#include "pch.h"
#if FEATURE_ADAPTER
#ifdef _WIN32
#include "../wintun/wintun.h"

#include <ws2ipdef.h>
#include <objbase.h>

#pragma comment(lib, "iphlpapi.lib")

#pragma warning (push)
#pragma warning (disable:5033) // 'register' is no longer a supported storage class
#pragma warning (disable:4100) // unreferenced formal parameter
#pragma warning (disable:4244) // possible loss of data
#pragma warning (disable:4267) // possible loss of data
#pragma warning (disable:4702) // unreachable code


#define module glb.module

#pragma warning (pop)
#endif

bool adapter::load(common_adapter_data&, loader& ldr, const asts* s)
{
    auto lazyinfo = [this]() -> str::astr
    {
        str::astr s(ASTR("adapter: ["));
        str::clean(name).append_to(s);
        s.push_back(']');
        return s;
    };

    if (!ups.load(ldr, *s, lazyinfo))
        return false;

    if (ups.is_proxychain_empty())
    {
        LOG_FATAL("upstream proxy not defined for adapter $", str::clean(name));
        return false;
    }

    ups.iterate_ips([this](const netkit::ipap& ip) {
        for (const auto& ipp : upsips)
            if (ipp.copmpare_a(ip))
                return;
        auto &nip = upsips.emplace_back(ip);
        nip.set_prefix(32);
    });

    return true;
}

#if 0
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

#endif



#ifdef _WIN32

#ifdef _DEBUG
static void reg_del_key(const str::wstr_view& regpath_)
{
    HKEY okey = HKEY_CURRENT_USER;
    str::wstr_view regpath = regpath_;
    str::wstr kn;
    if (regpath.length() > 5)
    {
        size_t ls = regpath.find_last_of('\\');
        if (regpath.starts_with(WSTR("HKCR\\"))) { okey = HKEY_CLASSES_ROOT; regpath = regpath_.substr(5, ls-5); }
        else if (regpath.starts_with(WSTR("HKCU\\"))) { okey = HKEY_CURRENT_USER; regpath = regpath_.substr(5, ls-5); }
        else if (regpath.starts_with(WSTR("HKLM\\"))) { okey = HKEY_LOCAL_MACHINE; regpath = regpath_.substr(5, ls-5); }
        kn = regpath_.substr(ls + 1);
    }

    HKEY k;
    if (RegOpenKeyExW(okey, str::wstr(regpath).c_str(), 0, KEY_ALL_ACCESS, &k) != ERROR_SUCCESS)
        return;

    RegDeleteTreeW(k, kn.c_str());
    RegCloseKey(k);

}
#endif

static str::wstr reg_read_string(const str::wstr_view& regpath_, const str::wstr_view& valname)
{
    HKEY okey = HKEY_CURRENT_USER;

    str::wstr_view regpath = regpath_;

    if (regpath.length() > 5)
    {
        if (regpath.starts_with(WSTR("HKCR\\"))) { okey = HKEY_CLASSES_ROOT; regpath = regpath_.substr(5); }
        else if (regpath.starts_with(WSTR("HKCU\\"))) { okey = HKEY_CURRENT_USER; regpath = regpath_.substr(5); }
        else if (regpath.starts_with(WSTR("HKLM\\"))) { okey = HKEY_LOCAL_MACHINE; regpath = regpath_.substr(5); }
    }

    HKEY k;
    if (RegOpenKeyExW(okey, str::wstr(regpath).c_str(), 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return str::wstr();

    DWORD len = 1024;
    wchar buf[1024];
    int rz = RegQueryValueExW(k, str::wstr(valname).c_str(), nullptr, nullptr, (LPBYTE)buf, &len);
    RegCloseKey(k);
    if (rz != ERROR_SUCCESS)
        return str::wstr();

    len /= 2;
    if (len == 0)
        return str::wstr();

    if (buf[len - 1] == 0)
        --len;

    return str::wstr(str::wstr_view(buf, len));
}

static void reg_set_string(const str::wstr_view& regpath_, const str::wstr_view& valname, const str::wstr_view& calcontent)
{
    HKEY okey = HKEY_CURRENT_USER;

    str::wstr_view regpath = regpath_;

    if (regpath.length() > 5)
    {
        if (regpath.starts_with(WSTR("HKCR\\"))) { okey = HKEY_CLASSES_ROOT; regpath = regpath_.substr(5); }
        else if (regpath.starts_with(WSTR("HKCU\\"))) { okey = HKEY_CURRENT_USER; regpath = regpath_.substr(5); }
        else if (regpath.starts_with(WSTR("HKLM\\"))) { okey = HKEY_LOCAL_MACHINE; regpath = regpath_.substr(5); }
    }

    HKEY k;
    if (RegCreateKeyExW(okey, str::wstr(regpath).c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &k, nullptr) != ERROR_SUCCESS)
        return;

    RegSetValueEx(k, str::wstr(valname).c_str(), 0, REG_SZ, (const u8 *)str::wstr(calcontent).c_str(), tools::as_dword(calcontent.length() * sizeof(wchar) + 1));
    RegCloseKey(k);
}

template< typename ENM > static void enum_reg_keys(const str::wstr_view& regpath_, ENM e)
{
    HKEY okey = HKEY_CURRENT_USER;

    str::wstr_view regpath = regpath_;

    if (regpath.length() > 5)
    {
        if (regpath.starts_with(WSTR("HKCR\\"))) { okey = HKEY_CLASSES_ROOT; regpath = regpath_.substr(5); }
        else if (regpath.starts_with(WSTR("HKCU\\"))) { okey = HKEY_CURRENT_USER; regpath = regpath_.substr(5); }
        else if (regpath.starts_with(WSTR("HKLM\\"))) { okey = HKEY_LOCAL_MACHINE; regpath = regpath_.substr(5); }
    }

    HKEY k;
    if (RegOpenKeyExW(okey, str::wstr(regpath).c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &k) != ERROR_SUCCESS) return;

    DWORD len = 1024;
    wchar buf[1024];
    for (int index = 0; ERROR_SUCCESS == RegEnumKeyExW(k, index, buf, &len, nullptr, nullptr, nullptr, nullptr); ++index, len = 1024)
    {
        if (e(str::wstr_view(buf, len)))
            break;
    }

    RegCloseKey(k);
}


static void CALLBACK wintun_logger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 /*Timestamp*/, _In_z_ const WCHAR* LogLine)
{
    str::wstr s(LogLine);
    s[0] = (wchar)std::tolower(s[0]);
    str::astr ss = str::to_str(s);

    for (signed_t x = ss.length()-1, y = -1; x >= 0; --x)
    {
        if (y < 0)
        {
            if ((u8)ss[x] > 127)
                y = x;
            continue;
        }
        if (ss[x] == ' ' || (u8)ss[x] > 127)
            continue;
        while (ss[x + 1] == ' ')
            ++x;
        ss.replace(x + 1, y - x, ASTR("..."));
        y = -1;
    }

    switch (Level)
    {
    case WINTUN_LOG_INFO:
        LOG_N("wintun: $", ss);
        break;
    case WINTUN_LOG_WARN:
        LOG_W("wintun: $", ss);
        break;
    case WINTUN_LOG_ERR:
        LOG_E("wintun: $", ss);
        break;
    }
}

#define DRIVER_NAME wintun
#define ADAPTER_CLASS wintun_adapter
#define WTFS \
        WTF(WINTUN_CREATE_ADAPTER_FUNC, WintunCreateAdapter) \
        WTF(WINTUN_SET_LOGGER_FUNC, WintunSetLogger) \
        WTF(WINTUN_CLOSE_ADAPTER_FUNC, WintunCloseAdapter) \
        WTF(WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC, WintunGetRunningDriverVersion) \
        WTF(WINTUN_GET_ADAPTER_LUID_FUNC, WintunGetAdapterLUID) \
        WTF(WINTUN_START_SESSION_FUNC, WintunStartSession) \
        WTF(WINTUN_END_SESSION_FUNC, WintunEndSession) \
        WTF(WINTUN_ALLOCATE_SEND_PACKET_FUNC, WintunAllocateSendPacket) \
        WTF(WINTUN_SEND_PACKET_FUNC, WintunSendPacket) \
        WTF(WINTUN_GET_READ_WAIT_EVENT_FUNC, WintunGetReadWaitEvent) \
        WTF(WINTUN_RECEIVE_PACKET_FUNC, WintunReceivePacket) \
        WTF(WINTUN_RELEASE_RECEIVE_PACKET_FUNC, WintunReleaseReceivePacket) \


struct adapter_data
{
    std::unique_ptr<ostools::dynlib> lib;

#define WTF(H, fn) H* fn = nullptr;
    WTFS
#undef WTF

    bool resolve()
    {
#define WTF(H, fn) fn = lib->resolve<H*>(str::astr(ASTR(#fn))); if (!fn) { LOG_FATAL(__STR1__(DRIVER_NAME) ": can't resolve func: $", ASTR(#fn)); return false; }
        WTFS
#undef WTF
        return true;
    }

    void clear()
    {
        lib.reset();
    }

    static adapter_data& get(common_adapter_data& cd)
    {
        return ref_cast<adapter_data>(cd);
    }
};
#else
#define ADAPTER_CLASS nix_adapter
struct adapter_data
{
    u8 dummy;

    void clear() {}

    static adapter_data& get(common_adapter_data& cd)
    {
        return ref_cast<adapter_data>(cd);
    }

};
#endif

static_assert(sizeof(adapter_data) <= sizeof(common_adapter_data));

adapters::adapters()
{
    new (&adapter_data::get(cad)) adapter_data();
}

void adapters::close()
{
    for (std::unique_ptr<adapter>& a : *this)
        a->close();
}

static inline bool iscomplare(const str::wstr& s1, const str::wstr& s2)
{
    if (s1.length() != s2.length())
        return false;
    for (size_t i = 0; i < s1.length(); ++i)
    {
        wchar c1 = s1[i];
        wchar c2 = s2[i];
        if (c1 >= 'A' && c1 <= 'Z')
            c1 |= 32;
        if (c2 >= 'A' && c2 <= 'Z')
            c2 |= 32;

        if (c1 != c2)
            return false;
    }
    return true;
}

static inline signed_t findi(const std::vector<str::wstr>& ar, const str::wstr& el)
{
    for (signed_t i = 0, c = ar.size(); i < c; ++i)
        if (iscomplare(ar[i],el))
            return i;
    return -1;
}


bool adapters::load(loader& ldr)
{
#ifdef _DEBUG
    // cleanup registry; this is only developer's tool to remove garbage registry keys


    std::vector<str::wstr> existed, clean1a, dell;
    str::wstr netlist(WSTR("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"));
    enum_reg_keys(netlist, [&](str::wstr_view g) {

        str::wstr kk(netlist); kk.push_back('\\'); kk.append(g);
        auto n = reg_read_string(kk, WSTR("Description"));
        if (n == WSTR("proxtopus"))
        {
            dell.emplace_back(kk);
        } else
            existed.emplace_back(g);
        return false;
    });

    for (auto &x : dell)
        reg_del_key( x );

    str::wstr clean1(WSTR("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\NcdAutoSetup\\NetworkSetting"));
    enum_reg_keys(clean1, [&](str::wstr_view g) {
        clean1a.emplace_back(g);
        return false;
    });

    for (auto& s : clean1a)
    {
        if (findi(existed, s) >= 0)
            continue;
        str::wstr xx(clean1); xx.push_back('\\'); xx.append(s);
        reg_del_key(xx);
    }

    clean1a.clear();
    clean1 = WSTR("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\Probe");
    enum_reg_keys(clean1, [&](str::wstr_view g) {
        clean1a.emplace_back(g);
        return false;
    });

    for (auto& s : clean1a)
    {
        if (findi(existed, s) >= 0)
            continue;
        str::wstr xx(clean1); xx.push_back('\\'); xx.append(s);
        reg_del_key(xx);
    }

    clean1a.clear();
    clean1 = WSTR("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged");
    enum_reg_keys(clean1, [&](str::wstr_view g) {

        str::wstr kk(clean1); kk.push_back('\\'); kk.append(g);
        auto n = reg_read_string(kk, WSTR("ProfileGuid"));
        if (!n.empty() && findi(existed, n) < 0)
            clean1a.emplace_back(kk);

        return false;
    });

    for (auto& s : clean1a)
    {
        reg_del_key(s);
    }


#endif

    if (!ldr.adapters->get_bool(ASTR("enable")))
        return true;

#ifdef _WIN32

    FN path = tofn(ldr.adapters->get_string(ASTR("lib"), glb.emptys));
    bool custom_path = true;
    if (path.empty())
    {
        custom_path = false;
        path = MAKEFN("wintun.dll");
    }
    adapter_data::get(cad).lib.reset(NEW ostools::dynlib(path));
    if (!*adapter_data::get(cad).lib)
    {
        ldr.exit_code = EXIT_FAIL_ADAPTER_INIT_ERROR;
        adapter_data::get(cad).lib.reset();

        if (custom_path)
        {
            LOG_FATAL(__STR1__(DRIVER_NAME) ": driver not found ($)", path_print_str(path));
            return false;
        }

        LOG_W(__STR1__(DRIVER_NAME) ": driver not found ($)", path_print_str(path));
        return true; // not error; no wintun - no redirect
    }
    if (!adapter_data::get(cad).resolve())
        return false;

    adapter_data::get(cad).WintunSetLogger(wintun_logger);

    LOG_N(__STR1__(DRIVER_NAME) ": driver was loaded ($)", path_print_str(path));
#endif

    for (auto it = ldr.adapters->begin_skip_comments(); it; ++it)
    {
        if (it->has_elements())
        {
            ADAPTER_CLASS* a = NEW ADAPTER_CLASS( it.name() );
            if (!a->load(cad, ldr, it))
            {
                close();
                delete a;
                adapter_data::get(cad).clear();
                ldr.exit_code = EXIT_FAIL_ADAPTER_INIT_ERROR;
                return false;
            }
            emplace_back(a);
        }
    }

    return true;
}

/*virtual*/ void adapter::on_new_stream(tcp_stream& s)
{
    glb.e->new_tcp_pipe(this, &s);
}

void adapter::handle_pipe(netkit::pipe* p)
{
#ifdef _DEBUG
    tcp_stream* stream = dynamic_cast<tcp_stream*>(p);
    ASSERT(stream);
#else
    tcp_stream* stream = static_cast<tcp_stream*>(p);
#endif

    netkit::endpoint ep(stream->dst);

    ups_conn_log clogger(name, p, &ep);

    if (netkit::pipe_ptr outcon = ups.connect(clogger, ep, false))
    {
        if (ipm_stream_accept(*stream))
            glb.e->bridge(p, outcon.get());
    }
    else
        ipm_stream_reject(*stream);
}

#ifdef _WIN32
wintun_adapter::~wintun_adapter()
{
    ASSERT(adpt_handler == nullptr);
}
void wintun_adapter::close()
{
    //for (auto& row : routes)
      //  DeleteIpForwardEntry(&row);

    HANDLE e = newsb;
    newsb = nullptr;
    CloseHandle(e);

    if (cad && adpt_handler)
    {
        if (adpt_session)
        {
            while (sendbufs.dequeue([this](u8* buf) {
                adapter_data::get(*cad).WintunSendPacket((WINTUN_SESSION_HANDLE)adpt_session, buf);
            }));

            adapter_data::get(*cad).WintunEndSession((WINTUN_SESSION_HANDLE)adpt_session);
        }
        adapter_data::get(*cad).WintunCloseAdapter((WINTUN_ADAPTER_HANDLE)adpt_handler);
    }
    adpt_session = nullptr;
    adpt_handler = nullptr;

}

DWORD find_adapter_index(const GUID& guid)
{
    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bufLen);

    std::unique_ptr<u8[]> buffer(NEW u8[bufLen]);
    IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get());

    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addresses, &bufLen) != NO_ERROR)
        return 0;

    for (auto* aa = addresses; aa; aa = aa->Next)
    {
        if (aa->AdapterName && aa->AdapterName[0])
        {
            GUID adapterGuid;
            if (SUCCEEDED(CLSIDFromString(str::from_utf8(aa->AdapterName).c_str(), &adapterGuid)))
            {
                if (IsEqualGUID(adapterGuid, guid))
                    return aa->IfIndex;
            }
        }
    }

    return 0; // not found
}

bool wintun_adapter::load(common_adapter_data& d, loader& ldr, const asts* s)
{
    ASSERT(newsb == nullptr);
    cad = nullptr;

    if (!adapter::load(d,ldr,s))
        return false;

    const str::astr& ip = s->get_string(ASTR("ip"), glb.emptys);
    if (ip.empty())
    {
        ipfail:
        LOG_FATAL(__STR1__(DRIVER_NAME) ": ip address not defined for adapter $ (define something like ip=1.2.3.4/24)", str::clean(name));
        return false;
    }

    ipaddr = netkit::ipap::parse(str::view(ip), netkit::ipap::f_prefix);

    if (!ipaddr.has_prefix())
    {
        LOG_FATAL(__STR1__(DRIVER_NAME) ": mask size not defined for adapter $ (define something like ip=1.2.3.4/24)", str::clean(name));
        return false;
    }

    if (ipaddr.is_empty() || !ipaddr.v4())
        goto ipfail;

    if (!ipaddr.is_private())
    {
        LOG_W(__STR1__(DRIVER_NAME) ": ip address for adapter $ is not private", str::clean(name));
    }

    str::wstr adesc = str::from_utf8(name);
    GUID guid;
    GUID* parsed = nullptr;

    /*
    *  get guid for adapter from registry
    */

    auto guids = reg_read_string(WSTR("HKLM\\SOFTWARE\\proxtopus"), adesc + WSTR(".guid"));
    HRESULT hr = CLSIDFromString(guids.c_str(), &guid);
    if (SUCCEEDED(hr))
    {
        parsed = &guid;
    }
    else
    {
        CoCreateGuid(&guid);
        parsed = &guid;

        guids.clear();

        guids.push_back('{');
        str::append_hex<decltype(guids), u32, 8>(guids, guid.Data1); guids.push_back('-');
        str::append_hex<decltype(guids), u16, 4>(guids, guid.Data2); guids.push_back('-');
        str::append_hex<decltype(guids), u16, 4>(guids, guid.Data3); guids.push_back('-');
        str::append_hex<decltype(guids), u8, 2>(guids, guid.Data4[0]);
        str::append_hex<decltype(guids), u8, 2>(guids, guid.Data4[1]);
        guids.push_back('-');
        for(size_t i=2; i<8; ++i)
            str::append_hex<decltype(guids), u8, 2>(guids, guid.Data4[i]);
        guids.push_back('}');

        reg_set_string(WSTR("HKLM\\SOFTWARE\\proxtopus"), adesc + WSTR(".guid"), guids);
    }

    signed_t trycount = 3;
tryag:
    LOG_N(__STR1__(DRIVER_NAME) ": try to create adapter: $; try $/3", name, 3-trycount+1);
    WINTUN_ADAPTER_HANDLE h = adapter_data::get(d).WintunCreateAdapter(adesc.c_str(), L"Wintune", parsed);
    if (!h)
    {
        if (trycount >= 0)
        {
            --trycount;
            goto tryag;
        }
        LOG_FATAL(__STR1__(DRIVER_NAME) ": failed to create adapter: $", name);
        return false;
    }
    cad = &d;
    adpt_handler = h;

    LOG_N(__STR1__(DRIVER_NAME) ": adapter [$] has been created", name);

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    adapter_data::get(d).WintunGetAdapterLUID(h, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.s_addr = ipaddr.ipv4.s_addr;
    AddressRow.OnLinkPrefixLength = tools::as_byte(ipaddr.port);
    AddressRow.DadState = IpDadStatePreferred;
    DWORD LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LOG_FATAL(__STR1__(DRIVER_NAME) ": failed to assign ip address to adapter: $", name);
        close();
        return false;
    }

    WINTUN_SESSION_HANDLE ses = adapter_data::get(d).WintunStartSession(h, WINTUN_MIN_RING_CAPACITY);
    if (!ses)
    {
        LOG_FATAL(__STR1__(DRIVER_NAME) ": failed start session of adapter: $", name);
        close();
        return false;
    }
    adpt_session = ses;
    newsb = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    std::thread th1(&wintun_adapter::receiver, this);
    th1.detach();

    std::thread th2(&wintun_adapter::sender, this);
    th2.detach();

    for (const auto& uip : upsips)
    {
        auto gate = ostools::get_best_route(uip);
        if (!gate.is_empty())
            ostools::add_route(uip, gate, gate.port);
    }


    DWORD aindex = 0;
    for (auto it = s->begin(ASTR("addroute")); it; ++it)
    {
        const str::astr& r = it->as_string(glb.emptys);
        netkit::ipap dst = netkit::ipap::parse(str::view(r), netkit::ipap::f_prefix);

        if (!dst.has_prefix())
        {
            LOG_W(__STR1__(DRIVER_NAME) ": invalid addroute value for adapter $ (define something like addroute=1.2.3.4/32)", str::clean(name));
            continue;
        }
        if (!dst.v4())
        {
            LOG_W(__STR1__(DRIVER_NAME) ": addroute ipv6 addrs not yet supported (adapter $)", str::clean(name));
            continue;
        }

        if (aindex == 0)
        {
            aindex = find_adapter_index(*parsed);
        }

        if (!ostools::add_route(dst, netkit::ipap(), aindex))
        {
            LOG_W(__STR1__(DRIVER_NAME) ": route add failed (adapter $)", str::clean(name));
            continue;
        }
    }


    return true;
}

void wintun_adapter::sender()
{
    ostools::set_current_thread_name(ASTR("asnd") + name);
    while (!glb.is_stop() && newsb != nullptr)
    {
        if (!sendbufs.dequeue([this](u8* buf) {
            if (buf)
                adapter_data::get(*cad).WintunSendPacket((WINTUN_SESSION_HANDLE)adpt_session, buf);
        })) {
            WaitForSingleObject(newsb, LOOP_PERIOD);
        }
    }
}

void wintun_adapter::receiver()
{
    ostools::set_current_thread_name(ASTR("arcv") + name);

    WINTUN_SESSION_HANDLE session = (WINTUN_SESSION_HANDLE)adpt_session;
    HANDLE newdata = adapter_data::get(*cad).WintunGetReadWaitEvent(session);

    while (!glb.is_stop() && newsb != nullptr)
    {
        DWORD packet_size;
        if (BYTE* packet = adapter_data::get(*cad).WintunReceivePacket(session, &packet_size))
        {
            ipm_handle_packet(packet, packet_size);
            adapter_data::get(*cad).WintunReleaseReceivePacket(session, packet);
            continue;
        }
        //else if (ERROR_NO_MORE_ITEMS == GetLastError())
        //{
        //    WaitForSingleObject(newdata, LOOP_PERIOD);
        //    continue;
        //}
        WaitForSingleObject(newdata, LOOP_PERIOD);
    }
}


/*virtual*/ bool wintun_adapter::inject(const u8* p, size_t sz)
{
    if (!newsb)
        return false;
    bool ok = false;
    if (sendbufs.enqueue([&](auto& slot) {
        u8* packet_space = adapter_data::get(*cad).WintunAllocateSendPacket((WINTUN_SESSION_HANDLE)adpt_session, tools::as_dword(sz));
        if (packet_space != nullptr)
        {
            memcpy(packet_space, p, sz);
            ok = true;
        }
        slot = packet_space;
    }))
    {
        if (ok)
            SetEvent(newsb);
        return ok;
    }

    return false;
}


#endif

#endif