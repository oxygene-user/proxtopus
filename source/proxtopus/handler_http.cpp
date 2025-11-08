#include "pch.h"

str::astr_view code_text(http_codes code)
{
    switch (code)
    {
    case HC_OK:
        return ASTR("200\r\n");
    case HC_OK_CONNECTION_ESTABLISHED:
        return ASTR("200 Connection Established\r\n");
    case HC_BAD_REQUEST:
        return ASTR("400 Bad Request\r\n");
    case HC_NOT_FOUND:
        return ASTR("404 Not Found\r\n");
    case HC_INTERNAL_SERVER_ERROR:
        return ASTR("500 Internal Server Error\r\n");
    case HC_NOT_IMPLEMENTED:
        return ASTR("501 Not Implemented\r\n");
    case HC_BAD_GATEWAY:
        return ASTR("502 Bad Gateway\r\n");
    }
    DEBUGBREAK();
    return str::astr_view();
}

/*virtual*/ bool host_mode_simple::load(const asts& b)
{
    root_path = tofn(b.get_string(ASTR("root"), glb.emptys));
    path_simplify(root_path, true);
    return true;
}

handler_http::handler_http(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e /*st*/) :handler(ldr, owner, bb)
{

    for (auto it = bb.begin_skip_comments(); it; ++it)
    {
        if (it->has_elements())
        {
            http_server_host &h = params.hosts.emplace_back(it.name());
            const str::astr &ms = it->get_string(ASTR("mode"), glb.emptys);
            if (ms == ASTR("api"))
                h.m.reset(NEW host_mode_api());
            else if (ms == ASTR("simple"))
                h.m.reset(NEW host_mode_simple());
            else if (ms == ASTR("proxy"))
                h.m.reset(NEW host_mode_proxy());
            else {
                ldr.exit_code = EXIT_FAIL_MODE_UNDEFINED;
                if (ms.empty())
                {
                    LOG_FATAL("{mode} not defined for http host of listener [$]^", str::clean(owner->get_name()));
                    return;
                }
                LOG_FATAL("unknown {mode} [$] for http host of listener [$]^", ms, str::clean(owner->get_name()));
                return;
            }
            if (!h.m->load(*it))
                return;
        }
    }

}

/*virtual*/ void handler_http::handle_pipe(netkit::pipe* pipe)
{
    http_server server(params, this, pipe);
    server.process();
}


http_server::http_server(const http_server_params& params, handler* ownerhandler, netkit::pipe* p):pipe_tools(p), params(params), ownerhandler(ownerhandler)
{
}
http_server::~http_server()
{
}


namespace
{
    struct sline
    {
        str::astr ln;
        signed_t pos = 0;
        void skip_spaces()
        {
            while (ln[pos] == ' ') ++pos;
        }
        str::astr_view token()
        {
            signed_t p2 = pos;
            for (; ln[p2] != ' ' && p2 < SIGNED % ln.length(); ++p2);
            str::astr_view v = str::astr_view( ln.c_str() + pos, p2-pos );
            pos = p2;
            skip_spaces();
            return v;
        }
    };
}

bool iscmd(sline& scmd, const str::astr_view c)
{
    if (scmd.ln.length() <= c.length())
        return false;
    for (signed_t i = 0; i < SIGNED % c.length(); ++i)
    {
        if ((scmd.ln[i] & (~32)) != c[i])
            return false;
    }

    if (scmd.ln[c.length()] == ' ')
    {
        scmd.pos = c.length() + 1;
        scmd.skip_spaces();
        return true;
    }
    return false;
}

bool http_server::receive_command()
{
    sline scmd;
    if (!read_line(&scmd.ln))
        return false;

#define CM(cc) if (iscmd(scmd, ASTR(#cc))) { cmd = CMD_##cc; } else
    CMDS
#undef CM
        return false;

    path = scmd.token();
    str::astr_view ver = scmd.token();

    if (ASTR("HTTP/1.1") == ver)
    {
        md = MODE_RECEIVING_FIELDS;
        return true;
    }

    return false;

}

bool http_server::receive_fields()
{
    str::astr fl;
    if (!read_line(&fl))
        return false;

    if (fl.empty())
    {
        md = MODE_RECEIVING_BODY;
        return true;
    }

    auto x = fl.find(':');
    if (x == fl.npos)
        return false;

    str::astr_view fn = str::substr(fl, 0, x);
    for (++x; fl[x] == ' '; ++x);
    fields.insert_or_assign(str::astr(fn), fl.substr(x));
    return true;
}

void http_server::process()
{
    for (; md == MODE_RECEIVING_COMMAND;)
        if (!receive_command())
            return;
    for (; md == MODE_RECEIVING_FIELDS;)
        if (!receive_fields())
            return;

    host.clear();
    auto ihost = fields.find(ASTR("Host"));
    if (ihost != fields.end())
        host = ihost->second;

    bool handled = false;
    for (const http_server_host& h : params.hosts)
    {
        if (h.match(host))
        {
            switch (cmd)
            {
#define CM(cc) case CMD_##cc: if (MR_OK == h.m->do_##cc(*this)) { handled = true; break; } else continue;
                CMDS
#undef CM
            }
            break;
        }
        if (handled)
            break;
    }
    if (!handled)
    {
        buffer b;
        answer(HC_NOT_IMPLEMENTED);
    }
}

void http_server::answer(http_codes code, str::astr_view content_type, const buffer& b)
{
    str::astr a(ASTR("HTTP/1.1 "));
    a.append(code_text(code));
    a.append(ASTR("Content-Length: "));
    str::append_num(a, b.size(), 0);
    a.append(ASTR("\r\nContent-Type: "));
    a.append(content_type);
    a.append(ASTR("\r\n\r\n"));
    send(a);
    if (b.size() > 0)
        send(b);
}

void http_server::answer(http_codes code)
{
    str::astr a(ASTR("HTTP/1.1 "));
    a.append(code_text(code));
    a.append(ASTR("\r\n"));
    send(a);
}

void host_mode_simple::compile(buffer& b)
{
    for (;;)
    {
        size_t ip = str::view(b).find(ASTR("{INCLUDE-"));
        if (ip != str::astr::npos)
        {
            str::astr_view d = str::view(std::span(b.data() + ip + 9, b.size() - ip - 9));
            if (d.starts_with(ASTR("TEXT:")))
            {
                size_t ei = d.find('}', 5);
                if (ei != str::astr::npos)
                {
                    FN fn = path_concat(root_path, tofn(str::substr(d, 5, ei)));
                    buffer ib;
                    load_buf(fn, ib);
                    str::replace_all(ib, ASTR("\r\n"), ASTR("<br>"));
                    str::replace_all(ib, ASTR("\t"), ASTR("&nbsp;&nbsp;"));
                    b.replace(ip, ei + 10, ib);
                }
            }
            continue;
        }

        break;
    }
}

mode_result host_mode_simple::do_GET(http_server& s)
{
    FN fn = tofn(s.path);
    path_simplify(fn, false);
    FN fni = path_concat(root_path, fn);

    buffer b;

    str::astr mimet;

    if (is_file_exists(fni))
    {
        if (fni.ends_with(MAKEFN(".htm")) || fni.ends_with(MAKEFN(".html")))
            mimet = ASTR("text/html");
        else if (fni.ends_with(MAKEFN(".css")))
            mimet = ASTR("text/css");
        else
            mimet = ASTR("application/octet-stream");

    } else if (is_path_exists(fni))
    {
        path_append(fni, MAKEFN("index.htm"));
        mimet = ASTR("text/html");
    }
    else
    {
        s.answer(HC_NOT_FOUND);
        return MR_OK;
    }

    load_buf(fni, b);

    compile(b);

    s.answer(HC_OK, mimet, b);
    return MR_OK;
}

bool host_mode_proxy::load(const asts& b)
{
    flags = 0;
    enum_tokens_a(tkn, b.get_string(ASTR("addr")), '|')
    {
        if (ASTR("host") == *tkn)
        {
            flags |= F_ADDR_FROM_HOST;
        } else if (ASTR("cmd") == *tkn || ASTR("command") == *tkn)
        {
            flags |= F_ADDR_FROM_COMMAND;
        }
    }
    if (flags == 0)
        flags = F_ADDR_FROM_COMMAND;

    return true;
}

mode_result host_mode_proxy::do_CONNECT(http_server& s)
{
    str::astr epa;
    switch (flags & F_ADDR_FROM_BOTH)
    {
    case F_ADDR_FROM_COMMAND:
        epa = s.path;
        break;
    case F_ADDR_FROM_HOST:
        epa = s.host;
        break;
    case F_ADDR_FROM_BOTH:
        if (s.path != s.host)
        {
            s.answer(HC_BAD_REQUEST);
            return MR_OK;
        }
        epa = s.path;
        break;
    }
    s.ownerhandler->make_bridge(s.rcvd, epa, s.pp.get(), [&](bool established) {
        s.answer(established ? HC_OK_CONNECTION_ESTABLISHED : HC_BAD_GATEWAY);
        if (established)
            s.pp = nullptr; // bridge is exclusive owner of pipe
    });

    return MR_OK;
}
