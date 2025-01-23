#pragma once

#define CMDS \
            CM(GET) \
            CM(POST) \
            CM(PUT) \
            CM(HEAD) \
            CM(OPTIONS) \
            CM(PATCH) \
            CM(TRACE) \
            CM(CONNECT) \

enum mode_result
{
    MR_OK,
    MR_COMMAND_NOT_SUPPORTED,
};

enum http_codes
{
    HC_OK,
    HC_OK_CONNECTION_ESTABLISHED,

    HC_BAD_REQUEST,
    HC_NOT_FOUND,

    HC_INTERNAL_SERVER_ERROR,
    HC_NOT_IMPLEMENTED,
    HC_BAD_GATEWAY,
};

class http_server;
struct host_mode
{
    virtual ~host_mode() {}
    virtual bool load(const asts &) = 0;

#define CM(cc) virtual mode_result do_##cc(http_server &) { return MR_COMMAND_NOT_SUPPORTED; }
    CMDS
#undef CM

};

struct host_mode_simple : public host_mode
{
    FN root_path;
    virtual ~host_mode_simple() {}
    virtual bool load(const asts& b) override;

    void compile(buffer &b);

    mode_result do_GET(http_server& s);
};

struct host_mode_proxy : public host_mode
{
    enum flags_vals
    {
        F_ADDR_FROM_COMMAND = 1,
        F_ADDR_FROM_HOST = 2,
        F_ADDR_FROM_BOTH = 3,
    };

    signed_t flags = 0;
    virtual ~host_mode_proxy() {}
    virtual bool load(const asts& b) override;

    mode_result do_CONNECT(http_server& s);
};

struct http_server_host
{
    http_server_host(const str::astr& mask) :mask(mask) {}
    str::astr mask;
    std::unique_ptr<host_mode> m;
    bool match(const str::astr_view& host) const
    {
        return str::mask_match(host, str::view(mask));
    }

};

struct http_server_params
{
    std::vector<http_server_host> hosts;
};

class http_server : public netkit::pipe_tools
{
    friend struct host_mode_simple;
    friend struct host_mode_api;
    friend struct host_mode_proxy;
    const http_server_params& params;
    handler* ownerhandler;

    enum mode
    {
        MODE_RECEIVING_COMMAND,
        MODE_RECEIVING_FIELDS,
        MODE_RECEIVING_BODY,
    } md = MODE_RECEIVING_COMMAND;

    enum command
    {
        CMD_UNKNOWN,
#define CM(cc) CMD_##cc,
        CMDS
#undef CM
    } cmd = CMD_UNKNOWN;


    std::map< str::astr, str::astr, std::less<> > fields;
    str::astr path, host;
    signed_t content_length = 0;

    bool receive_command();
    bool receive_fields();

    void answer(http_codes code, str::astr_view content_type, const buffer& b);
    void answer(http_codes code);
public:
    http_server(const http_server_params &params, handler *ownerhandler, netkit::pipe* p);
    ~http_server();
    void process();
};

class handler_http : public handler // http server
{
    http_server_params params;
protected:
public:
    handler_http(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st);
    virtual ~handler_http() { stop(); }

    /*virtual*/ str::astr desc() const { return str::astr(ASTR("http")); }
    /*virtual*/ bool compatible(netkit::socket_type_e st) const
    {
        return st == netkit::ST_TCP;
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

#include "http_api.h"