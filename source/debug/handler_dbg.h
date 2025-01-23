#pragma once


class handler_debug : public handler // just port mapper
{
    signed_t udp_timeout_ms = 10000;


public:
    handler_debug(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st);
    virtual ~handler_debug() { stop(); }

    /*virtual*/ str::astr desc() const { return str::astr(ASTR("debug")); }
    /*virtual*/ bool compatible(netkit::socket_type_e st) const
    {
        return netkit::ST_TCP == st;
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

