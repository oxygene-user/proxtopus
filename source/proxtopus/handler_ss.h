#pragma once

#include "cipher_ss.h"

class handler_ss : public handler // socks4 and socks5
{
	ss::core core;
    signed_t udp_timeout_ms = 10000;
    bool allow_private = false;

protected:
    /*virtual*/ bool handle_packet(netkit::thread_storage& ctx, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg) override;
    /*virtual*/ bool encode_packet(netkit::thread_storage& ctx, const netkit::ipap& from, netkit::pgen& pg) override;
    /*virtual*/ signed_t udp_timeout() const override
    {
        return udp_timeout_ms;
    }
    /*virtual*/ void log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to) override;
public:
	handler_ss(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st);
	virtual ~handler_ss() { stop(); }

	/*virtual*/ str::astr desc() const { return str::astr(ASTR("shadowsocks")); }
    /*virtual*/ bool compatible(netkit::socket_type_e /*st*/) const
    {
        return true; // compatible with both tcp and udp
    }


	/*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

