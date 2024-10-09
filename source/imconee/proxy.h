#pragma once

class proxy
{
protected:
	str::astr name;
	netkit::endpoint addr;

public:
	proxy(loader& ldr, const str::astr& name, const asts& bb, bool addr_required = true);
	virtual ~proxy() {}

	static proxy* build(loader& ldr, const str::astr& name, const asts& bb);

	/*
	* tcp pipe communication
	* caller must establish connection to current proxy (addr) and pass pipe
	* function will force the proxy to establish a connection to addr2
	* returned pipe is ready-to-communicate pipe with remote host at addr2
	*/
	virtual netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr2 ) const = 0;
	/*
	* udp communication via proxy
	* caller must provide low-level udp transport for sending custom udp packets
	* function will force the proxy to prepare udp tunneling and returns udp_pipe that will send/recv upd packets through proxy
	* IMPORTANT! it is necessary to ensure the life-time of the transport for the entire period of use of the returned pipe
	*/
	virtual std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const { return std::unique_ptr<netkit::udp_pipe>(); }
	virtual bool support(netkit::socket_type st) const { return st == netkit::ST_TCP; }

	const str::astr& get_name() const { return name; }
	str::astr desc() const;
	const netkit::endpoint& get_addr() const { return addr; }
};


class proxy_socks4 : public proxy
{
	str::astr userid;
public:
	proxy_socks4(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_socks4() {}

	/*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const override;
};

class proxy_socks5 : public proxy
{
	buffer authpacket;
	bool initial_setup(u8* packet, netkit::pipe* p2p) const;
	bool recv_rep(u8* packet, netkit::pipe* p2p, netkit::endpoint*ep, str::astr_view addr2domain) const;
public:
	proxy_socks5(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_socks5() {}

	/*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const override; // tcp tunnel
	/*virtual*/ std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const override; //udp tunnel
	/*virtual*/ bool support(netkit::socket_type) const { return true; }

	bool prepare_udp_assoc(netkit::ipap &ip, netkit::pipe_ptr &pip, bool log_fails) const;
};

#include "proxy_ss.h"