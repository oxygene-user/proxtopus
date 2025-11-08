#pragma once

class proxy : public apiobj
{
protected:
	str::astr name;
	netkit::endpoint addr;

public:
	proxy(loader& ldr, const str::astr& name, const asts& bb, bool addr_required = true, bool port_required = true);
	virtual ~proxy() {}

	static proxy* build(loader& ldr, const str::astr& name, const asts& bb);

	/*
	* tcp pipe communication
	* caller must establish connection to current proxy (addr) and pass pipe
	* function will force the proxy to establish a connection to addr2
	* returned pipe is ready-to-communicate pipe with remote host at addr2
	* addr2 can be modified (resolved)
	*/
	virtual netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr2 ) const = 0;
	/*
	* udp communication via proxy
	* caller must provide low-level udp transport for sending custom udp packets
	* function will force the proxy to prepare udp tunneling and returns udp_pipe that will send/recv upd packets through proxy
	* IMPORTANT! it is necessary to ensure the life-time of the transport for the entire period of use of the returned pipe
	*/
	virtual std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const { return std::unique_ptr<netkit::udp_pipe>(); }
	virtual bool support(netkit::socket_type_e st) const { return st == netkit::ST_TCP; }

	const str::astr& get_name() const { return name; }
	str::astr desc() const;
	const netkit::endpoint& get_addr() const { return addr; }

	/*virtual*/ void api(json_saver& j) const override;
};


class proxy_socks4 final : public proxy
{
	str::astr userid;
public:
	proxy_socks4(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_socks4() {}

	/*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const override;
	/*virtual*/ void api(json_saver& j) const override;
};

class proxy_socks5 final : public proxy
{
	tools::keep_buffer auth;
	bool obfs = false;

	bool initial_setup(tools::circular_buffer_extdata & rcvd, netkit::pipe* p2p, chacha20 &cryptor) const;
	bool recv_rep(tools::circular_buffer_extdata& rcvd, netkit::pipe* p2p, netkit::endpoint*ep, const str::astr_view *addr2domain) const; // addr2domain not null means logging
public:
	proxy_socks5(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_socks5() {}

	/*virtual*/ void api(json_saver&) const override;
	/*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const override; // tcp tunnel
	/*virtual*/ std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const override; //udp tunnel
	/*virtual*/ bool support(netkit::socket_type_e) const override { return true; }

	bool prepare_udp_assoc(netkit::endpoint & udp_assoc_ep, netkit::pipe_ptr &pip, bool log_fails) const;
	static void push_atyp(netkit::pgen& pg, const netkit::endpoint& addr, chacha20 *enc = nullptr);
	static signed_t atyp_size(const netkit::endpoint& addr); // including ATYP octet
	static bool read_atyp(netkit::pgen& pg, netkit::endpoint& addr);

};

class proxy_http final : public proxy
{
	str::astr host;
	std::vector<std::pair<str::astr, str::astr>> fields;

public:
	proxy_http(loader& ldr, const str::astr& name, const asts& bb);
    /*virtual*/ ~proxy_http() {}

    /*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const override;
    /*virtual*/ void api(json_saver& j) const override;
};


#include "proxy_ss.h"