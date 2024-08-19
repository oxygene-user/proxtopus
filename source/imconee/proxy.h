#pragma once

class proxy
{
protected:
	str::astr name;
	netkit::endpoint addr;


public:
	proxy(loader& ldr, const str::astr& name, const asts& bb);
	virtual ~proxy() {}

	static proxy* build(loader& ldr, const str::astr& name, const asts& bb);

	virtual netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const = 0;

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

	netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const;
};

class proxy_socks5 : public proxy
{
	buffer authpacket;
public:
	proxy_socks5(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_socks5() {}

	netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const;
};

#include "proxy_ss.h"