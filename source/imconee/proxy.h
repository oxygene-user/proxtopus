#pragma once

class proxy
{
protected:
	std::string name;
	netkit::endpoint addr;


public:
	proxy(loader& ldr, const std::string& name, const asts& bb);
	virtual ~proxy() {}

	static proxy* build(loader& ldr, const std::string& name, const asts& bb);

	virtual netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const = 0;

	const std::string& get_name() const { return name; }
	std::string desc() const;
	const netkit::endpoint& get_addr() const { return addr; }
};


class proxy_socks4 : public proxy
{
	std::string userid;
public:
	proxy_socks4(loader& ldr, const std::string& name, const asts& bb);
	/*virtual*/ ~proxy_socks4() {}

	netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const;
};

class proxy_socks5 : public proxy
{
	std::vector<u8> authpacket;
public:
	proxy_socks5(loader& ldr, const std::string& name, const asts& bb);
	/*virtual*/ ~proxy_socks5() {}

	netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const;
};

#include "proxy_ss.h"