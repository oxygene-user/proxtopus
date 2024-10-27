#pragma once


class proxy_shadowsocks : public proxy
{
	ss::core core;

public:
	proxy_shadowsocks(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_shadowsocks() {}

	/*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const override;
	/*virtual*/ std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const override;
	/*virtual*/ bool support(netkit::socket_type) const override { return true; }
};

