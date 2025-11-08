#pragma once


class proxy_shadowsocks final : public proxy
{
	ss::core core;

public:
	proxy_shadowsocks(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_shadowsocks() {}

	/*virtual*/ void api(json_saver&) const override;
	/*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const override;
	/*virtual*/ std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const override;
	/*virtual*/ bool support(netkit::socket_type_e) const override { return true; }
};

class proxy_ssp final : public proxy
{
    ss::core core;
    str::astr sni; // fake sni

public:
    proxy_ssp(loader& ldr, const str::astr& name, const asts& bb);
    /*virtual*/ ~proxy_ssp() {}

    /*virtual*/ void api(json_saver&) const override;
    /*virtual*/ netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const override;
    /*virtual*/ std::unique_ptr<netkit::udp_pipe> prepare(netkit::udp_pipe* /*transport*/) const override;
    /*virtual*/ bool support(netkit::socket_type_e) const override { return true; }
};
