#include "pch.h"

/*
class jpipe : public netkit::pipe
{
	buffer buf;
public:
	jpipe* opipe = nullptr;;

	jpipe() {}
	jpipe(jpipe* opipe) :opipe(opipe) {}

	virtual bool send(const u8* data, signed_t datasize)
	{
		std::span<const u8>x(data, datasize);
		buf.insert(buf.end(), x.begin(), x.end());
		return true;
	}
	virtual signed_t recv(u8* data, signed_t maxdatasz)
	{
		if (maxdatasz < 0)
		{
			ASSERT(opipe->buf.size() >= (-maxdatasz));
			maxdatasz = -maxdatasz;
		}

		signed_t mmm = math::minv(maxdatasz, opipe->buf.size());
		memcpy(data, opipe->buf.data(), mmm);
		opipe->buf.erase(opipe->buf.begin(), opipe->buf.begin() + mmm);
		return mmm;
	}
	virtual bool wait(long microsec)
	{
		return true;
	}

	virtual void close(bool flush_before_close)
	{

	}

};
*/

proxy_shadowsocks::proxy_shadowsocks(loader& ldr, const str::astr& name, const asts& bb) :proxy(ldr, name, bb, false)
{
	str::astr a = core.load(ldr, name, bb);
	if (!a.empty())
		addr.preparse(a);

	if (addr.state() == netkit::EPS_EMPTY)
	{
		ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
		LOG_FATAL("addr not defined for proxy [$]", str::clean(name));
		return;
	}
}

netkit::pipe_ptr proxy_shadowsocks::prepare(netkit::pipe_ptr pipe_2_proxy, netkit::endpoint& addr2) const
{
	if (addr2.state() == netkit::EPS_EMPTY || addr2.port() == 0)
		return netkit::pipe_ptr();

	netkit::pipe_ptr p_enc(NEW ss::core::crypto_pipe(pipe_2_proxy, core.masterkeys.lock_read()()[0].key, core.cp));

	// just send connect request (shadowsocks 2012 protocol spec)
	// no need to wait answer: stream mode just after request

	u8 packet[512];
	netkit::pgen pg(packet, 512);

	proxy_socks5::push_atyp(pg, addr2);

    return (p_enc->send(packet, pg.ptr) == netkit::pipe::SEND_FAIL) ? netkit::pipe_ptr() : p_enc;
}

/*virtual*/ std::unique_ptr<netkit::udp_pipe> proxy_shadowsocks::prepare(netkit::udp_pipe* transport) const
{
	return std::make_unique<ss::core::udp_crypto_pipe>(addr, transport, core.masterkeys.lock_read()()[0].key, core.cp);
}

/*virtual*/ void proxy_shadowsocks::api(json_saver& j) const
{
    proxy::api(j);
    j.field(ASTR("type"), ASTR("shadowsocks"));
}



