#include "pch.h"

handler_ss::handler_ss(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st) :handler(ldr, owner, bb)
{
	core.load(ldr, owner->get_name(), bb);

    if (netkit::ST_UDP == st)
    {
        udp_timeout_ms = bb.get_int(ASTR("udp-timeout"), udp_timeout_ms);
    }

}

void handler_ss::on_pipe(netkit::pipe* pipe)
{
	std::thread th(&handler_ss::worker, this, pipe);
	th.detach();
}

void handler_ss::worker(netkit::pipe* raw_pipe)
{
	netkit::pipe_ptr p(raw_pipe);
	netkit::pipe_ptr p_enc(new ss::core::crypto_pipe(p, std::move(core.cb()), core.masterKey, core.cp));

	u8 packet[512];
	signed_t rb = p_enc->recv(packet, -2);
	if (rb != 2)
		return;

	netkit::endpoint ep;
	signed_t len;

	switch (packet[0])
	{
	case 1: // ip4
		rb = p_enc->recv(packet + 2, -3);
		if (rb != 3)
			return;

		ep.set_ipap(netkit::ipap::build(packet + 1, 4));
		break;
	case 3: // domain name

		len = packet[1]; // len of domain
		rb = p_enc->recv(packet, -len);
		if (rb != len)
			return;
		ep.set_domain(std::string((const char*)packet, len));
		break;

	case 4: // ipv6
		/* ipv6 not supported yet */
		p_enc->recv(packet+2, -15); // read 15 of 16 bytes of ipv6 address (1st byte already read)
		ep.set_ipap(netkit::ipap::build(packet + 1, 16));
		return;
	}

	rb = p_enc->recv(packet, -2);
	if (rb != 2)
		return;

	signed_t port = ((signed_t)packet[0]) << 8 | packet[1];
	ep.set_port(port);

	if (netkit::pipe_ptr outcon = connect(ep, false))
		bridge(/*ep,*/ std::move(p_enc), std::move(outcon));
}

namespace
{
	struct udp_cipher : netkit::thread_storage_data
	{
		std::unique_ptr<ss::core::cryptor> crypto;
        randomgen rng;
		buffer buf2s;

		udp_cipher(std::unique_ptr<ss::core::cryptor>&& c)
		{
			crypto = std::move(c);
		}
	};
}

/*virtual*/ bool handler_ss::handle_packet(netkit::thread_storage& ctx, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg)
{
	// decipher and extract endpoint

    u8 skey[ss::core::maximum_key_size];
    std::span<u8> subkey(skey, core.cp.KeySize);
    core.deriveAeadSubkey(subkey, std::span<const u8>(p.packet, core.cp.KeySize));

	if (ctx.data == nullptr)
		ctx.data.reset(new udp_cipher( std::move(core.cb()) ));
	udp_cipher* context = static_cast<udp_cipher*>(ctx.data.get());

	ss::outbuffer buf2r;
	context->crypto->decipher(buf2r, std::span<const u8>(p.packet + core.cp.KeySize, p.sz - core.cp.KeySize), &subkey);
    auto decp = buf2r.get_1st_chunk();
    if (decp.size() == 0)
        return false;
    netkit::pgen repg((u8*)decp.data(), decp.size());
    if (!proxy_socks5::read_atyp(repg, epr))
        return false;

    std::span<const u8> p2s(decp.data() + repg.ptr, decp.size() - repg.ptr);
    memcpy(p.packet, p2s.data(), p2s.size());
    p.sz = tools::as_word(p2s.size());
    pg.set(p, 0);

    return true;
}

/*virtual*/ bool handler_ss::encode_packet(netkit::thread_storage& ctx, const netkit::ipap& from, netkit::pgen& pg)
{
	// encipher to send to client
	udp_cipher* context = static_cast<udp_cipher*>(ctx.data.get());
	context->buf2s.resize(core.cp.KeySize);
	context->rng.random_vec(context->buf2s);
    u8 skey[ss::core::maximum_key_size];
    std::span<u8> subkey(skey, core.cp.KeySize);
    core.deriveAeadSubkey(subkey, context->buf2s);

	netkit::endpoint ep(from);
    signed_t presize = proxy_socks5::atyp_size(ep);
    if (presize <= pg.extra)
    {
        netkit::pgen pgx(const_cast<u8*>(pg.get_data() - presize), presize + pg.sz);
        proxy_socks5::push_atyp(pgx, ep);
        context->crypto->encipher(pgx.to_span(), context->buf2s, &subkey);
    }
    else
    {
        u8* b2e = ALLOCA(pg.sz + presize);
        netkit::pgen pgx(b2e, presize + pg.sz);
        proxy_socks5::push_atyp(pgx, ep);
        memcpy(b2e + presize, pg.get_data(), pg.sz);
		context->crypto->encipher(pgx.to_span(), context->buf2s, &subkey);
    }

	pg.set_extra(0);
	memcpy(pg.get_data(), context->buf2s.data(), context->buf2s.size());
	pg.sz = tools::as_word(context->buf2s.size());

	return true;
}

/*virtual*/ void handler_ss::log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to)
{
	LOG_N("new UDP ss-stream (%s <-> %s) via listener [%s]", from.to_string(true).c_str(), to.desc().c_str(), str::printable(owner->get_name()));
}
