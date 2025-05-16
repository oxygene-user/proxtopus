#include "pch.h"

handler_ss::handler_ss(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st) :handler(ldr, owner, bb)
{
	core.load(ldr, owner->get_name(), bb);

    if (netkit::ST_UDP == st)
    {
        udp_timeout_ms = bb.get_int(ASTR("udp-timeout"), udp_timeout_ms);
    }

	allow_private = bb.get_bool(ASTR("allow-private"), true);
}

void handler_ss::handle_pipe(netkit::pipe* raw_pipe)
{
	DL(DLCH_THREADS, "ss worker in ($)", glb.numtcp);

	netkit::pipe_ptr p(raw_pipe);
	netkit::pipe_ptr p_enc;
	auto mkr = core.masterkeys.lock_read();
	if (mkr().size() == 0)
		return; // inactive

    u8 packet[512];

	if (mkr().size() == 1)
	{
		str::astr k = mkr()[0].key;
        mkr.unlock();
		p_enc = NEW ss::core::crypto_pipe(p, std::move(core.cb()), k, core.cp);

        if (signed_t rb = p_enc->recv(packet, -2); rb != 2)
            return;

	}
	else
	{
		mkr.unlock();

		/*
		p_enc = NEW ss::core::multipass_crypto_pipe(p, std::move(core.cb()), core.masterkeys, core.cp);
        if (signed_t rb = p_enc->recv(packet, -2); rb != 2)
            return;
			*/

		ss::core::multipass_crypto_pipe multipass(p, std::move(core.cb()), core.masterkeys, core.cp);

        if (signed_t rb = multipass.recv(packet, -2); rb != 2)
            return;

        p_enc = NEW ss::core::crypto_pipe(multipass);

	}

	netkit::endpoint ep;
	signed_t len;

	switch (packet[0])
	{
	case 1: // ip4
		if (signed_t rb = p_enc->recv(packet + 2, -3); rb != 3)
			return;

		ep.set_ipap(netkit::ipap::build(packet + 1, 4));
		break;
	case 3: // domain name

		len = packet[1]; // len of domain
		if (signed_t rb = p_enc->recv(packet, -len); rb != len)
			return;
		ep.set_domain(std::string((const char*)packet, len));
		break;

	case 4: // ipv6
		if (signed_t rb = p_enc->recv(packet + 2, -15); rb != 15)// read 15 of 16 bytes of ipv6 address (1st byte already read)
			return;
		ep.set_ipap(netkit::ipap::build(packet + 1, 16));
        break;
	}

	if (!allow_private && ep.state() == netkit::EPS_RESLOVED && ep.get_ip().is_private())
        return;

	if (signed_t rb = p_enc->recv(packet, -2); rb != 2)
		return;

	signed_t port = ((signed_t)packet[0]) << 8 | packet[1];
	ep.set_port(port);

	if (netkit::pipe_ptr outcon = connect(ep, false))
		bridge(/*ep,*/ std::move(p_enc), std::move(outcon));

	DL(DLCH_THREADS, "ss worker out ($)", glb.numtcp);
}

namespace
{
	struct udp_cipher : netkit::thread_storage_data
	{
		std::unique_ptr<ss::core::cryptor> crypto;
        randomgen rng;
		buffer buf2s;
		signed_t password_index = -1;

		udp_cipher(std::unique_ptr<ss::core::cryptor>&& c)
		{
			crypto = std::move(c);
		}
	};
}

/*virtual*/ bool handler_ss::handle_packet(netkit::thread_storage& ctx, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg)
{
	// decipher and extract endpoint

    if (ctx.data == nullptr)
        ctx.data.reset(NEW udp_cipher(std::move(core.cb())));
    udp_cipher* context = static_cast<udp_cipher*>(ctx.data.get());

    u8 skey[ss::core::maximum_key_size];
    std::span<u8> subkey(skey, core.cp.KeySize);

    ss::outbuffer buf2r;
	auto mkr = core.masterkeys.lock_read();
	signed_t pwdi = context->password_index;
	if (pwdi < 0)
	{
		pwdi = 0;
        i64 cur_sec = chrono::now();
		for (signed_t pwdi_end = mkr().size(); pwdi < pwdi_end; ++pwdi)
        {
			const ss::core::masterkey& k = mkr()[pwdi];
            if (k.expired < 0)
                continue;
            if (k.expired > 0 && k.expired < cur_sec)
            {
                const_cast<ss::core::masterkey&>(k).expired = -1; // acceptable hack due it final state of masterkey
                continue;
            }

            ss::deriveAeadSubkey(skey, k.key, std::span<const u8>(p.packet, core.cp.KeySize));
            bool ok = context->crypto->decipher(buf2r, std::span<const u8>(p.packet + core.cp.KeySize, p.sz - core.cp.KeySize), &subkey);
			if (ok)
			{
				mkr.unlock();
				context->password_index = pwdi;
				break;
			}
        }
	}
	else
	{
		const ss::core::masterkey& k = mkr()[pwdi];
		if (k.expired < 0)
			return false;

        ss::deriveAeadSubkey(skey, k.key, std::span<const u8>(p.packet, core.cp.KeySize));
		mkr.unlock();
        bool ok = context->crypto->decipher(buf2r, std::span<const u8>(p.packet + core.cp.KeySize, p.sz - core.cp.KeySize), &subkey);
		if (!ok)
			return false;
	}

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

	auto mkr = core.masterkeys.lock_read();
    ss::deriveAeadSubkey(subkey, mkr()[context->password_index].key, context->buf2s);
	mkr.unlock();

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
	LOG_N("new UDP ss-stream ($ <-> $) via listener [$]", from.to_string(true), to.desc(), str::clean(owner->get_name()));
}
