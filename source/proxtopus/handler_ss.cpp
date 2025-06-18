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
	netkit::pipe_ptr p(raw_pipe);
	netkit::pipe_ptr p_enc;
	auto mkr = core.masterkeys.lock_read();
	if (mkr().size() == 0)
		return; // inactive

    std::array<u8,512> packet;
	tools::circular_buffer_extdata rcvdata(packet);

	if (mkr().size() == 1)
	{
		ss::core::keyspace* key = NEW ss::core::keyspace(mkr()[0].key);
        mkr.unlock();
		p_enc = NEW ss::core::crypto_pipe(p, key, core.cp);

		ostools::set_current_thread_name(ASTR("ss-cp1"));

        if (signed_t rb = p_enc->recv(rcvdata, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 2)
            return;

	}
	else
	{
		mkr.unlock();

		/*
		p_enc = NEW ss::core::multipass_crypto_pipe(p, std::move(core.build_crypto(false)), core.masterkeys, core.cp);
        if (signed_t rb = p_enc->recv(packet, -2); rb != 2)
            return;
			*/

		ss::core::multipass_crypto_pipe multipass(p, core.masterkeys, core.cp);

		ostools::set_current_thread_name(ASTR("ss-cp2"));

        if (signed_t rb = multipass.recv(rcvdata, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 2)
            return;

        p_enc = NEW ss::core::crypto_pipe(multipass);

	}

	netkit::endpoint ep;
	signed_t len;

	switch (packet[0])
	{
	case 1: // ip4

		ostools::set_current_thread_name(ASTR("ss-cp3"));

		if (signed_t rb = p_enc->recv(rcvdata, 2+3, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 5)
			return;

		ep.set_ipap(netkit::ipap::build(packet.data() + 1, 4));
		rcvdata.skip(2 + 3);
		break;
	case 3: // domain name

		len = packet[1]; // len of domain
		rcvdata.skip(2);

		ostools::set_current_thread_name(ASTR("ss-cp4"));

		if (signed_t rb = p_enc->recv(rcvdata, len, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb == len)
		{
            const char* dm = (const char*)rcvdata.data1st(len);
            ep.set_domain(str::astr_view(dm, len));
            rcvdata.skip(len);
			break;
		}
		return;

	case 4: // ipv6
		if (signed_t rb = p_enc->recv(rcvdata, 2+15, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 17) // read 15 of 16 bytes of ipv6 address (1st byte already read)
			return;

		ostools::set_current_thread_name(ASTR("ss-cp5"));

		ep.set_ipap(netkit::ipap::build(packet.data() + 1, 16));
		rcvdata.skip(2 + 15);
        break;
	}

	if (!allow_private && ep.state() == netkit::EPS_RESLOVED && ep.get_ip().is_private())
        return;

	ostools::set_current_thread_name(ASTR("ss-cp6"));

	if (signed_t rb = p_enc->recv(rcvdata, 2, RECV_PREPARE_MODE_TIMEOUT DST(, nullptr)); rb != 2)
		return;

	const u8* port_ptr = rcvdata.data1st(2);
	signed_t port = ((signed_t)port_ptr[0]) << 8 | port_ptr[1];
	ep.set_port(port);
	rcvdata.skip(2);

	ostools::set_current_thread_name(ASTR("ss-cp7"));

	if (netkit::pipe_ptr outcon = connect(ep, false))
	{
		ostools::set_current_thread_name(ASTR("ss-cp8"));

		p_enc->unrecv(rcvdata);
		glb.e->bridge(std::move(p_enc), std::move(outcon));
	}

	ostools::set_current_thread_name(ASTR("ss-cp9"));
}

namespace
{
	struct udp_cipher : netkit::thread_storage_data
	{
		std::unique_ptr<ss::core::cryptor> crypto;
        randomgen rng;
		buffer buf2s;
		signed_t password_index = -1;

		udp_cipher(ss::core::crypto_par cp)
		{
			crypto = cp.build_crypto(true);
		}
	};
}

/*virtual*/ bool handler_ss::handle_packet(netkit::thread_storage& ctx, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg)
{
	// decipher and extract endpoint

    if (ctx.data == nullptr)
        ctx.data.reset(NEW udp_cipher(core.cp));
    udp_cipher* context = static_cast<udp_cipher*>(ctx.data.get());

    ss::core::keyspace skey;
    std::span<u8> subkey(skey.space, core.cp.KeySize);

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

            ss::derive_aead_subkey(skey.space, k.key.space, p.packet, core.cp.KeySize);
			tools::circular_buffer_extdata cd(std::span<u8>(p.packet + core.cp.KeySize, p.sz - core.cp.KeySize), true);
            bool ok = context->crypto->decipher(buf2r, cd, &subkey);
			if (ok)
			{
				mkr.unlock();
				context->password_index = pwdi;
				break;
			}
        }
		if (context->password_index < 0)
			return false;
	}
	else
	{
		const ss::core::masterkey& k = mkr()[pwdi];
		if (k.expired < 0)
			return false;

        ss::derive_aead_subkey(skey.space, k.key.space, p.packet, core.cp.KeySize);
		mkr.unlock();
		tools::circular_buffer_extdata cd(std::span<u8>(p.packet + core.cp.KeySize, p.sz - core.cp.KeySize), true);
        bool ok = context->crypto->decipher(buf2r, cd, &subkey);
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
    ss::core::keyspace skey;
    std::span<u8> subkey(skey.space, core.cp.KeySize);

	auto mkr = core.masterkeys.lock_read();
	ss::core::keyspace key(mkr()[context->password_index].key);
    mkr.unlock();
    ss::derive_aead_subkey(skey.space, key.space, context->buf2s.data(), core.cp.KeySize);

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
