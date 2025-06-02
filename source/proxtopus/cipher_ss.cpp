#include "pch.h"
#include "botan/internal/md5.h"
#include "botan/internal/gcm.h"
#include "botan/internal/aes.h"

std::unique_ptr<Botan::Cipher_Mode> ss::botan_aead::make_aesgcm_128(bool enc)
{
	auto bc = std::make_unique<Botan::AES_128>();

	if (enc) {
		return std::make_unique<Botan::GCM_Encryption>(std::move(bc), SS_AEAD_TAG_SIZE);
	}
	else {
		return std::make_unique<Botan::GCM_Decryption>(std::move(bc), SS_AEAD_TAG_SIZE);
	}
}
std::unique_ptr<Botan::Cipher_Mode> ss::botan_aead::make_aesgcm_192(bool enc)
{
	auto bc = std::make_unique<Botan::AES_192>();

	if (enc) {
		return std::make_unique<Botan::GCM_Encryption>(std::move(bc), SS_AEAD_TAG_SIZE);
	}
	else {
		return std::make_unique<Botan::GCM_Decryption>(std::move(bc), SS_AEAD_TAG_SIZE);
	}

}

std::unique_ptr<Botan::Cipher_Mode> ss::botan_aead::make_aesgcm_256(bool enc)
{
	auto bc = std::make_unique<Botan::AES_256>();

	if (enc) {
		return std::make_unique<Botan::GCM_Encryption>(std::move(bc), SS_AEAD_TAG_SIZE);
	}
	else {
		return std::make_unique<Botan::GCM_Decryption>(std::move(bc), SS_AEAD_TAG_SIZE);
	}

}


void md5Hash(str::astr &out, const str::astr_view& in)
{
	Botan::MD5 md5;
	md5.update(in);
	out.resize( md5.output_length() );
	md5.final( str::span(out) );
}

str::astr evpBytesToKey(unsigned keyLen, const str::astr_view& password)
{
	str::astr mss, prevm;
	for (;;) {
		prevm += password;
		md5Hash(prevm, prevm);
		mss += prevm;
		if (mss.size() >= keyLen)
		{
			mss.resize(keyLen);
			break;
		}
	}

	return mss;
}

std::unique_ptr<ss::core::cryptor> ss::core::crypto_par::build_crypto(bool udp) const
{
	switch (cryptoalg)
	{
	case crypto_chachapoly:
        if (NonceSize == 24)
        {
            if (udp)
                return std::move(std::make_unique<aead_chacha20poly1305_cryptor<24, true>>());
            return std::move(std::make_unique<aead_chacha20poly1305_cryptor<24, false>>());
        }
        if (udp)
            return std::move(std::make_unique<aead_chacha20poly1305_cryptor<12, true>>());
        return std::move(std::make_unique<aead_chacha20poly1305_cryptor<12, false>>());

	case crypto_aesgcm_256:
        return std::move(std::make_unique<botan_aead_cryptor>(*this, ss::botan_aead::make_aesgcm_256));
    case crypto_aesgcm_192:
        return std::move(std::make_unique<botan_aead_cryptor>(*this, ss::botan_aead::make_aesgcm_192));
    case crypto_aesgcm_128:
        return std::move(std::make_unique<botan_aead_cryptor>(*this, ss::botan_aead::make_aesgcm_128));
	}
    return std::move(std::make_unique<none_cryptor>());

}

void ss::botan_aead::keyed_filter::set_key(std::span<const u8> key, cipher* ciph)
{
    mode->set_key(key);
    memset(iv.data(), 0, sizeof(iv));

    ASSERT(m_next.size() == 1);
    m_next[0] = ciph;
}

/*virtual*/ void ss::botan_aead::keyed_filter::write(const uint8_t input[], size_t input_length)
{
	size_t idealg = mode->ideal_granularity();
	size_t mfz = idealg + mode->minimum_final_size();

	while (input_length >= mfz) {

		buf.assign(input, input + idealg);
		mode->update(buf);
		send(buf.data(), buf.size());

		input += idealg;
		input_length -= idealg;
	}

	if (input_length > 0)
		buf.assign(input, input + input_length);
	else
		buf.clear();

}

/*virtual*/ void ss::botan_aead::keyed_filter::end_msg()
{
	mode->finish(buf);
	send(buf.data(), buf.size());
	incnonce();
}

void ss::botan_aead::cipher_enc::process(std::span<const u8> input, buffer&output)
{
    current_output = &output;
	output.reserve(output.size() + input.size() + SS_AEAD_TAG_SIZE, output.size());
    //size_t offset = output.size();
	recoder.start_msg();
    recoder.write(input.data(), input.size());
    recoder.end_msg();
    //return output.size() == offset + input.size() + SS_AEAD_TAG_SIZE; // no need to check encoding, it always ok
}

bool ss::botan_aead::cipher_dec::process(std::span<const u8> input, tools::memory_pair& output)
{
	handled = 0;
	current_output = &output;
    try
    {
		Botan::Exception::quiet(true);
        recoder.start_msg();
        recoder.write(input.data(), input.size());
        recoder.end_msg();
		Botan::Exception::quiet(false);
    }
    catch (...)
    {
        return false;
    }

	return handled + SS_AEAD_TAG_SIZE == input.size();
}



str::astr ss::core::load(loader& ldr, const str::astr& name, const asts& bb)
{
	const str::astr &url = bb.get_string(ASTR("url"), glb.emptys);

	str::astr method = bb.get_string(ASTR("method"), glb.emptys);
	str::astr password = bb.get_string(ASTR("password"), glb.emptys);
	str::astr addr;

	if (url.starts_with(ASTR("ss://")))
	{
		size_t x = url.find('@');
		if (x != url.npos)
		{
			size_t y = url.find('#', x+1);
			if (y == url.npos) y = url.length();
			addr = url.substr(x + 1, y);
			char *outb = (char*)ALLOCA(x);
			signed_t sz = str::decode_base64(str::astr_view(url.data() + 5, x - 5), outb, x);
			str::astr_view dec(outb, sz);
			size_t z = dec.find(':');
			if (z != dec.npos)
			{
				method = dec.substr(0, z);
				password = dec.substr(z + 1);
			}
		}
	}

	bool allow_empty_password = false;

	if (method.starts_with(ASTR("xchacha20")))
	{
        LOG_W("meaningless cipher method used in shadowsocs core [$]; there are no advantages for using xchacha20 instead of chacha20-ietf; do not use xchacha20 unless a gun is held to your head", str::clean(name));

		cp = { 32, 24, crypto_chachapoly };
	}
	else if (method.starts_with(ASTR("chacha20")))
	{
		cp = { 32, 12, crypto_chachapoly };
	}
	else if (method == ASTR("aes-256-gcm"))
	{
		cp = { 32, 12, crypto_aesgcm_256 };
	}
	else if (method == ASTR("aes-192-gcm"))
	{
		cp = { 24, 12, crypto_aesgcm_192 };
	}
	else if (method == ASTR("aes-128-gcm"))
	{
		cp = { 16, 12, crypto_aesgcm_128 };
	}
	else if (method == ASTR("none"))
	{
		cp = { 0, 0, crypto_none };
		allow_empty_password = true;
	}
	else
	{
		ldr.exit_code = EXIT_FAIL_METHOD_UNDEFINED;
		LOG_FATAL("{method} not defined for shadowsocks core [$]", str::clean(name));
		return str::astr();
	}

	auto mkw = masterkeys.lock_write();

	if (!password.empty())
	{
		auto& mk = mkw().emplace_back();
		mk.name = ASTR("main");
		mk.key = evpBytesToKey(cp.KeySize, password);
	}

	if (const asts* pwds = bb.get(ASTR("passwords")))
	{
		for (auto it = pwds->begin(); it; ++it)
		{
            const str::astr_view& p = str::trim(str::view(it->as_string(password)));
            if (p.empty())
                continue;

            auto& mk1 = mkw().emplace_back();
            mk1.name = it.name();
            mk1.key = evpBytesToKey(cp.KeySize, p);

			for (signed_t i=0, cnt = mkw().size()-1; i<cnt; ++i)
			{
				if (mkw()[i].key == mk1.key)
				{
					// do not dup masterkeys
					mkw().resize(mkw().size()-1);
					break;
				}
			}
		}
	}

	if (mkw().size() == 0 && !allow_empty_password)
	{
        ldr.exit_code = EXIT_FAIL_NO_PASSWORDS_DEFINED;
        LOG_FATAL("no password defined for shadowsocks core [$]", str::clean(name));
        return str::astr();
	}

	return addr;
}

void ss::core::crypto_pipe_base::generate_outgoing_salt()
{
    randomgen rng;
    encrypted_data.resize(cp.KeySize);
    rng.random_vec(encrypted_data);
}

/*virtual*/ void ss::core::crypto_pipe_base::close(bool flush_before_close)
{
    bool io = spinlock::increment_by(busy, 10001) > 0;
    if (!io && pipe)
    {
        pipe->close(flush_before_close);
        pipe = nullptr;
    }
}

/*virtual*/ netkit::WAITABLE ss::core::crypto_pipe_base::get_waitable()
{
    if (!pipe)
        return NULL_WAITABLE;

    incdec ddd(busy, this);
    if (ddd) return NULL_WAITABLE;

    auto r = pipe->get_waitable();
    if (!decrypted_data.is_empty())
        netkit::make_ready(r, READY_PIPE);
    else
        netkit::clear_ready(r, READY_PIPE);
    return r;
}


/*virtual*/ bool ss::core::crypto_pipe_base::unrecv(const u8* data, signed_t sz)
{
    if (pipe && sz > 0)
    {
        decrypted_data.insert(std::span(data, sz));
        netkit::make_ready(pipe->get_waitable(), READY_PIPE);
    }
    return true;
}

/*virtual*/ netkit::pipe::sendrslt ss::core::crypto_pipe_base::send(const u8* data, signed_t datasize)
{
    if (!pipe)
        return SEND_FAIL;

    incdec ddd(busy, this);
    if (ddd) return SEND_FAIL;

    if (data == nullptr)
        return pipe->send(nullptr, 0); // check allow send

    if (datasize != 0)
        crypto->encipher(std::span<const u8>(data, datasize), encrypted_data, nullptr);
    sendrslt rslt = pipe->send(encrypted_data.data(), encrypted_data.size());
    encrypted_data.clear(); // IMPORTANT: clear after send, not before (due encrypted_data contains salt before 1st send)

    return rslt;
}

/*virtual*/ signed_t ss::core::crypto_pipe_base::recv(u8* data, signed_t maxdatasz)
{
    if (!pipe)
        return -1;

    incdec ddd(busy, this);
    if (ddd) return -1;

    u8 temp[65536];

	if (!crypto->is_decryptor_init() && !init_decryptor(temp))
		return -1;

    bool do_recv = decrypted_data.is_empty();
    if (do_recv)
        netkit::clear_ready(get_waitable(), READY_PIPE);
    else if (maxdatasz < 0 && !decrypted_data.enough(-maxdatasz))
        do_recv = true;

    signed_t recvsize = sizeof(temp);
    for (;; do_recv = true)
    {
        signed_t sz = do_recv ? pipe->recv(temp, recvsize) : 0;
        if (sz < 0)
            return sz;

        if (sz > 0)
        {
            if (!crypto->decipher(decrypted_data, std::span<const u8>(temp, sz), nullptr)) // try decrypt
                return -1;
        }

        if (maxdatasz < 0)
        {
            signed_t required = -maxdatasz; // required size to recv

			if (!decrypted_data.enough(required))
			{
				signed_t upsz = crypto->get_unprocessed_size();
				signed_t required_upsz = required + SS_AEAD_TAG_SIZE;
				ASSERT(required_upsz > upsz);
				recvsize = upsz - required_upsz; // negative value for recv
				continue; // not enough data
			}

            decrypted_data.peek(data, required);
            return required;
        }
        break;
    }
    signed_t rv = 0;
    if (decrypted_data.enough_for(maxdatasz))
    {
        // just copy whole decrypted data
        rv = decrypted_data.peek(data);
    }
    else
    {
        // output buffer is smaller then decrypted
        // copy some

        rv = decrypted_data.peek(data, maxdatasz);
        ASSERT(rv = maxdatasz);
    }

    return rv;
}

ss::core::crypto_pipe::crypto_pipe(netkit::pipe_ptr pipe, const str::astr & master_key, crypto_par cp) :crypto_pipe_base(pipe, cp), master_key(master_key)
{
	generate_outgoing_salt();

	u8 skey[maximum_key_size];
	ss::deriveAeadSubkey(std::span<u8>(skey, cp.KeySize), master_key, encrypted_data);
    crypto = cp.build_crypto(false);
	crypto->init_encryptor(std::span<u8>(skey, cp.KeySize));
}

/*virtual*/ bool ss::core::crypto_pipe::init_decryptor(u8* temp)
{
    signed_t rb = pipe->recv(temp, -(signed_t)cp.KeySize);
	if (rb != cp.KeySize)
		return false;

    ss::deriveAeadSubkey(std::span<u8>(temp + cp.KeySize, cp.KeySize), master_key, std::span<u8>(temp, cp.KeySize));

    // clear masterkey (not required anymore)
    str::astr mkc = std::move(master_key);
    memset(mkc.data(), 0, mkc.size());

    crypto->init_decryptor(std::span<u8>(temp + cp.KeySize, cp.KeySize));

	return true;
}

namespace {

	struct multipass_crypto : public ss::core::cryptor
	{
        std::unique_ptr<ss::core::cryptor> crypto;
        u8 nonce[ss::core::maximum_key_size];
		ss::core::masterkey_array& mks;
		const buffer& outsalt;
		str::astr maskerkey;

		enum
        {
            init_none,
            init_rcv_nonce,
			init_full,

        } init = init_none;

		multipass_crypto(ss::core::crypto_par p, ss::core::masterkey_array& mks, const buffer& outsalt):cryptor(p), mks(mks), outsalt(outsalt)
		{
			crypto = p.build_crypto(false);
		}

        /*virtual*/ bool is_decryptor_init() const override { return init != init_none; }

		/*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key) override
		{
			ASSERT(init == init_full);
			if (init == init_full)
			{
				crypto->encipher(plain, cipher, key);
			}
		}
		/*virtual*/ bool decipher(ss::outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* key) override
		{
			// TODO : selection cache

			ASSERT(init != init_none);

			[[unlikely]] if (init == init_rcv_nonce)
			{
				ASSERT(plain.is_empty());

				u8 temp[ss::core::maximum_key_size];

				[[likely]] if (key == nullptr && crypto->prebuf(cipher))
                {
					i64 cur_sec = chrono::now();
					bool ned = false;
                    auto mkr = mks.lock_read();
                    for (const auto& k : mkr())
                    {
						if (k.expired < 0)
							continue;
						if (k.expired > 0 && k.expired < cur_sec)
						{
							const_cast<ss::core::masterkey&>(k).expired = -1; // acceptable hack due it final state of masterkey
							continue;
						}

                        ss::deriveAeadSubkey(std::span<u8>(temp, pars.KeySize), k.key, nonce);
                        crypto->init_decryptor(std::span<u8>(temp, pars.KeySize));
						auto r = crypto->decipher_prebuffered(plain);
						if (r == dr_ok)
						{
							assume_init:
                            maskerkey = k.key;
							mkr.unlock();

							init = init_full;

							// now init encipher with found key
							ASSERT(outsalt.size() == pars.KeySize);
							ss::deriveAeadSubkey(std::span<u8>(temp, pars.KeySize), maskerkey, std::span(outsalt.data(), pars.KeySize));
							crypto->init_encryptor(std::span<u8>(temp, pars.KeySize));
							break;
						}
						else if (r == dr_not_enough_data)
						{
							if (!plain.is_empty()) // some data was decrypted
								goto assume_init;

							ned = true;
							break;
						}
                    }

					if (init != init_full)
						return ned;

					return true;
				}
				else
				{
					// no need to support non-aead cryptor
					return false;
				}
			}

			return crypto->decipher(plain, cipher, key);
		}

        /*virtual*/ bool prebuf(std::span<const u8> /*cipher_data*/) { return false; }
        /*virtual*/ dec_rslt decipher_prebuffered(ss::outbuffer& /*plain*/) { return dr_unsupported; }

	};
}

ss::core::crypto_pipe::crypto_pipe(ss::core::multipass_crypto_pipe& mpcp) :crypto_pipe_base(mpcp.get_pipe(), mpcp.get_pars())
{
	mpcp.pipe = nullptr;
    multipass_crypto* mpc = static_cast<multipass_crypto*>(mpcp.crypto.get());
	ASSERT(mpc->init == multipass_crypto::init_full);
	crypto = std::move(mpc->crypto);
	encrypted_data = std::move(mpcp.encrypted_data);
    decrypted_data = std::move(mpcp.decrypted_data);
}

ss::core::multipass_crypto_pipe::multipass_crypto_pipe(netkit::pipe_ptr pipe, masterkey_array &mks, crypto_par cp) :crypto_pipe_base(pipe, cp)
{
	generate_outgoing_salt();
    crypto.reset( NEW multipass_crypto(cp, mks, encrypted_data) );
}

/*virtual*/ bool ss::core::multipass_crypto_pipe::init_decryptor([[maybe_unused]] u8* temp)
{
    multipass_crypto* c = static_cast<multipass_crypto*>(crypto.get());

    ASSERT(c->init == multipass_crypto::init_none);

    if (signed_t rb = pipe->recv(c->nonce, -(signed_t)cp.KeySize); rb != cp.KeySize)
        return false;

    c->init = multipass_crypto::init_rcv_nonce;

    return true;
}

ss::core::udp_crypto_pipe::udp_crypto_pipe(const netkit::endpoint& ssproxyep, netkit::udp_pipe* transport, str::astr master_key, crypto_par cp) :transport(transport), master_key(master_key), cp(cp), ssproxyep(ssproxyep)
{
    crypto = cp.build_crypto(true);
}

/*virtual*/ netkit::io_result ss::core::udp_crypto_pipe::send(const netkit::endpoint& toaddr, const netkit::pgen& pg /* in */)
{
	signed_t presize = proxy_socks5::atyp_size(toaddr);
	buf2s.resize(cp.KeySize);

	u8 skey[maximum_key_size];
    rng.random_vec(buf2s); // make initial salt as starting sequence

	std::span<u8> subkey(skey, cp.KeySize);
    ss::deriveAeadSubkey(subkey, master_key, buf2s);

    if (presize <= pg.extra)
    {
        netkit::pgen pgx(const_cast<u8 *>(pg.get_data() - presize), presize + pg.sz);
        proxy_socks5::push_atyp(pgx, toaddr);
        crypto->encipher(pgx.to_span(), buf2s, &subkey);
	}
	else
	{
		u8* b2e = ALLOCA(pg.sz + presize);
        netkit::pgen pgx(b2e, presize + pg.sz);
        proxy_socks5::push_atyp(pgx, toaddr);
		memcpy(b2e + presize, pg.get_data(), pg.sz);
        crypto->encipher(pgx.to_span(), buf2s, &subkey);
	}
	netkit::pgen pgs(buf2s.data(), buf2s.size());
	return transport->send(ssproxyep, pgs);

}

/*virtual*/ netkit::io_result ss::core::udp_crypto_pipe::recv(netkit::ipap& from, netkit::pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/)
{
	u8 rcvbuf[16384];
	netkit::pgen pgr(rcvbuf, sizeof(rcvbuf));
	auto rslt = transport->recv(from, pgr, sizeof(rcvbuf));
	if (rslt != netkit::ior_ok)
		return rslt;

    u8 skey[maximum_key_size];
    std::span<u8> subkey(skey, cp.KeySize);
    ss::deriveAeadSubkey(subkey, master_key, std::span<const u8>(rcvbuf, cp.KeySize));
    ss::outbuffer buf2r;
	if (!crypto->decipher(buf2r, std::span<const u8>(rcvbuf + cp.KeySize, pgr.sz - cp.KeySize), &subkey))
		return netkit::ior_decrypt_fail;
	auto decp = buf2r.get_1st_chunk();
	if (decp.size() == 0)
		return netkit::ior_proxy_fail;
	netkit::pgen repg((u8 *)decp.data(), decp.size());
	netkit::endpoint aaa;
	if (!proxy_socks5::read_atyp(repg, aaa))
		return netkit::ior_proxy_fail;
	from = aaa.resolve_ip(glb.cfg.ipstack | conf::gip_log_it);
	if ((signed_t)(decp.size() - repg.ptr) > max_bufer_size)
		return netkit::ior_proxy_fail;
	memcpy(pg.get_data(), decp.data() + repg.ptr, decp.size() - repg.ptr);
	pg.sz = tools::as_word(decp.size() - repg.ptr);
	return netkit::ior_ok;
}

/*virtual*/ void ss::core::botan_aead_cryptor::init_encryptor(std::span<const u8> key)
{
	encryptor.set_key(key);
}

/*virtual*/ void ss::core::botan_aead_cryptor::init_decryptor(std::span<const u8> key)
{
	decryptor.set_key(key);
	buffered_decryptor::init_decryptor(key); // clear buffer
}

/*virtual*/ void ss::core::botan_aead_cryptor::encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key)
{
    auto encode = [this, &cipher](const u8* d, size_t sz)
    {
        encryptor.process(std::span<const u8>(d, sz), cipher);
    };

	if (key)
	{
		encryptor.set_key(*key);
		encode(plain.data(), plain.size());
		return;
	}

	u16 inLen = (u16)(0xffff & (plain.size() > SS_AEAD_CHUNK_SIZE_MASK ? SS_AEAD_CHUNK_SIZE_MASK : plain.size()));
	u16be size_be = inLen;

	// size block encode
	encode(reinterpret_cast<const u8*>(&size_be), sizeof(size_be));
	// payload block encode
	encode(plain.data(), inLen);

	if (inLen < plain.size()) {
		// Append the remaining part recursively if there is any
		encipher(std::span(plain.data() + inLen, plain.size() - inLen), cipher, key);
	}
}

signed_t ss::core::buffered_decryptor::decrypt_part(size_t& from, outbuffer& plain)
{
	auto decode = [this](signed_t skip, tools::memory_pair &out, size_t capacity) -> signed_t
	{
		if ((unprocessed.size() - skip) < capacity + SS_AEAD_TAG_SIZE)
			return 0;

		if (!decipher_packet(std::span<const u8>(unprocessed.data() + skip, capacity + SS_AEAD_TAG_SIZE), out))
			return -1;
		return capacity + SS_AEAD_TAG_SIZE;
	};

	size_t from_current = from;

	size_t payloadsize = last_block_payload_size;
	if (last_block_payload_size > 0)
	{
		ASSERT(from_current == 0);
		from_current = 2 + 16;
	}
	else
	{
		u16be payloadsize_network_endian;
		tools::memory_pair mp(payloadsize_network_endian);
		signed_t delta = decode(from_current, mp, sizeof(u16));
		if (delta < 0)
			return -1;
		if (delta == 0)
			return 0; // not yet ready data
		from_current += delta;
		payloadsize = payloadsize_network_endian;
		if (payloadsize > SS_AEAD_CHUNK_SIZE_MASK)
			return -1; // looks like chunk size is corrupted or wrong decrypted
		last_block_payload_size = payloadsize; // keep payloadsize in case of incomplete data because we have already increased IV

		if (payloadsize == 0)
			return -1;

	}

	if (payloadsize + SS_AEAD_TAG_SIZE > (unprocessed.size() - from_current))
		return 0; // not yet ready data

	auto mp = plain.alloc(payloadsize);

	signed_t d = decode(from_current, mp, payloadsize);
	if (d < 0)
		return -1;
	from_current += d;
	from = from_current;
	return payloadsize;
}

/*virtual*/ ss::core::cryptor::dec_rslt ss::core::buffered_decryptor::decipher_prebuffered(outbuffer& plain)
{
    size_t from = 0;
    signed_t decr = 0;
	bool not_enough = false;

    for (size_t usz = unprocessed.size(); from < usz;)
    {
        signed_t d = decrypt_part(from, plain);
        if (d < 0)
            return dr_fail;
		if (d == 0)
		{
			not_enough = true;
			break;
		}
        last_block_payload_size = 0;
        decr += d;
    }

    if (decr > 0)
    {
        if (from == unprocessed.size())
        {
            unprocessed.clear();
        }
        else
        {
            if (from == 0 && unprocessed.size() > SS_AEAD_CHUNK_SIZE_MASK)
            {
                // looks like data corrupt: decryptor can't process data
                return dr_fail;
            }
            unprocessed.erase(from);
        }
    }

    return not_enough ? dr_not_enough_data : dr_ok;
}

/*virtual*/ bool ss::core::botan_aead_cryptor::decipher(outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* key)
{
	if (key)
	{
		if (cipher.size() < SS_AEAD_TAG_SIZE)
			return false;
        decryptor.set_key(*key);
		auto mp = plain.alloc(cipher.size()-SS_AEAD_TAG_SIZE);
		return decryptor.process(cipher, mp);
	}

	unprocessed += cipher;
	return decipher_prebuffered(plain) != dr_fail;
}
