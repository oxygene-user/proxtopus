#include "pch.h"
#include "botan/internal/chacha20poly1305.h"
#include "botan/internal/gcm.h"
#include "botan/internal/aes.h"

std::unique_ptr<Botan::Cipher_Mode> ss::make_chachapoly(bool enc)
{
	if (enc) {
		return std::make_unique<Botan::ChaCha20Poly1305_Encryption>();
	}
	else {
		return std::make_unique<Botan::ChaCha20Poly1305_Decryption>();
	}
}
std::unique_ptr<Botan::Cipher_Mode> ss::make_aesgcm_128(bool enc)
{
	auto bc = std::make_unique<Botan::AES_128>();

	if (enc) {
		return std::make_unique<Botan::GCM_Encryption>(std::move(bc), AEAD_TAG_SIZE);
	}
	else {
		return std::make_unique<Botan::GCM_Decryption>(std::move(bc), AEAD_TAG_SIZE);
	}
}
std::unique_ptr<Botan::Cipher_Mode> ss::make_aesgcm_192(bool enc)
{
	auto bc = std::make_unique<Botan::AES_192>();

	if (enc) {
		return std::make_unique<Botan::GCM_Encryption>(std::move(bc), AEAD_TAG_SIZE);
	}
	else {
		return std::make_unique<Botan::GCM_Decryption>(std::move(bc), AEAD_TAG_SIZE);
	}

}

std::unique_ptr<Botan::Cipher_Mode> ss::make_aesgcm_256(bool enc)
{
	auto bc = std::make_unique<Botan::AES_256>();

	if (enc) {
		return std::make_unique<Botan::GCM_Encryption>(std::move(bc), AEAD_TAG_SIZE);
	}
	else {
		return std::make_unique<Botan::GCM_Decryption>(std::move(bc), AEAD_TAG_SIZE);
	}

}


void md5Hash(str::astr &out, const str::astr& in)
{
	Botan::MD5 md5;
	md5.update(in);
	out.resize( md5.output_length() );
	md5.final( str::span(out) );
}

str::astr evpBytesToKey(unsigned keyLen, const str::astr& password)
{
	str::astr mss, prevm;
	for (;;) {
		md5Hash(prevm, prevm + password);
		mss += prevm;
		if (mss.size() >= keyLen)
		{
			mss.resize(keyLen);
			break;
		}
	}

	return mss;
}


std::unique_ptr<ss::core::cryptor> ss::core::make_aead_crypto_chachapoly()
{
	return std::move(std::make_unique<aead_cryptor>(cp, ss::make_chachapoly));
}
std::unique_ptr<ss::core::cryptor> ss::core::make_aead_crypto_aesgcm_128()
{
	return std::move(std::make_unique<aead_cryptor>(cp, ss::make_aesgcm_128));
}
std::unique_ptr<ss::core::cryptor> ss::core::make_aead_crypto_aesgcm_192()
{
	return std::move(std::make_unique<aead_cryptor>(cp, ss::make_aesgcm_192));
}
std::unique_ptr<ss::core::cryptor> ss::core::make_aead_crypto_aesgcm_256()
{
	return std::move(std::make_unique<aead_cryptor>(cp, ss::make_aesgcm_256));
}
std::unique_ptr<ss::core::cryptor> ss::core::makeuncrypted()
{
	return std::move(std::make_unique<none_cryptor>());
}

void ss::keyed_filter::update_key(std::span<const u8> key)
{
    mode->set_key(key);
	iv.zeroise();
}

void ss::keyed_filter::setup(std::unique_ptr<Botan::Cipher_Mode>&& m, std::span<const u8> k, unsigned NonceSize, ss::cipher *ciph)
{
	mode = std::move(m);
	mode->set_key(k);
	iv.resize(NonceSize);
	iv.zeroise();

	ASSERT(m_next.size() == 1);
	m_next[0] = ciph;

}

/*virtual*/ void ss::keyed_filter::write(const uint8_t input[], size_t input_length)
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

/*virtual*/ void ss::keyed_filter::end_msg()
{
	mode->finish(buf);
	send(buf.data(), buf.size());
	incnonce();
}

void ss::cipher_enc::setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb)
{
	auto mode = cb(true);
	ASSERT(mode != nullptr);
	recoder.setup(std::move(mode), key, NonceSize, this);
}

bool ss::cipher_enc::process(std::span<const u8> input, buffer&output)
{
    current_output = &output;
	output.reserve(output.size() + input.size() + AEAD_TAG_SIZE);
    size_t offset = output.size();
	recoder.start_msg();
    recoder.write(input.data(), input.size());
    recoder.end_msg();
    return output.size() > offset;
}

void ss::cipher_dec::setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb)
{
	auto mode = cb(false);
	ASSERT(mode != nullptr);
	recoder.setup(std::move(mode), key, NonceSize, this);
}

bool ss::cipher_dec::process(std::span<const u8> input, data_acceptor &output)
{
	handled = 0;
	current_output = &output;
	recoder.start_msg();
	recoder.write(input.data(), input.size());
	recoder.end_msg();
	return handled + AEAD_TAG_SIZE == input.size();
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



	if (method == ASTR("xchacha20-ietf-poly1305"))
	{
		cp = { 32, 24 };
		cb = std::bind(&core::make_aead_crypto_chachapoly, this);
	}
	else if (method == ASTR("chacha20-ietf-poly1305"))
	{
		cp = { 32, 12 };
		cb = std::bind(&core::make_aead_crypto_chachapoly, this);
	}
	else if (method == ASTR("aes-256-gcm"))
	{
		cp = { 32, 12 };
		cb = std::bind(&core::make_aead_crypto_aesgcm_256, this);
	}
	else if (method == ASTR("aes-192-gcm"))
	{
		cp = { 24, 12 };
		cb = std::bind(&core::make_aead_crypto_aesgcm_192, this);
	}
	else if (method == ASTR("aes-128-gcm"))
	{
		cp = { 16, 12 };
		cb = std::bind(&core::make_aead_crypto_aesgcm_128, this);
	}
	else if (method == ASTR("none"))
	{
		cb = &makeuncrypted;
	}
	else
	{
		ldr.exit_code = EXIT_FAIL_METHOD_UNDEFINED;
		LOG_E("{method} not defined for proxy [%s]", str::printable(name));
		return str::astr();
	}

	masterKey = evpBytesToKey(cp.KeySize, password);
	return addr;
}

ss::core::crypto_pipe::crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<cryptor> &&c, const str::astr &masterKey, crypto_par cp) :pipe(pipe), masterKey(masterKey), cp(cp)
{
	randomgen rng;
	encrypted_data.resize(cp.KeySize);
	rng.random_vec(encrypted_data); // make initial salt as starting sequence

	u8 skey[maximum_key_size];
	ss::deriveAeadSubkey(std::span<u8>(skey, cp.KeySize), masterKey, encrypted_data);
	c->init_encryptor(std::span<u8>(skey, cp.KeySize));
	crypto = std::move(c);
}

/*virtual*/ ss::core::crypto_pipe::~crypto_pipe()
{
	close(true);
}

/*virtual*/ bool ss::core::crypto_pipe::alive()
{
	return pipe && pipe->alive();
}

/*virtual*/ netkit::pipe::sendrslt ss::core::crypto_pipe::send(const u8* data, signed_t datasize)
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

/*virtual*/ signed_t ss::core::crypto_pipe::recv(u8* data, signed_t maxdatasz)
{
	if (!pipe)
		return -1;

	incdec ddd(busy, this);
	if (ddd) return -1;

	u8 temp[65536];

	if (!crypto->is_decryptor_init())
	{
		signed_t rb = pipe->recv(temp, -(signed_t)cp.KeySize);
		if (rb != cp.KeySize)
			return -1;

		ss::deriveAeadSubkey(std::span<u8>(temp + cp.KeySize, cp.KeySize), masterKey, std::span<u8>(temp, cp.KeySize));
		crypto->init_decryptor(std::span<u8>(temp + cp.KeySize, cp.KeySize));
	}

	bool do_recv = decrypted_data.is_empty();
	if (do_recv)
		netkit::clear_ready(get_waitable(), READY_PIPE);
	for (;; do_recv = true)
	{
		signed_t sz = do_recv ? pipe->recv(temp, sizeof(temp)) : 0;
		if (sz < 0)
			return sz;

		if (sz > 0)
		{
			signed_t d = crypto->decipher(decrypted_data, std::span<const u8>(temp, sz), nullptr); // try decrypt
			if (d < 0)
				return -1;
		}

		if (maxdatasz < 0)
		{
			signed_t required = -maxdatasz; // required size to recv

			if (!decrypted_data.enough(required))
				continue; // not enough data


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

/*virtual*/ bool ss::core::crypto_pipe::unrecv(const u8* data, signed_t sz)
{
	if (pipe && sz > 0)
	{
		decrypted_data.insert(std::span(data, sz));
		netkit::make_ready(pipe->get_waitable(), READY_PIPE);
	}
	return true;
}

/*virtual*/ netkit::WAITABLE ss::core::crypto_pipe::get_waitable()
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
/*virtual*/ void ss::core::crypto_pipe::close(bool flush_before_close)
{
	bool io = spinlock::increment_by(busy, 10001) > 0;
	if (!io)
	{
		pipe->close(flush_before_close);
		pipe = nullptr;
	}
}


ss::core::udp_crypto_pipe::udp_crypto_pipe(const netkit::endpoint& ssproxyep, netkit::udp_pipe* transport, std::unique_ptr<cryptor> &&c, str::astr masterKey, crypto_par cp) :transport(transport), masterKey(masterKey), cp(cp), ssproxyep(ssproxyep)
{
    crypto = std::move(c);
}

/*virtual*/ netkit::io_result ss::core::udp_crypto_pipe::send(const netkit::endpoint& toaddr, const netkit::pgen& pg /* in */)
{
	signed_t presize = proxy_socks5::atyp_size(toaddr);
	buf2s.resize(cp.KeySize);

	u8 skey[maximum_key_size];
    rng.random_vec(buf2s); // make initial salt as starting sequence

	std::span<u8> subkey(skey, cp.KeySize);
    ss::deriveAeadSubkey(subkey, masterKey, buf2s);

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
    ss::deriveAeadSubkey(subkey, masterKey, std::span<const u8>(rcvbuf, cp.KeySize));
    ss::outbuffer buf2r;
	crypto->decipher(buf2r, std::span<const u8>(rcvbuf + cp.KeySize, pgr.sz - cp.KeySize), &subkey);
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

/*virtual*/ void ss::core::aead_cryptor::init_encryptor(std::span<const u8> key)
{
	encryptor.setup(key, pars.NonceSize, cb);
}

/*virtual*/ void ss::core::aead_cryptor::init_decryptor(std::span<const u8> key)
{
	decryptor.setup(key, pars.NonceSize, cb);
}

/*virtual*/ void ss::core::aead_cryptor::encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key)
{
    auto encode = [this, &cipher](const u8* d, size_t sz)
        {
            encryptor.process(std::span<const u8>(d, sz), cipher);
        };

	if (key)
	{
		[[likely]] if (encryptor.is_init())
		{
			encryptor.update_key(*key);
		}
		else {
			encryptor.setup(*key, pars.NonceSize, cb);
		}
		encode(plain.data(), plain.size());
		return;
	}

	u16 inLen = (u16)(0xffff & (plain.size() > AEAD_CHUNK_SIZE_MASK ? AEAD_CHUNK_SIZE_MASK : plain.size()));
	u16 size_be = netkit::to_ne(inLen);

	// size block encode
	encode(reinterpret_cast<const u8*>(&size_be), sizeof(size_be));
	// payload block encode
	encode(plain.data(), inLen);

	if (inLen < plain.size()) {
		// Append the remaining part recursively if there is any
		encipher(std::span(plain.data() + inLen, plain.size() - inLen), cipher, key);
	}
}

namespace
{
	struct u16acpt : public ss::data_acceptor
	{
		u16 data;
		/*virtual*/ void handle(const uint8_t input[], size_t size) override
		{
			ASSERT(size == sizeof(data));
			data = *(u16 *)input;
		}
	};

	struct chb_acpt : public ss::data_acceptor
	{
		ss::outbuffer* b;
		chb_acpt(ss::outbuffer* b) :b(b) {}
		/*virtual*/ void handle(const uint8_t input[], size_t size) override
		{
			b->append(std::span(input, size));
		}
	};
}

/*virtual*/ signed_t ss::core::aead_cryptor::decrypt(size_t& from, outbuffer& plain)
{
	auto decode = [this](signed_t skip, data_acceptor &out, size_t capacity) -> size_t
	{
		if ((unprocessed.size() - skip) < capacity + AEAD_TAG_SIZE)
			return 0;

		decryptor.process(std::span<const u8>(unprocessed.data() + skip, capacity + AEAD_TAG_SIZE), out);
		return capacity + AEAD_TAG_SIZE;
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
		try
		{
			u16acpt payloadsize_network_endian;
			size_t delta = decode(from_current, payloadsize_network_endian, sizeof(u16));
			if (delta == 0)
				return 0; // not yet ready data
			from_current += delta;
			payloadsize = netkit::to_he(payloadsize_network_endian.data);
			if (payloadsize > AEAD_CHUNK_SIZE_MASK)
				return -1; // looks like chunk size is corrupted or wrong decrypted
			last_block_payload_size = payloadsize; // keep payloadsize in case of incomplete data because we have already increased IV

			if (payloadsize == 0)
				return -1;

		}
		catch (...)
		{
			return -1;
		}
	}

	if (payloadsize + AEAD_TAG_SIZE > (unprocessed.size() - from_current))
		return 0; // not yet ready data

	chb_acpt acpt(&plain);

	from_current += decode(from_current, acpt, payloadsize);
	from = from_current;
	return payloadsize;
}

/*virtual*/ bool ss::core::aead_cryptor::decipher(outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* key)
{
	if (key)
	{
        [[likely]] if (decryptor.is_init())
        {
			decryptor.update_key(*key);
        }
        else {
			decryptor.setup(*key, pars.NonceSize, cb);
        }
		chb_acpt acpt(&plain);
		return decryptor.process(cipher, acpt);;
	}

	unprocessed += cipher;

	size_t from = 0;
	signed_t decr = 0;
	for (size_t usz = unprocessed.size(); from < usz;)
	{
		signed_t d = decrypt(from, plain);
		if (d < 0)
			return false;
		if (d == 0)
			break;
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
			if (from == 0 && unprocessed.size() > AEAD_CHUNK_SIZE_MASK)
			{
				// looks like data corrupt: decryptor can't process data
				return false;
			}
			unprocessed.erase(from);
		}
	}

	return true;
}
