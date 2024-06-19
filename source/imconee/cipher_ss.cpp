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


using SecureByteArray = Botan::secure_vector<u8>;

std::string md5Hash(const std::string& in)
{
	Botan::MD5 md5;
	SecureByteArray result = md5.process(in);
	return std::string(span2str(result));
}

std::string evpBytesToKey(unsigned keyLen, const std::string& password)
{
	std::string mss, prevm;
	for (;;) {
		prevm = md5Hash(prevm + password);
		mss += prevm;
		if (mss.size() >= keyLen)
		{
			mss.resize(keyLen);
			break;
		}
	}

	return mss;
}

void deriveAeadSubkey(SecureByteArray &skey, unsigned length, const std::string& masterKey, const std::span<const u8>& salt)
{
	std::unique_ptr<Botan::KDF> kdf = std::make_unique<Botan::HKDF>(std::make_unique<Botan::HMAC>(std::make_unique<Botan::SHA_1>()));
	skey = kdf->derive_key(length, str2span(masterKey), salt, str2span(ASTR("ss-subkey")));
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



void ss::keyed_filter::setup(std::unique_ptr<Botan::Cipher_Mode>&& m, std::span<const u8> k, unsigned NonceSize, ss::cipher *ciph)
{
	mode = std::move(m);
	mode->set_key(k);
	iv.raw().resize(NonceSize, 0);

	ASSERT(m_next.size() == 1);
	m_next[0] = ciph;

}

/*virtual*/ void ss::keyed_filter::write(const uint8_t input[], size_t input_length)
{
	size_t idealg = mode->ideal_granularity();
	size_t mfz = idealg + mode->minimum_final_size();

	while (input_length >= mfz) {
		
		buffer.assign(input, input + idealg);
		mode->update(buffer);
		send(buffer);

		input += idealg;
		input_length -= idealg;
	}

	if (input_length > 0)
		buffer.assign(input, input + input_length);
	else
		buffer.clear();

}

/*virtual*/ void ss::keyed_filter::end_msg()
{
	mode->finish(buffer);
	send(buffer);
	incnonce();
}

void ss::cipher_enc::setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb)
{
	//std::unique_ptr<Botan::Cipher_Mode> mode = Botan::Cipher_Mode::create(botan_cipher, Botan::Cipher_Dir::Encryption);
	auto mode = cb(true);
	ASSERT(mode != nullptr);
	recoder.setup(std::move(mode), key, NonceSize, this);
}

bool ss::cipher_enc::process(std::span<const u8> input, std::vector<u8> &output)
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
	//std::unique_ptr<Botan::Cipher_Mode> mode = Botan::Cipher_Mode::create(botan_cipher, Botan::Cipher_Dir::Decryption);
	auto mode = cb(false);
	ASSERT(mode != nullptr);
	recoder.setup(std::move(mode), key, NonceSize, this);
}

bool ss::cipher_dec::process(std::span<const u8> input, std::span<u8> output)
{
	offset = 0;
	current_output = output;
	recoder.start_msg();
	recoder.write(input.data(), input.size());
	recoder.end_msg();
	return output.size() == offset;
}



void ss::core::load(loader& ldr, const std::string& name, const asts& bb)
{
	std::string method = bb.get_string(ASTR("method"));
	std::string password = bb.get_string(ASTR("password"));

	if (method == ASTR("xchacha20-ietf-poly1305"))
	{
		cp = { 32,24 };
		cb = std::bind(&core::make_aead_crypto_chachapoly, this);
	}
	else if (method == ASTR("chacha20-ietf-poly1305"))
	{
		cp = { 32, 12 };
		cb = cb = std::bind(&core::make_aead_crypto_chachapoly, this);
	}
	else if (method == ASTR("aes-256-gcm"))
	{
		cp = { 32, 12 };
		cb = cb = std::bind(&core::make_aead_crypto_aesgcm_256, this);
	}
	else if (method == ASTR("aes-192-gcm"))
	{
		cp = { 24, 12 };
		cb = cb = std::bind(&core::make_aead_crypto_aesgcm_192, this);
	}
	else if (method == ASTR("aes-128-gcm"))
	{
		cp = { 16, 12 };
		cb = cb = std::bind(&core::make_aead_crypto_aesgcm_128, this);
	}
	else if (method == ASTR("none"))
	{
		cb = &makeuncrypted;
	}
	else
	{
		ldr.exit_code = EXIT_FAIL_METHOD_UNDEFINED;
		LOG_E("{method} not defined for proxy [%s]", str::printable(name));
		return;
	}

	masterKey = evpBytesToKey(cp.KeySize, password);

}

ss::core::crypto_pipe::crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<cryptor> c, std::string masterKey, crypto_par cp) :pipe(pipe), masterKey(masterKey), cp(cp)
{
	Botan::AutoSeeded_RNG rng;
	encrypted_data.resize(cp.KeySize);
	rng.random_vec(encrypted_data); // make initial salt as starting sequence

	SecureByteArray skey;
	deriveAeadSubkey(skey, cp.KeySize, masterKey, encrypted_data);
	c->init_encryptor(skey);
	crypto = std::move(c);

}

/*virtual*/ bool ss::core::crypto_pipe::send(const u8* data, signed_t datasize)
{
	if (!pipe)
		return false;

	incdec ddd(busy, this);
	if (ddd) return false;

	crypto->encipher(std::span<const u8>(data, datasize), encrypted_data);
	bool ok = pipe->send(encrypted_data.data(), encrypted_data.size());
	encrypted_data.clear(); // IMPORTANT: clear after send, not before (due encrypted_data contains salt before 1st send)

	return ok;
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

		SecureByteArray skey;
		deriveAeadSubkey(skey, cp.KeySize, masterKey, std::span<u8>(temp, cp.KeySize));
		crypto->init_decryptor(skey);
	}

	for (bool do_recv = decrypted_data.empty();; do_recv = true)
	{
		signed_t sz = do_recv ? pipe->recv(temp, sizeof(temp)) : 0;
		if (sz < 0)
			return sz;

		if (sz > 0)
		{
			signed_t d = crypto->decipher(decrypted_data, std::span<const u8>(temp, sz)); // try decrypt
			if (d < 0)
				return -1;
		}

		if (maxdatasz < 0)
		{
			signed_t required = -maxdatasz; // required size to recv

			if (decrypted_data.size() < static_cast<size_t>(required))
				continue; // not enough data

			memcpy(data, decrypted_data.data(), required);
			decrypted_data.erase(decrypted_data.begin(), decrypted_data.begin() + required);
			return required;
		}
		break;
	}
	signed_t rv = 0;
	if (static_cast<size_t>(maxdatasz) >= decrypted_data.size())
	{
		// just copy whole decrypted data
		rv = decrypted_data.size();
		memcpy(data, decrypted_data.data(), decrypted_data.size());
		decrypted_data.clear();
	}
	else
	{
		// output buffer is smaller then decrypted
		// copy some
		memcpy(data, decrypted_data.data(), maxdatasz);
		decrypted_data.erase(decrypted_data.begin(), decrypted_data.begin() + maxdatasz);
		rv = maxdatasz;
	}

	return rv;
}

/*virtual*/ std::tuple<netkit::WAITABLE, bool> ss::core::crypto_pipe::get_waitable()
{
	if (!pipe)
		return { NULL_WAITABLE, false };

	incdec ddd(busy, this);
	if (ddd) return { NULL_WAITABLE, false };

	auto r = pipe->get_waitable();
	if (decrypted_data.size() != 0)
		std::get<1>(r) = true;
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


/*virtual*/ void ss::core::aead_cryptor::init_encryptor(std::span<const u8> key)
{
	encryptor.setup(key, pars.NonceSize, cb);
}

/*virtual*/ void ss::core::aead_cryptor::init_decryptor(std::span<const u8> key)
{
	decryptor.setup(key, pars.NonceSize, cb);
}

/*virtual*/ signed_t ss::core::aead_cryptor::encipher(std::span<const u8> plain, std::vector<u8>& cipher)
{
	u16 inLen = (u16)(0xffff & (plain.size() > AEAD_CHUNK_SIZE_MASK ? AEAD_CHUNK_SIZE_MASK : plain.size()));
	u16 size_be = netkit::to_ne(inLen);

	auto encode = [this, &cipher](const u8* d, size_t sz)
		{
			encryptor.process(std::span<const u8>(d, sz), cipher);
		};

	// size block encode
	encode(reinterpret_cast<const u8*>(&size_be), sizeof(size_be));
	// payload block encode
	encode(plain.data(), inLen);

	if (inLen < plain.size()) {
		// Append the remaining part recursively if there is any
		encipher(std::span(plain.data() + inLen, plain.size() - inLen), cipher);
	}
	return inLen;
}
/*virtual*/ signed_t ss::core::aead_cryptor::decrypt(size_t& from, std::vector<u8>& plain)
{
	auto decode = [this](signed_t skip, std::span<u8> out) -> size_t
	{
		if ((unprocessed.size() - skip) < out.size() + AEAD_TAG_SIZE)
			return 0;

		decryptor.process(std::span<const u8>(unprocessed.data() + skip, out.size() + AEAD_TAG_SIZE), out);
		return out.size() + AEAD_TAG_SIZE;
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
			u16 payloadsize_network_endian;
			size_t delta = decode(from_current, std::span(reinterpret_cast<u8*>(&payloadsize_network_endian), sizeof(payloadsize_network_endian)));
			if (delta == 0)
				return 0; // not yet ready data
			from_current += delta;
			payloadsize = netkit::to_he(payloadsize_network_endian);
			if (payloadsize > AEAD_CHUNK_SIZE_MASK)
				return -1; // looks like chunk size is corrupted or wrong decrypted
			last_block_payload_size = payloadsize; // keep payloadsize in case of incomplete data because we have already increased IV
		}
		catch (...)
		{
			return -1;
		}
	}

	ASSERT(payloadsize > 0);
	if (payloadsize + AEAD_TAG_SIZE > (unprocessed.size() - from_current))
		return 0; // not yet ready data
	size_t pps = plain.size();
	plain.resize(pps + payloadsize);
	from_current += decode(from_current, std::span(plain.data() + pps, payloadsize));
	from = from_current;
	return payloadsize;
}

/*virtual*/ signed_t ss::core::aead_cryptor::decipher(std::vector<u8>& plain, std::span<const u8> cipher)
{
	unprocessed.insert(unprocessed.end(), cipher.begin(), cipher.end());
	size_t from = 0;
	signed_t decr = 0;
	for (size_t usz = unprocessed.size(); from < usz;)
	{
		signed_t d = decrypt(from, plain);
		if (d < 0)
			return -1;
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
				return -1;
			}
			unprocessed.erase(unprocessed.begin(), unprocessed.begin() + from);
		}
	}

	return decr;
}
