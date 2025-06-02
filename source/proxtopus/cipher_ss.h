#pragma once

#include "aead_chacha20poly1305.h"

#define SS_AEAD_CHUNK_SIZE_MASK 0x3FFF
#define SS_AEAD_TAG_SIZE 16

class proxy_shadowsocks;
class handler_ss;

namespace ss
{
	inline void nonce_increment(u8* n, const size_t nlen)
	{
		signed_t c = 1;
		for (size_t i = 0U; c != 0 && i < nlen; i++) {
			c += static_cast<signed_t>(n[i]);
			n[i] = static_cast<u8>(c & 0xff);
			c >>= 8;
		}
	}

	namespace botan_aead
	{
        using cipher_builder = std::function< std::unique_ptr<Botan::Cipher_Mode>(bool enc) >;

        std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_128(bool enc);
        std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_192(bool enc);
        std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_256(bool enc);

		class cipher;
		class keyed_filter : public Botan::Filter
		{
			std::unique_ptr<Botan::Cipher_Mode> mode;
			std::array<u8,12> iv;
			buffer buf;
			void incnonce()
			{
				nonce_increment(iv.data(), iv.size());
			}

		public:
			keyed_filter(std::unique_ptr<Botan::Cipher_Mode> &&m):mode(std::move(m)) {}

			bool is_init() const { return mode != nullptr; }
			void set_key(std::span<const u8> key, cipher* ciph);


			/*virtual*/ void write(const uint8_t input[], size_t input_length) override;
			/*virtual*/ void start_msg() override { mode->start(iv); }
			/*virtual*/ void end_msg() override;
		};

		class cipher : public Botan::Filter
		{
		protected:
			keyed_filter recoder;
		public:
			cipher(std::unique_ptr<Botan::Cipher_Mode>&& m) :recoder(std::move(m)) {}

			void set_key(std::span<const u8> key)
            {
                recoder.set_key(key, this);
            }
            bool ready() const { return recoder.is_init(); }

		};

		class cipher_enc : public cipher
		{
			buffer* current_output = nullptr; // valid only in process method
		public:
			cipher_enc(std::unique_ptr<Botan::Cipher_Mode>&& m):cipher(std::move(m)) {}

			void process(std::span<const u8> input, buffer& output); // will increment iv

			/*virtual*/ void write(const uint8_t input[], size_t length) override
			{
				size_t offset = current_output->size();
				current_output->resize(offset + length);
				memcpy(current_output->data() + offset, input, length);
			}
		};

		class cipher_dec : public cipher
		{
			tools::memory_pair *current_output; // valid only in process method
			size_t handled;
		public:
			cipher_dec(std::unique_ptr<Botan::Cipher_Mode>&& m) :cipher(std::move(m)) {}

			bool process(std::span<const u8> input, tools::memory_pair& output); // will increment iv

			/*virtual*/ void write(const uint8_t input[], size_t length) override
			{
				current_output->copy(handled, input, length);
				handled += length;
			}
		};
    } // namespace botan_aead

	using outbuffer = tools::chunk_buffer<16384>;

    inline void deriveAeadSubkey(std::span<u8> skey, const str::astr & master_key, const std::span<const u8>& salt)
    {
        glb.kdf.derive_key(skey, str::span(master_key), salt, str::span(ASTR("ss-subkey")));
    }

	struct core
	{
		enum {
			maximum_key_size = 32
		};

		constexpr const static u8 crypto_chachapoly = 1;
		constexpr const static u8 crypto_aesgcm_256 = 2;
		constexpr const static u8 crypto_aesgcm_192 = 3;
		constexpr const static u8 crypto_aesgcm_128 = 4;
		constexpr const static u8 crypto_none = 5;

		class cryptor;

#pragma pack(push,1)
		struct crypto_par
		{
			u8 KeySize = 0; // key size = salt size
			u8 NonceSize = 0; // reused as iv size
			u8 cryptoalg = 0;
			u8 _dummy2 = 0;
            std::unique_ptr<cryptor> build_crypto(bool udp) const;
		};
#pragma pack(pop)

		class cryptor
		{
		protected:
			crypto_par pars;

		public:

			enum dec_rslt
			{
				dr_ok,
				dr_fail,
				dr_not_enough_data,
				dr_unsupported,
			};

			cryptor(crypto_par p) :pars(p) {}
			virtual ~cryptor() {}

			virtual bool is_decryptor_init() const { return false; }

			virtual void init_encryptor(std::span<const u8> /*key*/) {}
			virtual void init_decryptor(std::span<const u8> /*key*/) {}
			virtual void encipher(std::span<const u8> plain, buffer& cipher_data, const std::span<u8>* key) = 0;

			// decipher and put result to plain (key != null for udp packets)
			virtual bool decipher(outbuffer& plain, std::span<const u8> cipher_data, const std::span<u8>* key) = 0;

			// The prebuf and decipher_prebuffered functions work together, allowing the same data to be deciphered multiple times with different keys.
			// This is necessary for the multipassword feature.
			// implemented in buffered_decryptor
			virtual bool prebuf(std::span<const u8> /*cipher_data*/) { return false; } // return false, if prebuf is not supported
			virtual dec_rslt decipher_prebuffered(outbuffer& /*plain*/) { return dr_unsupported; }
			virtual signed_t get_unprocessed_size() const { return 0; }

			//const crypto_par& get_pars() const { return pars; };
		};

		class none_cryptor : public cryptor
		{
		public:
			none_cryptor() :cryptor(crypto_par()) {}

			virtual bool is_decryptor_init() const { return true; }

			/*virtual*/ void init_encryptor(std::span<const u8> /*key*/) {}
			/*virtual*/ void init_decryptor(std::span<const u8> /*key*/) {}
			/*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* /*key*/)
			{
				cipher.assign(plain.begin(), plain.end());
			}
			/*virtual*/ bool decipher(outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* /*key*/)
			{
				plain.assign(cipher);
				return true;
			}

		};


		// handles prebuf and decipher_prebuffered
		// calls decipher_packet to actually decipher data
		class buffered_decryptor : public cryptor
		{
            signed_t decrypt_part(size_t& from, outbuffer& plain);
		protected:
            tools::skip_buf unprocessed; // buffer for unprocessed data
            size_t last_block_payload_size = 0;
			virtual bool decipher_packet(std::span<const u8> input, tools::memory_pair &outbuf) = 0; // main decipher; expects oubuf size at least (input.size()-SS_AEAD_TAG_SIZE) bytes
		public:
			buffered_decryptor(crypto_par p) :cryptor(p) {}

			/*virtual*/ void init_decryptor(std::span<const u8> /*key*/) override {
                last_block_payload_size = 0;
                //unprocessed.clear(); // buffer must not be cleared
            }

            /*virtual*/ bool prebuf(std::span<const u8> cipher_data) override {
                unprocessed += cipher_data;
                return true;
            }
			/*virtual*/ dec_rslt decipher_prebuffered(outbuffer& plain) override;
			/*virtual*/ signed_t get_unprocessed_size() const { return unprocessed.size(); }
		};

		class botan_aead_cryptor : public buffered_decryptor
		{
		protected:

			ss::botan_aead::cipher_enc encryptor;
			ss::botan_aead::cipher_dec decryptor;

			/*virtual*/ bool decipher_packet(std::span<const u8> input, tools::memory_pair& outbuf) override
            {
                return decryptor.process(input, outbuf);
            }

		public:
			botan_aead_cryptor(crypto_par p, ss::botan_aead::cipher_builder cb) :buffered_decryptor(p), encryptor(cb(true)), decryptor(cb(false)) {}

			/*virtual*/ bool is_decryptor_init() const { return decryptor.ready(); }

			/*virtual*/ void init_encryptor(std::span<const u8> key) override;
			/*virtual*/ void init_decryptor(std::span<const u8> key) override;
			/*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key) override;
			/*virtual*/ bool decipher(outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* key) override; // prebuf and decipher_prebuffered (see buffered_decryptor)
		};

		template<size_t nonce_size, bool udp> struct aead_chacha20poly1305_cryptor_core;
		template<size_t nonce_size> struct aead_chacha20poly1305_cryptor_core<nonce_size, true> : public cryptor
        {
            aead_chacha20poly1305 encryptor;
            aead_chacha20poly1305 decryptor;
			u8 zero_nonce[nonce_size] = {0};

            aead_chacha20poly1305_cryptor_core() :cryptor({ chacha20::key_size, nonce_size }) {}

			std::span<const u8> enc_nonce() const { return std::span(zero_nonce, nonce_size); }

            /*virtual*/ bool decipher(outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* key) override
            {
                ASSERT(key != nullptr);

                if (cipher.size() < poly1305::tag_size)
                    return false;

                decryptor.set_key(std::span<const u8, chacha20::key_size>(key->data(), chacha20::key_size));
                auto mp = plain.alloc(cipher.size() - poly1305::tag_size);
                bool ok = decryptor.decipher_packet(std::span(zero_nonce, nonce_size), cipher, mp);
                return ok;
            }

		};
        template<size_t nonce_size> struct aead_chacha20poly1305_cryptor_core<nonce_size, false> : public buffered_decryptor
        {
            aead_chacha20poly1305 encryptor;
            aead_chacha20poly1305 decryptor;
            u8 nonce_enc[nonce_size];
            u8 nonce_dec[nonce_size];

			aead_chacha20poly1305_cryptor_core() :buffered_decryptor({ chacha20::key_size, nonce_size }) {}

			std::span<const u8> enc_nonce() const { return std::span(nonce_enc, nonce_size); }

            /*virtual*/ bool decipher_packet(std::span<const u8> input, tools::memory_pair& outbuf) override
            {
				if (decryptor.decipher_packet(std::span(nonce_dec, nonce_size), input, outbuf))
				{
					nonce_increment(nonce_dec, nonce_size);
					return true;
				}
                return false;
            }

            /*virtual*/ bool decipher(outbuffer& plain, std::span<const u8> cipher, [[maybe_unused]] const std::span<u8>* key) override
            {
				ASSERT(key == nullptr); // non udp mode
                unprocessed += cipher;
                return decipher_prebuffered(plain) != dr_fail;
            }
            /*virtual*/ bool prebuf(std::span<const u8> cipher_data) override {
                unprocessed += cipher_data;
                return true;
            }
        };

        template<size_t nonce_size, bool udp> class aead_chacha20poly1305_cryptor : public aead_chacha20poly1305_cryptor_core<nonce_size, udp>
        {
			using super = aead_chacha20poly1305_cryptor_core<nonce_size, udp>;

        public:
			aead_chacha20poly1305_cryptor() {}

            /*virtual*/ bool is_decryptor_init() const { return super::decryptor.ready(); }

            /*virtual*/ void init_encryptor(std::span<const u8> key) override
            {
				if constexpr (!udp)
					memset(super::nonce_enc, 0, nonce_size);
				super::encryptor.set_key(std::span<const u8, chacha20::key_size>(key.data(), chacha20::key_size));
            }

            /*virtual*/ void init_decryptor(std::span<const u8> key) override
            {
				if constexpr (!udp)
				{
                    buffered_decryptor::init_decryptor(key); // clear buffer
					memset(super::nonce_dec, 0, nonce_size);
				}
				super::decryptor.set_key(std::span<const u8, chacha20::key_size>(key.data(), chacha20::key_size));
            }

            /*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key) override
            {
                auto encode = [this, &cipher](const u8* d, size_t sz)
                    {
                        //memset(iv_enc, 0, pars.NonceSize); // Each UDP packet is encrypted/decrypted independently, using the derived subkey and a nonce with all zero bytes.

						super::encryptor.encipher_packet(super::enc_nonce(), std::span(d, sz), [&cipher](size_t sz) -> u8* {

                            size_t osz = cipher.size();
                            cipher.resize(osz + sz, true);
                            return cipher.data() + osz;
                        });

						if constexpr (!udp)
							nonce_increment(super::nonce_enc, nonce_size);

                    };

				if constexpr (udp)
                {
					ASSERT(key != nullptr);
					super::encryptor.set_key(std::span<const u8, chacha20::key_size>(key->data(), chacha20::key_size));
                    encode(plain.data(), plain.size());
                    return;
				}
				else
				{
                    u16 inLen = (u16)(0xffff & (plain.size() > SS_AEAD_CHUNK_SIZE_MASK ? SS_AEAD_CHUNK_SIZE_MASK : plain.size()));
                    u16be size_be = inLen;

                    // size block encode
                    encode(reinterpret_cast<const u8*>(&size_be), sizeof(size_be));
                    // payload block encode
                    encode(plain.data(), inLen);

                    if (inLen < plain.size()) {
                        // Append the remaining part recursively if there is any
                        encipher(std::span(plain.data() + inLen, plain.size() - inLen), cipher, nullptr);
                    }
				}
            }
        };

        struct masterkey
        {
            i64 expired = 0; // deadline time (seconds) // -1 means expired
            str::astr name;
            str::astr key;
        };

		using masterkey_array = spinlock::syncvar<std::vector<masterkey>>;

		masterkey_array masterkeys; // multi-threaded due it can be modified dynamically
		crypto_par cp;

	public:

		class crypto_pipe_base : public netkit::pipe
		{
		protected:
			struct incdec
			{
				volatile spinlock::long3264& v;
				crypto_pipe_base* owner;
				incdec(volatile spinlock::long3264& v, crypto_pipe_base* owner) :v(v), owner(owner) { if (spinlock::increment(v) > 10000) owner = nullptr; }
				~incdec() { if (spinlock::decrement(v) > 10000 && owner) owner->close(true); }
				operator bool() const
				{
					return owner == nullptr;
				}
			};

			volatile spinlock::long3264 busy = 0;
			netkit::pipe_ptr pipe;
            std::unique_ptr<cryptor> crypto;
			buffer encrypted_data; // ready 2 send data
			outbuffer decrypted_data;
			crypto_par cp;
			friend class proxy_shadowsocks;

			virtual bool init_decryptor(u8* temp) = 0;
            void generate_outgoing_salt();  // make initial salt as starting sequence

		public:
			crypto_pipe_base(netkit::pipe_ptr pipe, crypto_par cp) :pipe(pipe), cp(cp) {}
			/*virtual*/ ~crypto_pipe_base()
            {
                close(true);
            }


			/*virtual*/ bool alive() override
            {
                return pipe && pipe->alive();
            }

			/*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;
			/*virtual*/ signed_t recv(u8* data, signed_t maxdatasz) override;
			/*virtual*/ bool unrecv(const u8* data, signed_t sz) override;
			/*virtual*/ netkit::WAITABLE get_waitable() override;
			/*virtual*/ void close(bool flush_before_close) override;


		};

		class multipass_crypto_pipe;
        class crypto_pipe : public crypto_pipe_base
        {
            str::astr master_key;

			friend class proxy_shadowsocks;

			/*virtual*/ bool init_decryptor(u8* temp);

        public:
			crypto_pipe(multipass_crypto_pipe& mpcp);
            crypto_pipe(netkit::pipe_ptr pipe, const str::astr& master_key, crypto_par cp);
			/*virtual*/ ~crypto_pipe() {}
        };

        class multipass_crypto_pipe : public crypto_pipe_base
        {
            friend class crypto_pipe;

            /*virtual*/ bool init_decryptor(u8* temp);

        public:

			multipass_crypto_pipe(netkit::pipe_ptr pipe, masterkey_array& mks, crypto_par cp);
            /*virtual*/ ~multipass_crypto_pipe() {}

			netkit::pipe_ptr get_pipe() { return pipe; }
			crypto_par get_pars() { return cp; }
        };

		str::astr load(loader& ldr, const str::astr& name, const asts& bb); // returns addr (if url field present)


        class udp_crypto_pipe : public netkit::udp_pipe
        {
            netkit::udp_pipe* transport;
            str::astr master_key;
            std::unique_ptr<cryptor> crypto;
            crypto_par cp;
            randomgen rng;
			buffer buf2s;

			netkit::endpoint ssproxyep;
        public:
			udp_crypto_pipe(const netkit::endpoint &ssproxyep, netkit::udp_pipe* transport, str::astr master_key, crypto_par cp);

			/*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg /* in */) override;
            /*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/) override;

        };
	};

} // namespace ss

