#pragma once

#include "botan/botan.h"

#define AEAD_CHUNK_SIZE_MASK 0x3FFF
#define AEAD_TAG_SIZE 16

class proxy_shadowsocks;
class handler_ss;

namespace ss
{
	inline void nonceIncrement(u8* n, const size_t nlen)
	{
		uint_fast16_t c = 1U;
		for (size_t i = 0U; i < nlen; i++) {
			c += static_cast<uint_fast16_t>(n[i]);
			n[i] = static_cast<unsigned char>(c & 0xff);
			c >>= 8;
		}
	}

	using cipher_builder = std::function< std::unique_ptr<Botan::Cipher_Mode>(bool enc) >;

	std::unique_ptr<Botan::Cipher_Mode> make_chachapoly(bool enc);
	std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_128(bool enc);
	std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_192(bool enc);
	std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_256(bool enc);

	class cipher;
	class keyed_filter : public Botan::Keyed_Filter
	{
		std::unique_ptr<Botan::Cipher_Mode> mode;
		Botan::InitializationVector iv;
		std::vector<u8> buffer;
		void incnonce()
		{
			nonceIncrement(iv.raw().data(), iv.raw().size());
		}

	public:
		keyed_filter() {}

		bool is_init() const { return iv.size() != 0; }
		void setup(std::unique_ptr<Botan::Cipher_Mode>&& mode, std::span<const u8> key, unsigned NonceSize, cipher* ciph);

		/*virtual*/ void set_key(const Botan::SymmetricKey& /*key*/) override {}
		/*virtual*/ Botan::Key_Length_Specification key_spec() const override { return mode->key_spec(); }
		/*virtual*/ bool valid_iv_length(size_t /*length*/) const override { return true; }

		/*virtual*/ std::string name() const override { return mode->name(); };
		/*virtual*/ void write(const uint8_t input[], size_t input_length) override;
		/*virtual*/ void start_msg() override { mode->start(iv); }
		/*virtual*/ void end_msg() override;
	};

	class cipher : public Botan::Filter
	{
		keyed_filter recoder;
	public:
		cipher() {}
		/*virtual*/ std::string name() const override { return recoder.name(); };
	};

	class cipher_enc : public cipher
	{

		keyed_filter recoder;
		std::vector<u8>* current_output = nullptr; // valid only in process method 
	public:
		cipher_enc() {}
		void setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb);
		bool process(std::span<const u8> input, std::vector<u8>& output);

		/*virtual*/ void write(const uint8_t input[], size_t length) override
		{
			size_t offset = current_output->size();
			current_output->resize(offset + length);
			memcpy(current_output->data() + offset, input, length);
		}
	};

	class cipher_dec : public cipher
	{

		keyed_filter recoder;
		std::span<u8> current_output; // valid only in process method 
		size_t offset = 0;
	public:
		cipher_dec() {}

		bool is_init() const { return recoder.is_init(); }
		void setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb);
		bool process(std::span<const u8> input, std::span<u8> output);

		/*virtual*/ void write(const uint8_t input[], size_t length) override
		{
			ASSERT(offset + length <= current_output.size());
			memcpy(current_output.data() + offset, input, length);
			offset += length;
		}
	};


	class core
	{
		friend class proxy_shadowsocks;
		friend class handler_ss;

#pragma pack(push,1)
		struct crypto_par
		{
			u8 KeySize = 0; // key size = salt size
			u8 NonceSize = 0; // reused as iv size
			u8 _dummy1 = 0;
			u8 _dummy2 = 0;

			//bool IsAead() const { return TagSize > 0; }
		};
#pragma pack(pop)

		class cryptor
		{
		protected:
			crypto_par pars;

		public:
			cryptor(crypto_par p) :pars(p) {}
			virtual ~cryptor() {}

			virtual bool is_decryptor_init() const { return false; }

			virtual void init_encryptor(std::span<const u8> /*key*/) {}
			virtual void init_decryptor(std::span<const u8> /*key*/) {}
			virtual signed_t encipher(std::span<const u8> plain, std::vector<u8>& cipher) = 0;
			virtual signed_t decipher(std::vector<u8>& plain, std::span<const u8> cipher) = 0;

			const crypto_par& getPars() const { return pars; };
		};

		class none_cryptor : public cryptor
		{
		public:
			none_cryptor() :cryptor(crypto_par()) {}

			virtual bool isDecoderInit() const { return true; }

			/*virtual*/ void init_encryptor(std::span<const u8> /*key*/) {}
			/*virtual*/ void init_decryptor(std::span<const u8> /*key*/) {}
			/*virtual*/ signed_t encipher(std::span<const u8> plain, std::vector<u8>& cipher)
			{
				cipher.assign(plain.begin(), plain.end());
				return cipher.size();
			}
			/*virtual*/ signed_t decipher(std::vector<u8>& plain, std::span<const u8> cipher)
			{
				plain.assign(cipher.begin(), cipher.end());
				return plain.size();
			}
		};

		class aead_cryptor : public cryptor
		{
		protected:

			ss::cipher_builder cb;
			ss::cipher_enc encryptor;
			ss::cipher_dec decryptor;
			std::vector<u8> unprocessed;
			size_t last_block_payload_size = 0;

			/*virtual*/ signed_t decrypt(size_t& from, std::vector<u8>& plain);

		public:
			aead_cryptor(crypto_par p, ss::cipher_builder cb) :cryptor(p), cb(cb) {}

			/*virtual*/ bool is_decryptor_init() const { return decryptor.is_init(); }

			/*virtual*/ void init_encryptor(std::span<const u8> key);
			/*virtual*/ void init_decryptor(std::span<const u8> key);
			/*virtual*/ signed_t encipher(std::span<const u8> plain, std::vector<u8>& cipher);
			/*virtual*/ signed_t decipher(std::vector<u8>& plain, std::span<const u8> cipher);
		};

		using cryptobuilder = std::function<std::unique_ptr<cryptor>(void)>;


		class crypto_pipe : public netkit::pipe
		{
			struct incdec
			{
				volatile spinlock::long3264& v;
				crypto_pipe* owner;
				incdec(volatile spinlock::long3264& v, crypto_pipe* owner) :v(v), owner(owner) { if (spinlock::increment(v) > 10000) owner = nullptr; }
				~incdec() { if (spinlock::decrement(v) > 10000) owner->close(true); }
				operator bool() const
				{
					return owner == nullptr;
				}
			};

			volatile spinlock::long3264 busy = 0;
			netkit::pipe_ptr pipe;

			std::unique_ptr<cryptor> crypto;
			std::vector<u8> encrypted_data;
			std::vector<u8> decrypted_data;
			std::string masterKey;
			ss::cipher_builder cb;
			crypto_par cp;
			friend class proxy_shadowsocks;

		public:
			crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<cryptor> c, std::string masterKey, crypto_par cp);

			/*virtual*/ bool send(const u8* data, signed_t datasize) override;
			/*virtual*/ signed_t recv(u8* data, signed_t maxdatasz) override;
			/*virtual*/ std::tuple<netkit::WAITABLE, bool> get_waitable() override;
			/*virtual*/ void close(bool flush_before_close) override;

		};

		std::unique_ptr<cryptor> make_aead_crypto_chachapoly();
		std::unique_ptr<cryptor> make_aead_crypto_aesgcm_256();
		std::unique_ptr<cryptor> make_aead_crypto_aesgcm_192();
		std::unique_ptr<cryptor> make_aead_crypto_aesgcm_128();
		static std::unique_ptr<cryptor> makeuncrypted();

		std::string masterKey;
		crypto_par cp;
		cryptobuilder cb;

	public:
		void load(loader& ldr, const std::string& name, const asts& bb);

	};

} // namespace ss

