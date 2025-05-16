#pragma once

#define AEAD_CHUNK_SIZE_MASK 0x3FFF
#define AEAD_TAG_SIZE 16

class proxy_shadowsocks;
class handler_ss;

namespace ss
{
	inline void nonceIncrement(u8* n, const size_t nlen)
	{
		signed_t c = 1;
		for (size_t i = 0U; c != 0 && i < nlen; i++) {
			c += static_cast<signed_t>(n[i]);
			n[i] = static_cast<u8>(c & 0xff);
			c >>= 8;
		}
	}

	using cipher_builder = std::function< std::unique_ptr<Botan::Cipher_Mode>(bool enc) >;

	std::unique_ptr<Botan::Cipher_Mode> make_chachapoly(bool enc);
	std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_128(bool enc);
	std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_192(bool enc);
	std::unique_ptr<Botan::Cipher_Mode> make_aesgcm_256(bool enc);

	class cipher;
	class keyed_filter : public Botan::Filter
	{
		std::unique_ptr<Botan::Cipher_Mode> mode;
		buffer iv;
		buffer buf;
		void incnonce()
		{
			nonceIncrement(iv.data(), iv.size());
		}

	public:
		keyed_filter() {}

		bool is_init() const { return iv.size() != 0; }
		void update_key(std::span<const u8> key);
		void setup(std::unique_ptr<Botan::Cipher_Mode>&& mode, std::span<const u8> key, unsigned NonceSize, cipher* ciph);

		/*virtual*/ void write(const uint8_t input[], size_t input_length) override;
		/*virtual*/ void start_msg() override { mode->start(iv); }
		/*virtual*/ void end_msg() override;
	};

	class cipher : public Botan::Filter
	{
		keyed_filter recoder;
	public:
		cipher() {}
	};

	class cipher_enc : public cipher
	{

		keyed_filter recoder;
		buffer* current_output = nullptr; // valid only in process method
	public:
		cipher_enc() {}

		bool is_init() const { return recoder.is_init(); }
        void update_key(std::span<const u8> key)
        {
            ASSERT(is_init());
            recoder.update_key(key);
        }

		void setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb);
		bool process(std::span<const u8> input, buffer& output);

		/*virtual*/ void write(const uint8_t input[], size_t length) override
		{
			size_t offset = current_output->size();
			current_output->resize(offset + length);
			memcpy(current_output->data() + offset, input, length);
		}
	};

	struct data_acceptor
	{
		virtual void handle(const uint8_t input[], size_t size) = 0;
	};

	class cipher_dec : public cipher
	{

		keyed_filter recoder;
		data_acceptor *current_output; // valid only in process method
		size_t handled;
	public:
		cipher_dec() {}

		bool is_init() const { return recoder.is_init(); }
        void update_key(std::span<const u8> key)
        {
            ASSERT(is_init());
            recoder.update_key(key);
        }
		void setup(std::span<const u8> key, unsigned NonceSize, cipher_builder cb);
		bool process(std::span<const u8> input, data_acceptor &output);

		/*virtual*/ void write(const uint8_t input[], size_t length) override
		{
			current_output->handle(input, length);
			handled += length;
		}
	};

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
			
			virtual bool decipher(outbuffer& plain, std::span<const u8> cipher_data, const std::span<u8>* key) = 0;
			virtual bool prebuf(std::span<const u8> cipher_data) = 0; // return false, if prebuf is not supported
			virtual dec_rslt decipher(outbuffer& plain) = 0;

			const crypto_par& getPars() const { return pars; };
		};

		class none_cryptor : public cryptor
		{
		public:
			none_cryptor() :cryptor(crypto_par()) {}

			virtual bool isDecoderInit() const { return true; }

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
			/*virtual*/ bool prebuf(std::span<const u8> /*cipher_data*/) { return false; }
			/*virtual*/ dec_rslt decipher(outbuffer& /*plain*/) { return dr_unsupported; }

		};

		class aead_cryptor : public cryptor
		{
		protected:

			ss::cipher_builder cb;
			ss::cipher_enc encryptor;
			ss::cipher_dec decryptor;
			tools::skip_buf unprocessed;
			size_t last_block_payload_size = 0;

			signed_t decrypt(size_t& from, outbuffer& plain);

		public:
			aead_cryptor(crypto_par p, ss::cipher_builder cb) :cryptor(p), cb(cb) {}

			/*virtual*/ bool is_decryptor_init() const { return decryptor.is_init(); }

			/*virtual*/ void init_encryptor(std::span<const u8> key) override;
			/*virtual*/ void init_decryptor(std::span<const u8> key) override;
			/*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key) override;
			/*virtual*/ bool decipher(outbuffer& plain, std::span<const u8> cipher, const std::span<u8>* key) override;

            /*virtual*/ bool prebuf(std::span<const u8> cipher_data) override {
                unprocessed += cipher_data;
                return true;
            }

			/*virtual*/ dec_rslt decipher(outbuffer& plain) override;

		};

		using cryptobuilder = std::function<std::unique_ptr<cryptor>(void)>;

		std::unique_ptr<cryptor> make_aead_crypto_chachapoly();
		std::unique_ptr<cryptor> make_aead_crypto_aesgcm_256();
		std::unique_ptr<cryptor> make_aead_crypto_aesgcm_192();
		std::unique_ptr<cryptor> make_aead_crypto_aesgcm_128();
		static std::unique_ptr<cryptor> makeuncrypted();

        struct masterkey
        {
            i64 expired = 0; // deadline time (seconds) // -1 means expired
            str::astr name;
            str::astr key;
        };

		using masterkey_array = spinlock::syncvar<std::vector<masterkey>>;

		masterkey_array masterkeys; // multi-threaded due it can be modified dynamically
		crypto_par cp;
		cryptobuilder cb;

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
            crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<cryptor>&& c, const str::astr& master_key, crypto_par cp);
			/*virtual*/ ~crypto_pipe() {}
        };

        class multipass_crypto_pipe : public crypto_pipe_base
        {
            friend class crypto_pipe;

            /*virtual*/ bool init_decryptor(u8* temp);

        public:

			multipass_crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<cryptor>&& c, masterkey_array& mks, crypto_par cp);
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
            ss::cipher_builder cb;
            crypto_par cp;
            randomgen rng;
			buffer buf2s;

			netkit::endpoint ssproxyep;
        public:
			udp_crypto_pipe(const netkit::endpoint &ssproxyep, netkit::udp_pipe* transport, std::unique_ptr<cryptor> &&c, str::astr master_key, crypto_par cp);

			/*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg /* in */) override;
            /*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/) override;

        };
	};

} // namespace ss

