#pragma once

#include "aead_chacha20poly1305.h"

#define SS_AEAD_CHUNK_SIZE_MASK 0x3FFF
#define SS_AEAD_TAG_SIZE 16
#define SSP_VERSION 0


// ssp packet spec
//
// client: [special-iv, 32 bytes][chunk type 0, variable size][chunk2 type 1, variable size][chunk2 type 1, variable size]...
//
//  chunk format:
//
//   [big endian, 2 bytes, 0..13 - size, 14..15 == 0][payload][aead tag, 16 bytes]
//
//   size - is only size of payload part



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
                current_output->copy_in(handled, input, length);
                handled += length;
            }
        };
    } // namespace botan_aead

    using outbuffer = tools::chunk_buffer<16384>;

    void derive_aead_subkey(u8* skey, const u8* master_key, const u8* salt, unsigned keylen);
    void derive_ssp_subkey(u8* skey, const u8* master_key, const u8* salt); // keylen == 32

    inline signed_t ssp_iv_pretest(const u8* iv) // fast iv check for compliance with the protocol ssp (32 bytes expected)
    {
        for (signed_t i = 0; i < 16-5; ++i)
        {
            if ((iv[i] ^ iv[i+5]) == 0xff)
                return i;
        }
        return -1;
    }
    signed_t ssp_iv_test(const u8* iv, const u8* ssp_key, signed_t shift); // slow iv check for compliance with the protocol ssp (32 bytes expected)
    void ssp_iv_gen(u8* iv, const u8* ssp_key, u8 par);

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

        enum crypto_type
        {
            CRYPTO_TCP,
            CRYPTO_TCP_SSP,
            CRYPTO_UDP,
        };

#pragma pack(push,1)
        struct crypto_par
        {
            u8 KeySize = 0; // key size = salt size
            u8 NonceSize = 0; // reused as iv size
            u8 cryptoalg = 0;
            u8 flags = 0; // |1 - ssp
            std::unique_ptr<cryptor> build_crypto(crypto_type) const;
            bool is_ssp_compliant() const
            {
                return crypto_chachapoly == cryptoalg;
            }
            bool is_ssp() const
            {
                return 0 != (flags & 1);
            }
            void set_ssp()
            {
                flags |= 1;
            }
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

            virtual void init_encryptor(std::span<const u8> /*key*/) {}
            virtual void init_decryptor(std::span<const u8> /*key*/) {}
            virtual void encipher(std::span<const u8> plain, buffer& cipher_data, const std::span<u8>* key) = 0;

            // decipher and put result to plain (key != null for udp packets)
            virtual bool decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher_data, const std::span<u8>* key) = 0;

            // The prebuf and decipher_prebuffered functions work together, allowing the same data to be deciphered multiple times with different keys.
            // This is necessary for the multipassword feature.
            // implemented in buffered_decryptor
            virtual bool prebuf(tools::circular_buffer_extdata& /*cipher_data*/, signed_t /*size*/) { return false; } // return false, if prebuf is not supported
            virtual dec_rslt decipher_prebuffered(outbuffer& /*plain*/) { return dr_unsupported; }
            virtual signed_t get_unprocessed_size() const { return 0; }

            //const crypto_par& get_pars() const { return pars; };
        };

        class none_cryptor : public cryptor
        {
        public:
            none_cryptor() :cryptor(crypto_par()) {}

            /*virtual*/ void init_encryptor(std::span<const u8> /*key*/) {}
            /*virtual*/ void init_decryptor(std::span<const u8> /*key*/) {}
            /*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* /*key*/)
            {
                cipher.assign(plain.begin(), plain.end());
            }
            /*virtual*/ bool decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher, const std::span<u8>* /*key*/)
            {
                cipher.peek(plain);
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
            virtual bool decipher_packet(std::span<const u8> input, tools::memory_pair& outbuf) = 0; // main decipher; expects oubuf size at least (input.size()-SS_AEAD_TAG_SIZE) bytes
        public:
            buffered_decryptor(crypto_par p) :cryptor(p) {}

            /*virtual*/ void init_decryptor(std::span<const u8> /*key*/) override {
                last_block_payload_size = 0;
                //unprocessed.clear(); // buffer must not be cleared
            }

            /*virtual*/ bool prebuf(tools::circular_buffer_extdata& cipher_data, signed_t size) override {
                cipher_data.peek(unprocessed, size);
                return true;
            }
            /*virtual*/ dec_rslt decipher_prebuffered(outbuffer& plain) override;
            /*virtual*/ signed_t get_unprocessed_size() const override { return unprocessed.size(); }
        };

        class ssp_cryptor : public cryptor
        {
        protected:
            aead_chacha20poly1305 encryptor;
            aead_chacha20poly1305 decryptor;
            u32 nonce_enc = 0; // 32 bits for nonce is enough
            u32 nonce_dec = 0;

            tools::skip_buf unprocessed; // buffer for unprocessed data
        public:
            ssp_cryptor(crypto_par p) :cryptor(p) {}

            /*virtual*/ void init_decryptor(std::span<const u8> /*key*/) override { }

            /*virtual*/ bool prebuf(tools::circular_buffer_extdata& cipher_data, signed_t size) override {
                cipher_data.peek(unprocessed, size);
                return true;
            }
            /*virtual*/ dec_rslt decipher_prebuffered(outbuffer& plain) override;
            /*virtual*/ signed_t get_unprocessed_size() const override { return unprocessed.size(); }

            void ssp_encipher(std::span<const u8> plain, buffer& cipher);
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

            /*virtual*/ void init_encryptor(std::span<const u8> key) override;
            /*virtual*/ void init_decryptor(std::span<const u8> key) override;
            /*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key) override;
            /*virtual*/ bool decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher, const std::span<u8>* key) override; // prebuf and decipher_prebuffered (see buffered_decryptor)
        };

        template<size_t nonce_size, crypto_type crt> struct aead_chacha20poly1305_cryptor_core;
        template<size_t nonce_size> struct aead_chacha20poly1305_cryptor_core<nonce_size, CRYPTO_UDP> : public cryptor
        {
            aead_chacha20poly1305 encryptor;
            aead_chacha20poly1305 decryptor;
            u8 zero_nonce[nonce_size] = { 0 };

            aead_chacha20poly1305_cryptor_core() :cryptor({ chacha20::key_size, nonce_size }) {}

            std::span<const u8> enc_nonce() const { return std::span(zero_nonce, nonce_size); }

            /*virtual*/ bool decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher, const std::span<u8>* key) override
            {
                ASSERT(key != nullptr);

                size_t ciphsz = cipher.datasize();
                if (ciphsz < poly1305::tag_size)
                    return false;
                u8* temp = ALLOCA(ciphsz);
                const u8* ciphpacket = cipher.plain_data(temp, ciphsz);
                decryptor.set_key(std::span<const u8, chacha20::key_size>(key->data(), chacha20::key_size));
                auto mp = plain.alloc(ciphsz - poly1305::tag_size);
                bool ok = decryptor.decipher_packet(std::span(zero_nonce, nonce_size), std::span(ciphpacket, ciphsz), mp);
                return ok;
            }

        };
        template<size_t nonce_size> struct aead_chacha20poly1305_cryptor_core<nonce_size, CRYPTO_TCP> : public buffered_decryptor
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

            /*virtual*/ bool decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher_data, [[maybe_unused]] const std::span<u8>* key) override
            {
                ASSERT(key == nullptr); // non udp mode
                cipher_data.peek(unprocessed);
                return decipher_prebuffered(plain) != dr_fail;
            }
            /*virtual*/ bool prebuf(tools::circular_buffer_extdata& cipher_data, signed_t size) override {
                cipher_data.peek(unprocessed, size);
                return true;
            }
        };

        template<size_t nonce_size> struct aead_chacha20poly1305_cryptor_core<nonce_size, CRYPTO_TCP_SSP> : public ssp_cryptor
        {
            aead_chacha20poly1305_cryptor_core() :ssp_cryptor({ chacha20::key_size, nonce_size }) {}

            /*virtual*/ bool decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher_data, [[maybe_unused]] const std::span<u8>* key) override
            {
                ASSERT(key == nullptr);
                cipher_data.peek(unprocessed);
                return decipher_prebuffered(plain) != dr_fail;
            }
            /*virtual*/ bool prebuf(tools::circular_buffer_extdata& cipher_data, signed_t size) override {
                cipher_data.peek(unprocessed, size);
                return true;
            }
        };


        template<size_t nonce_size, crypto_type crt> class aead_chacha20poly1305_cryptor : public aead_chacha20poly1305_cryptor_core<nonce_size, crt>
        {
            using super = aead_chacha20poly1305_cryptor_core<nonce_size, crt>;

        public:
            aead_chacha20poly1305_cryptor() {}

            /*virtual*/ void init_encryptor(std::span<const u8> key) override
            {
                if constexpr (crt == CRYPTO_TCP)
                    memset(super::nonce_enc, 0, nonce_size);
                super::encryptor.set_key(std::span<const u8, chacha20::key_size>(key.data(), chacha20::key_size));
                if constexpr (crt == CRYPTO_TCP_SSP)
                    super::encryptor.set_iv_size(nonce_size);
            }

            /*virtual*/ void init_decryptor(std::span<const u8> key) override
            {
                if constexpr (crt == CRYPTO_TCP)
                {
                    super::init_decryptor(key); // clear buffer
                    memset(super::nonce_dec, 0, nonce_size);
                }
                super::decryptor.set_key(std::span<const u8, chacha20::key_size>(key.data(), chacha20::key_size));
                if constexpr (crt == CRYPTO_TCP_SSP)
                    super::decryptor.set_iv_size(nonce_size);
            }

            /*virtual*/ void encipher(std::span<const u8> plain, buffer& cipher, [[maybe_unused]] const std::span<u8>* key) override
            {
                if constexpr (crt == CRYPTO_TCP_SSP)
                {
                    super::ssp_encipher(plain, cipher);
                }
                else
                {
                    auto encode = [this, &cipher](const u8* d, size_t sz)
                    {
                        //memset(iv_enc, 0, pars.NonceSize); // Each UDP packet is encrypted/decrypted independently, using the derived subkey and a nonce with all zero bytes.

                        super::encryptor.encipher_packet(super::enc_nonce(), std::span(d, sz), [&cipher](size_t sz) -> u8* {

                            size_t osz = cipher.size();
                            cipher.resize(osz + sz, true);
                            return cipher.data() + osz;
                        });

                        if constexpr (crt != CRYPTO_UDP)
                            nonce_increment(super::nonce_enc, nonce_size);

                    };

                    if constexpr (crt == CRYPTO_UDP)
                    {
                        ASSERT(key != nullptr);
                        super::encryptor.set_key(std::span<const u8, chacha20::key_size>(key->data(), chacha20::key_size));
                        encode(plain.data(), plain.size());
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

            }
        };

        struct keyspace
        {
            u8 space[maximum_key_size];
            explicit keyspace(bool zeroise = false) { if (zeroise) memset(space, 0, maximum_key_size); };
            keyspace(const keyspace& s)
            {
                tools::memcopy<sizeof(space)>(space, s.space);
            }
            keyspace &operator = (const keyspace& s)
            {
                tools::memcopy<sizeof(space)>(space, s.space);
                return *this;
            }
            std::span<const u8> span() const
            {
                return std::span(space, sizeof(space));
            }
        };

        struct masterkey
        {
            i64 expired = 0; // deadline time (seconds) // -1 means expired
            str::astr name;
            keyspace key;
            keyspace ssp_key;

            void gen_ssp_key();
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
                volatile size_t& v;
                crypto_pipe_base* owner;
                incdec(volatile size_t& v, crypto_pipe_base* owner) :v(v), owner(owner) { if (spinlock::atomic_increment(v) > 10000) owner = nullptr; }
                ~incdec() { if (spinlock::atomic_decrement(v) > 10000 && owner) owner->close(true); }
                operator bool() const
                {
                    return owner == nullptr;
                }
            };

            volatile size_t busy = 0;
            netkit::pipe_ptr pipe;
            std::unique_ptr<cryptor> crypto;
            buffer encrypted_data; // ready 2 send data
            outbuffer decrypted_data;
            friend class proxy_shadowsocks;

        protected:
            signed_t recv(tools::circular_buffer_extdata& outdata, tools::circular_buffer_extdata& temp, signed_t required, signed_t timeout DST(, deep_tracer*));

            void set_readypipe(bool v)
            {
                if (pipe)
                {
                    if (auto* s = pipe->get_socket())
                        s->readypipe(v);
                }
            }

        public:
            crypto_pipe_base(netkit::pipe_ptr pipe) :pipe(pipe) {}
            /*virtual*/ ~crypto_pipe_base()
            {
                close(true);
            }

            /*virtual*/ void replace(netkit::replace_socket* rsock) override
            {
                if (pipe)
                    pipe->replace(rsock);
                else
                    delete rsock;
            }


            /*virtual*/ bool alive() override
            {
                return pipe && pipe->alive();
            }

            /*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;
            /*virtual*/ signed_t recv(tools::circular_buffer_extdata& outdata, signed_t required, signed_t timeout DST(, deep_tracer*)) override;
            /*virtual*/ void unrecv(tools::circular_buffer_extdata& data) override;
            /*virtual*/ netkit::system_socket *get_socket() override;
            /*virtual*/ void close(bool flush_before_close) override;
            /*virtual*/ str::astr get_info(info i) const override
            {
                if (pipe)
                    return pipe->get_info(i);
                return glb.emptys;
            }
        };

        class crypto_pipe : public crypto_pipe_base
        {
            friend class proxy_shadowsocks;

        public:
            crypto_pipe(netkit::pipe_ptr pipe) : crypto_pipe_base(pipe) {}
            crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<ss::core::cryptor> &&cry, outbuffer &&dcd, buffer &&ecd);
            /*virtual*/ ~crypto_pipe() {}

            /*
            * build server ss pipe (based on 1st 32 + 18 bytes received in cipherdata)
            */
            static crypto_pipe *build(masterkey_array &masterkeys, crypto_par cp, netkit::pipe_ptr p, tools::circular_buffer_extdata & cipherdata);
            static crypto_pipe* build(const ss::core::keyspace& mastkey, crypto_par cp, netkit::pipe_ptr p, tools::circular_buffer_extdata& cipherdata, size_t packetsize);
        };

        class crypto_pipe_server : public crypto_pipe
        {
            str::astr username;
        public:
            crypto_pipe_server(netkit::pipe_ptr pipe, std::unique_ptr<ss::core::cryptor>&& cry, outbuffer&& dcd, buffer&& ecd, const str::astr& un) :crypto_pipe(pipe, std::move(cry), std::move(dcd), std::move(ecd)), username(un) {}
            /*virtual*/ ~crypto_pipe_server() {}

            /*virtual*/ str::astr get_info(info i) const
            {
                if (i == I_USERNANE)
                    return username;

                if (!pipe)
                    return glb.emptys;

                if (i == I_SUMMARY)
                    return str::astr(username).append(ASTR("/")) + pipe->get_info(I_SUMMARY);
                
                return pipe->get_info(i);
            }
        };

        class crypto_pipe_client : public crypto_pipe
        {
            std::unique_ptr<ss::core::masterkey> master_key;
            crypto_par cp;
        public:
            crypto_pipe_client(netkit::pipe_ptr pipe, ss::core::masterkey* key, crypto_par cp, const str::astr &sni);
            /*virtual*/ signed_t recv(tools::circular_buffer_extdata& outdata, signed_t required, signed_t timeout DST(, deep_tracer*)) override;
            /*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;

        };

        str::astr load(loader& ldr, const str::astr& name, const asts& bb); // returns addr (if url field present)


        class udp_crypto_pipe : public netkit::udp_pipe
        {
            ss::core::keyspace master_key;
            netkit::udp_pipe* transport;
            std::unique_ptr<cryptor> crypto;
            crypto_par cp;
            buffer buf2s;

            netkit::endpoint ssproxyep;
        public:
            udp_crypto_pipe(const netkit::endpoint &ssproxyep, netkit::udp_pipe* transport, const ss::core::keyspace &master_key, crypto_par cp);

            /*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg /* in */) override;
            /*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/) override;

        };
    };

} // namespace ss

