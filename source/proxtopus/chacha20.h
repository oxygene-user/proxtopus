#pragma once

#include <botan/stream_cipher.h>

class chacha20 {

public:

    constexpr const static size_t key_size = 32;

    struct impl
    {
        uint32_t input[16]; // context

        void cipher_ref(const uint8_t in[], uint8_t out[], size_t size);
        void cipher_ssse3(const uint8_t in[], uint8_t out[], size_t size);
#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__)
        void cipher_avx2(const uint8_t in[], uint8_t out[], size_t size);
#endif

        virtual ~impl()
        {
#ifdef _DEBUG
            memset(input, 0xab, sizeof(input));
#else
            Botan::secure_scrub_memory(input, sizeof(input));
#endif
        };
        virtual void cipher(const uint8_t in[], uint8_t out[], size_t size, size_t ic) = 0; // cipher 64 bytes
        virtual void prepare(const uint8_t* k, const uint8_t* nonce, uint8_t nonce_size);

        void key_setup_xchacha20(const unsigned char* k, const unsigned char* n);
        void key_setup(const uint8_t* k);
        void ic_setup(size_t ic);
        void ic_setup_ietf(size_t ic);
        void iv_setup(const uint8_t* iv);
        void iv_setup_ietf(const uint8_t* iv);
    };

private:

    uint8_t m_buf[64];
    std::unique_ptr<impl> m_impl;
    size_t m_position = 0;

    constexpr const static size_t f_nonce_set = 3;    // 0 - none, 1 - 8, 2 - 12, 3 - 24 (m_buf+32 contains iv)
    constexpr const static size_t f_impl_size = 3<<2; // 0 - none, 1 - 8, 2 - 12, 3 - 24
    constexpr const static size_t f_key_set = 1<<4;   // if true, m_buf contains key
    constexpr const static size_t f_buf_valid = 1<<5; // if true, m_buf contains keystream for (m_position>>6) ic
    constexpr const static size_t f_prepared = 1<<6;

    tools::flags<1> flags;
    u8 dummy[7];

    static uint8_t ivsize(size_t x)
    {
        if (x == 1)
            return 8;
        if (x == 2)
            return 12;
        if (x == 3)
            return 24;
        return 0;
    }

public:
    void set_key(std::span<const uint8_t, key_size> key)
    {
        m_position = 0;

#ifdef _DEBUG
        if (key.size() != key_size)
            DEBUGBREAK();
#endif
        if (flags.getn<f_nonce_set>() == 0)
        {
            // no nonce yet
            // just set key

            tools::memcopy<key_size>(m_buf, key.data());
            flags.setup<f_key_set, f_buf_valid| f_prepared>();
        }
        else {
            m_impl->prepare(key.data(), m_buf + key_size, ivsize(flags.getn<f_nonce_set>()));
            flags.setup<f_prepared, f_key_set>();
        }
    }
    void cipher(const uint8_t in[], uint8_t out[], size_t length);
    void keystream(uint8_t out[], size_t len)
    {
        cipher(nullptr, out, len);
    }
    void set_iv(std::span<const uint8_t> iv)
    {
        m_position = 0; // always restart position on iv change
        flags.unset<f_buf_valid>();

        if (ivsize(flags.getn<f_impl_size>()) != iv.size())
            setup_implementation(iv.size());

        if (flags.is<f_key_set>())
        {
            m_impl->prepare(m_buf, iv.data(), static_cast<uint8_t>(iv.size()));
            flags.setup<f_prepared, f_nonce_set>();
        }
        else
        {
            if (flags.is<f_prepared>())
            {
                if (flags.getn<f_impl_size>() == 1)
                {
                    m_impl->iv_setup(iv.data());
                }
                else if (flags.getn<f_impl_size>() == 2)
                {
                    m_impl->iv_setup_ietf(iv.data());
                }
                else if (flags.getn<f_impl_size>() == 3)
                {
                    m_impl->prepare(flags.is<f_key_set>() ? m_buf : nullptr, iv.data(), static_cast<uint8_t>(iv.size()));
                }
            }
            else
            {
                memcpy(m_buf + key_size, iv.data(), iv.size());
                flags.setn<f_nonce_set>(iv.size() == 8 ? 1 : (iv.size() == 12 ? 2 : 3));
            }

        }

    }
    void setup_implementation(size_t iv_size);

public:
    chacha20() {}
    ~chacha20()
    {
#ifdef _DEBUG
        memset(m_buf, 0xab, sizeof(m_buf));
#else
        Botan::secure_scrub_memory(m_buf, sizeof(m_buf));
#endif
    }

    void clear() {
        m_position = 0;
        flags.clear();
        m_impl.reset();
    }
    bool ready() const {
        return flags.is<f_prepared|f_key_set>();
    }

};

class BotanChaCha20 : public Botan::StreamCipher
{
    chacha20 core;
public:
    void key_schedule(std::span<const uint8_t> key) override
    {
        core.set_key(std::span<const uint8_t, chacha20::key_size>(key));
    }
    void cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) override
    {
        core.cipher(in, out, length);
    }
    void generate_keystream(uint8_t out[], size_t len) override
    {
        core.keystream(out, len);
    }
    void set_iv_bytes(const uint8_t iv[], size_t iv_len) override
    {
        core.set_iv(std::span(iv, iv_len));
    }
    bool valid_iv_length(size_t iv_len) const override { return (iv_len == 0 || iv_len == 8 || iv_len == 12 || iv_len == 24); }
    size_t default_iv_length() const override { return 24; }
    Botan::Key_Length_Specification key_spec() const override { return Botan::Key_Length_Specification(chacha20::key_size); }
    void clear() override
    {
        core.clear();
    }
    std::unique_ptr<StreamCipher> new_object() const override { return std::make_unique<BotanChaCha20>(); }
    void seek(uint64_t /*offset*/) override
    {
        BOTAN_ASSERT(false, "chacha20 seek"); // not implemented (looks like not used)
    }
    bool has_keying_material() const override {
        return core.ready();
    }
    size_t buffer_size() const override { return 64; }


};

