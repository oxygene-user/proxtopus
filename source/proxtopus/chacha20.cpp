#include "pch.h"

#include <botan/internal/cpuid.h>

void chacha20::impl::key_setup(const uint8_t* k)
{
    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;
    input[4] = tools::load32_le(k + 0);
    input[5] = tools::load32_le(k + 4);
    input[6] = tools::load32_le(k + 8);
    input[7] = tools::load32_le(k + 12);
    input[8] = tools::load32_le(k + 16);
    input[9] = tools::load32_le(k + 20);
    input[10] = tools::load32_le(k + 24);
    input[11] = tools::load32_le(k + 28);
}
void chacha20::impl::ic_setup(size_t ic)
{
    tools::store32_le((u8*)&input[12], static_cast<u32>(ic & 0xffffffff));

#ifdef MODE64
    u32 ic_high = ic >> 32;
    tools::store32_le((u8*)&input[13], ic_high);
#else
    input[13] = 0;
#endif

}
    
void chacha20::impl::ic_setup_ietf(size_t ic)
{
    tools::store32_le((u8*)&input[12], static_cast<u32>(ic));
}

void chacha20::impl::iv_setup(const uint8_t* iv)
{
    input[14] = tools::load32_le(iv + 0);
    input[15] = tools::load32_le(iv + 4);
}

void chacha20::impl::iv_setup_ietf(const uint8_t* iv)
{
    input[13] = tools::load32_le(iv + 0);
    input[14] = tools::load32_le(iv + 4);
    input[15] = tools::load32_le(iv + 8);
}

#ifdef _MSC_VER
#define ROTL(v,s) _rotl(v,s)
#endif
#ifdef __GNUC__
#define ROTL(v,s) _rotl(v,s)
#endif

inline void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d ^= a;
    d = ROTL(d,16);
    c += d;
    b ^= c;
    b = ROTL(b,12);
    a += b;
    d ^= a;
    d = ROTL(d,8);
    c += d;
    b ^= c;
    b = ROTL(b,7);
}


#define U32C(v) (v##U)
#define U32V(v) ((uint32_t)(v) &U32C(0xFFFFFFFF))

#define QUARTERROUND(A, B, C, D) chacha_quarter_round(A,B,C,D)

void chacha20::impl::key_setup_xchacha20(const unsigned char* k, const unsigned char* n)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;

    x0 = 0x61707865;
    x1 = 0x3320646e;
    x2 = 0x79622d32;
    x3 = 0x6b206574;

    x4 = tools::load32_le(k + 0);
    x5 = tools::load32_le(k + 4);
    x6 = tools::load32_le(k + 8);
    x7 = tools::load32_le(k + 12);
    x8 = tools::load32_le(k + 16);
    x9 = tools::load32_le(k + 20);
    x10 = tools::load32_le(k + 24);
    x11 = tools::load32_le(k + 28);
        
    if (n == nullptr)
    {
        x12 = 0;
        x13 = 0;
        x14 = 0;
        x15 = 0;
        input[14] = 0;
        input[15] = 0;

    } else
    {
        x12 = tools::load32_le(n + 0);
        x13 = tools::load32_le(n + 4);
        x14 = tools::load32_le(n + 8);
        x15 = tools::load32_le(n + 12);
        input[14] = tools::load32_le(n + 16);
        input[15] = tools::load32_le(n + 20);

    }

    for (size_t i = 0; i < 10; ++i) {
        QUARTERROUND(x0, x4, x8, x12);
        QUARTERROUND(x1, x5, x9, x13);
        QUARTERROUND(x2, x6, x10, x14);
        QUARTERROUND(x3, x7, x11, x15);
        QUARTERROUND(x0, x5, x10, x15);
        QUARTERROUND(x1, x6, x11, x12);
        QUARTERROUND(x2, x7, x8, x13);
        QUARTERROUND(x3, x4, x9, x14);
    }

    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;
    input[4] = x0;
    input[5] = x1;
    input[6] = x2;
    input[7] = x3;
    input[8] = x12;
    input[9] = x13;
    input[10] = x14;
    input[11] = x15;
      

}

void chacha20::impl::prepare(const uint8_t* k, const uint8_t* nonce, uint8_t nonce_size)
{
    if (nonce_size == 8)
    {
        key_setup(k);
        iv_setup(nonce);
    } else if (nonce_size == 12)
    {
        key_setup(k);
        iv_setup_ietf(nonce);
    }
    else
    {
        key_setup_xchacha20(k, nonce);
    }
}

#define GEN_IMPL(ivsz, ext) struct iml##ivsz##_chacha20_##ext : public chacha20::impl { void cipher(const uint8_t in[], uint8_t out[], size_t size, size_t ic) override {\
if (!size) return;\
ic_setup##ivsz(ic); cipher_##ext(in,out,size); }; }

#ifdef MODE64
GEN_IMPL(, ref); GEN_IMPL(, avx2); GEN_IMPL(, ssse3);
GEN_IMPL(_ietf, ref); GEN_IMPL(_ietf, avx2); GEN_IMPL(_ietf, ssse3);
#else
GEN_IMPL(, ref); GEN_IMPL(, ssse3);
GEN_IMPL(_ietf, ref); GEN_IMPL(_ietf, ssse3);
#endif
#undef GEN_IMPL
struct iml_buf
{
    u8 key[32];
    ~iml_buf()
    {
#ifdef _DEBUG
        memset(key, 0xab, sizeof(key));
#else
        Botan::secure_scrub_memory(key, sizeof(key));
#endif
    }
};
#define KEB void prepare(const uint8_t* k, const uint8_t* nonce, uint8_t nonce_size) override { if (k != nullptr) tools::memcopy<32>(key, k); impl::prepare(key, nonce, nonce_size); }
struct iml_chacha20_ref_keybuf : public iml_chacha20_ref, iml_buf { KEB };
#ifdef MODE64
struct iml_chacha20_avx2_keybuf : public iml_chacha20_avx2, iml_buf { KEB };
#endif
struct iml_chacha20_ssse3_keybuf : public iml_chacha20_ssse3, iml_buf { KEB };
#undef KEB

#include "sodium_chacha20_ref.inl"
#include "sodium_chacha20_ssse3.inl"
#ifdef MODE64
#include "sodium_chacha20_avx2.inl"
#endif

void chacha20::cipher(const uint8_t in[], uint8_t out[], size_t length)
{
    if (!flags.is<f_prepared>())
    {
        ASSERT((reinterpret_cast<size_t>(&m_buf) & (15)) == 0);

        if (!flags.is<f_key_set>())
            return;
        setup_implementation(24);
        m_impl->prepare(m_buf, nullptr, 24);
    }

    auto update_buf = [this]
    {
        if (!flags.is<f_buf_valid>())
        {
            m_impl->cipher(nullptr, m_buf, 64, m_position >> 6);
            flags.setup<f_buf_valid, f_nonce_set| f_key_set>();
        }
    };

    if (size_t pre = m_position & 63; pre > 0)
    {
        update_buf();

        size_t prelen = math::minv(64 - pre, length);
        if (in == nullptr)
            memcpy(out, m_buf + pre, prelen);
        else
        {
            Botan::xor_buf(out, in, m_buf + pre, prelen);
            in += prelen;
        }

        out += prelen;
        length -= prelen;
        m_position += prelen;
        if ((m_position & 63) == 0)
            flags.unset<f_buf_valid>();

        if (length == 0)
            return;
    }

    ASSERT((m_position & 63) == 0);
        
    size_t pure_size = length & (~63ull);
    size_t ic = m_position >> 6;
    if (flags.is<f_buf_valid>() && pure_size > 0)
    {
        if (in == nullptr)
            tools::memcopy<64>(out, m_buf);
        else
        {
            Botan::xor_buf(out, in, m_buf, 64);
            in += 64;
        }
        out += 64;
        length -= 64;
        pure_size -= 64;
        m_position += 64;
        flags.unset<f_buf_valid>();
        ++ic;
    }
    if (pure_size > 0)
    {
        m_impl->cipher(in, out, pure_size, ic);
        if (nullptr != in) in += pure_size;
        out += pure_size;
        length -= pure_size;
        m_position += pure_size;
        flags.unset<f_buf_valid>();
        ic += pure_size>>6;
    }
    ASSERT(length < 64);
    if (length > 0)
    {
        update_buf();

        if (in == nullptr)
            memcpy(out, m_buf, length);
        else
            Botan::xor_buf(out, in, m_buf, length);
        m_position += length;
    }

}

void chacha20::setup_implementation(size_t iv_size)
{
    switch (iv_size)
    {
    case 8:
#ifdef MODE64
        if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2)) {
            m_impl = std::make_unique<iml_chacha20_avx2>();
        }
#endif
        if (!m_impl && Botan::CPUID::has(Botan::CPUID::Feature::SSSE3)) {
            m_impl = std::make_unique<iml_chacha20_ssse3>();
        }
        if (!m_impl)
            m_impl = std::make_unique<iml_chacha20_ref>();

        flags.setn<f_impl_size>(1);
        break;
    case 12:

#ifdef MODE64
        if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2)) {
            m_impl = std::make_unique<iml_ietf_chacha20_avx2>();
        }
#endif
        if (!m_impl && Botan::CPUID::has(Botan::CPUID::Feature::SSSE3)) {
            m_impl = std::make_unique<iml_ietf_chacha20_ssse3>();
        }
        if (!m_impl)
            m_impl = std::make_unique<iml_ietf_chacha20_ref>();

        flags.setn<f_impl_size>(2); // means 12 bytes iv_len
        break;
    case 24:

#ifdef MODE64
        if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2)) {
            m_impl = std::make_unique<iml_chacha20_avx2_keybuf>();
        }
#endif
        if (!m_impl && Botan::CPUID::has(Botan::CPUID::Feature::SSSE3)) {
            m_impl = std::make_unique<iml_chacha20_ssse3_keybuf>();
        }
        if (!m_impl)
            m_impl = std::make_unique<iml_chacha20_ref_keybuf>();

        flags.setn<f_impl_size>(3);
        break;
    }
}

