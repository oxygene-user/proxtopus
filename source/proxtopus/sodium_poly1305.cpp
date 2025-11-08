/*
 * This file contains code derived from the Libsodium project (https://libsodium.org/)
 *
 * Original code:
 *   Copyright (c) 2013-2024 Frank Denis <j at pureftpd dot org>
 *   ISC License
 *
 * Modified by oxygene-user in 2025 for use in Proxtopus
 *
 * Permission to use, copy, modify, and/or distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright notice
 * and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include "pch.h"
#include <botan/internal/cpuid.h>

#ifdef ARCH_X86
# ifdef __clang__
#  pragma clang attribute push(__attribute__((target("sse2"))), apply_to = function)
# elif defined(__GNUC__)
#  pragma GCC target("sse2")
# endif
#endif

#ifndef SSE2_SUPPORTED
void poly1305::internal_donna::init(const uint8_t* k)
{
    ASSERT( (reinterpret_cast<size_t>(&buffer) & (15)) == 0);

#ifdef ARCH_64BIT

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    u64 t0 = load_le<8>(k + 0);
    u64 t1 = load_le<8>(k + 8);

    /* wiped after finalization */
    r[0] = (t0) & 0xffc0fffffffull;
    r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffull;
    r[2] = ((t1 >> 24)) & 0x00ffffffc0full;

    /* h = 0 */
    h[0] = 0;
    h[1] = 0;
    h[2] = 0;

    /* save pad for later */
    pad[0] = load_le<8>(k + 16);
    pad[1] = load_le<8>(k + 24);

#else
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff - wiped after finalization */
    r[0] = (tools::load32_le(k + 0)) & 0x3ffffff;
    r[1] = (tools::load32_le(k + 3) >> 2) & 0x3ffff03;
    r[2] = (tools::load32_le(k + 6) >> 4) & 0x3ffc0ff;
    r[3] = (tools::load32_le(k + 9) >> 6) & 0x3f03fff;
    r[4] = (tools::load32_le(k + 12) >> 8) & 0x00fffff;

    /* h = 0 */
    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;

    /* save pad for later */
    pad[0] = tools::load32_le(k + 16);
    pad[1] = tools::load32_le(k + 20);
    pad[2] = tools::load32_le(k + 24);
    pad[3] = tools::load32_le(k + 28);
#endif
    leftover = 0;
    final = false;
}
#endif

#ifdef ARCH_X86
void poly1305::internal_sse2::init(const uint8_t* k)
{
    using xmmi = __m128i;

    ASSERT((reinterpret_cast<size_t>(&buffer) & (15)) == 0);


    /* H = 0 */
    _mm_storeu_si128((xmmi*)(void*)&H.hh[0], _mm_setzero_si128());
    _mm_storeu_si128((xmmi*)(void*)&H.hh[4], _mm_setzero_si128());
    _mm_storeu_si128((xmmi*)(void*)&H.hh[8], _mm_setzero_si128());

    /* clamp key */
    struct
    {
        u64 t0, t1;
    } t01;
    tools::memcopy<16>(&t01, k);
    u64 r0 = t01.t0 & 0xffc0fffffff;
    t01.t0 >>= 44;
    t01.t0 |= t01.t1 << 20;
    u64 r1 = t01.t0 & 0xfffffc0ffff;
    t01.t1 >>= 24;
    u64 r2 = t01.t1 & 0x00ffffffc0f;

    /* r^1 */
    R[0] = static_cast<u32>(r0 & 0x3ffffff);
    R[1] = static_cast<u32>( ((r0 >> 26) | (r1 << 18)) & 0x3ffffff );
    R[2] = static_cast<u32>( (r1 >> 8) & 0x3ffffff );
    R[3] = static_cast<u32>( ((r1 >> 34) | (r2 << 10)) & 0x3ffffff );
    R[4] = static_cast<u32>( (r2 >> 16) );

    /* save pad */
    tools::memcopy<16>(&pad[0], k + 16);

    u64 rt0 = r0;
    u64 rt1 = r1;
    u64 rt2 = r2;

    /* r^2, r^4 */
    u32* RR = R2;
    for (size_t i = 0; i < 2; i++) {
        if (i == 1) {
            RR = R4;
        }
        u64 st2 = rt2 * (5 << 2);

        u128 d0 = (u128(rt0) * rt0) + (u128(rt1 * 2) * st2);
        u128 d1 = (u128(rt2) * st2) + (u128(rt0 * 2) * rt1);
        u128 d2 = (u128(rt1) * rt1) + (u128(rt2 * 2) * rt0);

        rt0 = (u64)d0 & 0xfffffffffff;
        d1 += (u64)(d0 >> 44);

        rt1 = (u64)d1 & 0xfffffffffff;
        d2 += (u64)(d1 >> 44);

        rt2 = (u64)d2 & 0x3ffffffffff;
        rt0 += ((u64)(d2 >> 42)) * 5;
        u64 c = (rt0 >> 44);
        rt0 = rt0 & 0xfffffffffff;
        rt1 += c;
        c = (rt1 >> 44);
        rt1 = rt1 & 0xfffffffffff;
        rt2 += c; /* even if rt2 overflows, it will still fit in rp4 safely, and
                     is safe to multiply with */

        RR[0] = static_cast<u32>(rt0 & 0x3ffffff);
        RR[1] = static_cast<u32>( ((rt0 >> 26) | (rt1 << 18)) & 0x3ffffff );
        RR[2] = static_cast<u32>( (rt1 >> 8) & 0x3ffffff );
        RR[3] = static_cast<u32>( ((rt1 >> 34) | (rt2 << 10)) & 0x3ffffff );
        RR[4] = static_cast<u32>( rt2 >> 16 );
    }

    flags = 0;
    leftover = 0U;
}
#endif

#define MUL(out, x, y) out = (u128(x) * y)
#define ADD(out, in) out += in
#define ADDLO(out, in) out += in
#define SHR(in, shift) (u64) (in >> (shift))
#define LO(in) (u64) (in)

#ifndef SSE2_SUPPORTED
void poly1305::internal_donna::poly1305_blocks(const uint8_t* m, size_t len)
{
#ifdef ARCH_64BIT
    const u64 hibit = (final) ? 0ULL : (1ULL << 40); /* 1 << 128 */

    u64 r0 = r[0];
    u64 r1 = r[1];
    u64 r2 = r[2];

    u64 h0 = h[0];
    u64 h1 = h[1];
    u64 h2 = h[2];

    u64 s1 = r1 * (5 << 2);
    u64 s2 = r2 * (5 << 2);

    while (len >= poly1305_block_size) {

        /* h += m[i] */
        u64 t0 = load_le<8>(m);
        u64 t1 = load_le<8>(m+8);

        h0 += t0 & 0xfffffffffff;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
        h2 += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

        u128 d0, d1, d2, d;

        /* h *= r */
        MUL(d0, h0, r0);
        MUL(d, h1, s2);
        ADD(d0, d);
        MUL(d, h2, s1);
        ADD(d0, d);
        MUL(d1, h0, r1);
        MUL(d, h1, r0);
        ADD(d1, d);
        MUL(d, h2, s2);
        ADD(d1, d);
        MUL(d2, h0, r2);
        MUL(d, h1, r1);
        ADD(d2, d);
        MUL(d, h2, r0);
        ADD(d2, d);

        /* (partial) h %= p */
        u64 c = SHR(d0, 44);
        h0 = LO(d0) & 0xfffffffffff;
        ADDLO(d1, c);
        c = SHR(d1, 44);
        h1 = LO(d1) & 0xfffffffffff;
        ADDLO(d2, c);
        c = SHR(d2, 42);
        h2 = LO(d2) & 0x3ffffffffff;
        h0 += c * 5;
        c = (h0 >> 44);
        h0 &= 0xfffffffffff;
        h1 += c;

        m += poly1305_block_size;
        len -= poly1305_block_size;
    }

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;

#else
    const u32 hibit = (final) ? 0UL : (1UL << 24); /* 1 << 128 */

    u32 r0 = r[0];
    u32 r1 = r[1];
    u32 r2 = r[2];
    u32 r3 = r[3];
    u32 r4 = r[4];

    u32 s1 = r1 * 5;
    u32 s2 = r2 * 5;
    u32 s3 = r3 * 5;
    u32 s4 = r4 * 5;

    u32 h0 = h[0];
    u32 h1 = h[1];
    u32 h2 = h[2];
    u32 h3 = h[3];
    u32 h4 = h[4];

    while (len >= poly1305_block_size) {
        /* h += m[i] */
        h0 += (tools::load32_le(m + 0)) & 0x3ffffff;
        h1 += (tools::load32_le(m + 3) >> 2) & 0x3ffffff;
        h2 += (tools::load32_le(m + 6) >> 4) & 0x3ffffff;
        h3 += (tools::load32_le(m + 9) >> 6) & 0x3ffffff;
        h4 += (tools::load32_le(m + 12) >> 8) | hibit;

        /* h *= r */
        u64 d0 = ((u64) h0 * r0) + ((u64) h1 * s4) + ((u64) h2 * s3) + ((u64) h3 * s2) + ((u64) h4 * s1);
        u64 d1 = ((u64) h0 * r1) + ((u64) h1 * r0) + ((u64) h2 * s4) + ((u64) h3 * s3) + ((u64) h4 * s2);
        u64 d2 = ((u64) h0 * r2) + ((u64) h1 * r1) + ((u64) h2 * r0) + ((u64) h3 * s4) + ((u64) h4 * s3);
        u64 d3 = ((u64) h0 * r3) + ((u64) h1 * r2) + ((u64) h2 * r1) + ((u64) h3 * r0) + ((u64) h4 * s4);
        u64 d4 = ((u64) h0 * r4) + ((u64) h1 * r3) + ((u64) h2 * r2) + ((u64) h3 * r1) + ((u64) h4 * r0);

        /* (partial) h %= p */
        u32 c = (u32)(d0 >> 26);
        h0 = (u32)d0 & 0x3ffffff;
        d1 += c;
        c = (u32)(d1 >> 26);
        h1 = (u32)d1 & 0x3ffffff;
        d2 += c;
        c = (u32)(d2 >> 26);
        h2 = (u32)d2 & 0x3ffffff;
        d3 += c;
        c = (u32)(d3 >> 26);
        h3 = (u32)d3 & 0x3ffffff;
        d4 += c;
        c = (u32)(d4 >> 26);
        h4 = (u32)d4 & 0x3ffffff;
        h0 += c * 5;
        c = (h0 >> 26);
        h0 &= 0x3ffffff;
        h1 += c;

        m += poly1305_block_size;
        len -= poly1305_block_size;
    }

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;

#endif
}
#endif

#ifdef ARCH_X86
void poly1305::internal_sse2::poly1305_blocks(const uint8_t* m, size_t len)
{
    using xmmi = __m128i;

    auto inithibit = [](auto flags) -> xmmi
        {
            if (flags & poly1305_final_shift16)
                return _mm_setzero_si128();

            if (flags & poly1305_final_shift8)
                return _mm_srli_si128(_mm_shuffle_epi32(_mm_cvtsi32_si128(1 << 24), _MM_SHUFFLE(1, 0, 1, 0)), 8);
            return _mm_shuffle_epi32(_mm_cvtsi32_si128(1 << 24), _MM_SHUFFLE(1, 0, 1, 0));
        };

    ALIGN(64) const xmmi HIBIT = inithibit(flags);
    const xmmi MMASK = _mm_shuffle_epi32(_mm_cvtsi32_si128((1 << 26) - 1), _MM_SHUFFLE(1, 0, 1, 0));
    const xmmi FIVE = _mm_shuffle_epi32(_mm_cvtsi32_si128(5), _MM_SHUFFLE(1, 0, 1, 0));

    xmmi H0, H1, H2, H3, H4;
    xmmi T0, T1, T2, T3, T4, T5, T6, T7, T8;
    xmmi M0, M1, M2, M3, M4;
    xmmi M5, M6, M7, M8;
    xmmi C1, C2;
    xmmi R20, R21, R22, R23, R24, S21, S22, S23, S24;
    xmmi R40, R41, R42, R43, R44, S41, S42, S43, S44;

    if (!(flags & poly1305_started)) {
        /* H = [Mx,My] */
        T5 = _mm_unpacklo_epi64(
            _mm_loadl_epi64((const xmmi*)(const void*)(m + 0)),
            _mm_loadl_epi64((const xmmi*)(const void*)(m + 16)));
        T6 = _mm_unpacklo_epi64(
            _mm_loadl_epi64((const xmmi*)(const void*)(m + 8)),
            _mm_loadl_epi64((const xmmi*)(const void*)(m + 24)));
        H0 = _mm_and_si128(MMASK, T5);
        H1 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26));
        T5 = _mm_or_si128(_mm_srli_epi64(T5, 52), _mm_slli_epi64(T6, 12));
        H2 = _mm_and_si128(MMASK, T5);
        H3 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26));
        H4 = _mm_srli_epi64(T6, 40);
        H4 = _mm_or_si128(H4, HIBIT);
        m += 32;
        len -= 32;
        flags |= poly1305_started;
    }
    else {
        T0 = _mm_loadu_si128((const xmmi*)(const void*)&H.hh[0]);
        T1 = _mm_loadu_si128((const xmmi*)(const void*)&H.hh[4]);
        T2 = _mm_loadu_si128((const xmmi*)(const void*)&H.hh[8]);
        H0 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1, 1, 0, 0));
        H1 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(3, 3, 2, 2));
        H2 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(1, 1, 0, 0));
        H3 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(3, 3, 2, 2));
        H4 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1, 1, 0, 0));
    }
    if (flags & (poly1305_final_r2_r | poly1305_final_r_1)) {
        if (flags & poly1305_final_r2_r) {
            /* use [r^2, r] */
            T2 = _mm_loadu_si128((const xmmi*)(const void*)&R[0]);
            T3 = _mm_cvtsi32_si128(R[4]);
            T0 = _mm_loadu_si128((const xmmi*)(const void*)&R2[0]);
            T1 = _mm_cvtsi32_si128(R2[4]);
            T4 = _mm_unpacklo_epi32(T0, T2);
            T5 = _mm_unpackhi_epi32(T0, T2);
            R24 = _mm_unpacklo_epi64(T1, T3);
        }
        else {
            /* use [r^1, 1] */
            T0 = _mm_loadu_si128((const xmmi*)(const void*)&R[0]);
            T1 = _mm_cvtsi32_si128(R[4]);
            T2 = _mm_cvtsi32_si128(1);
            T4 = _mm_unpacklo_epi32(T0, T2);
            T5 = _mm_unpackhi_epi32(T0, T2);
            R24 = T1;
        }
        R20 = _mm_shuffle_epi32(T4, _MM_SHUFFLE(1, 1, 0, 0));
        R21 = _mm_shuffle_epi32(T4, _MM_SHUFFLE(3, 3, 2, 2));
        R22 = _mm_shuffle_epi32(T5, _MM_SHUFFLE(1, 1, 0, 0));
        R23 = _mm_shuffle_epi32(T5, _MM_SHUFFLE(3, 3, 2, 2));
    }
    else {
        /* use [r^2, r^2] */
        T0 = _mm_loadu_si128((const xmmi*)(const void*)&R2[0]);
        T1 = _mm_cvtsi32_si128(R2[4]);
        R20 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(0, 0, 0, 0));
        R21 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1, 1, 1, 1));
        R22 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(2, 2, 2, 2));
        R23 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(3, 3, 3, 3));
        R24 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(0, 0, 0, 0));
    }
    S21 = _mm_mul_epu32(R21, FIVE);
    S22 = _mm_mul_epu32(R22, FIVE);
    S23 = _mm_mul_epu32(R23, FIVE);
    S24 = _mm_mul_epu32(R24, FIVE);

    if (len >= 64) {
        T0 = _mm_loadu_si128((const xmmi*)(const void*)&R4[0]);
        T1 = _mm_cvtsi32_si128(R4[4]);
        R40 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(0, 0, 0, 0));
        R41 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1, 1, 1, 1));
        R42 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(2, 2, 2, 2));
        R43 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(3, 3, 3, 3));
        R44 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(0, 0, 0, 0));
        S41 = _mm_mul_epu32(R41, FIVE);
        S42 = _mm_mul_epu32(R42, FIVE);
        S43 = _mm_mul_epu32(R43, FIVE);
        S44 = _mm_mul_epu32(R44, FIVE);

        while (len >= 64) {
            xmmi v00, v01, v02, v03, v04;
            xmmi v10, v11, v12, v13, v14;
            xmmi v20, v21, v22, v23, v24;
            xmmi v30, v31, v32, v33, v34;
            xmmi v40, v41, v42, v43, v44;
            xmmi T14, T15;

            /* H *= [r^4,r^4], preload [Mx,My] */
            T15 = S42;
            T0 = H4;
            T0 = _mm_mul_epu32(T0, S41);
            v01 = H3;
            v01 = _mm_mul_epu32(v01, T15);
            T14 = S43;
            T1 = H4;
            T1 = _mm_mul_epu32(T1, T15);
            v11 = H3;
            v11 = _mm_mul_epu32(v11, T14);
            T2 = H4;
            T2 = _mm_mul_epu32(T2, T14);
            T0 = _mm_add_epi64(T0, v01);
            T15 = S44;
            v02 = H2;
            v02 = _mm_mul_epu32(v02, T14);
            T3 = H4;
            T3 = _mm_mul_epu32(T3, T15);
            T1 = _mm_add_epi64(T1, v11);
            v03 = H1;
            v03 = _mm_mul_epu32(v03, T15);
            v12 = H2;
            v12 = _mm_mul_epu32(v12, T15);
            T0 = _mm_add_epi64(T0, v02);
            T14 = R40;
            v21 = H3;
            v21 = _mm_mul_epu32(v21, T15);
            v31 = H3;
            v31 = _mm_mul_epu32(v31, T14);
            T0 = _mm_add_epi64(T0, v03);
            T4 = H4;
            T4 = _mm_mul_epu32(T4, T14);
            T1 = _mm_add_epi64(T1, v12);
            v04 = H0;
            v04 = _mm_mul_epu32(v04, T14);
            T2 = _mm_add_epi64(T2, v21);
            v13 = H1;
            v13 = _mm_mul_epu32(v13, T14);
            T3 = _mm_add_epi64(T3, v31);
            T15 = R41;
            v22 = H2;
            v22 = _mm_mul_epu32(v22, T14);
            v32 = H2;
            v32 = _mm_mul_epu32(v32, T15);
            T0 = _mm_add_epi64(T0, v04);
            v41 = H3;
            v41 = _mm_mul_epu32(v41, T15);
            T1 = _mm_add_epi64(T1, v13);
            v14 = H0;
            v14 = _mm_mul_epu32(v14, T15);
            T2 = _mm_add_epi64(T2, v22);
            T14 = R42;
            T5 = _mm_unpacklo_epi64( _mm_loadl_epi64((const xmmi*)(const void*)(m + 0)), _mm_loadl_epi64((const xmmi*)(const void*)(m + 16)));
            v23 = H1;
            v23 = _mm_mul_epu32(v23, T15);
            T3 = _mm_add_epi64(T3, v32);
            v33 = H1;
            v33 = _mm_mul_epu32(v33, T14);
            T4 = _mm_add_epi64(T4, v41);
            v42 = H2;
            v42 = _mm_mul_epu32(v42, T14);
            T1 = _mm_add_epi64(T1, v14);
            T15 = R43;
            T6 = _mm_unpacklo_epi64( _mm_loadl_epi64((const xmmi*)(const void*)(m + 8)), _mm_loadl_epi64((const xmmi*)(const void*)(m + 24)));
            v24 = H0;
            v24 = _mm_mul_epu32(v24, T14);
            T2 = _mm_add_epi64(T2, v23);
            v34 = H0;
            v34 = _mm_mul_epu32(v34, T15);
            T3 = _mm_add_epi64(T3, v33);
            M0 = _mm_and_si128(MMASK, T5);
            v43 = H1;
            v43 = _mm_mul_epu32(v43, T15);
            T4 = _mm_add_epi64(T4, v42);
            M1 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26));
            v44 = H0;
            v44 = _mm_mul_epu32(v44, R44);
            T2 = _mm_add_epi64(T2, v24);
            T5 = _mm_or_si128(_mm_srli_epi64(T5, 52), _mm_slli_epi64(T6, 12));
            T3 = _mm_add_epi64(T3, v34);
            M3 = _mm_and_si128(MMASK, _mm_srli_epi64(T6, 14));
            T4 = _mm_add_epi64(T4, v43);
            M2 = _mm_and_si128(MMASK, T5);
            T4 = _mm_add_epi64(T4, v44);
            M4 = _mm_or_si128(_mm_srli_epi64(T6, 40), HIBIT);

            /* H += [Mx',My'] */
            T5 = _mm_loadu_si128((const xmmi*)(const void*)(m + 32));
            T6 = _mm_loadu_si128((const xmmi*)(const void*)(m + 48));
            T7 = _mm_unpacklo_epi32(T5, T6);
            T8 = _mm_unpackhi_epi32(T5, T6);
            M5 = _mm_unpacklo_epi32(T7, _mm_setzero_si128());
            M6 = _mm_unpackhi_epi32(T7, _mm_setzero_si128());
            M7 = _mm_unpacklo_epi32(T8, _mm_setzero_si128());
            M8 = _mm_unpackhi_epi32(T8, _mm_setzero_si128());
            M6 = _mm_slli_epi64(M6, 6);
            M7 = _mm_slli_epi64(M7, 12);
            M8 = _mm_slli_epi64(M8, 18);
            T0 = _mm_add_epi64(T0, M5);
            T1 = _mm_add_epi64(T1, M6);
            T2 = _mm_add_epi64(T2, M7);
            T3 = _mm_add_epi64(T3, M8);
            T4 = _mm_add_epi64(T4, HIBIT);

            /* H += [Mx,My]*[r^2,r^2] */
            T15 = S22;
            v00 = M4;
            v00 = _mm_mul_epu32(v00, S21);
            v01 = M3;
            v01 = _mm_mul_epu32(v01, T15);
            T14 = S23;
            v10 = M4;
            v10 = _mm_mul_epu32(v10, T15);
            v11 = M3;
            v11 = _mm_mul_epu32(v11, T14);
            T0 = _mm_add_epi64(T0, v00);
            v20 = M4;
            v20 = _mm_mul_epu32(v20, T14);
            T0 = _mm_add_epi64(T0, v01);
            T15 = S24;
            v02 = M2;
            v02 = _mm_mul_epu32(v02, T14);
            T1 = _mm_add_epi64(T1, v10);
            v30 = M4;
            v30 = _mm_mul_epu32(v30, T15);
            T1 = _mm_add_epi64(T1, v11);
            v03 = M1;
            v03 = _mm_mul_epu32(v03, T15);
            T2 = _mm_add_epi64(T2, v20);
            v12 = M2;
            v12 = _mm_mul_epu32(v12, T15);
            T0 = _mm_add_epi64(T0, v02);
            T14 = R20;
            v21 = M3;
            v21 = _mm_mul_epu32(v21, T15);
            T3 = _mm_add_epi64(T3, v30);
            v31 = M3;
            v31 = _mm_mul_epu32(v31, T14);
            T0 = _mm_add_epi64(T0, v03);
            v40 = M4;
            v40 = _mm_mul_epu32(v40, T14);
            T1 = _mm_add_epi64(T1, v12);
            v04 = M0;
            v04 = _mm_mul_epu32(v04, T14);
            T2 = _mm_add_epi64(T2, v21);
            v13 = M1;
            v13 = _mm_mul_epu32(v13, T14);
            T3 = _mm_add_epi64(T3, v31);
            T15 = R21;
            v22 = M2;
            v22 = _mm_mul_epu32(v22, T14);
            T4 = _mm_add_epi64(T4, v40);
            v32 = M2;
            v32 = _mm_mul_epu32(v32, T15);
            T0 = _mm_add_epi64(T0, v04);
            v41 = M3;
            v41 = _mm_mul_epu32(v41, T15);
            T1 = _mm_add_epi64(T1, v13);
            v14 = M0;
            v14 = _mm_mul_epu32(v14, T15);
            T2 = _mm_add_epi64(T2, v22);
            T14 = R22;
            v23 = M1;
            v23 = _mm_mul_epu32(v23, T15);
            T3 = _mm_add_epi64(T3, v32);
            v33 = M1;
            v33 = _mm_mul_epu32(v33, T14);
            T4 = _mm_add_epi64(T4, v41);
            v42 = M2;
            v42 = _mm_mul_epu32(v42, T14);
            T1 = _mm_add_epi64(T1, v14);
            T15 = R23;
            v24 = M0;
            v24 = _mm_mul_epu32(v24, T14);
            T2 = _mm_add_epi64(T2, v23);
            v34 = M0;
            v34 = _mm_mul_epu32(v34, T15);
            T3 = _mm_add_epi64(T3, v33);
            v43 = M1;
            v43 = _mm_mul_epu32(v43, T15);
            T4 = _mm_add_epi64(T4, v42);
            v44 = M0;
            v44 = _mm_mul_epu32(v44, R24);
            T2 = _mm_add_epi64(T2, v24);
            T3 = _mm_add_epi64(T3, v34);
            T4 = _mm_add_epi64(T4, v43);
            T4 = _mm_add_epi64(T4, v44);

            /* reduce */
            C1 = _mm_srli_epi64(T0, 26);
            C2 = _mm_srli_epi64(T3, 26);
            T0 = _mm_and_si128(T0, MMASK);
            T3 = _mm_and_si128(T3, MMASK);
            T1 = _mm_add_epi64(T1, C1);
            T4 = _mm_add_epi64(T4, C2);
            C1 = _mm_srli_epi64(T1, 26);
            C2 = _mm_srli_epi64(T4, 26);
            T1 = _mm_and_si128(T1, MMASK);
            T4 = _mm_and_si128(T4, MMASK);
            T2 = _mm_add_epi64(T2, C1);
            T0 = _mm_add_epi64(T0, _mm_mul_epu32(C2, FIVE));
            C1 = _mm_srli_epi64(T2, 26);
            C2 = _mm_srli_epi64(T0, 26);
            T2 = _mm_and_si128(T2, MMASK);
            T0 = _mm_and_si128(T0, MMASK);
            T3 = _mm_add_epi64(T3, C1);
            T1 = _mm_add_epi64(T1, C2);
            C1 = _mm_srli_epi64(T3, 26);
            T3 = _mm_and_si128(T3, MMASK);
            T4 = _mm_add_epi64(T4, C1);

            /* Final: H = (H*[r^4,r^4] + [Mx,My]*[r^2,r^2] + [Mx',My']) */
            H0 = T0;
            H1 = T1;
            H2 = T2;
            H3 = T3;
            H4 = T4;

            m += 64;
            len -= 64;
        }
    }

    if (len >= 32) {
        xmmi v01, v02, v03, v04;
        xmmi v11, v12, v13, v14;
        xmmi v21, v22, v23, v24;
        xmmi v31, v32, v33, v34;
        xmmi v41, v42, v43, v44;
        xmmi T14, T15;

        /* H *= [r^2,r^2] */
        T15 = S22;
        T0 = H4;
        T0 = _mm_mul_epu32(T0, S21);
        v01 = H3;
        v01 = _mm_mul_epu32(v01, T15);
        T14 = S23;
        T1 = H4;
        T1 = _mm_mul_epu32(T1, T15);
        v11 = H3;
        v11 = _mm_mul_epu32(v11, T14);
        T2 = H4;
        T2 = _mm_mul_epu32(T2, T14);
        T0 = _mm_add_epi64(T0, v01);
        T15 = S24;
        v02 = H2;
        v02 = _mm_mul_epu32(v02, T14);
        T3 = H4;
        T3 = _mm_mul_epu32(T3, T15);
        T1 = _mm_add_epi64(T1, v11);
        v03 = H1;
        v03 = _mm_mul_epu32(v03, T15);
        v12 = H2;
        v12 = _mm_mul_epu32(v12, T15);
        T0 = _mm_add_epi64(T0, v02);
        T14 = R20;
        v21 = H3;
        v21 = _mm_mul_epu32(v21, T15);
        v31 = H3;
        v31 = _mm_mul_epu32(v31, T14);
        T0 = _mm_add_epi64(T0, v03);
        T4 = H4;
        T4 = _mm_mul_epu32(T4, T14);
        T1 = _mm_add_epi64(T1, v12);
        v04 = H0;
        v04 = _mm_mul_epu32(v04, T14);
        T2 = _mm_add_epi64(T2, v21);
        v13 = H1;
        v13 = _mm_mul_epu32(v13, T14);
        T3 = _mm_add_epi64(T3, v31);
        T15 = R21;
        v22 = H2;
        v22 = _mm_mul_epu32(v22, T14);
        v32 = H2;
        v32 = _mm_mul_epu32(v32, T15);
        T0 = _mm_add_epi64(T0, v04);
        v41 = H3;
        v41 = _mm_mul_epu32(v41, T15);
        T1 = _mm_add_epi64(T1, v13);
        v14 = H0;
        v14 = _mm_mul_epu32(v14, T15);
        T2 = _mm_add_epi64(T2, v22);
        T14 = R22;
        v23 = H1;
        v23 = _mm_mul_epu32(v23, T15);
        T3 = _mm_add_epi64(T3, v32);
        v33 = H1;
        v33 = _mm_mul_epu32(v33, T14);
        T4 = _mm_add_epi64(T4, v41);
        v42 = H2;
        v42 = _mm_mul_epu32(v42, T14);
        T1 = _mm_add_epi64(T1, v14);
        T15 = R23;
        v24 = H0;
        v24 = _mm_mul_epu32(v24, T14);
        T2 = _mm_add_epi64(T2, v23);
        v34 = H0;
        v34 = _mm_mul_epu32(v34, T15);
        T3 = _mm_add_epi64(T3, v33);
        v43 = H1;
        v43 = _mm_mul_epu32(v43, T15);
        T4 = _mm_add_epi64(T4, v42);
        v44 = H0;
        v44 = _mm_mul_epu32(v44, R24);
        T2 = _mm_add_epi64(T2, v24);
        T3 = _mm_add_epi64(T3, v34);
        T4 = _mm_add_epi64(T4, v43);
        T4 = _mm_add_epi64(T4, v44);

        /* H += [Mx,My] */
        if (m) {
            T5 = _mm_loadu_si128((const xmmi*)(const void*)(m + 0));
            T6 = _mm_loadu_si128((const xmmi*)(const void*)(m + 16));
            T7 = _mm_unpacklo_epi32(T5, T6);
            T8 = _mm_unpackhi_epi32(T5, T6);
            M0 = _mm_unpacklo_epi32(T7, _mm_setzero_si128());
            M1 = _mm_unpackhi_epi32(T7, _mm_setzero_si128());
            M2 = _mm_unpacklo_epi32(T8, _mm_setzero_si128());
            M3 = _mm_unpackhi_epi32(T8, _mm_setzero_si128());
            M1 = _mm_slli_epi64(M1, 6);
            M2 = _mm_slli_epi64(M2, 12);
            M3 = _mm_slli_epi64(M3, 18);
            T0 = _mm_add_epi64(T0, M0);
            T1 = _mm_add_epi64(T1, M1);
            T2 = _mm_add_epi64(T2, M2);
            T3 = _mm_add_epi64(T3, M3);
            T4 = _mm_add_epi64(T4, HIBIT);
        }

        /* reduce */
        C1 = _mm_srli_epi64(T0, 26);
        C2 = _mm_srli_epi64(T3, 26);
        T0 = _mm_and_si128(T0, MMASK);
        T3 = _mm_and_si128(T3, MMASK);
        T1 = _mm_add_epi64(T1, C1);
        T4 = _mm_add_epi64(T4, C2);
        C1 = _mm_srli_epi64(T1, 26);
        C2 = _mm_srli_epi64(T4, 26);
        T1 = _mm_and_si128(T1, MMASK);
        T4 = _mm_and_si128(T4, MMASK);
        T2 = _mm_add_epi64(T2, C1);
        T0 = _mm_add_epi64(T0, _mm_mul_epu32(C2, FIVE));
        C1 = _mm_srli_epi64(T2, 26);
        C2 = _mm_srli_epi64(T0, 26);
        T2 = _mm_and_si128(T2, MMASK);
        T0 = _mm_and_si128(T0, MMASK);
        T3 = _mm_add_epi64(T3, C1);
        T1 = _mm_add_epi64(T1, C2);
        C1 = _mm_srli_epi64(T3, 26);
        T3 = _mm_and_si128(T3, MMASK);
        T4 = _mm_add_epi64(T4, C1);

        /* H = (H*[r^2,r^2] + [Mx,My]) */
        H0 = T0;
        H1 = T1;
        H2 = T2;
        H3 = T3;
        H4 = T4;
    }

    if (m) {
        T0 = _mm_shuffle_epi32(H0, _MM_SHUFFLE(0, 0, 2, 0));
        T1 = _mm_shuffle_epi32(H1, _MM_SHUFFLE(0, 0, 2, 0));
        T2 = _mm_shuffle_epi32(H2, _MM_SHUFFLE(0, 0, 2, 0));
        T3 = _mm_shuffle_epi32(H3, _MM_SHUFFLE(0, 0, 2, 0));
        T4 = _mm_shuffle_epi32(H4, _MM_SHUFFLE(0, 0, 2, 0));
        T0 = _mm_unpacklo_epi64(T0, T1);
        T1 = _mm_unpacklo_epi64(T2, T3);
        _mm_storeu_si128((xmmi*)(void*)&H.hh[0], T0);
        _mm_storeu_si128((xmmi*)(void*)&H.hh[4], T1);
        _mm_storel_epi64((xmmi*)(void*)&H.hh[8], T4);
    }
    else {

        /* H = H[0]+H[1] */
        T0 = H0;
        T1 = H1;
        T2 = H2;
        T3 = H3;
        T4 = H4;

        T0 = _mm_add_epi64(T0, _mm_srli_si128(T0, 8));
        T1 = _mm_add_epi64(T1, _mm_srli_si128(T1, 8));
        T2 = _mm_add_epi64(T2, _mm_srli_si128(T2, 8));
        T3 = _mm_add_epi64(T3, _mm_srli_si128(T3, 8));
        T4 = _mm_add_epi64(T4, _mm_srli_si128(T4, 8));

        u32 t0 = _mm_cvtsi128_si32(T0);
        u32 b = (t0 >> 26);
        t0 &= 0x3ffffff;
        u32 t1 = _mm_cvtsi128_si32(T1) + b;
        b = (t1 >> 26);
        t1 &= 0x3ffffff;
        u32 t2 = _mm_cvtsi128_si32(T2) + b;
        b = (t2 >> 26);
        t2 &= 0x3ffffff;
        u32 t3 = _mm_cvtsi128_si32(T3) + b;
        b = (t3 >> 26);
        t3 &= 0x3ffffff;
        u32 t4 = _mm_cvtsi128_si32(T4) + b;

        /* everything except t4 is in range, so this is all safe */
        u64 h0 = (((u64)t0) | ((u64)t1 << 26)) & 0xfffffffffffull;
        u64 h1 = (((u64)t1 >> 18) | ((u64)t2 << 8) | ((u64)t3 << 34)) & 0xfffffffffffull;
        u64 h2 = (((u64)t3 >> 10) | ((u64)t4 << 16));

        u64 c = (h2 >> 42);
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = (h0 >> 44);
        h0 &= 0xfffffffffff;
        h1 += c;
        c = (h1 >> 44);
        h1 &= 0xfffffffffff;
        h2 += c;
        c = (h2 >> 42);
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = (h0 >> 44);
        h0 &= 0xfffffffffff;
        h1 += c;

        u64 g0 = h0 + 5;
        c = (g0 >> 44);
        g0 &= 0xfffffffffff;
        u64 g1 = h1 + c;
        c = (g1 >> 44);
        g1 &= 0xfffffffffff;
        u64 g2 = h2 + c - ((u64)1 << 42);

        c = (g2 >> 63) - 1;
        u64 nc = ~c;
        h0 = (h0 & nc) | (g0 & c);
        h1 = (h1 & nc) | (g1 & c);
        h2 = (h2 & nc) | (g2 & c);

        H.h[0] = h0;
        H.h[1] = h1;
        H.h[2] = h2;
    }

}
#endif

#ifndef SSE2_SUPPORTED
void poly1305::internal_donna::fin(uint8_t* tag)
{
    /* process the remaining block */
    if (leftover) {
        buffer[leftover] = 1;
        for (size_t i = leftover + 1; i < poly1305_block_size; ++i)
            buffer[i] = 0;
        final = true;
        poly1305_blocks(buffer, poly1305_block_size);
    }

#ifdef ARCH_64BIT

    /* fully carry h */
    u64 h0 = h[0];
    u64 h1 = h[1];
    u64 h2 = h[2];

    u64 c = h1 >> 44;
    h1 &= 0xfffffffffff;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffff;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffff;
    h1 += c;
    c = h1 >> 44;
    h1 &= 0xfffffffffff;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffff;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffff;
    h1 += c;

    /* compute h + -p */
    u64 g0 = h0 + 5;
    c = g0 >> 44;
    g0 &= 0xfffffffffff;
    u64 g1 = h1 + c;
    c = g1 >> 44;
    g1 &= 0xfffffffffff;
    u64 g2 = h2 + c - (1ULL << 42);

    /* select h if h < p, or h + -p if h >= p */
    u64 mask = (g2 >> ((sizeof(u64) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;

    /* h = (h + pad) */
    u64 t0 = pad[0];
    u64 t1 = pad[1];

    h0 += ((t0) & 0xfffffffffff);
    c = (h0 >> 44);
    h0 &= 0xfffffffffff;
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
    c = (h1 >> 44);
    h1 &= 0xfffffffffff;
    h2 += (((t1 >> 24)) & 0x3ffffffffff) + c;
    h2 &= 0x3ffffffffff;

    /* mac = h % (2^128) */
    h0 = (h0) | (h1 << 44);
    h1 = (h1 >> 20) | (h2 << 24);

    tools::store64_le(tag+0, h0);
    tools::store64_le(tag+8, h1);

#else

    /* fully carry h */
    u32 h0 = h[0];
    u32 h1 = h[1];
    u32 h2 = h[2];
    u32 h3 = h[3];
    u32 h4 = h[4];

    u32 c = h1 >> 26;
    h1 = h1 & 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 = h2 & 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 = h3 & 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 = h4 & 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 = h0 & 0x3ffffff;
    h1 += c;

    /* compute h + -p */
    u32 g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    u32 g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    u32 g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    u32 g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    u32 g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    u32 mask = (g4 >> ((sizeof(u32) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;

    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    u64 f = (u64) h0 + pad[0];
    h0 = (u32)f;
    f = (u64) h1 + pad[1] + (f >> 32);
    h1 = (u32)f;
    f = (u64) h2 + pad[2] + (f >> 32);
    h2 = (u32)f;
    f = (u64) h3 + pad[3] + (f >> 32);
    h3 = (u32)f;

    tools::store32_le(tag + 0, h0);
    tools::store32_le(tag + 4, h1);
    tools::store32_le(tag + 8, h2);
    tools::store32_le(tag + 12, h3);

#endif

    /* zero out the state */
    secure::scrub_memory(this, sizeof(internal_donna));
}
#endif

/* copy 0-31 bytes */
static inline void poly1305_block_copy31(u8* dst, const u8* src, u64 bytes)
{
#ifdef ARCH_X86
    using xmmi = __m128i;

    if (bytes & 16) {
        _mm_store_si128((xmmi*)(void*)dst, _mm_loadu_si128((const xmmi*)(const void*)src));
        src += 16;
        dst += 16;
    }
#else
    if (bytes & 16) {
        tools::memcopy<16>(dst, src);
        src += 16;
        dst += 16;
    }
#endif

    if (bytes & 8) {
        tools::memcopy<8>(dst, src);
        src += 8;
        dst += 8;
    }
    if (bytes & 4) {
        tools::memcopy<4>(dst, src);
        src += 4;
        dst += 4;
    }
    if (bytes & 2) {
        tools::memcopy<2>(dst, src);
        src += 2;
        dst += 2;
    }
    if (bytes & 1) {
        *dst = *src;
    }
}

#ifdef ARCH_X86
void poly1305::internal_sse2::fin(uint8_t* tag)
{
    using xmmi = __m128i;

    if (leftover) {
        ALIGN(16) u8 final_block[32] = { 0 };

        poly1305_block_copy31(final_block, buffer, leftover);
        if (leftover != 16) {
            final_block[leftover] = 1;
        }
        flags |= (leftover >= 16) ? poly1305_final_shift8 : poly1305_final_shift16;
        poly1305_blocks(final_block, 32);
    }

    if (flags & poly1305_started) {
        /* finalize, H *= [r^2,r], or H *= [r,1] */
        if (!leftover || (leftover > 16)) {
            flags |= poly1305_final_r2_r;
        }
        else {
            flags |= poly1305_final_r_1;
        }
        poly1305_blocks(nullptr, 32);
    }

    struct
    {
        u64 h0;
        u64 h1;
    } h01;

    h01.h0 = H.h[0];
    h01.h1 = H.h[1];
    u64 h2 = H.h[2];

    /* pad */
    h01.h0 = ((h01.h0) | (h01.h1 << 44));
    h01.h1 = ((h01.h1 >> 20) | (h2 << 24));
    u128 h;
    tools::memcopy<16>(&h, &pad[0]);
    h += ((u128)h01.h1 << 64) | h01.h0;
    h01.h0 = (u64)h;
    h01.h1 = (u64)(h >> 64);

    // super paranoic clear
    _mm_storeu_si128(((xmmi*)(void*)this) + 0, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 1, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 2, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 3, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 4, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 5, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 6, _mm_setzero_si128());
    _mm_storeu_si128(((xmmi*)(void*)this) + 7, _mm_setzero_si128());

    tools::memcopy<16>(tag, &h01);

    /* zero out the state */
    secure::scrub_memory(this, sizeof(internal_sse2));
}
#endif

void poly1305::init(const uint8_t* k)
{
#ifdef SSE2_SUPPORTED
    if (k == nullptr)
        memset(&internal.data(), 0, sizeof(internal_sse2));
    else
        internal.data().init(k);
#else

#ifdef ARCH_X86
    if (Botan::CPUID::has(Botan::CPUID::Feature::SSE2))
    {
        if (k == nullptr)
            memset(&internal.data(), 0, sizeof(internal_sse2));
        else
            internal.data().isse2.init(k);
    }
    else
#endif
    {
        if (k == nullptr)
            memset(&internal.data(), 0, sizeof(internal_donna));
        else
            internal.data().idonna.init(k);
    }
#endif

}
void poly1305::update(std::span<const uint8_t> m)
{
#ifdef SSE2_SUPPORTED
    update_core(internal.data(), m.data(), m.size());
#else
#ifdef ARCH_X86
    if (Botan::CPUID::has(Botan::CPUID::Feature::SSE2))
        update_core(internal.data().isse2, m.data(), m.size());
    else
#endif
        update_core(internal.data().idonna, m.data(), m.size());
#endif
}
void poly1305::fin(uint8_t* tag)
{
#ifdef SSE2_SUPPORTED
    internal.data().fin(tag);
#else
#ifdef ARCH_X86
    if (Botan::CPUID::has(Botan::CPUID::Feature::SSE2))
        internal.data().isse2.fin(tag);
    else
#endif
       internal.data().idonna.fin(tag);
#endif

}

#ifdef ARCH_X86
# ifdef __clang__
#  pragma clang attribute pop
# endif
#endif

