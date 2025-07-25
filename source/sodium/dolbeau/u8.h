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

#define VEC8_ROT(A, IMM) _mm256_or_si256(_mm256_slli_epi32(A, IMM), _mm256_srli_epi32(A, (32 - IMM)))

/* same, but replace 2 of the shift/shift/or "rotation" by byte shuffles (8 &
 * 16) (better) */
#define VEC8_QUARTERROUND_SHUFFLE(A, B, C, D)  \
    x_##A = _mm256_add_epi32(x_##A, x_##B);    \
    t_##A = _mm256_xor_si256(x_##D, x_##A);    \
    x_##D = _mm256_shuffle_epi8(t_##A, rot16); \
    x_##C = _mm256_add_epi32(x_##C, x_##D);    \
    t_##C = _mm256_xor_si256(x_##B, x_##C);    \
    x_##B = VEC8_ROT(t_##C, 12);               \
    x_##A = _mm256_add_epi32(x_##A, x_##B);    \
    t_##A = _mm256_xor_si256(x_##D, x_##A);    \
    x_##D = _mm256_shuffle_epi8(t_##A, rot8);  \
    x_##C = _mm256_add_epi32(x_##C, x_##D);    \
    t_##C = _mm256_xor_si256(x_##B, x_##C);    \
    x_##B = VEC8_ROT(t_##C, 7)

#define VEC8_QUARTERROUND(A, B, C, D) VEC8_QUARTERROUND_SHUFFLE(A, B, C, D)

#define VEC8_LINE1(A, B, C, D)              \
    x_##A = _mm256_add_epi32(x_##A, x_##B); \
    x_##D = _mm256_shuffle_epi8(_mm256_xor_si256(x_##D, x_##A), rot16_256)
#define VEC8_LINE2(A, B, C, D)              \
    x_##C = _mm256_add_epi32(x_##C, x_##D); \
    x_##B = VEC8_ROT(_mm256_xor_si256(x_##B, x_##C), 12)
#define VEC8_LINE3(A, B, C, D)              \
    x_##A = _mm256_add_epi32(x_##A, x_##B); \
    x_##D = _mm256_shuffle_epi8(_mm256_xor_si256(x_##D, x_##A), rot8_256)
#define VEC8_LINE4(A, B, C, D)              \
    x_##C = _mm256_add_epi32(x_##C, x_##D); \
    x_##B = VEC8_ROT(_mm256_xor_si256(x_##B, x_##C), 7)

#define VEC8_ROUND_SEQ(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, D4) \
    VEC8_LINE1(A1, B1, C1, D1); \
    VEC8_LINE1(A2, B2, C2, D2); \
    VEC8_LINE1(A3, B3, C3, D3); \
    VEC8_LINE1(A4, B4, C4, D4); \
    VEC8_LINE2(A1, B1, C1, D1); \
    VEC8_LINE2(A2, B2, C2, D2); \
    VEC8_LINE2(A3, B3, C3, D3); \
    VEC8_LINE2(A4, B4, C4, D4); \
    VEC8_LINE3(A1, B1, C1, D1); \
    VEC8_LINE3(A2, B2, C2, D2); \
    VEC8_LINE3(A3, B3, C3, D3); \
    VEC8_LINE3(A4, B4, C4, D4); \
    VEC8_LINE4(A1, B1, C1, D1); \
    VEC8_LINE4(A2, B2, C2, D2); \
    VEC8_LINE4(A3, B3, C3, D3); \
    VEC8_LINE4(A4, B4, C4, D4)

#define VEC8_ROUND_HALF(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, D4) \
    VEC8_LINE1(A1, B1, C1, D1); \
    VEC8_LINE1(A2, B2, C2, D2); \
    VEC8_LINE2(A1, B1, C1, D1); \
    VEC8_LINE2(A2, B2, C2, D2); \
    VEC8_LINE3(A1, B1, C1, D1); \
    VEC8_LINE3(A2, B2, C2, D2); \
    VEC8_LINE4(A1, B1, C1, D1); \
    VEC8_LINE4(A2, B2, C2, D2); \
    VEC8_LINE1(A3, B3, C3, D3); \
    VEC8_LINE1(A4, B4, C4, D4); \
    VEC8_LINE2(A3, B3, C3, D3); \
    VEC8_LINE2(A4, B4, C4, D4); \
    VEC8_LINE3(A3, B3, C3, D3); \
    VEC8_LINE3(A4, B4, C4, D4); \
    VEC8_LINE4(A3, B3, C3, D3); \
    VEC8_LINE4(A4, B4, C4, D4)

#define VEC8_ROUND_HALFANDHALF(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, D4) \
    VEC8_LINE1(A1, B1, C1, D1); \
    VEC8_LINE1(A2, B2, C2, D2); \
    VEC8_LINE2(A1, B1, C1, D1); \
    VEC8_LINE2(A2, B2, C2, D2); \
    VEC8_LINE1(A3, B3, C3, D3); \
    VEC8_LINE1(A4, B4, C4, D4); \
    VEC8_LINE2(A3, B3, C3, D3); \
    VEC8_LINE2(A4, B4, C4, D4); \
    VEC8_LINE3(A1, B1, C1, D1); \
    VEC8_LINE3(A2, B2, C2, D2); \
    VEC8_LINE4(A1, B1, C1, D1); \
    VEC8_LINE4(A2, B2, C2, D2); \
    VEC8_LINE3(A3, B3, C3, D3); \
    VEC8_LINE3(A4, B4, C4, D4); \
    VEC8_LINE4(A3, B3, C3, D3); \
    VEC8_LINE4(A4, B4, C4, D4)

#define VEC8_ROUND(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, D4) VEC8_ROUND_SEQ(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, D4)

#define ONEQUAD_UNPCK(A, B, C, D) \
    x_##A = _mm256_add_epi32(x_##A, orig##A);    \
    x_##B = _mm256_add_epi32(x_##B, orig##B);    \
    x_##C = _mm256_add_epi32(x_##C, orig##C);    \
    x_##D = _mm256_add_epi32(x_##D, orig##D);    \
    t_##A = _mm256_unpacklo_epi32(x_##A, x_##B); \
    t_##B = _mm256_unpacklo_epi32(x_##C, x_##D); \
    t_##C = _mm256_unpackhi_epi32(x_##A, x_##B); \
    t_##D = _mm256_unpackhi_epi32(x_##C, x_##D); \
    x_##A = _mm256_unpacklo_epi64(t_##A, t_##B); \
    x_##B = _mm256_unpackhi_epi64(t_##A, t_##B); \
    x_##C = _mm256_unpacklo_epi64(t_##C, t_##D); \
    x_##D = _mm256_unpackhi_epi64(t_##C, t_##D)


#define ONEOCTO(A, B, C, D, A2, B2, C2, D2, offs) \
    ONEQUAD_UNPCK(A, B, C, D);                                   \
    ONEQUAD_UNPCK(A2, B2, C2, D2);                               \
    t_##A  = _mm256_permute2x128_si256(x_##A, x_##A2, 0x20);     \
    t_##A2 = _mm256_permute2x128_si256(x_##A, x_##A2, 0x31);     \
    t_##B  = _mm256_permute2x128_si256(x_##B, x_##B2, 0x20);     \
    t_##B2 = _mm256_permute2x128_si256(x_##B, x_##B2, 0x31);     \
    t_##C  = _mm256_permute2x128_si256(x_##C, x_##C2, 0x20);     \
    t_##C2 = _mm256_permute2x128_si256(x_##C, x_##C2, 0x31);     \
    t_##D  = _mm256_permute2x128_si256(x_##D, x_##D2, 0x20);     \
    t_##D2 = _mm256_permute2x128_si256(x_##D, x_##D2, 0x31);     \
    _mm256_storeu_si256((__m256i*) (c + 0+offs), _mm256_xor_si256(t_##A, _mm256_loadu_si256((const __m256i*) (m + 0+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 64+offs), _mm256_xor_si256(t_##B, _mm256_loadu_si256((const __m256i*) (m + 64+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 128+offs), _mm256_xor_si256(t_##C, _mm256_loadu_si256((const __m256i*) (m + 128+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 192+offs), _mm256_xor_si256(t_##D, _mm256_loadu_si256((const __m256i*) (m + 192+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 256+offs), _mm256_xor_si256(t_##A2, _mm256_loadu_si256((const __m256i*) (m + 256+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 320+offs), _mm256_xor_si256(t_##B2, _mm256_loadu_si256((const __m256i*) (m + 320+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 384+offs), _mm256_xor_si256(t_##C2, _mm256_loadu_si256((const __m256i*) (m + 384+offs)))); \
    _mm256_storeu_si256((__m256i*) (c + 448+offs), _mm256_xor_si256(t_##D2, _mm256_loadu_si256((const __m256i*) (m + 448+offs))))


#define ONEOCTO_NULL_SOURCE(A, B, C, D, A2, B2, C2, D2, offs) \
    ONEQUAD_UNPCK(A, B, C, D);                                   \
    ONEQUAD_UNPCK(A2, B2, C2, D2);                               \
    t_##A  = _mm256_permute2x128_si256(x_##A, x_##A2, 0x20);     \
    t_##A2 = _mm256_permute2x128_si256(x_##A, x_##A2, 0x31);     \
    t_##B  = _mm256_permute2x128_si256(x_##B, x_##B2, 0x20);     \
    t_##B2 = _mm256_permute2x128_si256(x_##B, x_##B2, 0x31);     \
    t_##C  = _mm256_permute2x128_si256(x_##C, x_##C2, 0x20);     \
    t_##C2 = _mm256_permute2x128_si256(x_##C, x_##C2, 0x31);     \
    t_##D  = _mm256_permute2x128_si256(x_##D, x_##D2, 0x20);     \
    t_##D2 = _mm256_permute2x128_si256(x_##D, x_##D2, 0x31);     \
    _mm256_storeu_si256((__m256i*) (c + 0+offs), t_##A);              \
    _mm256_storeu_si256((__m256i*) (c + 64+offs), t_##B);             \
    _mm256_storeu_si256((__m256i*) (c + 128+offs), t_##C);            \
    _mm256_storeu_si256((__m256i*) (c + 192+offs), t_##D);            \
    _mm256_storeu_si256((__m256i*) (c + 256+offs), t_##A2);           \
    _mm256_storeu_si256((__m256i*) (c + 320+offs), t_##B2);           \
    _mm256_storeu_si256((__m256i*) (c + 384+offs), t_##C2);           \
    _mm256_storeu_si256((__m256i*) (c + 448+offs), t_##D2)


#define orig0 _mm256_set1_epi32(0x61707865)
#define orig1 _mm256_set1_epi32(0x3320646e)
#define orig2 _mm256_set1_epi32(0x79622d32)
#define orig3 _mm256_set1_epi32(0x6b206574)
#define orig4 _mm256_set1_epi32(input4)
#define orig5 _mm256_set1_epi32(input5)
#define orig6 _mm256_set1_epi32(input6)
#define orig7 _mm256_set1_epi32(input7)
#define orig8 _mm256_set1_epi32(input8)
#define orig9 _mm256_set1_epi32(input9)
#define orig10 _mm256_set1_epi32(input10)
#define orig11 _mm256_set1_epi32(input11)
#define orig14 _mm256_set1_epi32(input14)
#define orig15 _mm256_set1_epi32(input15)

    while (bytes >= 512) {
        const __m256i addv12  = _mm256_set_epi64x(3, 2, 1, 0);
        const __m256i addv13  = _mm256_set_epi64x(7, 6, 5, 4);
        const __m256i permute = _mm256_set_epi32(7, 6, 3, 2, 5, 4, 1, 0);

        __m256i x_0 = orig0;
        __m256i x_1 = orig1;
        __m256i x_2 = orig2;
        __m256i x_3 = orig3;
        __m256i x_4 = orig4;
        __m256i x_5 = orig5;
        __m256i x_6 = orig6;
        __m256i x_7 = orig7;
        __m256i x_8 = orig8;
        __m256i x_9 = orig9;
        __m256i x_10 = orig10;
        __m256i x_11 = orig11;
        __m256i x_14 = orig14;
        __m256i x_15 = orig15;

        __m256i x_12 = _mm256_broadcastq_epi64(_mm_cvtsi64_si128(ic));
        __m256i x_13 = x_12;

        __m256i t12 = _mm256_add_epi64(addv12, x_12);
        __m256i t13 = _mm256_add_epi64(addv13, x_13);

        x_12 = _mm256_unpacklo_epi32(t12, t13);
        x_13 = _mm256_unpackhi_epi32(t12, t13);

        t12 = _mm256_unpacklo_epi32(x_12, x_13);
        t13 = _mm256_unpackhi_epi32(x_12, x_13);

        /* required because unpack* are intra-lane */
        x_12 = _mm256_permutevar8x32_epi32(t12, permute);
        x_13 = _mm256_permutevar8x32_epi32(t13, permute);

        __m256i orig12 = x_12;
        __m256i orig13 = x_13;

        ic += 8;

        __m256i t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11, t_12, t_13, t_14, t_15;

        for (size_t i = 0; i < ROUNDS; i += 2) {
            VEC8_ROUND(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15);
            VEC8_ROUND(0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14);
        }

        if (nullptr != m)
        {
            ONEOCTO(0, 1, 2, 3, 4, 5, 6, 7, 0);
            ONEOCTO(8, 9, 10, 11, 12, 13, 14, 15, 32);
            m += 512;
        }
        else
        {
            ONEOCTO_NULL_SOURCE(0, 1, 2, 3, 4, 5, 6, 7, 0);
            ONEOCTO_NULL_SOURCE(8, 9, 10, 11, 12, 13, 14, 15, 32);
        }

        bytes -= 512;
        c += 512;
    }

#undef orig0
#undef orig1
#undef orig2
#undef orig3
#undef orig4
#undef orig5
#undef orig6
#undef orig7
#undef orig8
#undef orig9
#undef orig10
#undef orig11
#undef orig14
#undef orig15

#undef ONEOCTO
#undef ONEQUAD_UNPCK
#undef VEC8_ROT
#undef VEC8_QUARTERROUND
#undef VEC8_QUARTERROUND_SHUFFLE
#undef VEC8_LINE1
#undef VEC8_LINE2
#undef VEC8_LINE3
#undef VEC8_LINE4
#undef VEC8_ROUND
#undef VEC8_ROUND_SEQ
#undef VEC8_ROUND_HALF
#undef VEC8_ROUND_HALFANDHALF
