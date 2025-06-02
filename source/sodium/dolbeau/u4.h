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

#define VEC4_ROT(A, IMM) _mm_or_si128(_mm_slli_epi32(A, IMM), _mm_srli_epi32(A, (32 - IMM)))

/* same, but replace 2 of the shift/shift/or "rotation" by byte shuffles (8 &
 * 16) (better) */
#define VEC4_QUARTERROUND_SHUFFLE(A, B, C, D) \
    x_##A = _mm_add_epi32(x_##A, x_##B);      \
    t_##A = _mm_xor_si128(x_##D, x_##A);      \
    x_##D = _mm_shuffle_epi8(t_##A, rot16);   \
    x_##C = _mm_add_epi32(x_##C, x_##D);      \
    t_##C = _mm_xor_si128(x_##B, x_##C);      \
    x_##B = VEC4_ROT(t_##C, 12);              \
    x_##A = _mm_add_epi32(x_##A, x_##B);      \
    t_##A = _mm_xor_si128(x_##D, x_##A);      \
    x_##D = _mm_shuffle_epi8(t_##A, rot8);    \
    x_##C = _mm_add_epi32(x_##C, x_##D);      \
    t_##C = _mm_xor_si128(x_##B, x_##C);      \
    x_##B = VEC4_ROT(t_##C, 7)

#define VEC4_QUARTERROUND(A, B, C, D) VEC4_QUARTERROUND_SHUFFLE(A, B, C, D)

#define ONEQUAD_TRANSPOSE(A, B, C, D, offs) \
        x_##A = _mm_add_epi32(x_##A, orig##A);     \
        x_##B = _mm_add_epi32(x_##B, orig##B);     \
        x_##C = _mm_add_epi32(x_##C, orig##C);     \
        x_##D = _mm_add_epi32(x_##D, orig##D);     \
        t_##A = _mm_unpacklo_epi32(x_##A, x_##B);  \
        t_##B = _mm_unpacklo_epi32(x_##C, x_##D);  \
        t_##C = _mm_unpackhi_epi32(x_##A, x_##B);  \
        t_##D = _mm_unpackhi_epi32(x_##C, x_##D);  \
        x_##A = _mm_unpacklo_epi64(t_##A, t_##B);  \
        x_##B = _mm_unpackhi_epi64(t_##A, t_##B);  \
        x_##C = _mm_unpacklo_epi64(t_##C, t_##D);  \
        x_##D = _mm_unpackhi_epi64(t_##C, t_##D);  \
                                                   \
        _mm_storeu_si128((__m128i*) (c + 0 + offs), _mm_xor_si128(x_##A, _mm_loadu_si128((const __m128i*) (m + 0 + offs))));     \
        _mm_storeu_si128((__m128i*) (c + 64 + offs), _mm_xor_si128(x_##B, _mm_loadu_si128((const __m128i*) (m + 64 + offs))));   \
        _mm_storeu_si128((__m128i*) (c + 128 + offs), _mm_xor_si128(x_##C, _mm_loadu_si128((const __m128i*) (m + 128 + offs)))); \
        _mm_storeu_si128((__m128i*) (c + 192 + offs), _mm_xor_si128(x_##D, _mm_loadu_si128((const __m128i*) (m + 192 + offs))))


#define ONEQUAD_TRANSPOSE_NULL_SOURCE(A, B, C, D, offs) \
        x_##A = _mm_add_epi32(x_##A, orig##A);          \
        x_##B = _mm_add_epi32(x_##B, orig##B);          \
        x_##C = _mm_add_epi32(x_##C, orig##C);          \
        x_##D = _mm_add_epi32(x_##D, orig##D);          \
        t_##A = _mm_unpacklo_epi32(x_##A, x_##B);       \
        t_##B = _mm_unpacklo_epi32(x_##C, x_##D);       \
        t_##C = _mm_unpackhi_epi32(x_##A, x_##B);       \
        t_##D = _mm_unpackhi_epi32(x_##C, x_##D);       \
        x_##A = _mm_unpacklo_epi64(t_##A, t_##B);       \
        x_##B = _mm_unpackhi_epi64(t_##A, t_##B);       \
        x_##C = _mm_unpacklo_epi64(t_##C, t_##D);       \
        x_##D = _mm_unpackhi_epi64(t_##C, t_##D);       \
                                                        \
        _mm_storeu_si128((__m128i*) (c + 0 + offs), x_##A);   \
        _mm_storeu_si128((__m128i*) (c + 64 + offs), x_##B);  \
        _mm_storeu_si128((__m128i*) (c + 128 + offs), x_##C); \
        _mm_storeu_si128((__m128i*) (c + 192 + offs), x_##D)


if (bytes >= 256) {
    /* constant for shuffling bytes (replacing multiple-of-8 rotates) */
    const __m128i rot16 =
        _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m128i rot8 =
        _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

    const __m128i orig0  = _mm_set1_epi32(x[0]);
    const __m128i orig1 = _mm_set1_epi32(x[1]);
    const __m128i orig2 = _mm_set1_epi32(x[2]);
    const __m128i orig3 = _mm_set1_epi32(x[3]);
    const __m128i orig4 = _mm_set1_epi32(x[4]);
    const __m128i orig5 = _mm_set1_epi32(x[5]);
    const __m128i orig6 = _mm_set1_epi32(x[6]);
    const __m128i orig7 = _mm_set1_epi32(x[7]);
    const __m128i orig8 = _mm_set1_epi32(x[8]);
    const __m128i orig9 = _mm_set1_epi32(x[9]);
    const __m128i orig10 = _mm_set1_epi32(x[10]);
    const __m128i orig11 = _mm_set1_epi32(x[11]);
    const __m128i orig14 = _mm_set1_epi32(x[14]);
    const __m128i orig15 = _mm_set1_epi32(x[15]);

    while (bytes >= 256) {

        __m128i x_0  = orig0;
        __m128i x_1  = orig1;
        __m128i x_2  = orig2;
        __m128i x_3  = orig3;
        __m128i x_4  = orig4;
        __m128i x_5  = orig5;
        __m128i x_6  = orig6;
        __m128i x_7  = orig7;
        __m128i x_8  = orig8;
        __m128i x_9  = orig9;
        __m128i x_10 = orig10;
        __m128i x_11 = orig11;
        __m128i x_14 = orig14;
        __m128i x_15 = orig15;

        __m128i x_12 = _mm_add_epi64(_mm_set_epi64x(1, 0), _mm_set1_epi64x(ic));
        __m128i x_13 = _mm_add_epi64(_mm_set_epi64x(3, 2), _mm_set1_epi64x(ic));

        __m128i t12 = _mm_unpacklo_epi32(x_12, x_13);
        __m128i t13 = _mm_unpackhi_epi32(x_12, x_13);

        x_12 = _mm_unpacklo_epi32(t12, t13);
        x_13 = _mm_unpackhi_epi32(t12, t13);

        __m128i orig12 = x_12;
        __m128i orig13 = x_13;

        ic += 4;

        __m128i t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11, t_12, t_13, t_14, t_15;

        for (size_t i = 0; i < ROUNDS; i += 2) {
            VEC4_QUARTERROUND(0, 4, 8, 12);
            VEC4_QUARTERROUND(1, 5, 9, 13);
            VEC4_QUARTERROUND(2, 6, 10, 14);
            VEC4_QUARTERROUND(3, 7, 11, 15);
            VEC4_QUARTERROUND(0, 5, 10, 15);
            VEC4_QUARTERROUND(1, 6, 11, 12);
            VEC4_QUARTERROUND(2, 7, 8, 13);
            VEC4_QUARTERROUND(3, 4, 9, 14);
        }
        
        if (m != nullptr)
        {
#define ONEQUAD(A, B, C, D, offs) ONEQUAD_TRANSPOSE(A, B, C, D, offs)
            ONEQUAD(0, 1, 2, 3, 0);
            ONEQUAD(4, 5, 6, 7, 16);
            ONEQUAD(8, 9, 10, 11, 32);
            ONEQUAD(12, 13, 14, 15, 48);
#undef ONEQUAD
            m += 256;
        }
        else
        {
#define ONEQUAD(A, B, C, D, offs) ONEQUAD_TRANSPOSE_NULL_SOURCE(A, B, C, D, offs)
            ONEQUAD(0, 1, 2, 3, 0);
            ONEQUAD(4, 5, 6, 7, 16);
            ONEQUAD(8, 9, 10, 11, 32);
            ONEQUAD(12, 13, 14, 15, 48);
#undef ONEQUAD
        }

        bytes -= 256;
        c += 256;
    }
}

#undef ONEQUAD_TRANSPOSE
#undef ONEQUAD_TRANSPOSE_NULL_SOURCE
#undef VEC4_ROT
#undef VEC4_QUARTERROUND
#undef VEC4_QUARTERROUND_SHUFFLE
