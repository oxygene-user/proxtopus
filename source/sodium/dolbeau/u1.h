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

while (bytes >= 64) {

    const __m128i rot16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m128i rot8 = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

    __m128i x_0 = _mm_loadu_si128((const __m128i*) (x + 0));
    __m128i x_1 = _mm_loadu_si128((const __m128i*) (x + 4));
    __m128i x_2 = _mm_loadu_si128((const __m128i*) (x + 8));
    __m128i x_3 = _mm_loadu_si128((const __m128i*) (x + 12));

    for (size_t i = 0; i < ROUNDS; i += 2) {
        x_0 = _mm_add_epi32(x_0, x_1);
        x_3 = _mm_xor_si128(x_3, x_0);
        x_3 = _mm_shuffle_epi8(x_3, rot16);

        x_2 = _mm_add_epi32(x_2, x_3);
        x_1 = _mm_xor_si128(x_1, x_2);

        __m128i t_1 = x_1;
        x_1 = _mm_slli_epi32(x_1, 12);
        t_1 = _mm_srli_epi32(t_1, 20);
        x_1 = _mm_xor_si128(x_1, t_1);

        x_0 = _mm_add_epi32(x_0, x_1);
        x_3 = _mm_xor_si128(x_3, x_0);
        x_0 = _mm_shuffle_epi32(x_0, 0x93);
        x_3 = _mm_shuffle_epi8(x_3, rot8);

        x_2 = _mm_add_epi32(x_2, x_3);
        x_3 = _mm_shuffle_epi32(x_3, 0x4e);
        x_1 = _mm_xor_si128(x_1, x_2);
        x_2 = _mm_shuffle_epi32(x_2, 0x39);

        t_1 = x_1;
        x_1 = _mm_slli_epi32(x_1, 7);
        t_1 = _mm_srli_epi32(t_1, 25);
        x_1 = _mm_xor_si128(x_1, t_1);

        x_0 = _mm_add_epi32(x_0, x_1);
        x_3 = _mm_xor_si128(x_3, x_0);
        x_3 = _mm_shuffle_epi8(x_3, rot16);

        x_2 = _mm_add_epi32(x_2, x_3);
        x_1 = _mm_xor_si128(x_1, x_2);

        t_1 = x_1;
        x_1 = _mm_slli_epi32(x_1, 12);
        t_1 = _mm_srli_epi32(t_1, 20);
        x_1 = _mm_xor_si128(x_1, t_1);

        x_0 = _mm_add_epi32(x_0, x_1);
        x_3 = _mm_xor_si128(x_3, x_0);
        x_0 = _mm_shuffle_epi32(x_0, 0x39);
        x_3 = _mm_shuffle_epi8(x_3, rot8);

        x_2 = _mm_add_epi32(x_2, x_3);
        x_3 = _mm_shuffle_epi32(x_3, 0x4e);
        x_1 = _mm_xor_si128(x_1, x_2);
        x_2 = _mm_shuffle_epi32(x_2, 0x93);

        t_1 = x_1;
        x_1 = _mm_slli_epi32(x_1, 7);
        t_1 = _mm_srli_epi32(t_1, 25);
        x_1 = _mm_xor_si128(x_1, t_1);
    }

    if (m == nullptr)
    {
        x_0 = _mm_add_epi32(x_0, _mm_loadu_si128((const __m128i*) (x + 0)));
        x_1 = _mm_add_epi32(x_1, _mm_loadu_si128((const __m128i*) (x + 4)));
        x_2 = _mm_add_epi32(x_2, _mm_loadu_si128((const __m128i*) (x + 8)));
        x_3 = _mm_add_epi32(x_3, _mm_loadu_si128((const __m128i*) (x + 12)));
    }
    else
    {
        x_0 = _mm_add_epi32(x_0, _mm_loadu_si128((const __m128i*) (x + 0)));
        x_1 = _mm_add_epi32(x_1, _mm_loadu_si128((const __m128i*) (x + 4)));
        x_2 = _mm_add_epi32(x_2, _mm_loadu_si128((const __m128i*) (x + 8)));
        x_3 = _mm_add_epi32(x_3, _mm_loadu_si128((const __m128i*) (x + 12)));
        x_0 = _mm_xor_si128(x_0, _mm_loadu_si128((const __m128i*) (m + 0)));
        x_1 = _mm_xor_si128(x_1, _mm_loadu_si128((const __m128i*) (m + 16)));
        x_2 = _mm_xor_si128(x_2, _mm_loadu_si128((const __m128i*) (m + 32)));
        x_3 = _mm_xor_si128(x_3, _mm_loadu_si128((const __m128i*) (m + 48)));
        m += 64;
    }

    _mm_storeu_si128((__m128i*) (c + 0), x_0);
    _mm_storeu_si128((__m128i*) (c + 16), x_1);
    _mm_storeu_si128((__m128i*) (c + 32), x_2);
    _mm_storeu_si128((__m128i*) (c + 48), x_3);

    ++ic;

    bytes -= 64;
    c += 64;
}
