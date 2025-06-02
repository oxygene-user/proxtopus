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

#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

void chacha20::impl::cipher_ref(const uint8_t m[], uint8_t c[], size_t bytes)
{
    ASSERT((bytes & 63) == 0);
    size_t blocks = bytes >> 6;

    const uint32_t j0 = input[0];
    const uint32_t j1 = input[1];
    const uint32_t j2 = input[2];
    const uint32_t j3 = input[3];
    const uint32_t j4 = input[4];
    const uint32_t j5 = input[5];
    const uint32_t j6 = input[6];
    const uint32_t j7 = input[7];
    const uint32_t j8 = input[8];
    const uint32_t j9 = input[9];
    const uint32_t j10 = input[10];
    const uint32_t j11 = input[11];
    const uint32_t j14 = input[14];
    const uint32_t j15 = input[15];

    u64 ic = tools::load64_le(reinterpret_cast<const u8*>(input + 12));

    for (;blocks > 0; --blocks, ++ic) {
        uint32_t x0 = j0;
        uint32_t x1 = j1;
        uint32_t x2 = j2;
        uint32_t x3 = j3;
        uint32_t x4 = j4;
        uint32_t x5 = j5;
        uint32_t x6 = j6;
        uint32_t x7 = j7;
        uint32_t x8 = j8;
        uint32_t x9 = j9;
        uint32_t x10 = j10;
        uint32_t x11 = j11;
        uint32_t x12 = uints::low(ic);
        uint32_t x13 = uints::high(ic);
        uint32_t x14 = j14;
        uint32_t x15 = j15;
        for (size_t i = 20; i > 0; i -= 2) {
            QUARTERROUND(x0, x4, x8, x12);
            QUARTERROUND(x1, x5, x9, x13);
            QUARTERROUND(x2, x6, x10, x14);
            QUARTERROUND(x3, x7, x11, x15);
            QUARTERROUND(x0, x5, x10, x15);
            QUARTERROUND(x1, x6, x11, x12);
            QUARTERROUND(x2, x7, x8, x13);
            QUARTERROUND(x3, x4, x9, x14);
        }
        
        if (m == nullptr)
        {
            x0 = PLUS(x0, j0);
            x1 = PLUS(x1, j1);
            x2 = PLUS(x2, j2);
            x3 = PLUS(x3, j3);
            x4 = PLUS(x4, j4);
            x5 = PLUS(x5, j5);
            x6 = PLUS(x6, j6);
            x7 = PLUS(x7, j7);
            x8 = PLUS(x8, j8);
            x9 = PLUS(x9, j9);
            x10 = PLUS(x10, j10);
            x11 = PLUS(x11, j11);
            x12 = PLUS(x12, uints::low(ic));
            x13 = PLUS(x13, uints::high(ic));
            x14 = PLUS(x14, j14);
            x15 = PLUS(x15, j15);
        } else 
        {
            x0 = PLUS(x0, j0);
            x1 = PLUS(x1, j1);
            x2 = PLUS(x2, j2);
            x3 = PLUS(x3, j3);
            x4 = PLUS(x4, j4);
            x5 = PLUS(x5, j5);
            x6 = PLUS(x6, j6);
            x7 = PLUS(x7, j7);
            x8 = PLUS(x8, j8);
            x9 = PLUS(x9, j9);
            x10 = PLUS(x10, j10);
            x11 = PLUS(x11, j11);
            x12 = PLUS(x12, uints::low(ic));
            x13 = PLUS(x13, uints::high(ic));
            x14 = PLUS(x14, j14);
            x15 = PLUS(x15, j15);

            x0 = XOR(x0, tools::load32_le(m + 0));
            x1 = XOR(x1, tools::load32_le(m + 4));
            x2 = XOR(x2, tools::load32_le(m + 8));
            x3 = XOR(x3, tools::load32_le(m + 12));
            x4 = XOR(x4, tools::load32_le(m + 16));
            x5 = XOR(x5, tools::load32_le(m + 20));
            x6 = XOR(x6, tools::load32_le(m + 24));
            x7 = XOR(x7, tools::load32_le(m + 28));
            x8 = XOR(x8, tools::load32_le(m + 32));
            x9 = XOR(x9, tools::load32_le(m + 36));
            x10 = XOR(x10, tools::load32_le(m + 40));
            x11 = XOR(x11, tools::load32_le(m + 44));
            x12 = XOR(x12, tools::load32_le(m + 48));
            x13 = XOR(x13, tools::load32_le(m + 52));
            x14 = XOR(x14, tools::load32_le(m + 56));
            x15 = XOR(x15, tools::load32_le(m + 60));
            m += 64;
        }

        tools::store32_le(c + 0, x0);
        tools::store32_le(c + 4, x1);
        tools::store32_le(c + 8, x2);
        tools::store32_le(c + 12, x3);
        tools::store32_le(c + 16, x4);
        tools::store32_le(c + 20, x5);
        tools::store32_le(c + 24, x6);
        tools::store32_le(c + 28, x7);
        tools::store32_le(c + 32, x8);
        tools::store32_le(c + 36, x9);
        tools::store32_le(c + 40, x10);
        tools::store32_le(c + 44, x11);
        tools::store32_le(c + 48, x12);
        tools::store32_le(c + 52, x13);
        tools::store32_le(c + 56, x14);
        tools::store32_le(c + 60, x15);

        c += 64;
    }
}


#undef XOR
#undef PLUS
#undef PLUSONE
