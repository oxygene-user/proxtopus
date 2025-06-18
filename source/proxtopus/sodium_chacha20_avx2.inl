
#if defined(MODE64) && defined (ARCH_X86)
#ifdef GCC_OR_CLANG
__attribute__((target("avx2")))
#endif
void chacha20::impl::cipher_avx2(const uint8_t m[], uint8_t c[], size_t bytes, u64 ic)
{
    const size_t ROUNDS = 20;
    static_assert(Endian::little); // avx2 on x86 arch only, so it is little endian

    /* constant for shuffling bytes (replacing multiple-of-8 rotates) */
    const __m128i rot16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m128i rot8 = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
    const __m256i rot16_256 = _mm256_broadcastsi128_si256(rot16);
    const __m256i rot8_256 = _mm256_broadcastsi128_si256(rot8);

#include "../sodium/dolbeau/u8.h" // >= 512 bytes
#include "../sodium/dolbeau/u4.h" // >= 256 bytes
#include "../sodium/dolbeau/u1.h" // >= 64 bytes
}
#endif
