#if defined (GCC_OR_CLANG)
__attribute__((target("ssse3")))
#endif
void chacha20::impl::cipher_ssse3(const uint8_t m[], uint8_t c[], size_t bytes, u64 ic)
{
    const size_t ROUNDS = 20;
    static_assert(Endian::little); // ssse3 on x86 arch only, so it is little endian

    /* constant for shuffling bytes (replacing multiple-of-8 rotates) */
    const __m128i rot16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m128i rot8 = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

#include "../sodium/dolbeau/u4.h" // >= 256 bytes
#include "../sodium/dolbeau/u1.h" // >= 64 bytes
//#include "../sodium/dolbeau/u0.h" // no need to cipher blocks less then 64 bytes
}
