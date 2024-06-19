#pragma once

#ifdef _WIN32
#define BOTAN_TARGET_OS_HAS_WIN32
#define BOTAN_BUILD_COMPILER_IS_MSVC
#define BOTAN_TARGET_OS_HAS_RTLGENRANDOM
#define BOTAN_TARGET_OS_IS_WINDOWS
#define BOTAN_TARGET_OS_HAS_THREAD_LOCAL
#define BOTAN_TARGET_OS_HAS_THREADS
#define BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
#endif

#define BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN
#define BOTAN_TARGET_CPU_IS_X86_FAMILY
#define BOTAN_TARGET_SUPPORTS_SSE2
#define BOTAN_TARGET_SUPPORTS_SSSE3
#define BOTAN_TARGET_SUPPORTS_SSE41
#define BOTAN_TARGET_SUPPORTS_SSE42
#define BOTAN_TARGET_SUPPORTS_AVX512
#define BOTAN_TARGET_SUPPORTS_AVX2
#define BOTAN_HAS_SHA1_X86_SHA_NI
#define BOTAN_HAS_GHASH_CLMUL_CPU
#define BOTAN_HAS_GHASH_CLMUL_VPERM

#define BOTAN_HAS_AES
#define BOTAN_HAS_AES_VPERM
#define BOTAN_HAS_AES_NI

#define BOTAN_HAS_HMAC
#define BOTAN_HAS_KECCAK_PERM_BMI2

#define BOTAN_HAS_AUTO_RNG
#define BOTAN_HAS_AUTO_SEEDING_RNG
#define BOTAN_HAS_STATEFUL_RNG
#define BOTAN_HAS_SYSTEM_RNG

#define BOTAN_HAS_CHACHA
#define BOTAN_HAS_CHACHA_SIMD32
#define BOTAN_HAS_CHACHA_AVX2
#define BOTAN_HAS_CHACHA_AVX512

#define BOTAN_HAS_POLY1305
#define BOTAN_HAS_BLOCK_CIPHER

#define BOTAN_HAS_AEAD_CHACHA20_POLY1305
#define BOTAN_HAS_AEAD_GCM
#define BOTAN_HAS_AEAD_MODES

#define BOTAN_DEFAULT_BUFFER_SIZE 4096
#define BOTAN_BLOCK_CIPHER_PAR_MULT 4

/**
* Userspace RNGs like HMAC_DRBG will reseed after a specified number
* of outputs are generated. Set to zero to disable automatic reseeding.
*/
#define BOTAN_RNG_DEFAULT_RESEED_INTERVAL 1024

/** Number of entropy bits polled for reseeding userspace RNGs like HMAC_DRBG */
#define BOTAN_RNG_RESEED_POLL_BITS 256

#define BOTAN_RNG_RESEED_DEFAULT_TIMEOUT std::chrono::milliseconds(50)

#define BOTAN_ENTROPY_DEFAULT_SOURCES \
   { "rdseed", "hwrng", "getentropy", "system_rng", "system_stats" }


#define BOTAN_HAS_MD5
#define BOTAN_HAS_SALSA20
#define BOTAN_HAS_SHA1_SSE2
#define BOTAN_HAS_SHA2_32_X86
#define BOTAN_HAS_SHA2_32_X86_BMI2
#define BOTAN_HAS_SHA2_64_BMI2
#define BOTAN_HAS_SHA3_BMI2
#define BOTAN_HAS_TLS

#define BOTAN_HAS_SHA1
#define BOTAN_HAS_SHA2_64
#define BOTAN_HAS_SHA2_32
#define BOTAN_HAS_SHA3

/**
* Controls how AutoSeeded_RNG is instantiated
*/
#if !defined(BOTAN_AUTO_RNG_HMAC)

  #if defined(BOTAN_HAS_SHA2_64)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-384)"
  #elif defined(BOTAN_HAS_SHA2_32)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-256)"
  #elif defined(BOTAN_HAS_SHA3)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-3(256))"
  #elif defined(BOTAN_HAS_SHA1)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-1)"
  #endif
  /* Otherwise, no hash found: leave BOTAN_AUTO_RNG_HMAC undefined */

#endif
