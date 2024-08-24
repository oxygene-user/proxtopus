#pragma once

#ifdef _WIN32
#define BOTAN_TARGET_OS_HAS_WIN32
#define BOTAN_BUILD_COMPILER_IS_MSVC
#define BOTAN_TARGET_OS_IS_WINDOWS
#define BOTAN_TARGET_OS_HAS_THREAD_LOCAL
#define BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
#define BOTAN_TARGET_OS_HAS_RTLGENRANDOM
#else
#define _NIX
#define BOTAN_USE_GCC_INLINE_ASM
#define BOTAN_TARGET_OS_IS_LINUX
#define BOTAN_TARGET_OS_HAS_GETRANDOM
#define BOTAN_TARGET_OS_HAS_POSIX1
#endif

#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__)
#define BOTAN_MP_WORD_BITS 64
#else
#define BOTAN_MP_WORD_BITS 32
#endif

#define BOTAN_TARGET_OS_HAS_THREADS


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

#define BOTAN_TARGET_CPU_HAS_NATIVE_64BIT
#define BOTAN_TARGET_ARCH_IS_X86_64

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


#define BOTAN_DLL
#define BOTAN_IS_BEING_BUILT

#include <vector>
#include <span>

#ifdef _NIX
#include <stdint.h>
#include <memory.h>
#endif

namespace ma
{
	void* ma(size_t size);
	void* rs(void* p, size_t size);
	void mf(void* p);
}

namespace Botan {

//template <typename T> using secure_vector = std::vector<T>;
	template <typename T> struct secure_vector;
    template<> struct secure_vector<uint32_t> : public std::vector<uint32_t> {
        template <typename T2, typename T3> secure_vector(const T2 &t, const T3 &t2) : std::vector<uint32_t>(t,t2) {}
        secure_vector() {}
        secure_vector(size_t fill_cnt):std::vector<uint32_t>(fill_cnt) {}
    };
	template<> struct secure_vector<uint64_t> : public std::vector<uint64_t> {
		template <typename T2, typename T3> secure_vector(const T2& t, const T3& t2) : std::vector<uint64_t>(t, t2) {}
		secure_vector() {}
		secure_vector(size_t fill_cnt) :std::vector<uint64_t>(fill_cnt) {}
	};
	/*
	template<> struct secure_vector<uint8_t> : public std::vector<uint8_t> {
		template <typename T2, typename T3> secure_vector(const T2& t, const T3& t2) : std::vector<uint8_t>(t, t2) {}
		secure_vector() {}
		secure_vector(size_t fill_cnt) :std::vector<uint8_t>(fill_cnt) {}
		void zeroise()
		{
			memset(data(), 0, size());
		}
	};
	*/
	template<> struct secure_vector<uint8_t> {
		secure_vector():buf((uint8_t*)ma::ma(32)), cap(32) {}
		~secure_vector() {
			ma::mf(buf);
		}
		secure_vector(const secure_vector& ov) = delete;
		secure_vector(secure_vector&& ov)
		{
			buf = ov.buf;
			cap = ov.cap;
			sz = ov.sz;

			ov.buf = nullptr;
			ov.cap = 0;
			ov.sz = 0;
		}

		static size_t capsize(size_t sz)
		{
			return (sz + 31) & (~31);
		}

		secure_vector(size_t fill_cnt) {
			sz = fill_cnt;
			cap = capsize(sz);
			buf = (uint8_t*)ma::ma(cap);
		}

		secure_vector(const uint8_t *ds, const uint8_t* de)
		{
			sz = de - ds;
			cap = capsize(sz);
			buf = (uint8_t  *)ma::ma(cap);
			memcpy(buf, ds, sz);
		}
		template<typename Iter> secure_vector(const Iter&bgn, const Iter& end)
		{
			sz = end - bgn;
			cap = capsize(sz);
			buf = (uint8_t*)ma::ma(cap);
			memcpy(buf, &*bgn, sz);
		}

		template<typename Iter> void assign(const Iter& bgn, const Iter& end)
		{
			sz = end - bgn;
			if (sz <= cap)
			{
				memcpy(buf, &*bgn, sz);
			}
			else
			{
				cap = capsize(sz);
				buf = (uint8_t*)ma::rs( buf, cap );
				memcpy(buf, &*bgn, sz);
			}
		}

		secure_vector& operator=(const secure_vector& ov)
		{
			if (cap >= ov.sz)
			{
				memcpy( buf, ov.buf, ov.sz );
				sz = ov.sz;
				return *this;
			}

			sz = ov.sz;
			cap = capsize(ov.sz);
			buf = (uint8_t*)ma::rs(buf, cap);
			memcpy(buf, ov.buf, ov.sz);

			return *this;
		}
		secure_vector& operator=(secure_vector&& ov)
		{
			ma::mf(buf);

			buf = ov.buf;
			cap = ov.cap;
			sz = ov.sz;

			ov.buf = nullptr;
			ov.cap = 0;
			ov.sz = 0;

			return *this;
		}


		using pointer = uint8_t*;
		using const_pointer = const uint8_t*;
		using size_type = size_t;
		using iterator = uint8_t*;
		using const_iterator = const uint8_t*;
		using value_type = uint8_t;

		uint8_t * begin() const { return buf; }
		uint8_t* end() const { return buf + sz; }
		const uint8_t* cbegin() const { return buf; }
		const uint8_t* cend() const { return buf + sz; }

		uint8_t* data() { return buf; }
		const uint8_t* data() const { return buf; }
		size_t size() const { return sz; }

		uint8_t& operator[](size_t index) { return buf[index]; }
		uint8_t operator[](size_t index) const { return buf[index]; }

		secure_vector& operator+=(const std::span<const uint8_t> &in) {

			if (in.size() + sz <= cap)
			{
				memcpy(buf + sz, in.data(), in.size());
				sz += in.size();
				return *this;
			}

			size_t nsz = sz + in.size();
			cap = capsize(nsz);
			buf = (uint8_t*)ma::rs(buf, cap);
			memcpy(buf + sz, in.data(), in.size());
			sz += in.size();

			return *this;
		}

		secure_vector& operator+=(const std::pair<const uint8_t*, size_t>& in) {

			return *this += std::span<const uint8_t>(in.first, in.second);
		}


		void clear()
		{
			sz = 0;
		}

		/*
		void erase(size_t szerase) // erase from begin
		{
			memcpy( buf, buf + szerase, sz - szerase );
			sz -= szerase;
		}
		*/

		bool empty() const { return sz == 0; }

		void resize(size_t nsz)
		{
			if (nsz <= cap)
			{
				sz = nsz;
				return;
			}

			cap = capsize(nsz);
			buf = (uint8_t *)ma::rs(buf, cap);
			//memset(buf + sz, 0, nsz - sz);
			sz = nsz;
		}

		void reserve(size_t size)
		{
			if (size > cap)
			{
				cap = capsize(size);
				buf = (uint8_t*)ma::rs(buf, cap);
			}
		}

		void zeroise()
		{
			memset(buf, 0, sz);
		}

		uint8_t* buf;
		size_t sz = 0, cap;
	};

	struct OctetString //= std::vector<uint8_t>;
	{

	};

    struct SymmetricKey //: public std::vector<uint8_t>
	{
        //size_t length() const { return size(); }
		const uint8_t* begin() const { return nullptr; }
		size_t length() const { return 0; }
    };

	using InitializationVector = SymmetricKey;

	template <typename T, typename Alloc> void zeroise(std::vector<T, Alloc>& vec) {
		std::fill(vec.begin(), vec.end(), static_cast<T>(0));
	}
	inline void zeroise(secure_vector<uint8_t>& vec) {
		vec.zeroise();
	}

	template <typename T, typename Alloc> void zap(std::vector<T, Alloc>& vec) {
		//zeroise(vec);
		vec.clear();
		//vec.shrink_to_fit();
	}

	inline void zap(secure_vector<uint8_t>& vec) {
		vec.clear();
	}

	/*
	template <typename T, typename Alloc, typename Alloc2>
	std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::vector<T, Alloc2>& in) {
		out.insert(out.end(), in.begin(), in.end());
		return out;
	}

	template <typename T, typename Alloc>
	std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, T in) {
		out.push_back(in);
		return out;
	}
	*/


	template <typename T, typename Alloc, typename L>
	std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::pair<const T*, L>& in) {
		out.insert(out.end(), in.first, in.first + in.second);
		return out;
	}

	template <typename T, typename Alloc, typename L>
	std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::pair<T*, L>& in) {
		out.insert(out.end(), in.first, in.first + in.second);
		return out;
	}
}

using buffer = Botan::secure_vector<uint8_t>;
