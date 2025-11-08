#pragma once

#include "../conf.h"

#ifdef _WIN32
#define BOTAN_TARGET_OS_HAS_WIN32
#define BOTAN_BUILD_COMPILER_IS_MSVC
#define BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
#define BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY
#define BOTAN_TARGET_CPU_IS_X86_FAMILY
#else
#define _NIX
#define BOTAN_USE_GCC_INLINE_ASM
#ifdef __linux__
#define BOTAN_TARGET_OS_IS_LINUX
#endif
#define BOTAN_TARGET_OS_HAS_GETRANDOM
#define BOTAN_TARGET_OS_HAS_POSIX1
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)
#define BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO
#endif
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(ARCH_X86)
#ifndef ARCH_X86
#dfine ARCH_X86
#endif
#define BOTAN_TARGET_CPU_IS_X86_FAMILY
#define BOTAN_TARGET_CPU_SUPPORTS_SSSE3
#define BOTAN_TARGET_CPU_SUPPORTS_AVX2
#define BOTAN_SIMD_USE_SSSE3
#ifndef AES_VAES_SKIP
#define BOTAN_HAS_AES_VAES
#endif
#define BOTAN_HAS_AES_NI
#define BOTAN_HAS_KECCAK_PERM_BMI2
#define BOTAN_HAS_SHA2_32_X86_AVX2
#define BOTAN_HAS_SHA2_32_X86
#define BOTAN_HAS_SHA2_64_X86_AVX2
#define BOTAN_HAS_SHA1_X86_SHA_NI
#define BOTAN_HAS_GHASH_CLMUL_VPERM
#define BOTAN_HAS_GHASH_CLMUL_CPU
#elif defined(ARCH_ARM)
#define BOTAN_TARGET_CPU_SUPPORTS_NEON
#define BOTAN_SIMD_USE_NEON
#ifdef ARCH_64BIT
#define BOTAN_TARGET_ARCH_IS_ARM64
#define BOTAN_HAS_SHA1_ARMV8
#define BOTAN_HAS_SHA2_32_ARMV8
#define BOTAN_HAS_SHA2_64_ARMV8
#define BOTAN_HAS_AES_ARMV8
#define BOTAN_HAS_GHASH_CLMUL_CPU
#else
#define BOTAN_TARGET_ARCH_IS_ARM32
#endif
#endif

#define BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK
#define BOTAN_TARGET_OS_HAS_THREADS

/*
* Define BOTAN_COMPILER_HAS_BUILTIN
*/
#if defined(__has_builtin)
#define BOTAN_COMPILER_HAS_BUILTIN(x) __has_builtin(x)
#else
#define BOTAN_COMPILER_HAS_BUILTIN(x) 0
#endif


#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__) || defined(ARCH_64BIT)
#ifndef ARCH_64BIT
#define ARCH_64BIT
#endif
#define BOTAN_MP_WORD_BITS 64
#ifdef BOTAN_TARGET_CPU_IS_X86_FAMILY
#define BOTAN_TARGET_ARCH_IS_X86_64
#endif
#else
#ifndef ARCH_32BIT
#define ARCH_32BIT
#endif
#define BOTAN_MP_WORD_BITS 32
#endif

#define BOTAN_HAS_CPUID
#define BOTAN_HAS_CPUID_DETECTION

#define BOTAN_HAS_PSS

#define BOTAN_HAS_AES
#define BOTAN_HAS_AES_VPERM

#define BOTAN_HAS_AEAD_CHACHA20_POLY1305
#define BOTAN_HAS_AEAD_GCM
#define BOTAN_HAS_AEAD_MODES

#define BOTAN_HAS_DL_GROUP
#define BOTAN_HAS_DIFFIE_HELLMAN
#define BOTAN_HAS_ECDSA
#define BOTAN_HAS_RSA
#define BOTAN_HAS_ECDH
#define BOTAN_HAS_X25519
#define BOTAN_HAS_X448
#define BOTAN_HAS_ED25519
//#define BOTAN_HAS_DSA //do not support
//#define BOTAN_HAS_ED448 //do not support

#define BOTAN_HAS_TLS_CBC
#define BOTAN_HAS_TLS
#define BOTAN_HAS_TLS_12
//#define BOTAN_HAS_TLS_13 // TODO enable later
#define BOTAN_HAS_TLS_V12_PRF
#define BOTAN_HAS_EMSA_PKCS1
#define BOTAN_HAS_EMSA_PSSR
#define BOTAN_HAS_EME_PKCS1
//#define BOTAN_HAS_EME_OAEP

#define BOTAN_HAS_PCURVES_SECP224R1
#define BOTAN_HAS_PCURVES_SECP256R1
#define BOTAN_HAS_PCURVES_SECP384R1
#define BOTAN_HAS_PCURVES_SECP521R1
#define BOTAN_HAS_XMD
#define BOTAN_HAS_PCURVES_GENERIC

#define BOTAN_HAS_MD5
#define BOTAN_HAS_BLAKE2B
#define BOTAN_HAS_SALSA20

#define BOTAN_HAS_SHA1_SIMD_4X32
#define BOTAN_HAS_SHA2_32_SIMD
#define BOTAN_HAS_SHA2_64
#ifndef SHA512_SKIP
#if defined(__GNUC__)
#if __GNUC__ > 13 || (__GNUC__ == 13 && __GNUC_MINOR__ >= 1)
#define BOTAN_HAS_SHA2_64_X86
#endif
#endif
#if defined(_MSC_VER) && _MSC_VER >= 1938
#define BOTAN_HAS_SHA2_64_X86
#endif
#endif
#define BOTAN_HAS_SHA3
#define BOTAN_HAS_SHA_256
#define BOTAN_HAS_RIPEMD_160
#define BOTAN_HAS_SM3

#define BOTAN_DLL
#define BOTAN_IS_BEING_BUILT

#undef min
#undef max
struct IUnknown;

#ifdef _NIX
#include <cstring>
#include <utility>
#endif // _NIX

#include <bit>
#include <optional>
#include <numbers>
#include <string>
#include <stdexcept>
#include <cmath>
#include <sstream>
#include <proxtopus/secure_vector.h>

namespace tools
{
    template<size_t sz> void memcopy(void* tgt, const void* src)
    {
        if constexpr (sz == 2)
        {
            *reinterpret_cast<uint16_t*>(tgt) = *reinterpret_cast<const uint16_t*>(src);
        } else if constexpr (sz == 4)
        {
            *reinterpret_cast<uint32_t*>(tgt) = *reinterpret_cast<const uint32_t*>(src);
        }
        else if constexpr (sz == 8)
        {
            static_assert(sizeof(size_t) == 8 || sizeof(size_t) == 4);
            if constexpr (sizeof(size_t) == 8)
            {
                *reinterpret_cast<size_t*>(tgt) = *reinterpret_cast<const size_t*>(src);
            }
            else
            {
                *reinterpret_cast<size_t*>(tgt) = *reinterpret_cast<const size_t*>(src);
                *(reinterpret_cast<size_t*>(tgt) + 1) = *(reinterpret_cast<const size_t*>(src) + 1);
            }
        } else
#ifdef SSE2_SUPPORTED
        if constexpr (sz == 16)
        {
            _mm_storeu_si128((__m128i*)tgt, _mm_loadu_si128((const __m128i*)src));
        }
        else if constexpr (sz == 32)
        {
            _mm_storeu_si128((__m128i*)tgt, _mm_loadu_si128((const __m128i*)src));
            _mm_storeu_si128(((__m128i*)tgt) + 1, _mm_loadu_si128(((const __m128i*)src) + 1));
        }
        else if constexpr (sz == 64)
        {
            _mm_storeu_si128((__m128i*)tgt, _mm_loadu_si128((const __m128i*)src));
            _mm_storeu_si128(((__m128i*)tgt) + 1, _mm_loadu_si128(((const __m128i*)src) + 1));
            _mm_storeu_si128(((__m128i*)tgt) + 2, _mm_loadu_si128(((const __m128i*)src) + 2));
            _mm_storeu_si128(((__m128i*)tgt) + 3, _mm_loadu_si128(((const __m128i*)src) + 3));
        }
        else
#endif
            memcpy(tgt, src, sz);
    }

    inline void memcopy(void* tgt, const void* src, size_t sz)
    {
        memcpy(tgt, src, sz);
    }

}

namespace Botan {

    /// PROXTOPUS : hash type to avoid use of strings
	struct ALG
	{
		enum alg : uint8_t
		{
            Undefined,
			_Unknown,
            _Pure,
			_Raw,
			_Randomized,
			_Ed25519ph,

			_mac_start,
            AEAD,

            hash_start,

            // hash
            SHA_1,
            SHA_256,
            SHA_384,

			_mac_end,

            BLAKE2B,
            SHA_224,

            SHA_512,
            SHA_512_256,
            SHA_3_224,
            SHA_3_256,
            SHA_3_384,
			SHA_3_512,
            MD5,
			RIPEMD_160,
			SM3,

			hash_end,

#if FEATURE_TLS
            kex_start,

            STATIC_RSA,
            DH,
            ECDH,
            PSK,
            ECDHE_PSK,
            DHE_PSK,
            KEM,
            KEM_PSK,
            HYBRID,
            HYBRID_PSK,

            X25519,
            X448,

			ffdhe_ietf_2048,
			ffdhe_ietf_3072,
			ffdhe_ietf_4096,
			ffdhe_ietf_6144,
			ffdhe_ietf_8192,

			modp_ietf_1024,
			modp_ietf_1536,
			modp_ietf_2048,
			modp_ietf_3072,
			modp_ietf_4096,
			modp_ietf_6144,
			modp_ietf_8192,

			modp_srp_1024,
            modp_srp_1536,
            modp_srp_2048,
            modp_srp_3072,
            modp_srp_4096,
            modp_srp_6144,
            modp_srp_8192,

			dsa_botan_2048,

            // To support TLS 1.3 ciphersuites, which do not determine the kex algo
            KEX_UNDEFINED,

			kex_end,

			auth_start,
            DSA,
            RSA,
            ECDSA,
            ECGDSA,
            ECKCDSA,
            // To support TLS 1.3 ciphersuites, which do not determine the auth method
            AUTH_UNDEFINED,
            IMPLICIT,
			ML_DSA,
			SLH_DSA,
			auth_end,

			dilithium_start,
			DILITHIUM_4X4_AES_R3,
			DILITHIUM_6X5_AES_R3,
			DILITHIUM_8X7_AES_R3,
            DILITHIUM_4X4_R3,
            DILITHIUM_6X5_R3,
            DILITHIUM_8X7_R3,
			dilithium_end,

			HSS_LMS,
			XMSS,
			GOST_3410,
			GOST_3410_2012_256,
			GOST_3410_2012_512,
			EMSA1,
			EMSA3,
            EMSA4,
            EMSA_PKCS1,
			TLS_12_PRF,

			sign_start,

			Ed25519,
            //Ed448, // do not support for now

			sign_end,
#endif

			cipher_start,

			CHACHA20_POLY1305,
            AES_128_GCM,
            AES_256_GCM,
            AES_256_OCB,

            CAMELLIA_128_GCM,
            CAMELLIA_256_GCM,

            ARIA_128_GCM,
            ARIA_256_GCM,

            AES_128_CCM,
            AES_256_CCM,
            AES_128_CCM_8,
            AES_256_CCM_8,

			AES_128_CBC,
			AES_256_CBC,
            //AES_128_CBC_HMAC_SHA1,
            //AES_128_CBC_HMAC_SHA256,
            //AES_256_CBC_HMAC_SHA1,
            //AES_256_CBC_HMAC_SHA256,
            //AES_256_CBC_HMAC_SHA384,

            DES_DES_DES,

			cipher_end,

#if FEATURE_TLS
            curv_start,
			secp256r1,
			secp224r1,
			secp384r1,
			secp521r1,
			curv_end,

			PSSR,
			MGF1,
			PKCS1v15,
			HMAC,

			na_start,
			id_prime_Field,

			X509v3_BasicConstraints,
			X509v3_KeyUsage,
			X509v3_SubjectKeyIdentifier,
			X509v3_AuthorityKeyIdentifier,
			X509v3_SubjectAlternativeName,
			X509v3_IssuerAlternativeName,
			X509v3_ExtendedKeyUsage,
			X509v3_NameConstraints,
			X509v3_CertificatePolicies,
            X509v3_CRLNumber,
			X509v3_ReasonCode,
			X509v3_CRLDistributionPoints,
			X509v3_CRLIssuingDistributionPoint,
			PKIX_AuthorityInformationAccess,
			PKIX_OCSP_NoCheck,
			PKIX_TNAuthList,
            PKIX_ServerAuth,
			PKIX_ClientAuth,
			PKIX_OCSPSigning,
			PKIX_OCSP,
			PKIX_OCSP_BasicResponse,
			PKIX_CertificateAuthorityIssuers,
            PKCS9_EmailAddress,

			X520_CommonName,
			X520_SerialNumber,
			X520_Country,
			X520_Organization,
			X520_OrganizationalUnit,
			X520_Locality,
			X520_State,
			na_end,
#endif
        };

		alg a = Undefined;

		ALG() {}

#if FEATURE_TLS
        bool is_dilithium() const
        {
            return a > dilithium_start && a < dilithium_end;
        }
#endif

		std::string to_string() const;

	protected:
        ALG(alg aa) :a(aa) {}
	};

	struct Any_Algo;
#if FEATURE_TLS
    struct Auth_Method : public ALG {

        explicit Auth_Method(alg a = Undefined) :ALG(a) {
            if (a < auth_start || a > auth_end)
                a = Undefined;
        }
		Auth_Method(Any_Algo aa);
		bool operator<(Auth_Method am) const
		{
			return a < am.a;
		}
        bool operator!=(Auth_Method am) const
        {
            return a != am.a;
        }
        bool operator!=(alg am) const
        {
            return a != am;
        }
        bool operator==(alg am) const
        {
            return a == am;
        }
    };
#endif
	struct Any_Algo : public ALG
	{
		Any_Algo():ALG(Undefined) {}
		explicit Any_Algo(alg aa) :ALG(aa) {}

#if FEATURE_TLS
        bool operator == (Auth_Method am) const
        {
            return a == am.a;
        }
#endif
        bool operator == (Any_Algo aa) const
        {
            return a == aa.a;
        }
        bool operator != (Any_Algo aa) const
        {
            return a != aa.a;
        }
        bool operator == (alg aa) const
        {
            return a == aa;
        }
	};

#if FEATURE_TLS
    struct Non_Algo : public ALG
	{
		Non_Algo() :ALG(Undefined) {}
		Non_Algo(alg a) :ALG(a)
        {
            if (a < na_start || a > na_end)
                a = Undefined;
        }
        bool operator == (alg aa) const
        {
            return a == aa;
        }
		bool empty() const { return a == Undefined; }
	};
#endif


    struct Cipher_Algo : public ALG {
        explicit Cipher_Algo(alg a = Undefined) :ALG(a) {
            if (a < cipher_start || a > cipher_end)
                a = Undefined;
        }
        bool operator==(alg am) const
        {
            return a == am;
        }
        bool operator!=(Cipher_Algo am) const
        {
            return a != am.a;
        }
        bool operator==(Cipher_Algo am) const
        {
            return a == am.a;
        }
        bool operator==(Any_Algo am) const
        {
            return a == am.a;
        }

    };

#if FEATURE_TLS
    inline Auth_Method::Auth_Method(Any_Algo aa) :ALG(aa.a) {
        if (a < auth_start || a > auth_end)
            a = Undefined;
    }
#endif

    struct KDF_Algo : public ALG {

        KDF_Algo(alg a) :ALG(a)
        {
            if (a != SHA_1 && a != SHA_256 && a != SHA_384)
                a = Undefined;
        }
		bool operator == (alg aa) const
		{
			return a == aa;
		}
	};

	struct Hash_Algo : public ALG
	{
		Hash_Algo(alg aa) :ALG(aa) {
			if (a < hash_start || a > hash_end)
				a = Undefined;
		}
        Hash_Algo(Any_Algo aa) :ALG(aa.a) {
            if (a < hash_start || a > hash_end)
                a = Undefined;
        }
		Hash_Algo(KDF_Algo aa) :ALG(aa.a) {}

        static Hash_Algo Pure() {
			return Hash_Algo(_Pure, false);
        }
        static Hash_Algo Unknown() {
            return Hash_Algo(_Unknown, false);
        }
		bool empty() const
		{
			return a < hash_start || a > hash_end;
		}
        bool operator == (Hash_Algo h) const
        {
            return a == h.a;
        }
        bool operator != (Hash_Algo h) const
        {
            return a != h.a;
        }
        bool operator < (Hash_Algo h) const
        {
            return a < h.a;
        }

	private:
		Hash_Algo(alg aa, bool) :ALG(aa) {}
	};

    struct Mac_Algo : public ALG {
		Mac_Algo(alg a) :ALG(a)
        {
            if (a < _mac_start || a > _mac_end)
                a = Undefined;
        }
        bool operator != (Mac_Algo h) const
        {
            return a != h.a;
        }
        bool operator == (Any_Algo h) const
        {
            return a == h.a;
        }
        bool operator == (alg h) const
        {
            return a == h;
        }

    };

#if FEATURE_TLS
    struct Kex_Algo : public ALG {

        explicit Kex_Algo(alg a = Undefined) :ALG(a)
        {
            if (a < kex_start || a > kex_end)
                a = Undefined;
        }
        bool operator != (Kex_Algo h) const
        {
            return a != h.a;
        }
        bool operator == (Any_Algo h) const
        {
            return a == h.a;
        }
        bool operator == (alg aa) const
        {
            return a == aa;
        }

    };

    class OID;
	struct PrimeOrderCurveId : public ALG
	{
		explicit PrimeOrderCurveId(alg a = Undefined) :ALG(a)
		{
			if (a < curv_start || a > curv_end)
				a = Undefined;
		}

		enum cod
		{
			secp224r1 = ALG::secp224r1,
			secp256r1 = ALG::secp256r1,
			secp384r1 = ALG::secp384r1,
			secp521r1 = ALG::secp521r1,
		};

		cod code() const { return static_cast<cod>(a); }
		static std::optional<PrimeOrderCurveId> from_oid(const OID& oid);

	};
#endif

	struct Algo_Group_Iterator
	{
		Any_Algo a[7] = {};
		uint8_t index = 0;
		Algo_Group_Iterator(const Any_Algo *aa, uint8_t ii) :index(ii) {
			for (size_t i = 0; i < std::size(a); ++i)
				a[i] = aa[i];
		}
		bool operator != (const Algo_Group_Iterator& oi) const
		{
			static_assert(sizeof(*this) == sizeof(uint64_t));
			return *reinterpret_cast<const uint64_t*>(this) != *reinterpret_cast<const uint64_t*>(&oi);
		}

		Algo_Group_Iterator& operator++() {
            ++index;
            return *this;
        }

		Algo_Group_Iterator operator++(int) {
			Algo_Group_Iterator _Ans = *this;
            ++index;
            return _Ans;
        }

		Any_Algo operator *() const
		{
			return a[index];
		}
	};


#if FEATURE_TLS
    struct Algo_Group
	{
		Any_Algo a[7];
		uint8_t saltl = 0xff; // salt length
        Algo_Group(Algo_Group ag, ALG::alg a2) {

			*this = ag;
			for(size_t i=0;i<std::size(a);++i)
				if (a[i] == Any_Algo::Undefined)
				{
					a[i].a = a2;
					return;
				}
#ifdef WIN32
			__debugbreak();
#endif
        }
        Algo_Group(Algo_Group ag1, Algo_Group ag2) {

            *this = ag1;
            for (size_t i = 0; i < std::size(a); ++i)
                if (a[i] == Any_Algo::Undefined)
                {
					size_t j = 0;
					for (; j < std::size(a);)
					{
						a[i++].a = ag2.a[j++].a;
#ifdef WIN32
						if (i == std::size(a))
							__debugbreak();
#endif
					}
					saltl = ag2.saltl;
                    return;
                }
#ifdef WIN32
            __debugbreak();
#endif
        }
        //Algo_Group(ALG::alg a1, Hash_Algo a2) {
          //  a[0].a = a1; a[1].a = a2.a; a[2] = Any_Algo(); a[3] = Any_Algo();
        //}
		explicit Algo_Group(ALG::alg a1 = ALG::Undefined, ALG::alg a2 = ALG::Undefined, ALG::alg a3 = ALG::Undefined, ALG::alg a4 = ALG::Undefined,
			ALG::alg a5 = ALG::Undefined, ALG::alg a6 = ALG::Undefined, ALG::alg a7 = ALG::Undefined) {
			a[0].a = a1; a[1].a = a2; a[2].a = a3; a[3].a = a4;
			a[4].a = a5; a[5].a = a6; a[6].a = a7;;
        }
        explicit Algo_Group(Any_Algo h) {
            a[0] = h; a[1] = Any_Algo(); a[2] = Any_Algo(); a[3] = Any_Algo();
			a[4] = Any_Algo(); a[5] = Any_Algo(); a[6] = Any_Algo();
        }
        explicit Algo_Group(Hash_Algo h) {
            a[0].a = h.a; a[1] = Any_Algo(); a[2] = Any_Algo(); a[3] = Any_Algo();
			a[4] = Any_Algo(); a[5] = Any_Algo(); a[6] = Any_Algo();
        }
        explicit Algo_Group(Auth_Method am) {
            a[0].a = am.a; a[1] = Any_Algo(); a[2] = Any_Algo(); a[3] = Any_Algo();
			a[4] = Any_Algo(); a[5] = Any_Algo(); a[6] = Any_Algo();
        }

		bool is_raw() const
		{
			return a[0].a == ALG::_Raw;
		}

		size_t size() const
		{
			for (size_t i = 0; i < std::size(a); ++i)
				if (a[i].a == ALG::Undefined)
					return i;
			return std::size(a);
		}

		Hash_Algo hash() const
		{
			return a[0].a > ALG::hash_start && a[0].a < ALG::hash_end ? Hash_Algo(a[0]) : Hash_Algo(ALG::Undefined);
		}
        Hash_Algo hashif(ALG::alg aa) const
        {
			if (a[0].a == aa)
				return a[1].a > ALG::hash_start && a[1].a < ALG::hash_end ? Hash_Algo(a[1]) : Hash_Algo(ALG::Undefined);
			return Hash_Algo(ALG::Undefined);
        }

		Any_Algo first() const
		{
			return a[0];
		}
        Any_Algo second() const
        {
            return a[1];
        }
        Any_Algo third() const
        {
            return a[2];
        }
		Algo_Group skip_first() const
		{
			return Algo_Group(a[1].a, a[2].a, a[3].a, a[4].a, a[5].a, a[6].a);
		}

		Algo_Group& operator += (ALG::alg aa)
		{
			a[size()].a = aa;
			return *this;
		}

		bool present(ALG aa) const
		{
			if (a[0].a == aa.a) return true;
			if (a[1].a == aa.a) return true;
			if (a[2].a == aa.a) return true;
			if (a[3].a == aa.a) return true;
			if (a[4].a == aa.a) return true;
			if (a[5].a == aa.a) return true;
			return a[6].a == aa.a;
		}
        bool empty() const
        {
            return a[0] == ALG::Undefined;
        }

		Algo_Group& salt(uint8_t ss)
		{
			saltl = ss;
			return *this;
		}

		std::string to_string() const;
        bool operator == (ALG::alg aa) const
        {
            return a[0] == aa;
        }

		Algo_Group_Iterator begin() const
		{
			return Algo_Group_Iterator(a, 0);
		}
        Algo_Group_Iterator end() const
        {
            return Algo_Group_Iterator(a, 7);
        }

	};
    inline Algo_Group operator+(Algo_Group ag1, Algo_Group ag2)
    {
        return Algo_Group(ag1, ag2);
    }

	inline Algo_Group operator+(Algo_Group ag, ALG::alg a)
	{
		return Algo_Group(ag, a);
	}
    inline Algo_Group operator+(Algo_Group ag, Hash_Algo a)
    {
        return Algo_Group(ag, a.a);
    }

	inline bool value_exists(Algo_Group ag, ALG val) {
		return ag.present(val);
    }

	inline std::string operator+(const char* oss, Non_Algo format) {
        return oss + format.to_string();
    }

    inline std::string operator+(const char *oss, Any_Algo format) {
        return oss + format.to_string();
    }
    inline std::string operator+(const char* oss, Kex_Algo format) {
        return oss + format.to_string();
    }
	inline std::string operator+(Any_Algo format, const char* oss) {
		return format.to_string().append(oss);
	}

	inline std::string operator+(const char* oss, Algo_Group format) {
        return oss + format.to_string();
    }
    inline std::string operator+(Any_Algo format, const std::string_view &oss) {
        return format.to_string().append(oss);
    }
    inline std::string operator+(Any_Algo format, const std::string& oss) {
        return format.to_string().append(oss);
    }

    inline std::string operator+(const std::string& oss, Any_Algo format) {
        return oss + format.to_string();
    }
    inline std::string operator+(const std::string& oss, Hash_Algo format) {
        return oss + format.to_string();
    }

    inline std::string operator+(const std::string& oss, Algo_Group format) {
        return oss + format.to_string();
    }
#endif

	class RandomNumberGenerator;
	class OctetString : private secure_vector<uint8_t>
	{
		using parent = secure_vector<uint8_t>;

    public:

        size_t length() const { return parent::size(); }
        const uint8_t* begin() const { return parent::data(); }
        const uint8_t* end() const { return begin() + parent::size(); }
        bool empty() const { return parent::empty(); }
        const secure_vector<uint8_t>& bits_of() const { return *this; }

		OctetString() {}
		OctetString(secure_vector<uint8_t>&& sv):secure_vector(std::move(sv))
		{
		}
		OctetString(RandomNumberGenerator& rng, size_t len);

		/*
		OctetString& operator+=(const std::span<const uint8_t>& in) {

			secure_vector& me = (secure_vector&)*this;
			me += in;
            return *this;
        }
		*/
	};

	template<typename W, size_t n> class hash_digest
	{
		W bits[n];
	public:
		W* data() { return bits; }
		const W* data() const { return bits; }

		const W* begin() const { return bits; }
		W* begin() { return bits; }
        const W* end() const { return bits + n; }
        W* end() { return bits + n; }

        const W* cbegin() const { return bits; }
        W* cbegin() { return bits; }
        const W* cend() const { return bits + n; }
        W* cend() { return bits + n; }

		size_t size() { return n; }

		W operator[](size_t index) const { return bits[index]; }
		W &operator[](size_t index) { return bits[index]; }

		using iterator = W*;
		using const_iterator = const W*;
        using pointer = W*;
        using const_pointer = const W*;
		using size_type = size_t;
		using value_type = W;

		void assign(const std::array<W, n>& d)
		{
			tools::memcopy<sizeof(bits)>(bits, d.data());
		}
	};

	using SymmetricKey = OctetString;
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

	template <typename T, typename Alloc, typename Alloc2>
	std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const std::vector<T, Alloc2>& in) {
		out.insert(out.end(), in.begin(), in.end());
		return out;
	}

    template <typename T, typename Alloc>
    std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, const secure_vector<T>& in) {
        out.insert(out.end(), in.begin(), in.end());
        return out;
    }

    /*
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

    template <typename T> std::vector<T> unlock(const secure_vector<T>& in) {
        return std::vector<T>(in.begin(), in.end());
    }

    inline uint32_t to_u32bit(std::string_view str) {
        size_t v = 0;

        for (char c : str)
        {
            size_t y = c - 48;
            if (y >= 10)
                throw std::runtime_error("to_u32bit invalid decimal string");
            v = v * 10 + y;
        }

        if (v & 0xffffffff00000000ull)
            throw std::runtime_error("to_u32bit exceeds 32 bit range");

        return v & 0xffffffffull;

    }

	template<typename N> inline constexpr uint8_t as_byte(N n)
	{
		return static_cast<uint8_t>(n & 0xff);
	}
    template<typename N> inline constexpr uint16_t as_u16(N n)
    {
        return static_cast<uint16_t>(n & 0xffff);
    }
    template<typename N> inline constexpr uint32_t as_u32(N n)
    {
        return static_cast<uint32_t>(n & 0xffffffff);
    }
	namespace hidden
	{
        inline size_t nfs_workfactor(size_t bits, double log2_k) {
            // approximates natural logarithm of an integer of given bitsize
            const double log_p = bits / std::numbers::log2e;

            const double log_log_p = std::log(log_p);

            // RFC 3766: k * e^((1.92 + o(1)) * cubrt(ln(n) * (ln(ln(n)))^2))
            const double est = 1.92 * std::pow(log_p * log_log_p * log_log_p, 1.0 / 3.0);

            // return log2 of the workfactor
            return static_cast<size_t>(log2_k + std::numbers::log2e * est);
        }
	}

    inline size_t ecp_work_factor(size_t bits) {
        return bits / 2;
    }

    inline size_t dl_exponent_size(size_t bits) {
        if (bits == 0) {
            return 0;
        }
        if (bits <= 256) {
            return bits - 1;
        }
        if (bits <= 1024) {
            return 192;
        }
        if (bits <= 1536) {
            return 224;
        }
        if (bits <= 2048) {
            return 256;
        }
        if (bits <= 4096) {
            return 384;
        }
        return 512;
    }

    inline size_t if_work_factor(size_t bits) {
        if (bits < 512) {
            return 0;
        }

        // RFC 3766 estimates k at .02 and o(1) to be effectively zero for sizes of interest

        const double log2_k = -5.6438;  // log2(.02)
        return hidden::nfs_workfactor(bits, log2_k);
    }

	inline size_t dl_work_factor(size_t bits) {
        // Lacking better estimates...
        return if_work_factor(bits);
    }



    inline std::string string_join(const std::vector<std::string>& strs, char delim) {
		std::string out;

        for (size_t i = 0; i != strs.size(); ++i) {
            if (i != 0) {
                out.push_back(delim);
            }
            out.append(strs[i]);
        }

        return out;
    }

	std::optional<uint32_t> string_to_ipv4(std::string_view str); // returns in native endian!!! ex: "127.0.0.1" -> 127 is high octet of uint32_t value
    std::string ipv4_to_string(uint32_t ip); // accepts uint32_t value in native endian!!! ex: "127.0.0.1" -> 127 is high octet of uint32_t value
    std::string check_and_canonicalize_dns_name(std::string_view name);

    inline std::string tolower_string(std::string_view in) {
        std::string s(in);
        for (size_t i = 0; i != s.size(); ++i) {
            const int cu = static_cast<unsigned char>(s[i]);
            if (std::isalpha(cu)) {
                s[i] = static_cast<char>(std::tolower(cu));
            }
        }
        return s;
    }

	bool host_wildcard_match(std::string_view issued_, std::string_view host_);

	secure_vector<uint8_t> base64_decode(const char* s, size_t sl);

#if FEATURE_TLS
	void DER_encode(secure_vector<uint8_t>& outb, const uint32_t* data, size_t size);

	enum class oid_index
	{
		_empty,

        _1_0_14888_3_0_5,
        _1_2_156_10197_1_401,
        _1_2_156_10197_1_504,
        _1_2_410_200004_1_100_4_3,
        _1_2_410_200004_1_100_4_4,
        _1_2_410_200004_1_100_4_5,
        _1_2_840_113549_1_1_1,
        _1_2_840_113549_1_1_5,
        _1_2_840_113549_1_1_8,
        _1_2_840_113549_1_1_10,
        _1_2_840_113549_1_1_11,
        _1_2_840_113549_1_1_12,
        _1_2_840_113549_1_1_13,
        _1_2_840_113549_1_1_14,
        _1_2_840_113549_1_1_16,
        _1_2_840_113549_1_9_1,
        _1_2_840_113549_1_9_16_3_18,
        _1_2_840_113549_2_7,
        _1_2_840_113549_2_8,
        _1_2_840_113549_2_9,
        _1_2_840_113549_2_10,
        _1_2_840_113549_2_11,
        _1_2_840_113549_2_13,
        _1_2_840_10040_4_1,
        _1_2_840_10040_4_3,
        _1_2_840_10045_1_1,
        _1_2_840_10045_2_1,
        _1_2_840_10045_3_1_7,
        _1_2_840_10045_4_1,
        _1_2_840_10045_4_3_1,
        _1_2_840_10045_4_3_2,
        _1_2_840_10045_4_3_3,
        _1_2_840_10045_4_3_4,
        _1_2_840_10046_2_1,
        _1_3_6_1_5_5_7_1_1,
        _1_3_6_1_5_5_7_1_26,
        _1_3_6_1_5_5_7_3_1,
        _1_3_6_1_5_5_7_3_2,
        _1_3_6_1_5_5_7_3_9,
        _1_3_6_1_5_5_7_48_1,
        _1_3_6_1_5_5_7_48_1_1,
        _1_3_6_1_5_5_7_48_1_5,
        _1_3_6_1_5_5_7_48_2,
        _1_3_14_3_2_26,
        _1_3_36_3_2_1,
        _1_3_36_3_3_1_2,
        _1_3_36_3_3_2_5_2_1,
        _1_3_36_3_3_2_5_4_1,
        _1_3_36_3_3_2_5_4_2,
        _1_3_36_3_3_2_5_4_3,
        _1_3_36_3_3_2_5_4_4,
        _1_3_36_3_3_2_5_4_5,
        _1_3_36_3_3_2_5_4_6,
        _1_3_101_110,
        _1_3_101_111,
        _1_3_101_112,
        _1_3_132_0_33,
        _1_3_132_0_34,
        _1_3_132_0_35,
        _1_3_132_1_12,
        _2_5_4_3,
        _2_5_4_5,
        _2_5_4_6,
        _2_5_4_7,
        _2_5_4_8,
        _2_5_4_10,
        _2_5_4_11,
        _2_5_29_14,
        _2_5_29_15,
        _2_5_29_17,
        _2_5_29_18,
        _2_5_29_19,
        _2_5_29_20,
        _2_5_29_21,
        _2_5_29_28,
        _2_5_29_30,
        _2_5_29_31,
        _2_5_29_32,
        _2_5_29_35,
        _2_5_29_37,
        _2_16_840_1_101_3_4_1_2,
        _2_16_840_1_101_3_4_1_6,
        _2_16_840_1_101_3_4_1_42,
        _2_16_840_1_101_3_4_1_46,
        _2_16_840_1_101_3_4_2_1,
        _2_16_840_1_101_3_4_2_2,
        _2_16_840_1_101_3_4_2_3,
        _2_16_840_1_101_3_4_2_4,
        _2_16_840_1_101_3_4_2_6,
        _2_16_840_1_101_3_4_2_7,
        _2_16_840_1_101_3_4_2_8,
        _2_16_840_1_101_3_4_2_9,
        _2_16_840_1_101_3_4_2_10,
        _2_16_840_1_101_3_4_3_1,
        _2_16_840_1_101_3_4_3_2,
        _2_16_840_1_101_3_4_3_3,
        _2_16_840_1_101_3_4_3_4,
        _2_16_840_1_101_3_4_3_5,
        _2_16_840_1_101_3_4_3_6,
        _2_16_840_1_101_3_4_3_7,
        _2_16_840_1_101_3_4_3_8,
        _2_16_840_1_101_3_4_3_9,
        _2_16_840_1_101_3_4_3_10,
        _2_16_840_1_101_3_4_3_11,
        _2_16_840_1_101_3_4_3_12,
        _2_16_840_1_101_3_4_3_13,
        _2_16_840_1_101_3_4_3_14,
        _2_16_840_1_101_3_4_3_15,
        _2_16_840_1_101_3_4_3_16,

		_count,
	};

    inline std::strong_ordering int2so(int cmp)
    {
        if (cmp < 0)
            return std::strong_ordering::less;
        else if (cmp > 0)
            return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
	inline std::strong_ordering gr(std::strong_ordering cmp)
	{
		if (std::strong_ordering::equal == cmp)
			return std::strong_ordering::greater;
		return cmp;
	}

    inline std::strong_ordering compare_spans(std::span<const uint8_t> lhs, std::span<const uint8_t> rhs) noexcept {

        if (lhs.size() > rhs.size())
			return gr(int2so(memcmp(lhs.data(), rhs.data(), rhs.size())));

        auto cmp = int2so(memcmp(lhs.data(), rhs.data(), lhs.size()));
		if (lhs.size() < rhs.size() && cmp == std::strong_ordering::equal)
			return std::strong_ordering::less;
		return cmp;
    }

	struct OID_core
	{
		std::span<const uint8_t> id;
		Algo_Group alg;

		std::strong_ordering operator <=>(std::span<const uint8_t> id2) const
		{
			return compare_spans(id, id2);
		}
	};

	static_assert(static_cast<int>(oid_index::_count) < 256);

	extern OID_core g_oids[];
	extern uint8_t g_oids_by_algs[];
	inline const OID_core& oid_core(oid_index i) { return g_oids[static_cast<int>(i)]; }
	oid_index oid_find_index(std::span<const uint8_t> id);
#endif

} // namespace Botan

#if FEATURE_TLS
namespace str
{
    void __append(std::string & sout, Botan::ALG alg);
    void __append(std::string& sout, Botan::Algo_Group alg);
    void __append(std::string& sout, Botan::Any_Algo alg);
    void __append(std::string& sout, Botan::Auth_Method alg);
    void __append(std::string& sout, Botan::ALG::alg alg);
    void __append(std::string& sout, const Botan::OID &oid);
}
#endif


template<typename T> constexpr bool is_plain_old_struct_v =
std::is_trivially_default_constructible_v<T> &&
std::is_trivially_copy_constructible_v<T> &&
std::is_trivially_move_constructible_v<T> &&
std::is_trivially_destructible_v<T>;

template<typename T, size_t align> requires(is_plain_old_struct_v<T>&& std::has_single_bit(align)) class aligned_data
{
    uint8_t data_space[sizeof(T) + align];
public:
    aligned_data()
    {
        size_t addr_ok = (reinterpret_cast<size_t>(data_space + 1) + align - 1) & ~(align - 1U);
        size_t addr_cur = reinterpret_cast<size_t>(data_space + 0);
        data_space[0] = static_cast<uint8_t>(addr_ok - addr_cur); // offset to aligned
    }
    T& operator->() { return *(T*)(data_space + data_space[0]); }
    const T& operator->() const { return *(const T*)(data_space + data_space[0]); }

    T& data() { return *(T*)(data_space + data_space[0]); }
    const T& data() const { return *(T*)(data_space + data_space[0]); }
};

#define BOTAN_PUBLIC_API(...)
#include <botan/exceptn.h>
