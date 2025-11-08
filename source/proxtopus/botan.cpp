#include "pch.h"

#include "botan/aead.h"
#include "botan/internal/chacha20poly1305.h"
#include "botan/internal/aes.h"
#include "botan/internal/gcm.h"
#include "botan/internal/sha2_32.h"
#include "botan/internal/sha2_64.h"
#include "botan/internal/sha3.h"
#include "botan/internal/blake2b.h"
#include <botan/internal/md5.h>
#include <botan/internal/rmd160.h>
#include <botan/internal/sm3.h>
#include "botan/internal/prf_tls.h"
#include <botan/internal/emsa.h>
#include <botan/internal/pssr.h>
#include <botan/internal/emsa_pkcs1.h>
#include <botan/internal/eme.h>
#include <botan/internal/eme_pkcs.h>
#include <botan/internal/rounding.h>
#include <botan/internal/hmac.h>

#if FEATURE_TLS
namespace str
{
    void __append(std::string& sout, Botan::ALG alg) {
        sout.append(alg.to_string());
    }

    void __append(std::string& sout, Botan::Algo_Group alg) {
        sout.append(alg.to_string());
    }
    void __append(std::string& sout, Botan::Any_Algo alg) {
        sout.append(alg.to_string());
    }
    void __append(std::string& sout, Botan::Auth_Method alg) {
        sout.append(alg.to_string());
    }

    void __append(std::string& sout, Botan::ALG::alg alg) {
        sout.append(Botan::Any_Algo(alg).to_string());
    }

    void __append(std::string& sout, const Botan::OID& oid) {
        sout.append(oid.to_string());
    }
}
#endif

namespace Botan
{

	std::unique_ptr<AEAD_Mode> AEAD_Mode::create_or_throw(Cipher_Algo algo, Cipher_Dir direction)
	{
		bool enc = direction == Cipher_Dir::Encryption;
		switch (algo.a)
		{
		case Cipher_Algo::CHACHA20_POLY1305:

			if (enc)
				return std::make_unique<ChaCha20Poly1305_Encryption>();
            return std::make_unique<ChaCha20Poly1305_Decryption>();

		case Cipher_Algo::AES_128_GCM:
		{
            auto bc = std::make_unique<AES_128>();
            if (enc)
                return std::make_unique<GCM_Encryption>(std::move(bc), 16);
            return std::make_unique<GCM_Decryption>(std::move(bc), 16);
		}
		case Cipher_Algo::AES_256_GCM:
        {
            auto bc = std::make_unique<AES_256>();
            if (enc)
                return std::make_unique<GCM_Encryption>(std::move(bc), 16);
            return std::make_unique<GCM_Decryption>(std::move(bc), 16);
        }
#if defined (BOTAN_HAS_AEAD_OCB)
		case Cipher_Algo::AES_256_OCB:
			-break; todo : add creation
#endif
#if defined (BOTAN_HAS_CAMELLIA)
		case Cipher_Algo::CAMELLIA_128_GCM:
			-break; todo: add creation
		case Cipher_Algo::CAMELLIA_256_GCM:
			-break; todo: add creation
#endif
#if defined (BOTAN_HAS_ARIA)
		case Cipher_Algo::ARIA_128_GCM:
			-break; todo: add creation
		case Cipher_Algo::ARIA_256_GCM:
			-break; todo: add creation
#endif
#if defined (BOTAN_HAS_AEAD_CCM)
		case Cipher_Algo::AES_128_CCM:
			-break; todo: add creation
		case Cipher_Algo::AES_256_CCM:
			-break; todo: add creation
		case Cipher_Algo::AES_128_CCM_8:
			-break; todo: add creation
		case Cipher_Algo::AES_256_CCM_8:
			-break; todo: add creation
#endif

		}
        throw Lookup_Error("Cipher mode");

	}

	std::unique_ptr<HashFunction> HashFunction::create(Hash_Algo hasht)
	{
        switch (hasht.a)
        {
        case Botan::Hash_Algo::BLAKE2B:
            return std::make_unique<BLAKE2b>();
        case Botan::Hash_Algo::SHA_1:
            return std::make_unique<SHA_1>();
        case Botan::Hash_Algo::SHA_224:
            return std::make_unique<SHA_224>();
        case Botan::Hash_Algo::SHA_256:
            return std::make_unique<SHA_256>();
        case Botan::Hash_Algo::SHA_384:
            return std::make_unique<SHA_384>();
        case Botan::Hash_Algo::SHA_512:
            return std::make_unique<SHA_512>();
        case Botan::Hash_Algo::SHA_512_256:
            return std::make_unique<SHA_512_256>();
        case Botan::Hash_Algo::SHA_3_224:
            return std::make_unique<SHA_3_224>();
        case Botan::Hash_Algo::SHA_3_256:
            return std::make_unique<SHA_3_256>();
        case Botan::Hash_Algo::SHA_3_384:
            return std::make_unique<SHA_3_384>();
        case Botan::Hash_Algo::SHA_3_512:
            return std::make_unique<SHA_3_512>();
        case Botan::Hash_Algo::MD5:
            return std::make_unique<MD5>();
#if FEATURE_TLS
        case Botan::Hash_Algo::RIPEMD_160:
            return std::make_unique<RIPEMD_160>();
        case Botan::Hash_Algo::SM3:
            return std::make_unique<SM3>();
#endif
        }

		return std::unique_ptr<HashFunction>();
	}

#if FEATURE_TLS
    std::unique_ptr<HashFunction> HashFunction::create_or_throw(Hash_Algo hasht)
    {
        if (auto hf = create(hasht))
            return hf;

        throw Lookup_Error("Hash: " + hasht);
    }


    /// PROXTOPUS
    template <typename KDF_Type> std::unique_ptr<KDF> kdf_create_mac_or_hash(Hash_Algo h) {

        auto mac = std::make_unique<HMAC>(HashFunction::create_or_throw(h));
        return std::make_unique<KDF_Type>(std::move(mac));
    }

    std::unique_ptr<KDF> KDF::create(Algo_Group ag) {

        switch (ag.first().a)
        {
#if defined(BOTAN_HAS_TLS_V12_PRF)
        case ALG::TLS_12_PRF:
            return kdf_create_mac_or_hash<TLS_12_PRF>(ag.second());
#endif

        default:
            break;
        }

#if defined(BOTAN_HAS_HKDF)
        if (req.algo_name() == "HKDF" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return kdf_create_mac_or_hash<HKDF>(req.arg(0));
            }
        }

        if (req.algo_name() == "HKDF-Extract" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return kdf_create_mac_or_hash<HKDF_Extract>(req.arg(0));
            }
        }

        if (req.algo_name() == "HKDF-Expand" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return kdf_create_mac_or_hash<HKDF_Expand>(req.arg(0));
            }
        }
#endif

#if defined(BOTAN_HAS_KDF2)
        if (req.algo_name() == "KDF2" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    return std::make_unique<KDF2>(std::move(hash));
                }
            }
        }
#endif

#if defined(BOTAN_HAS_KDF1_18033)
        if (req.algo_name() == "KDF1-18033" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    return std::make_unique<KDF1_18033>(std::move(hash));
                }
            }
        }
#endif

#if defined(BOTAN_HAS_KDF1)
        if (req.algo_name() == "KDF1" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    return std::make_unique<KDF1>(std::move(hash));
                }
            }
        }
#endif

#if defined(BOTAN_HAS_X942_PRF)
        if (req.algo_name() == "X9.42-PRF" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return std::make_unique<X942_PRF>(req.arg(0));
            }
        }
#endif

#if defined(BOTAN_HAS_SP800_108)
        if (req.algo_name() == "SP800-108-Counter" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return kdf_create_mac_or_hash<SP800_108_Counter>(req.arg(0));
            }
        }

        if (req.algo_name() == "SP800-108-Feedback" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0));
            }
        }

        if (req.algo_name() == "SP800-108-Pipeline" && req.arg_count() == 1) {
            if (provider.empty() || provider == "base") {
                return kdf_create_mac_or_hash<SP800_108_Pipeline>(req.arg(0));
            }
        }
#endif

#if defined(BOTAN_HAS_SP800_56A)
        if (req.algo_name() == "SP800-56A" && req.arg_count() == 1) {
            if (auto hash = HashFunction::create(req.arg(0))) {
                return std::make_unique<SP800_56C_One_Step_Hash>(std::move(hash));
            }
            if (req.arg(0) == "KMAC-128") {
                return std::make_unique<SP800_56C_One_Step_KMAC128>();
            }
            if (req.arg(0) == "KMAC-256") {
                return std::make_unique<SP800_56C_One_Step_KMAC256>();
            }
            if (auto mac = MessageAuthenticationCode::create(req.arg(0))) {
                return std::make_unique<SP800_56C_One_Step_HMAC>(std::move(mac));
            }
        }
#endif

#if defined(BOTAN_HAS_SP800_56C)
        if (req.algo_name() == "SP800-56C" && req.arg_count() == 1) {
            std::unique_ptr<KDF> exp(kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0)));
            if (exp) {
                if (auto mac = MessageAuthenticationCode::create(req.arg(0))) {
                    return std::make_unique<SP800_56C_Two_Step>(std::move(mac), std::move(exp));
                }

                if (auto mac = MessageAuthenticationCode::create(fmt("HMAC({})", req.arg(0)))) {
                    return std::make_unique<SP800_56C_Two_Step>(std::move(mac), std::move(exp));
                }
            }
        }
#endif

        return nullptr;
    }

    //static
    std::unique_ptr<KDF> KDF::create_or_throw(Algo_Group ag) {
        if (ag.is_raw())
            return nullptr;

        if (auto kdf = KDF::create(ag)) {
            return kdf;
        }
        throw Lookup_Error("KDF: " + ag.to_string());
    }


    std::unique_ptr<EMSA> EMSA::create(Algo_Group algo_spec)
    {
        std::unique_ptr<HashFunction> hash;
        switch (algo_spec.first().a)
        {
#if defined(BOTAN_HAS_EMSA_PKCS1)
        case ALG::EMSA_PKCS1:
        case ALG::PKCS1v15:
        case ALG::EMSA3:

            hash = HashFunction::create(algo_spec.second());
            if (hash)
                return std::make_unique<EMSA_PKCS1v15>(std::move(hash));

            break;
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)

            /*
        if (req.algo_name() == "PSS_Raw" || req.algo_name() == "PSSR_Raw") {
            if (req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1") {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    if (req.arg_count() == 3) {
                        const size_t salt_size = req.arg_as_integer(2, 0);
                        return std::make_unique<PSSR_Raw>(std::move(hash), salt_size);
                    }
                    else {
                        return std::make_unique<PSSR_Raw>(std::move(hash));
                    }
                }
            }
        }
        */
        case ALG::PSSR:
        case ALG::EMSA4:

            if (algo_spec.third() == ALG::MGF1) {
                hash = HashFunction::create(algo_spec.second());
                if (hash) {
                    if (algo_spec.saltl != 0xff) {
                        return std::make_unique<PSSR>(std::move(hash), algo_spec.saltl);
                    }
                    else {
                        return std::make_unique<PSSR>(std::move(hash));
                    }
                }
            }
#endif
        }

#if defined(BOTAN_HAS_ISO_9796)
        if (req.algo_name() == "ISO_9796_DS2") {
            if (req.arg_count_between(1, 3)) {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    const size_t salt_size = req.arg_as_integer(2, hash->output_length());
                    const bool implicit = req.arg(1, "exp") == "imp";
                    return std::make_unique<ISO_9796_DS2>(std::move(hash), implicit, salt_size);
                }
            }
        }
        //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
        if (req.algo_name() == "ISO_9796_DS3") {
            if (req.arg_count_between(1, 2)) {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    const bool implicit = req.arg(1, "exp") == "imp";
                    return std::make_unique<ISO_9796_DS3>(std::move(hash), implicit);
                }
            }
        }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
        if (req.algo_name() == "EMSA_X931" || req.algo_name() == "EMSA2" || req.algo_name() == "X9.31") {
            if (req.arg_count() == 1) {
                if (auto hash = HashFunction::create(req.arg(0))) {
                    return std::make_unique<EMSA_X931>(std::move(hash));
                }
            }
        }
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
        if (req.algo_name() == "Raw") {
            if (req.arg_count() == 0) {
                return std::make_unique<EMSA_Raw>();
            }
            else {
                auto hash = HashFunction::create(req.arg(0));
                if (hash) {
                    return std::make_unique<EMSA_Raw>(hash->output_length());
                }
            }
        }
#endif

        return nullptr;

    }

    std::unique_ptr<EMSA> EMSA::create_or_throw(Algo_Group algo_spec)
    {
        auto emsa = EMSA::create(algo_spec);
        if (emsa) {
            return emsa;
        }
        throw Algorithm_Not_Found("" + algo_spec);

    }

    std::unique_ptr<EME> EME::create(Algo_Group algo_spec) {

        switch (algo_spec.first().a)
        {
#if defined(BOTAN_HAS_EME_PKCS1)
        case ALG::PKCS1v15:
                return std::make_unique<EME_PKCS1v15>();
#endif
#if defined(BOTAN_HAS_EME_OAEP)
        case ALG::MGF1:

                if (req.algo_name() == "OAEP" || req.algo_name() == "EME-OAEP" || req.algo_name() == "EME1") {
                    if (req.arg_count() == 1 || ((req.arg_count() == 2 || req.arg_count() == 3) && req.arg(1) == "MGF1")) {
                        if (auto hash = HashFunction::create(req.arg(0))) {
                            return std::make_unique<OAEP>(std::move(hash), req.arg(2, ""));
                        }
                    }
                    else if (req.arg_count() == 2 || req.arg_count() == 3) {
                        auto mgf_params = parse_algorithm_name(req.arg(1));

                        if (mgf_params.size() == 2 && mgf_params[0] == "MGF1") {
                            auto hash = HashFunction::create(req.arg(0));
                            auto mgf1_hash = HashFunction::create(mgf_params[1]);

                            if (hash && mgf1_hash) {
                                return std::make_unique<OAEP>(std::move(hash), std::move(mgf1_hash), req.arg(2, ""));
                            }
                        }
                    }
                }
#endif

        default:
            DEBUGBREAK();
    }

#if defined(BOTAN_HAS_EME_RAW)
        if (algo_spec == "Raw") {
            return std::make_unique<EME_Raw>();
        }
#endif



        throw Algorithm_Not_Found(algo_spec.to_string());
    }
    EME::~EME() = default;

#endif

    std::unique_ptr<BlockCipher> BlockCipher::create(Cipher_Algo alg) {

        switch (alg.a)
        {
#if defined(BOTAN_HAS_AES)
        case ALG::AES_128_CBC:
        //case ALG::AES_128_CBC_HMAC_SHA1:
        case ALG::AES_128_CCM:
        case ALG::AES_128_CCM_8:
                return std::make_unique<AES_128>();

            //if (algo == "AES-192") {
            //    return std::make_unique<AES_192>();
            //}

        case ALG::AES_256_CBC:
        //case ALG::AES_256_CBC_HMAC_SHA1:
        //case ALG::AES_256_CBC_HMAC_SHA256:
        //case ALG::AES_256_CBC_HMAC_SHA384:
        case ALG::AES_256_CCM:
        case ALG::AES_256_CCM_8:
            return std::make_unique<AES_256>();
#endif
        default:
            break;
        }


#if defined(BOTAN_HAS_ARIA)
        if (algo == "ARIA-128") {
            return std::make_unique<ARIA_128>();
        }

        if (algo == "ARIA-192") {
            return std::make_unique<ARIA_192>();
        }

        if (algo == "ARIA-256") {
            return std::make_unique<ARIA_256>();
        }
#endif

#if defined(BOTAN_HAS_SERPENT)
        if (algo == "Serpent") {
            return std::make_unique<Serpent>();
        }
#endif

#if defined(BOTAN_HAS_SHACAL2)
        if (algo == "SHACAL2") {
            return std::make_unique<SHACAL2>();
        }
#endif

#if defined(BOTAN_HAS_TWOFISH)
        if (algo == "Twofish") {
            return std::make_unique<Twofish>();
        }
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
        if (algo == "Threefish-512") {
            return std::make_unique<Threefish_512>();
        }
#endif

#if defined(BOTAN_HAS_BLOWFISH)
        if (algo == "Blowfish") {
            return std::make_unique<Blowfish>();
        }
#endif

#if defined(BOTAN_HAS_CAMELLIA)
        if (algo == "Camellia-128") {
            return std::make_unique<Camellia_128>();
        }

        if (algo == "Camellia-192") {
            return std::make_unique<Camellia_192>();
        }

        if (algo == "Camellia-256") {
            return std::make_unique<Camellia_256>();
        }
#endif

#if defined(BOTAN_HAS_DES)
        if (algo == "DES") {
            return std::make_unique<DES>();
        }

        if (algo == "TripleDES" || algo == "3DES" || algo == "DES-EDE") {
            return std::make_unique<TripleDES>();
        }
#endif

#if defined(BOTAN_HAS_NOEKEON)
        if (algo == "Noekeon") {
            return std::make_unique<Noekeon>();
        }
#endif

#if defined(BOTAN_HAS_CAST_128)
        if (algo == "CAST-128" || algo == "CAST5") {
            return std::make_unique<CAST_128>();
        }
#endif

#if defined(BOTAN_HAS_IDEA)
        if (algo == "IDEA") {
            return std::make_unique<IDEA>();
        }
#endif

#if defined(BOTAN_HAS_KUZNYECHIK)
        if (algo == "Kuznyechik") {
            return std::make_unique<Kuznyechik>();
        }
#endif

#if defined(BOTAN_HAS_SEED)
        if (algo == "SEED") {
            return std::make_unique<SEED>();
        }
#endif

#if defined(BOTAN_HAS_SM4)
        if (algo == "SM4") {
            return std::make_unique<SM4>();
        }
#endif

        //const SCAN_Name req(algo);

#if defined(BOTAN_HAS_GOST_28147_89)
        if (req.algo_name() == "GOST-28147-89") {
            return std::make_unique<GOST_28147_89>(req.arg(0, "R3411_94_TestParam"));
        }
#endif

#if defined(BOTAN_HAS_CASCADE)
        if (req.algo_name() == "Cascade" && req.arg_count() == 2) {
            auto c1 = BlockCipher::create(req.arg(0));
            auto c2 = BlockCipher::create(req.arg(1));

            if (c1 && c2) {
                return std::make_unique<Cascade_Cipher>(std::move(c1), std::move(c2));
            }
        }
#endif

#if defined(BOTAN_HAS_LION)
        if (req.algo_name() == "Lion" && req.arg_count_between(2, 3)) {
            auto hash = HashFunction::create(req.arg(0));
            auto stream = StreamCipher::create(req.arg(1));

            if (hash && stream) {
                const size_t block_size = req.arg_as_integer(2, 1024);
                return std::make_unique<Lion>(std::move(hash), std::move(stream), block_size);
            }
        }
#endif

        return nullptr;
    }

    //static
    std::unique_ptr<BlockCipher> BlockCipher::create_or_throw(Cipher_Algo alg) {
        if (auto bc = BlockCipher::create(alg)) {
            return bc;
        }
        throw Lookup_Error("Block cipher");
    }




	OctetString::OctetString(RandomNumberGenerator& rng, size_t len)
    {
		resize(len);
        rng.random_vec(std::span(data(), size()));
    }


	size_t StreamCipher::default_iv_length() const {
		return 0;
	}

	void StreamCipher::generate_keystream(uint8_t out[], size_t len) {
		clear_mem(out, len);
		cipher1(out, len);
	}

	void MessageAuthenticationCode::start_msg(std::span<const uint8_t> nonce) {
		BOTAN_UNUSED(nonce);
		if (!nonce.empty()) {
			throw Invalid_IV_Length("", nonce.size());
		}
	}

	bool MessageAuthenticationCode::verify_mac_result(std::span<const uint8_t> mac) {
		secure_vector<uint8_t> our_mac = final();

		if (our_mac.size() != mac.size()) {
			return false;
		}

		return Botan::CT::is_equal(our_mac.data(), mac.data(), mac.size()).as_bool();
	}

    void assert_unreachable(const char* file, int line) {

        debug_print("$($): $\n", filename(file, strlen(file)), line, "Codepath that was marked unreachable was reached");
        for (;;) spinlock::sleep(10000);
    }


    void assertion_failure(const char* expr_str,
		const char* assertion_made,
		const char* func,
		const char* file,
		int line)
	{
        debug_print("$($): assertion ($) ($) ($)\n", filename(file, strlen(file)), line, assertion_made, func, expr_str);
		for (;;) spinlock::sleep(10000);
	}

	void throw_invalid_argument(const char* /*message*/,
		const char* /*func*/,
		const char* /*file*/)
	{
		SMART_DEBUG_BREAK;
		for (;;) spinlock::sleep(10000);
	}

	void throw_invalid_state(const char* /*expr*/,
		const char* /*func*/,
		const char* /*file*/)
	{
		SMART_DEBUG_BREAK;
		for (;;) spinlock::sleep(10000);
	}

    void SymmetricAlgorithm::throw_key_not_set_error() const {
        throw Key_Not_Set(ASTR(""));
    }

	std::string ALG::to_string() const
	{
        switch (a)
        {
        case Botan::ALG::Undefined:
            break;
        case Botan::ALG::_Unknown:
            break;
        case Botan::ALG::_Pure:
            break;
        case Botan::ALG::_Raw:
            break;
        case Botan::ALG::_Randomized:
            break;
        case Botan::ALG::_Ed25519ph:
            break;
        case Botan::ALG::_mac_start:
            break;
        case Botan::ALG::AEAD:
            break;
        case Botan::ALG::hash_start:
            break;
        case Botan::ALG::SHA_1:
            break;
        case Botan::ALG::SHA_256:
            break;
        case Botan::ALG::SHA_384:
            break;
        case Botan::ALG::_mac_end:
            break;
        case Botan::ALG::BLAKE2B:
            break;
        case Botan::ALG::SHA_224:
            break;
        case Botan::ALG::SHA_512:
            break;
        case Botan::ALG::SHA_512_256:
            break;
        case Botan::ALG::SHA_3_224:
            break;
        case Botan::ALG::SHA_3_256:
            break;
        case Botan::ALG::SHA_3_384:
            break;
        case Botan::ALG::SHA_3_512:
            break;
        case Botan::ALG::MD5:
            break;
        case Botan::ALG::RIPEMD_160:
            break;
        case Botan::ALG::SM3:
            break;
        case Botan::ALG::hash_end:
            break;
#if FEATURE_TLS
        case Botan::ALG::kex_start:
            break;
        case Botan::ALG::STATIC_RSA:
            break;
        case Botan::ALG::DH:
            break;
        case Botan::ALG::ECDH:
            break;
        case Botan::ALG::PSK:
            break;
        case Botan::ALG::ECDHE_PSK:
            break;
        case Botan::ALG::DHE_PSK:
            break;
        case Botan::ALG::KEM:
            break;
        case Botan::ALG::KEM_PSK:
            break;
        case Botan::ALG::HYBRID:
            break;
        case Botan::ALG::HYBRID_PSK:
            break;
        case Botan::ALG::X25519:
            break;
        case Botan::ALG::X448:
            break;
        case Botan::ALG::ffdhe_ietf_2048:
            break;
        case Botan::ALG::ffdhe_ietf_3072:
            break;
        case Botan::ALG::ffdhe_ietf_4096:
            break;
        case Botan::ALG::ffdhe_ietf_6144:
            break;
        case Botan::ALG::ffdhe_ietf_8192:
            break;
        case Botan::ALG::modp_ietf_1024:
            break;
        case Botan::ALG::modp_ietf_1536:
            break;
        case Botan::ALG::modp_ietf_2048:
            break;
        case Botan::ALG::modp_ietf_3072:
            break;
        case Botan::ALG::modp_ietf_4096:
            break;
        case Botan::ALG::modp_ietf_6144:
            break;
        case Botan::ALG::modp_ietf_8192:
            break;
        case Botan::ALG::modp_srp_1024:
            break;
        case Botan::ALG::modp_srp_1536:
            break;
        case Botan::ALG::modp_srp_2048:
            break;
        case Botan::ALG::modp_srp_3072:
            break;
        case Botan::ALG::modp_srp_4096:
            break;
        case Botan::ALG::modp_srp_6144:
            break;
        case Botan::ALG::modp_srp_8192:
            break;
        case Botan::ALG::KEX_UNDEFINED:
            break;
        case Botan::ALG::kex_end:
            break;
        case Botan::ALG::auth_start:
            break;
        case Botan::ALG::DSA:
            break;
        case Botan::ALG::RSA:
            return str::astr(ASTR("RSA"));
        case Botan::ALG::ECDSA:
            break;
        case Botan::ALG::ECGDSA:
            break;
        case Botan::ALG::ECKCDSA:
            break;
        case Botan::ALG::AUTH_UNDEFINED:
            break;
        case Botan::ALG::IMPLICIT:
            break;
        case Botan::ALG::ML_DSA:
            break;
        case Botan::ALG::SLH_DSA:
            break;
        case Botan::ALG::auth_end:
            break;
        case Botan::ALG::dilithium_start:
            break;
        case Botan::ALG::DILITHIUM_4X4_AES_R3:
            break;
        case Botan::ALG::DILITHIUM_6X5_AES_R3:
            break;
        case Botan::ALG::DILITHIUM_8X7_AES_R3:
            break;
        case Botan::ALG::DILITHIUM_4X4_R3:
            break;
        case Botan::ALG::DILITHIUM_6X5_R3:
            break;
        case Botan::ALG::DILITHIUM_8X7_R3:
            break;
        case Botan::ALG::dilithium_end:
            break;
        case Botan::ALG::HSS_LMS:
            break;
        case Botan::ALG::XMSS:
            break;
        case Botan::ALG::GOST_3410:
            break;
        case Botan::ALG::GOST_3410_2012_256:
            break;
        case Botan::ALG::GOST_3410_2012_512:
            break;
        case Botan::ALG::EMSA1:
            break;
        case Botan::ALG::EMSA3:
            break;
        case Botan::ALG::EMSA4:
            break;
        case Botan::ALG::EMSA_PKCS1:
            break;
        case Botan::ALG::TLS_12_PRF:
            break;
        case Botan::ALG::sign_start:
            break;
        case Botan::ALG::Ed25519:
            break;
        case Botan::ALG::sign_end:
            break;
#endif
        case Botan::ALG::cipher_start:
            break;
        case Botan::ALG::CHACHA20_POLY1305:
            break;
        case Botan::ALG::AES_128_GCM:
            break;
        case Botan::ALG::AES_256_GCM:
            break;
        case Botan::ALG::AES_256_OCB:
            break;
        case Botan::ALG::CAMELLIA_128_GCM:
            break;
        case Botan::ALG::CAMELLIA_256_GCM:
            break;
        case Botan::ALG::ARIA_128_GCM:
            break;
        case Botan::ALG::ARIA_256_GCM:
            break;
        case Botan::ALG::AES_128_CCM:
            break;
        case Botan::ALG::AES_256_CCM:
            break;
        case Botan::ALG::AES_128_CCM_8:
            break;
        case Botan::ALG::AES_256_CCM_8:
            break;
        case Botan::ALG::AES_128_CBC:
            break;
        case Botan::ALG::AES_256_CBC:
            break;
        case Botan::ALG::DES_DES_DES:
            break;
        case Botan::ALG::cipher_end:
            break;
#if FEATURE_TLS
        case Botan::ALG::curv_start:
            break;
        case Botan::ALG::secp256r1:
            break;
        case Botan::ALG::secp224r1:
            break;
        case Botan::ALG::secp384r1:
            break;
        case Botan::ALG::secp521r1:
            break;
        case Botan::ALG::curv_end:
            break;
        case Botan::ALG::PSSR:
            break;
        case Botan::ALG::MGF1:
            break;
        case Botan::ALG::PKCS1v15:
            break;
        case Botan::ALG::HMAC:
            break;
        case Botan::ALG::na_start:
            break;
        case Botan::ALG::id_prime_Field:
            break;
        case Botan::ALG::X509v3_BasicConstraints:
            break;
        case Botan::ALG::X509v3_KeyUsage:
            break;
        case Botan::ALG::X509v3_SubjectKeyIdentifier:
            break;
        case Botan::ALG::X509v3_AuthorityKeyIdentifier:
            break;
        case Botan::ALG::X509v3_SubjectAlternativeName:
            break;
        case Botan::ALG::X509v3_IssuerAlternativeName:
            break;
        case Botan::ALG::X509v3_ExtendedKeyUsage:
            break;
        case Botan::ALG::X509v3_NameConstraints:
            break;
        case Botan::ALG::X509v3_CertificatePolicies:
            break;
        case Botan::ALG::X509v3_CRLNumber:
            break;
        case Botan::ALG::X509v3_ReasonCode:
            break;
        case Botan::ALG::X509v3_CRLDistributionPoints:
            break;
        case Botan::ALG::X509v3_CRLIssuingDistributionPoint:
            break;
        case Botan::ALG::PKIX_AuthorityInformationAccess:
            break;
        case Botan::ALG::PKIX_OCSP_NoCheck:
            break;
        case Botan::ALG::PKIX_TNAuthList:
            break;
        case Botan::ALG::PKIX_ServerAuth:
            break;
        case Botan::ALG::PKIX_ClientAuth:
            break;
        case Botan::ALG::PKIX_OCSPSigning:
            break;
        case Botan::ALG::PKIX_OCSP:
            break;
        case Botan::ALG::PKIX_OCSP_BasicResponse:
            break;
        case Botan::ALG::PKIX_CertificateAuthorityIssuers:
            break;
        case Botan::ALG::PKCS9_EmailAddress:
            break;
        case Botan::ALG::X520_CommonName:
            break;
        case Botan::ALG::X520_SerialNumber:
            break;
        case Botan::ALG::X520_Country:
            break;
        case Botan::ALG::X520_Organization:
            break;
        case Botan::ALG::X520_OrganizationalUnit:
            break;
        case Botan::ALG::X520_Locality:
            break;
        case Botan::ALG::X520_State:
            break;
        case Botan::ALG::na_end:
            break;
#endif
        default:
            break;
        }
        DEBUGBREAK();
		return glb.emptys;
	}

#if FEATURE_TLS
    std::string Algo_Group::to_string() const
    {
        if (a[1].a == ALG::Undefined)
        {
            return a[0].to_string();
        }

        DEBUGBREAK();
        return glb.emptys;
	}
#endif

    std::optional<uint32_t> string_to_ipv4(std::string_view s)
    {
        if (s.empty())
            return {};

        u32 ipv4 = 0;
        uints::from_low_to_high<u32, Endian::big> dst(ipv4);

        signed_t index = 0;
        for (str::token<char, str::sep_onechar<char, '.'>> tkn(s); tkn; tkn(), ++index, ++dst)
        {
            if (index >= 4)
            {
                return {};
            }

            signed_t oktet = str::parse_int(*tkn, 255, 256);
            if (oktet > 255)
            {
                return {};
            }
            *dst = tools::as_byte(oktet);

        }
        if (index == 4)
            return ipv4;

        return {};

    }

    std::string ipv4_to_string(uint32_t ip)
    {
        uints::from_low_to_high<u32, Endian::big> octs(ip);

        str::astr s;
        str::append_num(s, octs[0], 0);
        s.push_back('.'); str::append_num(s, octs[1], 0);
        s.push_back('.'); str::append_num(s, octs[2], 0);
        s.push_back('.'); str::append_num(s, octs[3], 0);
        return s;

    }

    std::string check_and_canonicalize_dns_name(std::string_view name) {

        std::string canon(name);
        if (!dns_resolver::check_and_canonicalize(canon))
        {
            throw Decoding_Error("bad DNS name");
        }
        return canon;
    }

    bool host_wildcard_match(std::string_view issued_, std::string_view host_)
    {
        if (issued_.find(char(0)) != issued_.npos)
            return false;
        if (host_.find('*') != host_.npos)
            return false;
        // Similarly a DNS name can't end in .
        if (host_[host_.size() - 1] == '.') {
            return false;
        }
        if (host_.find(ASTR("..")) != std::string::npos) {
            return false;
        }
        if (issued_ == host_) {
            return true;
        }

        return str::mask_match(host_, issued_);
    }


    void DER_encode(secure_vector<uint8_t>& outb, const uint32_t* data, size_t size) {

        auto append = [&](uint32_t z) {
            if (z <= 0x7F) {
                outb.push_back(static_cast<uint8_t>(z));
            }
            else {
                size_t z7 = (high_bit(z) + 7 - 1) / 7;

                for (size_t j = 0; j != z7; ++j) {
                    uint8_t zp = static_cast<uint8_t>(z >> (7 * (z7 - j - 1)) & 0x7F);

                    if (j != z7 - 1) {
                        zp |= 0x80;
                    }

                    outb.push_back(zp);
                }
            }
        };

        for (size_t i = 0; i < size; ++i)
            append(data[i]);
    }

    inline size_t decode_max_output(size_t input_length) {

        return (Botan::round_up(input_length, 4) * 3) / 4;
    }


    secure_vector<uint8_t> base64_decode(const char* s, size_t sl)
    {
        secure_vector<uint8_t> v(decode_max_output(sl));
        size_t decoded = str::decode_base64(str::astr_view(s,sl), v.data(), v.size());
        v.resize(decoded);
        return v;

    }

#if FEATURE_TLS
    size_t X509_DN::lookup_ub(const OID& oid) {

        switch (oid.index())
        {
        case oid_index::_2_5_4_10: return 64;     // X520.Organization
        case oid_index::_2_5_4_11: return 64;     // X520.OrganizationalUnit
        //case oid_index::_2_5_4_12: return 64;     // X520.Title
        case oid_index::_2_5_4_3: return 64;      // X520.CommonName
        //case oid_index::_2_5_4_4: return 40;      // X520.Surname
        //case oid_index::_2_5_4_42: return 32768;  // X520.GivenName
        //case oid_index::_2_5_4_43: return 32768;  // X520.Initials
        //case oid_index::_2_5_4_44: return 32768;  // X520.GenerationalQualifier
        //case oid_index::_2_5_4_46: return 64;     // X520.DNQualifier
        case oid_index::_2_5_4_5: return 64;      // X520.SerialNumber
        case oid_index::_2_5_4_6: return 3;       // X520.Country
        //case oid_index::_2_5_4_65: return 128;    // X520.Pseudonym
        case oid_index::_2_5_4_7: return 128;     // X520.Locality
        case oid_index::_2_5_4_8: return 128;     // X520.State
        //case oid_index::_2_5_4_9: return 128;      // X520.StreetAddress

        default:
            break;
        }

        return 0;

    }

    const char* to_string(Certificate_Status_Code /*code*/) {
        return "fail";
    }
#endif

}



