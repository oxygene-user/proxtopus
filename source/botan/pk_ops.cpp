/*
* PK Operation Types
* (C) 2010,2015,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../proxtopus/pch.h"

#include <botan/internal/pk_ops_impl.h>

#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/eme.h>

#if defined(BOTAN_HAS_RAW_HASH_FN)
   #include <botan/internal/raw_hash.h>
#endif

namespace Botan {

AlgorithmIdentifier PK_Ops::Signature::algorithm_identifier() const {
   throw Not_Implemented("This signature scheme does not have an algorithm identifier available");
}

PK_Ops::Encryption_with_EME::Encryption_with_EME(Algo_Group eme) : m_eme(EME::create(eme)) {}

PK_Ops::Encryption_with_EME::~Encryption_with_EME() = default;

size_t PK_Ops::Encryption_with_EME::max_input_bits() const {
   return 8 * m_eme->maximum_input_size(max_ptext_input_bits());
}

std::vector<uint8_t> PK_Ops::Encryption_with_EME::encrypt(std::span<const uint8_t> msg, RandomNumberGenerator& rng) {
   const size_t max_input_bits = max_ptext_input_bits();
   const size_t max_input_bytes = (max_input_bits + 7) / 8;
   BOTAN_ARG_CHECK(msg.size() <= max_input_bytes, "Plaintext too large");

   secure_vector<uint8_t> eme_output(max_input_bits);
   const size_t written = m_eme->pad(eme_output, msg, max_input_bits, rng);
   return raw_encrypt(std::span{eme_output}.first(written), rng);
}

PK_Ops::Decryption_with_EME::Decryption_with_EME(Algo_Group eme) : m_eme(EME::create(eme)) {}

PK_Ops::Decryption_with_EME::~Decryption_with_EME() = default;

secure_vector<uint8_t> PK_Ops::Decryption_with_EME::decrypt(uint8_t& valid_mask, std::span<const uint8_t> ctext) {
   const secure_vector<uint8_t> raw = raw_decrypt(ctext);

   secure_vector<uint8_t> ptext(raw.size());
   auto len = m_eme->unpad(ptext, raw);

   valid_mask = CT::Mask<uint8_t>::from_choice(len.has_value()).if_set_return(0xFF);

   /*
   This is potentially not const time, depending on how std::vector is
   implemented. But since we are always reducing length, it should
   just amount to setting the member var holding the length. Resizing
   downwards is guaranteed to not change the capacity, and since we
   set ctext to the maximum possible size (equal to the raw input) we
   know that this is always, if anything, resizing smaller than the
   capacity, so no reallocation occurs.
   */

   ptext.resize(len.value_or(0));
   return ptext;
}

PK_Ops::Key_Agreement_with_KDF::Key_Agreement_with_KDF(Algo_Group kdf) {
    m_kdf = KDF::create_or_throw(kdf);
}

PK_Ops::Key_Agreement_with_KDF::~Key_Agreement_with_KDF() = default;

secure_vector<uint8_t> PK_Ops::Key_Agreement_with_KDF::agree(size_t key_len,
                                                             std::span<const uint8_t> other_key,
                                                             std::span<const uint8_t> salt) {
   if(!salt.empty() && m_kdf == nullptr) {
      throw Invalid_Argument("PK_Key_Agreement::derive_key requires a KDF to use a salt");
   }

   secure_vector<uint8_t> z = raw_agree(other_key.data(), other_key.size());
   if(m_kdf) {
      return m_kdf->derive_key(key_len, z, salt.data(), salt.size());
   }
   return z;
}

namespace {

std::unique_ptr<HashFunction> create_signature_hash(Algo_Group padding) {
   if(auto hash = HashFunction::create(padding.hash())) {
      return hash;
   }
   if (auto hash = HashFunction::create(padding.hashif(ALG::EMSA1))) {
       return hash;
   }

#if defined(BOTAN_HAS_RAW_HASH_FN)
   if(req.algo_name() == "Raw") {
      if(req.arg_count() == 0) {
         return std::make_unique<RawHashFunction>("Raw", 0);
      }

      if(req.arg_count() == 1) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<RawHashFunction>(std::move(hash));
         }
      }
   }
#endif

   throw Algorithm_Not_Found(padding.to_string());
}

}  // namespace

PK_Ops::Signature_with_Hash::Signature_with_Hash(Algo_Group hash) :
      Signature(), m_hash(create_signature_hash(hash)) {}

PK_Ops::Signature_with_Hash::~Signature_with_Hash() = default;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
std::string PK_Ops::Signature_with_Hash::rfc6979_hash_function() const {
   std::string hash = m_hash->name();
   if(hash != "Raw") {
      return hash;
   }
   return "SHA-512";
}
#endif

void PK_Ops::Signature_with_Hash::update(std::span<const uint8_t> msg) {
   m_hash->update(msg);
}

std::vector<uint8_t> PK_Ops::Signature_with_Hash::sign(RandomNumberGenerator& rng) {
   const std::vector<uint8_t> msg = m_hash->final_stdvec();
   return raw_sign(msg, rng);
}

PK_Ops::Verification_with_Hash::Verification_with_Hash(Algo_Group padding) :
      Verification(), m_hash(create_signature_hash(padding)) {}

PK_Ops::Verification_with_Hash::~Verification_with_Hash() = default;

PK_Ops::Verification_with_Hash::Verification_with_Hash(const AlgorithmIdentifier& alg_id,
    Auth_Method pk_algo,
                                                       bool allow_null_parameters) {
   //const auto oid_info = split_on(alg_id.oid().to_formatted_string(), '/');
    auto oid_info = (Algo_Group)alg_id.oid();

   if(oid_info.size() != 2 || oid_info.first() != pk_algo) {
      throw Decoding_Error(
         str::build_string("Unexpected AlgorithmIdentifier OID $ in association with $ key", alg_id.oid(), pk_algo));
   }

   if(!alg_id.parameters_are_empty()) {
      if(alg_id.parameters_are_null()) {
         if(!allow_null_parameters) {
            throw Decoding_Error(str::build_string("Unexpected NULL AlgorithmIdentifier parameters for $", pk_algo));
         }
      } else {
         throw Decoding_Error(str::build_string("Unexpected AlgorithmIdentifier parameters for $", pk_algo));
      }
   }

   //m_hash = HashFunction::create_or_throw(oid_info[1]);
   m_hash = HashFunction::create_or_throw(Hash_Algo::SHA_256);
   #ifdef _WIN32
   __debugbreak(); // oid_info[1] ?
   #endif
}

void PK_Ops::Verification_with_Hash::update(std::span<const uint8_t> msg) {
   m_hash->update(msg);
}

bool PK_Ops::Verification_with_Hash::is_valid_signature(std::span<const uint8_t> sig) {
   const std::vector<uint8_t> msg = m_hash->final_stdvec();
   return verify(msg, sig);
}

size_t PK_Ops::KEM_Encryption_with_KDF::shared_key_length(size_t desired_shared_key_len) const {
   if(m_kdf) {
      return desired_shared_key_len;
   } else {
      return this->raw_kem_shared_key_length();
   }
}

void PK_Ops::KEM_Encryption_with_KDF::kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                                                  std::span<uint8_t> out_shared_key,
                                                  RandomNumberGenerator& rng,
                                                  size_t desired_shared_key_len,
                                                  std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(salt.empty() || m_kdf, "PK_KEM_Encryptor::encrypt requires a KDF to use a salt");
   BOTAN_ASSERT_NOMSG(out_encapsulated_key.size() == encapsulated_key_length());

   if(m_kdf) {
      BOTAN_ASSERT_EQUAL(
         out_shared_key.size(), desired_shared_key_len, "KDF output length and shared key length match");

      secure_vector<uint8_t> raw_shared(raw_kem_shared_key_length());
      this->raw_kem_encrypt(out_encapsulated_key, raw_shared, rng);
      m_kdf->derive_key(out_shared_key, raw_shared, salt, {});
   } else {
      BOTAN_ASSERT_EQUAL(out_shared_key.size(), raw_kem_shared_key_length(), "Shared key has raw KEM output length");
      this->raw_kem_encrypt(out_encapsulated_key, out_shared_key, rng);
   }
}

PK_Ops::KEM_Encryption_with_KDF::KEM_Encryption_with_KDF(Algo_Group kdf) {
    m_kdf = KDF::create_or_throw(kdf);
}

PK_Ops::KEM_Encryption_with_KDF::~KEM_Encryption_with_KDF() = default;

size_t PK_Ops::KEM_Decryption_with_KDF::shared_key_length(size_t desired_shared_key_len) const {
   if(m_kdf) {
      return desired_shared_key_len;
   } else {
      return this->raw_kem_shared_key_length();
   }
}

void PK_Ops::KEM_Decryption_with_KDF::kem_decrypt(std::span<uint8_t> out_shared_key,
                                                  std::span<const uint8_t> encapsulated_key,
                                                  size_t desired_shared_key_len,
                                                  std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(salt.empty() || m_kdf, "PK_KEM_Decryptor::decrypt requires a KDF to use a salt");

   if(m_kdf) {
      BOTAN_ASSERT_EQUAL(
         out_shared_key.size(), desired_shared_key_len, "KDF output length and shared key length match");

      secure_vector<uint8_t> raw_shared(raw_kem_shared_key_length());
      this->raw_kem_decrypt(raw_shared, encapsulated_key);
      m_kdf->derive_key(out_shared_key, raw_shared, salt, {});
   } else {
      BOTAN_ASSERT_EQUAL(out_shared_key.size(), raw_kem_shared_key_length(), "Shared key has raw KEM output length");
      this->raw_kem_decrypt(out_shared_key, encapsulated_key);
   }
}

PK_Ops::KEM_Decryption_with_KDF::KEM_Decryption_with_KDF(Algo_Group kdf) {
if (!kdf.is_raw())
    m_kdf = KDF::create_or_throw(kdf);
}

PK_Ops::KEM_Decryption_with_KDF::~KEM_Decryption_with_KDF() = default;

}  // namespace Botan
