/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../proxtopus/pch.h"

#if FEATURE_TLS
#include <botan/pk_keys.h>

#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pk_ops.h>

namespace Botan {

const BigInt& Asymmetric_Key::get_int_field(std::string_view field) const {
   throw Unknown_PK_Field_Name(algo_name(), field);
}

OID Asymmetric_Key::object_identifier() const {
   try {
      return OID::from_ag(Algo_Group(algo_name()));
   } catch(Lookup_Error&) {
      throw Lookup_Error(str::build_string("Public key algorithm {} has no defined OIDs", algo_name()));
   }
}

Signature_Format Asymmetric_Key::_default_x509_signature_format() const {
   if(_signature_element_size_for_DER_encoding()) {
      return Signature_Format::DerSequence;
   } else {
      return Signature_Format::Standard;
   }
}

std::string create_hex_fingerprint(const uint8_t bits[], size_t bits_len, HashFunction *hash_fn) {
   //auto hash_fn = HashFunction::create_or_throw(hash_name);
   const std::string hex_hash = hex_encode(hash_fn->process(bits, bits_len));

   std::string fprint;

   for(size_t i = 0; i != hex_hash.size(); i += 2) {
      if(i != 0) {
         fprint.push_back(':');
      }

      fprint.push_back(hex_hash[i]);
      fprint.push_back(hex_hash[i + 1]);
   }

   return fprint;
}

std::vector<uint8_t> Public_Key::subject_public_key() const {
   std::vector<uint8_t> output;

   DER_Encoder(output)
      .start_sequence()
      .encode(algorithm_identifier())
      .encode(public_key_bits(), ASN1_Type::BitString)
      .end_cons();

   return output;
}

secure_vector<uint8_t> Private_Key::private_key_info() const {
   const size_t PKCS8_VERSION = 0;

   return DER_Encoder()
      .start_sequence()
      .encode(PKCS8_VERSION)
      .encode(pkcs8_algorithm_identifier())
      .encode(private_key_bits(), ASN1_Type::OctetString)
      .end_cons()
      .get_contents();
}

secure_vector<uint8_t> Private_Key::raw_private_key_bits() const {
   throw Not_Implemented(algo_name() + " does not implement raw_private_key_bits");
}

/*
* Hash of the X.509 subjectPublicKey encoding
*/
std::string Public_Key::fingerprint_public(HashFunction* hash) const {
   return create_hex_fingerprint(subject_public_key(), hash);
}

/*
* Hash of the PKCS #8 encoding for this key object
*/
std::string Private_Key::fingerprint_private(HashFunction* hash) const {
   return create_hex_fingerprint(private_key_bits(), hash);
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::Encryption> Public_Key::create_encryption_op(RandomNumberGenerator& /*rng*/,
    Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support encryption", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::KEM_Encryption> Public_Key::create_kem_encryption_op(Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support KEM encryption", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::Verification> Public_Key::create_verification_op(Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support verification", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::Verification> Public_Key::create_x509_verification_op(const AlgorithmIdentifier& /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support X.509 verification", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::Decryption> Private_Key::create_decryption_op(RandomNumberGenerator& /*rng*/,
    Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support decryption", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::KEM_Decryption> Private_Key::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
    Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support KEM decryption", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::Signature> Private_Key::create_signature_op(RandomNumberGenerator& /*rng*/,
    Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support signatures", algo_name()));
}

/// PROXTOPUS : provider removed
std::unique_ptr<PK_Ops::Key_Agreement> Private_Key::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
    Algo_Group /*params*/) const {
   throw Lookup_Error(str::build_string("$ does not support key agreement", algo_name()));
}

}  // namespace Botan
#endif