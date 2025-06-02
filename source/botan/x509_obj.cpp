/*
* X.509 SIGNED Object
* (C) 1999-2007,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../proxtopus/pch.h"

#include <botan/x509_obj.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pem.h>
#include <botan/pubkey.h>
#include <algorithm>
#include <sstream>

namespace Botan {

/*
* Read a PEM or BER X.509 object
*/
void X509_Object::load_data(DataSource& in) {
   try {
      if(ASN1::maybe_BER(in) && !PEM_Code::matches(in)) {
         BER_Decoder dec(in);
         decode_from(dec);
      } else {
         std::string got_label;
         DataSource_Memory ber(PEM_Code::decode(in, got_label));

         if(got_label != PEM_label()) {
            bool is_alternate = false;
            for(std::string_view alt_label : alternate_PEM_labels()) {
               if(got_label == alt_label) {
                  is_alternate = true;
                  break;
               }
            }

            if(!is_alternate) {
               throw Decoding_Error("Unexpected PEM label for " + PEM_label() + " of " + got_label);
            }
         }

         BER_Decoder dec(ber);
         decode_from(dec);
      }
   } catch(Decoding_Error& e) {
      throw Decoding_Error(PEM_label() + " decoding", e);
   }
}

void X509_Object::encode_into(DER_Encoder& to) const {
   to.start_sequence()
      .start_sequence()
      .raw_bytes(signed_body())
      .end_cons()
      .encode(signature_algorithm())
      .encode(signature(), ASN1_Type::BitString)
      .end_cons();
}

/*
* Read a BER encoded X.509 object
*/
void X509_Object::decode_from(BER_Decoder& from) {
   from.start_sequence()
      .start_sequence()
      .raw_bytes(m_tbs_bits)
      .end_cons()
      .decode(m_sig_algo)
      .decode(m_sig, ASN1_Type::BitString)
      .end_cons();

   force_decode();
}

#if 0
/*
* Return a PEM encoded X.509 object
*/
std::string X509_Object::PEM_encode() const {
   return PEM_Code::encode(BER_encode(), PEM_label());
}
#endif

/*
* Return the TBS data
*/
std::vector<uint8_t> X509_Object::tbs_data() const {
   return ASN1::put_in_sequence(m_tbs_bits);
}

/*
* Check the signature on an object
*/
bool X509_Object::check_signature(const Public_Key& pub_key) const {
   const auto result = this->verify_signature(pub_key);
   return (result.first == Certificate_Status_Code::VERIFIED);
}

std::pair<Certificate_Status_Code, Hash_Algo> X509_Object::verify_signature(const Public_Key& pub_key) const {
   try {
      PK_Verifier verifier(pub_key, signature_algorithm());
      const bool valid = verifier.verify_message(tbs_data(), signature());

      if(valid) {
         return std::make_pair(Certificate_Status_Code::VERIFIED, verifier.hash_function());
      } else {
         return std::make_pair(Certificate_Status_Code::SIGNATURE_ERROR, Hash_Algo::Undefined);
      }
   } catch(Decoding_Error&) {
      return std::make_pair(Certificate_Status_Code::SIGNATURE_ALGO_BAD_PARAMS, Hash_Algo::Undefined);
   } catch(Algorithm_Not_Found&) {
      return std::make_pair(Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN, Hash_Algo::Undefined);
   } catch(...) {
      // This shouldn't happen, fallback to generic signature error
      return std::make_pair(Certificate_Status_Code::SIGNATURE_ERROR, Hash_Algo::Undefined);
   }
}

/*
* Apply the X.509 SIGNED macro
*/
std::vector<uint8_t> X509_Object::make_signed(PK_Signer& signer,
                                              RandomNumberGenerator& rng,
                                              const AlgorithmIdentifier& algo,
                                              const secure_vector<uint8_t>& tbs_bits) {
   const std::vector<uint8_t> signature = signer.sign_message(tbs_bits, rng);

   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .raw_bytes(tbs_bits)
      .encode(algo)
      .encode(signature, ASN1_Type::BitString)
      .end_cons();

   return output;
}

namespace {

    Algo_Group x509_signature_padding_for(Any_Algo algo_name, Hash_Algo hash_fn, Algo_Group user_specified_padding) {
   if(algo_name == ALG::DSA || algo_name == ALG::ECDSA || algo_name == ALG::ECGDSA || algo_name == ALG::ECKCDSA ||
      algo_name == ALG::GOST_3410 || algo_name == ALG::GOST_3410_2012_256 || algo_name == ALG::GOST_3410_2012_512) {
      BOTAN_ARG_CHECK(user_specified_padding.empty() || user_specified_padding == ALG::EMSA1,
                      "Invalid padding scheme for DSA-like scheme");

      return hash_fn.empty() ? Algo_Group(ALG::SHA_256) : Algo_Group(hash_fn);
   } else if(algo_name == ALG::RSA) {
      // set to PKCSv1.5 for compatibility reasons, originally it was the only option

      if(user_specified_padding.empty()) {
         if(hash_fn.empty()) {
            return Algo_Group(ALG::EMSA3, ALG::SHA_256);
         } else {
             return Algo_Group(ALG::EMSA3, hash_fn.a);
         }
      } else {
         if(hash_fn.empty()) {

             return user_specified_padding + ALG::SHA_256;
            //return fmt("{}(SHA-256)", user_specified_padding);
         } else {
             return user_specified_padding + hash_fn;
            //return fmt("{}({})", user_specified_padding, hash_fn);
         }
      }
   } else if(algo_name == ALG::Ed25519 /*|| algo_name == ALG::Ed448*/) {
      return user_specified_padding.empty() ? Algo_Group(ALG::_Pure) : user_specified_padding;
   } else if(algo_name.is_dilithium() || algo_name == ALG::ML_DSA) {
      return user_specified_padding.empty() ? Algo_Group(ALG::_Randomized) : user_specified_padding;
   } else if(algo_name == ALG::XMSS || algo_name == ALG::HSS_LMS || algo_name == ALG::SLH_DSA) {
      // These algorithms do not take any padding, but if the user insists, we pass it along
      return user_specified_padding;
   } else {
      throw Invalid_Argument("Unknown X.509 signing key type: " + algo_name.to_string());
   }
}

std::string format_padding_error_message(Any_Algo key_name,
    Hash_Algo signer_hash_fn, Hash_Algo user_hash_fn, Algo_Group chosen_padding, Algo_Group user_specified_padding) {
   
    str::astr oss;
    str::impl_build_string(oss, "Specified hash function $ is incompatible with $", user_hash_fn, key_name);

   if(!signer_hash_fn.empty()) {
       oss.append(ASTR(" chose hash function "));
       oss.append(signer_hash_fn.to_string());
   }

   if(!chosen_padding.empty()) {
       oss.append(ASTR(" chose padding "));
       oss.append(chosen_padding.to_string());
   }

   if(!user_specified_padding.empty()) {
       oss.append(ASTR(" with user specified padding "));
       oss.append(user_specified_padding.to_string());
   }

   return oss;
}

}  // namespace

/*
* Choose a signing format for the key
*/
std::unique_ptr<PK_Signer> X509_Object::choose_sig_format(const Private_Key& key, RandomNumberGenerator& rng, Hash_Algo hash_fn, Algo_Group user_specified_padding) {
   const Signature_Format format = key._default_x509_signature_format();

   if(!user_specified_padding.empty()) {
      try {
         auto pk_signer = std::make_unique<PK_Signer>(key, rng, user_specified_padding, format);
         if(!hash_fn.empty() && pk_signer->hash_function() != hash_fn) {
            throw Invalid_Argument(format_padding_error_message(
               key.algo_name(), pk_signer->hash_function(), hash_fn, Algo_Group(), user_specified_padding));
         }
         return pk_signer;
      } catch(Lookup_Error&) {}
   }

   Algo_Group padding = x509_signature_padding_for(key.algo_name(), hash_fn, user_specified_padding);

   try {
      auto pk_signer = std::make_unique<PK_Signer>(key, rng, padding, format);
      if(!hash_fn.empty() && pk_signer->hash_function() != hash_fn) {
         throw Invalid_Argument(format_padding_error_message(
            key.algo_name(), pk_signer->hash_function(), hash_fn, padding, user_specified_padding));
      }
      return pk_signer;
   } catch(Not_Implemented&) {
      throw Invalid_Argument("Signatures using " + key.algo_name() + "/" + padding + " are not supported");
   }
}

}  // namespace Botan
