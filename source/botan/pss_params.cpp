/*
* (C) 2017 Daniel Neus
*     2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../proxtopus/pch.h"

#include <botan/pss_params.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>

namespace Botan {

//static
PSS_Params PSS_Params::from_emsa_name(Algo_Group emsa_name)
{
    if ((emsa_name != ALG::EMSA4 && emsa_name != ALG::PSSR) || emsa_name.saltl == 0xff) {
        throw Invalid_Argument(str::build_string("PSS_Params::from_emsa_name unexpected param '$'", emsa_name));
    }

    Hash_Algo hash_fn = emsa_name.second();
    BOTAN_ASSERT_NOMSG(emsa_name.third() == ALG::MGF1);
    const size_t salt_len = emsa_name.saltl;
    return PSS_Params(hash_fn, salt_len);
}

PSS_Params::PSS_Params(Hash_Algo hash_fn, size_t salt_len) :
      m_hash(Algo_Group(hash_fn), AlgorithmIdentifier::USE_NULL_PARAM),
      m_mgf(Algo_Group(ALG::MGF1), m_hash.BER_encode()),
      m_mgf_hash(m_hash),
      m_salt_len(salt_len) {}

PSS_Params::PSS_Params(std::span<const uint8_t> der) {
   BER_Decoder decoder(der);
   this->decode_from(decoder);
}

std::vector<uint8_t> PSS_Params::serialize() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(*this);
   return output;
}

void PSS_Params::encode_into(DER_Encoder& to) const {
   to.start_sequence()
      .start_context_specific(0)
      .encode(m_hash)
      .end_cons()
      .start_context_specific(1)
      .encode(m_mgf)
      .end_cons()
      .start_context_specific(2)
      .encode(m_salt_len)
      .end_cons()
      .end_cons();
}

void PSS_Params::decode_from(BER_Decoder& from) {
   const AlgorithmIdentifier default_hash(Algo_Group(ALG::SHA_1), AlgorithmIdentifier::USE_NULL_PARAM);
   const AlgorithmIdentifier default_mgf(Algo_Group(ALG::MGF1), default_hash.BER_encode());
   const size_t default_salt_len = 20;
   const size_t default_trailer = 1;

   from.start_sequence()
      .decode_optional(m_hash, ASN1_Type(0), ASN1_Class::ExplicitContextSpecific, default_hash)
      .decode_optional(m_mgf, ASN1_Type(1), ASN1_Class::ExplicitContextSpecific, default_mgf)
      .decode_optional(m_salt_len, ASN1_Type(2), ASN1_Class::ExplicitContextSpecific, default_salt_len)
      .decode_optional(m_trailer_field, ASN1_Type(3), ASN1_Class::ExplicitContextSpecific, default_trailer)
      .end_cons();

   BER_Decoder(m_mgf.parameters()).decode(m_mgf_hash);
}

}  // namespace Botan
