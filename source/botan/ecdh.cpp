/*
* ECDH implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecdh.h>

#include <botan/bigint.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

std::unique_ptr<Public_Key> ECDH_PrivateKey::public_key() const {
   return std::make_unique<ECDH_PublicKey>(domain(), _public_ec_point());
}

namespace {

/**
* ECDH operation
*/
class ECDH_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      ECDH_KA_Operation(const ECDH_PrivateKey& key, Algo_Group kdf, RandomNumberGenerator& rng) :
            PK_Ops::Key_Agreement_with_KDF(kdf),
            m_group(key.domain()),
            m_l_times_priv(mul_cofactor_inv(m_group, key._private_key())),
            m_rng(rng) {}

      size_t agreed_value_size() const override { return m_group.get_p_bytes(); }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
         const auto input_point = [&] {
            if(m_group.has_cofactor()) {
#if defined(BOTAN_HAS_LEGACY_EC_POINT)
               return EC_AffinePoint(m_group, m_group.get_cofactor() * m_group.OS2ECP(w, w_len));
#else
               throw Not_Implemented(
                  "Support for DH with cofactor adjustment not available in this build configuration");
#endif
            } else {
               if(auto point = EC_AffinePoint::deserialize(m_group, {w, w_len})) {
                  return *point;
               } else {
                  throw Decoding_Error("ECDH - Invalid elliptic curve point: not on curve");
               }
            }
         }();

         // Typical specs (such as BSI's TR-03111 Section 4.3.1) require that
         // we check the resulting point of the multiplication to not be the
         // point at infinity. However, since we ensure that our ECC private
         // scalar can never be zero, checking the peer's input point is
         // equivalent.
         if(input_point.is_identity()) {
            throw Decoding_Error("ECDH - Invalid elliptic curve point: identity");
         }

         return input_point.mul_x_only(m_l_times_priv, m_rng);
      }

   private:
      static EC_Scalar mul_cofactor_inv(const EC_Group& group, const EC_Scalar& x) {
         // We implement BSI TR-03111 ECKAEG which only matters in the (rare/deprecated)
         // case of a curve with cofactor.

         if(group.has_cofactor()) {
            // We could precompute this but cofactors are rare
            return x * EC_Scalar::from_bigint(group, group.get_cofactor()).invert_vartime();
         } else {
            return x;
         }
      }

      const EC_Group m_group;
      const EC_Scalar m_l_times_priv;
      RandomNumberGenerator& m_rng;
};

}  // namespace

std::unique_ptr<Private_Key> ECDH_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ECDH_PrivateKey>(rng, domain());
}

std::vector<uint8_t> ECDH_PublicKey::public_value(EC_Point_Format format) const {
   return _public_ec_point().serialize(format);
}

std::unique_ptr<PK_Ops::Key_Agreement> ECDH_PrivateKey::create_key_agreement_op(RandomNumberGenerator& rng,
    Algo_Group params) const {
      return std::make_unique<ECDH_KA_Operation>(*this, params, rng);
}

}  // namespace Botan
