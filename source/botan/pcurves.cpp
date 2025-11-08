/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves.h>
#if FEATURE_TLS

#include <botan/assert.h>
#include <botan/internal/pcurves_instance.h>

namespace Botan::PCurve {

//static
std::shared_ptr<const PrimeOrderCurve> PrimeOrderCurve::from_params(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) {
#if defined(BOTAN_HAS_PCURVES_GENERIC)
   return PCurveInstance::from_params(p, a, b, base_x, base_y, order);
#else
    BOTAN_UNUSED(p, a, b, base_x, base_y, order);
    return {};
#endif

}

//static
std::shared_ptr<const PrimeOrderCurve> PrimeOrderCurve::for_named_curve(ALG::alg alg) {

    switch (alg)
    {
#if defined(BOTAN_HAS_PCURVES_SECP224R1)
    case ALG::secp224r1:
        return PCurveInstance::secp224r1();
#endif
#if defined(BOTAN_HAS_PCURVES_SECP256R1)
    case ALG::secp256r1:
        return PCurveInstance::secp256r1();
#endif

#if defined(BOTAN_HAS_PCURVES_SECP384R1)
    case ALG::secp384r1:
        return PCurveInstance::secp384r1();
#endif
#if defined(BOTAN_HAS_PCURVES_SECP521R1)
    case ALG::secp521r1:
        return PCurveInstance::secp521r1();
#endif

    default:
        ;
    }


#if defined(BOTAN_HAS_PCURVES_SECP192R1)
   if(name == "secp192r1") {
      return PCurveInstance::secp192r1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_SECP256K1)
   if(name == "secp256k1") {
      return PCurveInstance::secp256k1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_BRAINPOOL256R1)
   if(name == "brainpool256r1") {
      return PCurveInstance::brainpool256r1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_BRAINPOOL384R1)
   if(name == "brainpool384r1") {
      return PCurveInstance::brainpool384r1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_BRAINPOOL512R1)
   if(name == "brainpool512r1") {
      return PCurveInstance::brainpool512r1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_FRP256V1)
   if(name == "frp256v1") {
      return PCurveInstance::frp256v1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_SM2P256V1)
   if(name == "sm2p256v1") {
      return PCurveInstance::sm2p256v1();
   }
#endif

#if defined(BOTAN_HAS_PCURVES_NUMSP512D1)
   if(name == "numsp512d1") {
      return PCurveInstance::numsp512d1();
   }
#endif

   BOTAN_UNUSED(alg);
   return {};
}

}  // namespace Botan::PCurve
#endif