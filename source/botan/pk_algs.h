/*
* PK Key Factory
* (C) 1999-2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_KEY_FACTORY_H_
#define BOTAN_PK_KEY_FACTORY_H_

#include <botan/asn1_obj.h>
#include <botan/pk_keys.h>
#include <memory>

namespace Botan {

BOTAN_PUBLIC_API(2, 0)
std::unique_ptr<Public_Key> load_public_key(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

BOTAN_PUBLIC_API(2, 0)
std::unique_ptr<Private_Key> load_private_key(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

/**
* Create a new key
* For ECC keys, algo_params specifies EC group (eg, "secp256r1")
* For DH/DSA/ElGamal keys, algo_params is DL group (eg, "modp/ietf/2048")
* For RSA, algo_params is integer keylength
* For McEliece, algo_params is n,t
* If algo_params is left empty, suitable default parameters are chosen.
*/
BOTAN_PUBLIC_API(2, 0)
std::unique_ptr<Private_Key> create_private_key(Any_Algo algo_name,
                                                RandomNumberGenerator& rng,
                                                uint32_t algo_params = 0);

class EC_Group;

/**
* Create a new ECC key
*/
BOTAN_PUBLIC_API(3, 0)
std::unique_ptr<Private_Key> create_ec_private_key(Any_Algo algo_name,
                                                   const EC_Group& group,
                                                   RandomNumberGenerator& rng);


}  // namespace Botan

#endif
