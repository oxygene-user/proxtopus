/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_hash.h>
#if FEATURE_TLS

#include <botan/hash.h>

namespace Botan::TLS {

/**
* Return a TLS Handshake Hash
*/
secure_vector<uint8_t> Handshake_Hash::final(Hash_Algo mac_algo) const {
   if(mac_algo == ALG::SHA_1) {
       mac_algo = ALG::SHA_256;
   }

   auto hash = HashFunction::create_or_throw(mac_algo);
   hash->update(m_data);
   return hash->final();
}

}  // namespace Botan::TLS
#endif