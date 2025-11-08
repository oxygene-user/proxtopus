/*
* TLS Cipher Suite
* (C) 2004-2010,2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_ciphersuite.h>
#if FEATURE_TLS

#include <botan/assert.h>
#include <botan/block_cipher.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/stream_cipher.h>
#include <algorithm>

namespace Botan::TLS {

size_t Ciphersuite::nonce_bytes_from_handshake() const {
   switch(m_nonce_format) {
      case Nonce_Format::CBC_MODE: {
         //if(m_cipher_algo == ALG::DES_DES_DES) {
         //   return 8;
         //} else {
            return 16;
         //}
      }
      case Nonce_Format::AEAD_IMPLICIT_4:
         return 4;
      case Nonce_Format::AEAD_XOR_12:
         return 12;
   }

   throw Invalid_State("In Ciphersuite::nonce_bytes_from_handshake invalid enum value");
}

size_t Ciphersuite::nonce_bytes_from_record(Protocol_Version version) const {
   BOTAN_UNUSED(version);
   switch(m_nonce_format) {
      case Nonce_Format::CBC_MODE:
         //return Cipher_Algo::DES_DES_DES == m_cipher_algo ? 8 : 16;
          return 16;
      case Nonce_Format::AEAD_IMPLICIT_4:
         return 8;
      case Nonce_Format::AEAD_XOR_12:
         return 0;
   }

   throw Invalid_State("In Ciphersuite::nonce_bytes_from_handshake invalid enum value");
}

bool Ciphersuite::is_scsv(uint16_t suite) {
   // TODO: derive from IANA file in script
   return (suite == 0x00FF || suite == 0x5600);
}

bool Ciphersuite::psk_ciphersuite() const {
   return kex_method() == Kex_Algo::PSK || kex_method() == Kex_Algo::ECDHE_PSK;
}

bool Ciphersuite::ecc_ciphersuite() const {
   return kex_method() == Kex_Algo::ECDH || kex_method() == Kex_Algo::ECDHE_PSK || auth_method() == Auth_Method::ECDSA;
}

bool Ciphersuite::usable_in_version(Protocol_Version version) const {
   // RFC 8446 B.4.:
   //   Although TLS 1.3 uses the same cipher suite space as previous
   //   versions of TLS, TLS 1.3 cipher suites are defined differently, only
   //   specifying the symmetric ciphers, and cannot be used for TLS 1.2.
   //   Similarly, cipher suites for TLS 1.2 and lower cannot be used with
   //   TLS 1.3.
   //
   // Currently cipher suite codes {0x13,0x01} through {0x13,0x05} are
   // allowed for TLS 1.3. This may change in the future.
   const auto is_legacy_suite = (ciphersuite_code() & 0xFF00) != 0x1300;
   return version.is_pre_tls_13() == is_legacy_suite;
}

bool Ciphersuite::cbc_ciphersuite() const {
   //return (mac_algo() != "AEAD"); /// PROXTOPUS
    return !m_mac_algo_aead;
}

bool Ciphersuite::aead_ciphersuite() const {
   //return (mac_algo() == "AEAD"); /// PROXTOPUS
   return m_mac_algo_aead;
}

bool Ciphersuite::signature_used() const {
   return auth_method() != Auth_Method::IMPLICIT;
}

std::optional<Ciphersuite> Ciphersuite::by_id(uint16_t suite) {
   const std::vector<Ciphersuite>& all_suites = all_known_ciphersuites();
   auto s = std::lower_bound(all_suites.begin(), all_suites.end(), suite);

   if(s != all_suites.end() && s->ciphersuite_code() == suite) {
      return *s;
   }

   return std::nullopt;  // some unknown ciphersuite
}

std::optional<Ciphersuite> Ciphersuite::from_name(std::string_view name) {
   const std::vector<Ciphersuite>& all_suites = all_known_ciphersuites();

   for(auto suite : all_suites) {
      if(suite.to_string() == name) {
         return suite;
      }
   }

   return std::nullopt;  // some unknown ciphersuite
}

bool Ciphersuite::is_usable() const {
   if(!m_cipher_keylen) {  // uninitialized object
      return false;
   }

   /* /// PROXTOPUS : SHA_1, SHA_256, SHA_384 available
   if(!have_hash(prf_algo())) {
      return false;
   }
   */

#if !defined(BOTAN_HAS_TLS_CBC)
   if(cbc_ciphersuite())
      return false;
#endif

   if(m_mac_algo_aead) { /// PROXTOPUS

        switch (m_cipher_algo.a)
        {
        case Cipher_Algo::CHACHA20_POLY1305:
#if !defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
            if (true) return false;
#endif
            break;
        case Cipher_Algo::AES_128_GCM:
        case Cipher_Algo::AES_256_GCM:
#if !defined(BOTAN_HAS_AES)
            return false;
#endif
#if !defined(BOTAN_HAS_AEAD_GCM)
            if (true) return false;
#endif
            break;
        case Cipher_Algo::AES_256_OCB:
#if !defined(BOTAN_HAS_AES)
            if (true) return false;
#endif
#if !defined(BOTAN_HAS_AEAD_OCB)
            if (true) return false;
#endif
            break;
        case Cipher_Algo::CAMELLIA_128_GCM:
        case Cipher_Algo::CAMELLIA_256_GCM:
#if !defined (BOTAN_HAS_CAMELLIA)
            if (true) return false;
#endif
#if !defined(BOTAN_HAS_AEAD_GCM)
            if (true) return false;
#endif

            break;
        case Cipher_Algo::ARIA_128_GCM:
        case Cipher_Algo::ARIA_256_GCM:
#if !defined (BOTAN_HAS_ARIA)
            if (true) return false;
#endif
#if !defined(BOTAN_HAS_AEAD_GCM)
            if (true) return false;
#endif

            break;

        case Cipher_Algo::AES_128_CCM:
        case Cipher_Algo::AES_256_CCM:
        case Cipher_Algo::AES_128_CCM_8:
        case Cipher_Algo::AES_256_CCM_8:
#if !defined(BOTAN_HAS_AEAD_CCM)
            if (true) return false;
#endif
            break;
        default:
            return false;
        }
   } else {
       switch (m_cipher_algo.a)
       {
       case Cipher_Algo::AES_128_CBC:
       case Cipher_Algo::AES_256_CBC:
        //case Cipher_Algo::AES_128_CBC_HMAC_SHA1:
        //case Cipher_Algo::AES_128_CBC_HMAC_SHA256:
        //case Cipher_Algo::AES_256_CBC_HMAC_SHA1:
        //case Cipher_Algo::AES_256_CBC_HMAC_SHA256:
        //case Cipher_Algo::AES_256_CBC_HMAC_SHA384:
#if !defined(BOTAN_HAS_TLS_CBC)
           if (true) return false;
#endif
           break;
       default:
            return false;
       }
   }

   if(kex_method() == Kex_Algo::ECDH || kex_method() == Kex_Algo::ECDHE_PSK) {
#if !defined(BOTAN_HAS_ECDH)
      return false;
#endif
   } else if(kex_method() == Kex_Algo::DH) {
#if !defined(BOTAN_HAS_DIFFIE_HELLMAN)
      return false;
#endif
   }

   if(auth_method() == Auth_Method::ECDSA) {
#if !defined(BOTAN_HAS_ECDSA)
      return false;
#endif
   } else if(auth_method() == Auth_Method::RSA) {
#if !defined(BOTAN_HAS_RSA)
      return false;
#endif
   }

   return true;
}

}  // namespace Botan::TLS
#endif
