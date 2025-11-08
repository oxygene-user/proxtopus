/*
* TLS Cipher Suites
* (C) 2004-2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CIPHER_SUITES_H_
#define BOTAN_TLS_CIPHER_SUITES_H_
#include "../conf.h"
#if FEATURE_TLS

#include <botan/tls_algos.h>
#include <botan/tls_version.h>
#include <botan/types.h>
#include <optional>
#include <string>
#include <vector>

namespace Botan::TLS {

/**
* Ciphersuite Information
*/
class BOTAN_PUBLIC_API(2, 0) Ciphersuite final {
   public:
      /**
      * Convert an SSL/TLS ciphersuite to algorithm fields
      * @param suite the ciphersuite code number
      * @return ciphersuite object or std::nullopt if it is unknown to the library
      */
      static std::optional<Ciphersuite> by_id(uint16_t suite);

      /**
      * Convert an SSL/TLS ciphersuite name to algorithm fields
      * @param name the IANA name for the desired ciphersuite
      * @return ciphersuite object or std::nullopt if it is unknown to the library
      */
      static std::optional<Ciphersuite> from_name(std::string_view name);

      /**
      * Returns true iff this suite is a known SCSV
      */
      static bool is_scsv(uint16_t suite);

      /**
      * Generate a static list of all known ciphersuites and return it.
      *
      * @return list of all known ciphersuites
      */
      static const std::vector<Ciphersuite>& all_known_ciphersuites();

      /**
      * Formats the ciphersuite back to an RFC-style ciphersuite string
      *
      * e.g "RSA_WITH_RC4_128_SHA" or "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
      * @return RFC ciphersuite string identifier
      */
      std::string to_string() const { return (!m_iana_id) ? "unknown cipher suite" : m_iana_id; }

      /**
      * @return ciphersuite number
      */
      uint16_t ciphersuite_code() const { return m_ciphersuite_code; }

      /**
      * @return true if this is a PSK ciphersuite
      */
      bool psk_ciphersuite() const;

      /**
      * @return true if this is an ECC ciphersuite
      */
      bool ecc_ciphersuite() const;

      /**
       * @return true if this suite uses a CBC cipher
       */
      bool cbc_ciphersuite() const;

      /**
       * @return true if this suite uses a AEAD cipher
       */
      bool aead_ciphersuite() const;

      bool signature_used() const;

      Kex_Algo kex_algo() const { return m_kex_algo; }
      Kex_Algo kex_method() const { return m_kex_algo; }

      Auth_Method sig_algo() const { return m_auth_method; }
      Auth_Method auth_method() const { return m_auth_method; }

      // PROXTOPUS : avoid use of strings to identify types
      Cipher_Algo cipher_algo() const { return m_cipher_algo; }
      Mac_Algo mac_algo() const { return m_mac_algo_aead ? Mac_Algo::AEAD : Mac_Algo::Undefined; }

      KDF_Algo prf_algo() const { return m_prf_algo; }

      /**
      * @return cipher key length used by this ciphersuite
      */
      size_t cipher_keylen() const { return m_cipher_keylen; }

      size_t nonce_bytes_from_handshake() const;

      size_t nonce_bytes_from_record(Protocol_Version version) const;

      Nonce_Format nonce_format() const { return m_nonce_format; }

      size_t mac_keylen() const { return m_mac_keylen; }

      /**
      * @return true if this is a valid/known ciphersuite
      */
      bool valid() const { return m_usable; }

      bool usable_in_version(Protocol_Version version) const;

      bool operator<(const Ciphersuite& o) const { return ciphersuite_code() < o.ciphersuite_code(); }

      bool operator<(const uint16_t c) const { return ciphersuite_code() < c; }

   private:
      bool is_usable() const;

      Ciphersuite(uint16_t ciphersuite_code,
                  const char* iana_id,
                  Auth_Method auth_method,
                  Kex_Algo kex_algo,
                  Cipher_Algo cipher_algo,
                  size_t cipher_keylen,
                  Mac_Algo mac_algo,
                  size_t mac_keylen,
                  KDF_Algo prf_algo,
                  Nonce_Format nonce_format) :
            m_ciphersuite_code(ciphersuite_code),
            m_iana_id(iana_id),
            m_auth_method(auth_method),
            m_kex_algo(kex_algo),
            m_prf_algo(prf_algo),
            m_nonce_format(nonce_format),
            m_cipher_algo(cipher_algo),
            m_cipher_keylen(cipher_keylen),
            m_mac_keylen(mac_keylen),
            m_mac_algo_aead(mac_algo == Mac_Algo::AEAD)
     {
         m_usable = is_usable();
      }

      uint16_t m_ciphersuite_code = 0;

      /*
      All of these const char* strings are references to compile time
      constants in tls_suite_info.cpp
      */
      const char* m_iana_id;

      Auth_Method m_auth_method;
      Kex_Algo m_kex_algo;
      KDF_Algo m_prf_algo;
      Nonce_Format m_nonce_format;

      Cipher_Algo m_cipher_algo; /// PROXTOPUS : avoid use strings
      //const char* m_mac_algo; /// PROXTOPUS : mac_algo currently has only one value: "AEAD" (or not "AEAD"), so we can replace it with bool

      size_t m_cipher_keylen;
      size_t m_mac_keylen;

      bool m_usable = false;
      bool m_mac_algo_aead = false; /// PROXTOPUS
};

}  // namespace Botan::TLS

#endif
#endif