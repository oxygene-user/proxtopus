/*
* HMAC
* (C) 1999-2007,2014,2020 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hmac.h>

#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* Update a HMAC Calculation
*/
void HMAC::add_data(std::span<const uint8_t> input) {
   assert_key_material_set();
   m_hash->update(input);
}

/*
* Finalize a HMAC Calculation
*/
void HMAC::final_result(std::span<uint8_t> mac) {
   assert_key_material_set();
   m_hash->final(mac);
   m_hash->update(m_okey);
   m_hash->update(mac.first(m_hash_output_length));
   m_hash->final(mac);
   m_hash->update(m_ikey);
}

Key_Length_Specification HMAC::key_spec() const {
   // Support very long lengths for things like PBKDF2 and the TLS PRF
   return Key_Length_Specification(0, 4096);
}

size_t HMAC::output_length() const {
   return m_hash_output_length;
}

bool HMAC::has_keying_material() const {
   return !m_okey.empty();
}

/*
* HMAC Key Schedule
*/
void HMAC::key_schedule(std::span<const uint8_t> key) {
   const uint8_t ipad = 0x36;
   const uint8_t opad = 0x5C;

   m_hash->clear();

   m_ikey.resize(m_hash_block_size, true);
   m_okey.resize(m_hash_block_size, true);

   clear_mem(m_ikey.data(), m_ikey.size());
   clear_mem(m_okey.data(), m_okey.size());

   /*
   * Sometimes the HMAC key length itself is sensitive, as with PBKDF2 where it
   * reveals the length of the passphrase. Make some attempt to hide this to
   * side channels. Clearly if the secret is longer than the block size then the
   * branch to hash first reveals that. In addition, counting the number of
   * compression functions executed reveals the size at the granularity of the
   * hash function's block size.
   *
   * The greater concern is for smaller keys; being able to detect when a
   * passphrase is say 4 bytes may assist choosing weaker targets. Even though
   * the loop bounds are constant, we can only actually read key[0..length] so
   * it doesn't seem possible to make this computation truly constant time.
   *
   * We don't mind leaking if the length is exactly zero since that's
   * trivial to simply check.
   */

   if(key.size() > m_hash_block_size) {
      m_hash->update(key);
      m_hash->final(m_ikey.data());
   } else if(key.size() >= 20) {
      // For long keys we just leak the length either it is a cryptovariable
      // or a long enough password that just the length is not a useful signal
      copy_mem(std::span{m_ikey}.first(key.size()), key);
   } else if(!key.empty()) {
      for(size_t i = 0, i_mod_length = 0; i != m_hash_block_size; ++i) {
         /*
         access key[i % length] but avoiding division due to variable
         time computation on some processors.
         */
         auto needs_reduction = CT::Mask<size_t>::is_lte(key.size(), i_mod_length);
         i_mod_length = needs_reduction.select(0, i_mod_length);
         const uint8_t kb = key[i_mod_length];

         auto in_range = CT::Mask<size_t>::is_lt(i, key.size());
         m_ikey[i] = static_cast<uint8_t>(in_range.if_set_return(kb));
         i_mod_length += 1;
      }
   }

   for(size_t i = 0; i != m_hash_block_size; ++i) {
      m_ikey[i] ^= ipad;
      m_okey[i] = m_ikey[i] ^ ipad ^ opad;
   }

   m_hash->update(m_ikey);
}

/*
* Clear memory of sensitive data
*/
void HMAC::clear() {
   m_hash->clear();
   zap(m_ikey);
   zap(m_okey);
}

/// PROXTOPUS : name removed

/*
* Return a new_object of this object
*/
std::unique_ptr<MessageAuthenticationCode> HMAC::new_object() const {
   return std::make_unique<HMAC>(m_hash->new_object());
}

/*
* HMAC Constructor
*/
HMAC::HMAC(std::unique_ptr<HashFunction> hash) :
      m_hash(std::move(hash)),
      m_hash_output_length(m_hash->output_length()),
      m_hash_block_size(m_hash->hash_block_size()) {
   BOTAN_ARG_CHECK(m_hash_block_size >= m_hash_output_length, "HMAC is not compatible with this hash function");
}

}  // namespace Botan
