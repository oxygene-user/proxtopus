/*
* RIPEMD-160
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RIPEMD_160_H_
#define BOTAN_RIPEMD_160_H_

#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* RIPEMD-160
*/
class RIPEMD_160 final : public HashFunction {
   public:
      using digest_type = hash_digest<uint32_t, 5>;

      static constexpr MD_Endian byte_endianness = MD_Endian::Little;
      static constexpr MD_Endian bit_endianness = MD_Endian::Big;
      static constexpr size_t block_bytes = 64;
      static constexpr size_t output_bytes = 20;
      static constexpr size_t ctr_bytes = 8;

      static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
      static void init(digest_type& digest);

   public:
      //std::string name() const override { return "RIPEMD-160"; }
      Hash_Algo alg() const override { return ALG::RIPEMD_160; }

      size_t output_length() const override { return output_bytes; }

      size_t hash_block_size() const override { return block_bytes; }

      std::unique_ptr<HashFunction> new_object() const override;

      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override { m_md.clear(); }

   private:
      void add_data(std::span<const uint8_t> input) override;

      void final_result(std::span<uint8_t> output) override;

   private:
      MerkleDamgard_Hash<RIPEMD_160> m_md;
};

}  // namespace Botan

#endif
