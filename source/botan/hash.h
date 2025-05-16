/*
* Hash Function Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HASH_FUNCTION_BASE_CLASS_H_
#define BOTAN_HASH_FUNCTION_BASE_CLASS_H_

#include <botan/buf_comp.h>
#include <memory>
#include <string>
#include <string_view>

namespace Botan {

/**
* This class represents hash function (message digest) objects
*/
class BOTAN_PUBLIC_API(2, 0) HashFunction : public Buffered_Computation {
   public:
      /**
      * Create an instance based on a name, or return null if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<HashFunction> create(Hash_Algo hasht);

      /// PROXTOPUS : avoid use of strings
      static std::unique_ptr<HashFunction> create_or_throw(Hash_Algo hasht);

      /// PROXTOPUS : provider removed

      ~HashFunction() override = default;

      /**
      * Reset the state.
      */
      virtual void clear() = 0;

      virtual Hash_Algo alg() const = 0;

      /**
      * @return hash block size as defined for this algorithm
      */
      virtual size_t hash_block_size() const { return 0; }

      /**
      * Return a new hash object with the same state as *this. This
      * allows computing the hash of several messages with a common
      * prefix more efficiently than would otherwise be possible.
      *
      * This function should be called `clone` but that was already
      * used for the case of returning an uninitialized object.
      * @return new hash object
      */
      virtual std::unique_ptr<HashFunction> copy_state() const = 0;

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<HashFunction> new_object() const = 0;

      /**
      * @return new object representing the same algorithm as *this
      */
      HashFunction* clone() const { return this->new_object().release(); }
};

}  // namespace Botan

#endif
