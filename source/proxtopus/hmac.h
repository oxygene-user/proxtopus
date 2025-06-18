#pragma once

#include "botan/internal/ct_utils.h"

template<typename HASH> class hmac
{
    HASH hash;

    std::array<u8, HASH::block_bytes> ikey;
    std::array<u8, HASH::block_bytes> okey;

public:

    constexpr const static size_t output_bytes = HASH::output_bytes;

    void set_key(std::span<const u8> key)
    {
        hash.clear();
        memset(ikey.data(), 0, sizeof(ikey));

        if (key.size() > HASH::block_bytes) {
            hash.update(key);
            hash.fin(ikey);
        }
        else if (key.size() >= 20) {

            memcpy(ikey.data(), key.data(), key.size());
        }
        else if (!key.empty()) {
            for (size_t i = 0, i_mod_length = 0; i != HASH::block_bytes; ++i) {

                auto needs_reduction = Botan::CT::Mask<size_t>::is_lte(key.size(), i_mod_length);
                i_mod_length = needs_reduction.select(0, i_mod_length);
                const uint8_t kb = key[i_mod_length];

                auto in_range = Botan::CT::Mask<size_t>::is_lt(i, key.size());
                ikey[i] = static_cast<u8>(in_range.if_set_return(kb));
                ++i_mod_length;
            }
        }

        static_assert(HASH::block_bytes % sizeof(size_t) == 0);

        for (size_t i = 0; i != HASH::block_bytes; i += sizeof(size_t)) {

            constinit const static size_t ipad = math::fill<size_t, 0x36>();
            constinit const static size_t opad = math::fill<size_t, 0x5C>();

            size_t& ik = *reinterpret_cast<size_t*>(ikey.data() + i);
            size_t& ok = *reinterpret_cast<size_t*>(okey.data() + i);

            ok = ik ^ opad;
            ik ^= ipad;
        }

        hash.update(ikey);
    }

    void update(std::span<const uint8_t> d)
    {
        hash.update(d);
    }

    void fin(std::span<uint8_t> mac, bool restart) {
        
        ASSERT(mac.size() <= HASH::output_bytes);

        u8 temp[HASH::output_bytes];

        hash.fin(temp);
        hash.update(okey);
        hash.update(temp);
        hash.fin(mac);
        if (restart)
            hash.update(ikey); // restart with previous key
    }


};