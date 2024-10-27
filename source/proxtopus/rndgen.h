#pragma once

#include "botan/botan.h"
#include "botan/hmac_drbg.h"
#include "botan/entropy_src.h"

class randomgen : public Botan::RandomNumberGenerator {

    Botan::HMAC_DRBG sfrng;

    public:
        bool is_seeded() const override
        {
            return sfrng.is_seeded();
        }

        bool accepts_input() const override { return true; }

        void force_reseed();

        size_t reseed(Botan::Entropy_Sources& srcs, size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS, std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override
        {
            return sfrng.reseed(srcs, poll_bits, poll_timeout);
        }

        std::string name() const override
        {
            return sfrng.name();
        }

        void clear() override
        {
            sfrng.clear();
        }

        randomgen(size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

    private:
        void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override;

};
