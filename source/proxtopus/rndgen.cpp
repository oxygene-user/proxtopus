#include "pch.h"

#include "botan/system_rng.h"
#include "botan/mac.h"
#include <botan/internal/sha2_64.h>

inline std::unique_ptr<Botan::MessageAuthenticationCode> auto_rng_hmac() {
	
	return std::make_unique<Botan::HMAC>(std::make_unique<Botan::SHA_512>());
}

randomgen::randomgen(size_t reseed_interval):sfrng(auto_rng_hmac(), Botan::system_rng(), reseed_interval)
{
}

void randomgen::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in)
{
	if (in.empty()) {
		sfrng.randomize_with_ts_input(out);
	}
	else {
		sfrng.randomize_with_input(out, in);
	}
}


void randomgen::force_reseed()
{
	sfrng.force_reseed();
	sfrng.next_byte();

	ASSERT(sfrng.is_seeded());

}