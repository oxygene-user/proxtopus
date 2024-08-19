#include "pch.h"

#include "botan/stream_cipher.h"
#include "botan/internal/ct_utils.h"

namespace Botan
{
	size_t StreamCipher::default_iv_length() const {
		return 0;
	}

	void StreamCipher::generate_keystream(uint8_t out[], size_t len) {
		clear_mem(out, len);
		cipher1(out, len);
	}

	void MessageAuthenticationCode::start_msg(std::span<const uint8_t> nonce) {
		BOTAN_UNUSED(nonce);
		if (!nonce.empty()) {
			throw Invalid_IV_Length(name(), nonce.size());
		}
	}

	bool MessageAuthenticationCode::verify_mac_result(std::span<const uint8_t> mac) {
		secure_vector<uint8_t> our_mac = final();

		if (our_mac.size() != mac.size()) {
			return false;
		}

		return Botan::CT::is_equal(our_mac.data(), mac.data(), mac.size()).as_bool();
	}

	size_t Entropy_Sources::poll(RandomNumberGenerator& /*rng*/, size_t /*poll_bits*/, std::chrono::milliseconds /*timeout*/) {

		DEBUGBREAK();
		return 0;
	}

    void assertion_failure(const char* expr_str,
		const char* assertion_made,
		const char* func,
		const char* file,
		int line)
	{
		ERRORM(file, line, "assertion (%s) (%s) (%s)", assertion_made, func, expr_str);
		for(;;);
	}

	void throw_invalid_argument(const char* /*message*/,
		const char* /*func*/,
		const char* /*file*/)
	{
		SMART_DEBUG_BREAK;
		for(;;);
	}

	void throw_invalid_state(const char* /*expr*/,
		const char* /*func*/,
		const char* /*file*/)
	{
		SMART_DEBUG_BREAK;
		for(;;);
	}

}



