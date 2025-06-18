#pragma once

template<typename HMAC> class hkdf
{
public:

    static void perform_extract(std::span<u8> key, std::span<const u8> secret, std::span<const u8> salt)
    {
        ASSERT(!key.empty());
        ASSERT(key.size() <= HMAC::output_bytes, "HKDF-Extract maximum output length exceeeded");

        HMAC mac;

        if (salt.empty()) {

            u8 zeros[HMAC::output_bytes] = { 0 };
            mac.set_key(zeros);
        }
        else {
            mac.set_key(salt);
        }

        mac.update(secret);
        mac.fin(key, false);
    }
    static void perform_expand(std::span<u8> key, std::span<const u8> secret /*, std::span<const u8> salt*/ , std::span<const u8> label)
    {
        ASSERT(!key.empty());
        ASSERT(key.size() <= HMAC::output_bytes * 255, "HKDF-Expand maximum output length exceeeded");

        // Keep a reference to the previous PRF output (empty by default).
        std::span<uint8_t> h = {};
        Botan::BufferStuffer k(key);

        HMAC mac;
        mac.set_key(secret);
        for (u8 counter = 1; !k.full(); ++counter) {
            mac.update(h);
            mac.update(label);
            //mac.update(salt);
            mac.update(std::span<const u8>(&counter, 1));

            // Write straight into the output buffer, except if the PRF output needs
            // a truncation in the final iteration.
            if (k.remaining_capacity() > HMAC::output_bytes) {
                h = k.next(HMAC::output_bytes);
                mac.fin(h, true);
            }
            else {
                mac.fin(k.next(k.remaining_capacity()), false);
                break;
            }
        }

    }

    static void perform_kdf(std::span<u8> key, std::span<const u8> secret, std::span<const u8> salt, std::span<const u8> label)
    {
        u8 prk[HMAC::output_bytes];
        perform_extract(prk, secret, salt);
        perform_expand(key, prk /*, {}*/, label);
    }
};