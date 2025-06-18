#pragma once

// TODO : implement associated data support if need

class aead_chacha20poly1305
{
    chacha20 chacha;

    void encipher_packet_impl(std::span<const u8> nonce, std::span<const u8> packet, u8 *outbuf); // full process; no associated data
    bool decipher_packet_impl(std::span<const u8> nonce, std::span<const u8> packet, tools::memory_pair &outbuf); // full process; no associated data

protected:

    void start(poly1305& poly, std::span<const uint8_t> nonce, std::span<const uint8_t> ad = std::span<const uint8_t>());

public:

    bool ready() const { return chacha.ready(); }

    void set_key(std::span<const uint8_t, chacha20::key_size> key) // 32 bytes len
    {
        chacha.set_key(key);
    }

    template<typename ALLOC> void encipher_packet(std::span<const uint8_t> nonce, std::span<const uint8_t> packet, ALLOC space_reserver) // full process; no associated data
    {
        uint8_t* outbuf = space_reserver(packet.size() + poly1305::tag_size);
        encipher_packet_impl(nonce, packet, outbuf);
    }

    bool decipher_packet(std::span<const uint8_t> nonce, std::span<const u8> packet, tools::memory_pair &reslt)
    {
        if (packet.size() < poly1305::tag_size)
            return false;
        return decipher_packet_impl(nonce, packet, reslt);
    }

};

