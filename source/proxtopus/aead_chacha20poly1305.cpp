#include "pch.h"

void aead_chacha20poly1305::start(poly1305 &poly, std::span<const uint8_t> nonce, std::span<const uint8_t> ad)
{
    chacha.set_iv(nonce);

    uint8_t first_block[64];
    chacha.keystream(first_block, sizeof(first_block));

    poly.init(first_block);
    secure::scrub_memory(first_block, sizeof(first_block));

    poly.update(ad);

    if (nonce.size() == 12 || nonce.size() == 24) {
        if (ad.size() & 15) {
            const uint8_t zeros[16] = {0};
            poly.update(std::span(zeros, 16 - (ad.size() & 15)));
        }
    }
    else {

        if constexpr (Endian::little)
        {
            u64 adlen = ad.size();
            poly.update(std::span<const u8>(reinterpret_cast<const u8*>(&adlen), 8));
        }
        else
        {
            uint8_t len8[8] = { 0 };
            tools::store64_le(len8, ad.size());
            poly.update(std::span(len8, 8));
        }
    }

}

void aead_chacha20poly1305::encipher_packet_impl(std::span<const uint8_t> nonce, std::span<const uint8_t> packet, u8 *outbuf)
{
    poly1305 poly;
    start(poly, nonce);

    chacha.cipher(packet.data(), outbuf, packet.size());
    poly.update(std::span(outbuf, packet.size()));

    ALIGN(16) u8 temp[sizeof(u64) * 2];
    size_t templ = 0;

    if (nonce.size() == 12 || nonce.size() == 24)
    {
        if (packet.size() & 15) {
            const uint8_t zeros[16] = { 0 };
            poly.update(std::span(zeros, 16 - (packet.size() & 15)));
        }
        ref_cast<u64>(temp) = 0; // ad zero
        templ = sizeof(u64);
    }
    if constexpr (Endian::little)
    {
        *(u64*)(temp + templ) = packet.size();
    }
    else
    {
        tools::store64_le(temp+templ, packet.size());
    }

    poly.update(std::span(temp, templ+sizeof(u64)));
    poly.fin(outbuf + packet.size());

}

void aead_chacha20poly1305::encipher_packet_impl(std::span<const uint8_t> nonce, std::span<const uint8_t> packet1, std::span<const uint8_t> packet2, u8* outbuf)
{
    poly1305 poly;
    start(poly, nonce);

    chacha.cipher(packet1.data(), outbuf, packet1.size());
    chacha.cipher(packet2.data(), outbuf+packet1.size(), packet2.size());
    poly.update(std::span(outbuf, packet1.size() + packet2.size()));

    ALIGN(16) u8 temp[sizeof(u64) * 2];
    size_t templ = 0;

    size_t packet_size = packet1.size() + packet2.size();

    if (nonce.size() == 12 || nonce.size() == 24)
    {
        if (packet_size & 15) {
            const uint8_t zeros[16] = { 0 };
            poly.update(std::span(zeros, 16 - (packet_size & 15)));
        }
        ref_cast<u64>(temp) = 0; // ad zero
        templ = sizeof(u64);
    }
    if constexpr (Endian::little)
    {
        *(u64*)(temp + templ) = packet_size;
    }
    else
    {
        tools::store64_le(temp + templ, packet_size);
    }

    poly.update(std::span(temp, templ + sizeof(u64)));
    poly.fin(outbuf + packet_size);

}

bool aead_chacha20poly1305::decipher_packet_impl(std::span<const u8> nonce, std::span<const u8> packet, tools::memory_pair& outbuf)
{
    if (packet.size() < poly1305::tag_size)
        return false;

    poly1305 poly;
    start(poly, nonce);

    size_t packet_size = packet.size() - poly1305::tag_size;

    poly.update(std::span(packet.data(), packet_size));

    ASSERT(outbuf.size() == packet_size);

    if (packet_size <= outbuf.p0.size())
    {
        chacha.cipher(packet.data(), outbuf.p0.data(), packet_size);
    }
    else {
        chacha.cipher(packet.data(), outbuf.p0.data(), outbuf.p0.size());
        chacha.cipher(packet.data() + outbuf.p0.size(), outbuf.p1.data(), outbuf.p1.size());
    }

    ALIGN(16) u8 temp[sizeof(u64) * 2];
    size_t templ = 0;

    if (nonce.size() == 12 || nonce.size() == 24)
    {
        if (packet_size & 15) {
            const uint8_t zeros[16] = { 0 };
            poly.update(std::span(zeros, 16 - (packet_size & 15)));
        }
        ref_cast<u64>(temp) = 0; // ad zero
        templ = sizeof(u64);
    }

    if constexpr (Endian::little)
    {
        *(u64*)(temp + templ) = packet_size;
    }
    else
    {
        tools::store64_le(temp + templ, packet_size);
    }
    poly.update(std::span(temp, templ + sizeof(u64)));
    poly.fin(temp);

    const u8* included_tag = packet.data() + packet_size;
    if (memcmp(included_tag, temp, poly1305::tag_size) != 0)
        return false;

    return true;
}

signed_t aead_chacha20poly1305::decipher_packet_ssp(u32 nonce, std::span<const u8> packet, ss::outbuffer& outbuf)
{
    if (packet.size() < poly1305::tag_size + 2)
        return 0;
    u8 nonce_array[24] = {};
    tools::store32_le(nonce_array, nonce);

    poly1305 poly;
    u8 noncesz = chacha.get_iv_size();
    start(poly, std::span(nonce_array, noncesz));

    u16be packetsize;
    chacha.cipher(packet.data(), reinterpret_cast<u8 *>(&packetsize), 2);
    size_t packet_payload_size = packetsize;
    if (packet_payload_size > SS_AEAD_CHUNK_SIZE_MASK)
        return -1;

    if (packet.size() < poly1305::tag_size + packet_payload_size + 2)
        return 0;

    poly.update(std::span(packet.data(), packet_payload_size + 2));

    auto rsltbuf = outbuf.alloc(packet_payload_size);
    if (packet_payload_size <= rsltbuf.p0.size())
    {
        chacha.cipher(packet.data()+2, rsltbuf.p0.data(), packet_payload_size);
    }
    else {
        chacha.cipher(packet.data()+2, rsltbuf.p0.data(), rsltbuf.p0.size());
        chacha.cipher(packet.data()+2 + rsltbuf.p0.size(), rsltbuf.p1.data(), rsltbuf.p1.size());
    }

    ALIGN(16) u8 temp[sizeof(u64) * 2];
    size_t templ = 0;

    size_t packet_size = packet_payload_size + 2;
    if (noncesz == 12 || noncesz == 24)
    {
        if (packet_size & 15) {
            const uint8_t zeros[16] = { 0 };
            poly.update(std::span(zeros, 16 - (packet_size & 15)));
        }
        ref_cast<u64>(temp) = 0; // ad zero
        templ = sizeof(u64);
    }

    if constexpr (Endian::little)
    {
        *(u64*)(temp + templ) = packet_size;
    }
    else
    {
        tools::store64_le(temp + templ, packet_size);
    }
    poly.update(std::span(temp, templ + sizeof(u64)));
    poly.fin(temp);

    const u8* included_tag = packet.data() + packet_size;
    if (memcmp(included_tag, temp, poly1305::tag_size) != 0)
        return -1;

    return packet_size + poly1305::tag_size;
}
