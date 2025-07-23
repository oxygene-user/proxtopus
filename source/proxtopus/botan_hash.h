#pragma once

#include <botan/internal/mdx_hash.h>
#include <botan/internal/sha1.h>
#include <botan/internal/sha2_32.h>
#include <botan/internal/md5.h>

class sha1 {

public:
    using digest_type = Botan::hash_digest<uint32_t, 5>;

    static constexpr Botan::MD_Endian byte_endianness = Botan::MD_Endian::Big;
    static constexpr Botan::MD_Endian bit_endianness = Botan::MD_Endian::Big;
    static constexpr size_t block_bytes = 64;
    static constexpr size_t output_bytes = 20;
    static constexpr size_t ctr_bytes = 8;

    static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks)
    {
        Botan::SHA_1::compress_n(digest, input, blocks);
    }
    static void init(digest_type& digest)
    {
        Botan::SHA_1::init(digest);
    }

private:
    Botan::MerkleDamgard_Hash<sha1> md;

public:

    void clear() { md.clear(); }
    void update(std::span<const u8> d)
    {
        md.update(d);
    }
    void fin(std::span<u8> output)
    {
        if (output.size() >= output_bytes)
            md.final(output);
        else
        {
            u8 temp[output_bytes];
            md.final(temp);
            memcpy(output.data(), temp, output.size());
        }
    }
};

class sha256 {

public:
    using digest_type = Botan::hash_digest<uint32_t, 8>;

    static constexpr Botan::MD_Endian byte_endianness = Botan::MD_Endian::Big;
    static constexpr Botan::MD_Endian bit_endianness = Botan::MD_Endian::Big;
    static constexpr size_t block_bytes = 64;
    static constexpr size_t output_bytes = 32;
    static constexpr size_t ctr_bytes = 8;

    static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks)
    {
        Botan::SHA_256::compress_n(digest, input, blocks);
    }
    static void init(digest_type& digest)
    {
        Botan::SHA_256::init(digest);
    }

private:
    Botan::MerkleDamgard_Hash<sha256> md;

public:

    void clear() { md.clear(); }
    void update(std::span<const u8> d)
    {
        md.update(d);
    }
    void fin(std::span<u8> output)
    {
        if (output.size() >= output_bytes)
            md.final(output);
        else
        {
            u8 temp[output_bytes];
            md.final(temp);
            memcpy(output.data(), temp, output.size());
        }
    }
};


class md5 {
public:

    using digest_type = Botan::hash_digest<uint32_t, 4>;

    static constexpr Botan::MD_Endian byte_endianness = Botan::MD_Endian::Little;
    static constexpr Botan::MD_Endian bit_endianness = Botan::MD_Endian::Big;
    static constexpr size_t block_bytes = 64;
    static constexpr size_t output_bytes = 16;
    static constexpr size_t ctr_bytes = 8;

    static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks)
    {
        Botan::MD5::compress_n(digest, input, blocks);
    }
    static void init(digest_type& digest)
    {
        Botan::MD5::init(digest);
    }
private:
    Botan::MerkleDamgard_Hash<md5> md;

public:
    void clear() { md.clear(); }
    void update(std::span<const u8> d)
    {
        md.update(d);
    }
    void fin(std::span<u8, output_bytes> output)
    {
        md.final(output);
    }

};
