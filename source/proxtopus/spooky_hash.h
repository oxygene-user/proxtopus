#pragma once

// https://burtleburtle.net/bob/hash/spooky.html
//
// SpookyHash: a 128-bit noncryptographic hash function
// By Bob Jenkins, public domain
//   Oct 31 2010: alpha, framework + SpookyHash::Mix appears right
//   Oct 31 2011: alpha again, Mix only good to 2^^69 but rest appears right
//   Dec 31 2011: beta, improved Mix, tested it for 2-bit deltas
//   Feb  2 2012: production, same bits as beta
//   Feb  5 2012: adjusted definitions of uint* to be more portable
//   Mar 30 2012: 3 bytes/cycle, not 4.  Alpha was 4 but wasn't thorough enough.
//   August 5 2012: SpookyV2 (different results)
// 
// Up to 3 bytes/cycle for long messages.  Reasonably fast for short messages.
// All 1 or 2 bit deltas achieve avalanche within 1% bias per output bit.
//
// This was developed for and tested on 64-bit x86-compatible processors.
// It assumes the processor is little-endian.  There is a macro
// controlling whether unaligned reads are allowed (by default they are).
// This should be an equally good hash on big-endian machines, but it will
// compute different results on them than on little-endian machines.
//
// Google's CityHash has similar specs to SpookyHash, and CityHash is faster
// on new Intel boxes.  MD4 and MD5 also have similar specs, but they are orders
// of magnitude slower.  CRCs are two or more times slower, but unlike 
// SpookyHash, they have nice math for combining the CRCs of pieces to form 
// the CRCs of wholes.  There are also cryptographic hashes, but those are even 
// slower than MD5.
//

namespace spooky
{
#define ALLOW_UNALIGNED_READS 1

    enum consts : u64
    {
        sc_numVars = 12,                // number of u64's in internal state
        sc_blockSize = sc_numVars * 8,  // size of the internal state
        sc_bufSize = 2 * sc_blockSize,  // size of buffer of unhashed data, in bytes

        // sc_const: a constant which:
        //  * is not zero
        //  * is odd
        //  * is a not-very-regular mix of 1's and 0's
        //  * does not need any other special mathematical properties
        sc_const = 0xdeadbeefdeadbeefull,
    };

    //
    // left rotate a 64-bit value by k bytes
    //
    template<size_t k> u64 Rot64(u64 x)
    {
        return (x << k) | (x >> (64 - k));
    }

    //
    // The goal is for each bit of the input to expand into 128 bits of 
    //   apparent entropy before it is fully overwritten.
    // n trials both set and cleared at least m bits of h0 h1 h2 h3
    //   n: 2   m: 29
    //   n: 3   m: 46
    //   n: 4   m: 57
    //   n: 5   m: 107
    //   n: 6   m: 146
    //   n: 7   m: 152
    // when run forwards or backwards
    // for all 1-bit and 2-bit diffs
    // with diffs defined by either xor or subtraction
    // with a base of all zeros plus a counter, or plus another bit, or random
    //
    inline void ShortMix(u64& h0, u64& h1, u64& h2, u64& h3)
    {
        h2 = Rot64<50>(h2);  h2 += h3;  h0 ^= h2;
        h3 = Rot64<52>(h3);  h3 += h0;  h1 ^= h3;
        h0 = Rot64<30>(h0);  h0 += h1;  h2 ^= h0;
        h1 = Rot64<41>(h1);  h1 += h2;  h3 ^= h1;
        h2 = Rot64<54>(h2);  h2 += h3;  h0 ^= h2;
        h3 = Rot64<48>(h3);  h3 += h0;  h1 ^= h3;
        h0 = Rot64<38>(h0);  h0 += h1;  h2 ^= h0;
        h1 = Rot64<37>(h1);  h1 += h2;  h3 ^= h1;
        h2 = Rot64<62>(h2);  h2 += h3;  h0 ^= h2;
        h3 = Rot64<34>(h3);  h3 += h0;  h1 ^= h3;
        h0 = Rot64<5>(h0);   h0 += h1;  h2 ^= h0;
        h1 = Rot64<36>(h1);  h1 += h2;  h3 ^= h1;
    }

    //
    // Mix all 4 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3% (it is probably better than that)
    // For every pair of input bits,
    // with probability 50 +- .75% (the worst case is approximately that)
    //
    inline void ShortEnd(u64& h0, u64& h1, u64& h2, u64& h3)
    {
        h3 ^= h2;  h2 = Rot64<15>(h2);  h3 += h2;
        h0 ^= h3;  h3 = Rot64<52>(h3);  h0 += h3;
        h1 ^= h0;  h0 = Rot64<26>(h0);  h1 += h0;
        h2 ^= h1;  h1 = Rot64<51>(h1);  h2 += h1;
        h3 ^= h2;  h2 = Rot64<28>(h2);  h3 += h2;
        h0 ^= h3;  h3 = Rot64<9>(h3);   h0 += h3;
        h1 ^= h0;  h0 = Rot64<47>(h0);  h1 += h0;
        h2 ^= h1;  h1 = Rot64<54>(h1);  h2 += h1;
        h3 ^= h2;  h2 = Rot64<32>(h2);  h3 += h2;
        h0 ^= h3;  h3 = Rot64<25>(h3);  h0 += h3;
        h1 ^= h0;  h0 = Rot64<63>(h0);  h1 += h0;
    }

    inline void hash_short(const void* message, size_t length, u64* hash1, u64* hash2)
    {
        u64 buf[2 * sc_numVars];
        union
        {
            const u8* p8;
            u32* p32;
            u64* p64;
            size_t i;
        } u;

        u.p8 = (const u8*)message;

        if constexpr (!ALLOW_UNALIGNED_READS && (u.i & 0x7))
        {
            memcpy(buf, message, length);
            u.p64 = buf;
        }

        size_t remainder = length % 32;
        u64 a = *hash1;
        u64 b = *hash2;
        u64 c = sc_const;
        u64 d = sc_const;

        if (length > 15)
        {
            const u64* end = u.p64 + (length / 32) * 4;

            // handle all complete sets of 32 bytes
            for (; u.p64 < end; u.p64 += 4)
            {
                c += u.p64[0];
                d += u.p64[1];
                ShortMix(a, b, c, d);
                a += u.p64[2];
                b += u.p64[3];
            }

            //Handle the case of 16+ remaining bytes.
            if (remainder >= 16)
            {
                c += u.p64[0];
                d += u.p64[1];
                ShortMix(a, b, c, d);
                u.p64 += 2;
                remainder -= 16;
            }
        }

        // Handle the last 0..15 bytes, and its length
        d += ((u64)length) << 56;
        switch (remainder)
        {
        case 15:
            d += ((u64)u.p8[14]) << 48;
        case 14:
            d += ((u64)u.p8[13]) << 40;
        case 13:
            d += ((u64)u.p8[12]) << 32;
        case 12:
            d += u.p32[2];
            c += u.p64[0];
            break;
        case 11:
            d += ((u64)u.p8[10]) << 16;
        case 10:
            d += ((u64)u.p8[9]) << 8;
        case 9:
            d += (u64)u.p8[8];
        case 8:
            c += u.p64[0];
            break;
        case 7:
            c += ((u64)u.p8[6]) << 48;
        case 6:
            c += ((u64)u.p8[5]) << 40;
        case 5:
            c += ((u64)u.p8[4]) << 32;
        case 4:
            c += u.p32[0];
            break;
        case 3:
            c += ((u64)u.p8[2]) << 16;
        case 2:
            c += ((u64)u.p8[1]) << 8;
        case 1:
            c += (u64)u.p8[0];
            break;
        case 0:
            c += sc_const;
            d += sc_const;
        }
        ShortEnd(a, b, c, d);
        *hash1 = a;
        *hash2 = b;
    }

    //
    // This is used if the input is 96 bytes long or longer.
    //
    // The internal state is fully overwritten every 96 bytes.
    // Every input bit appears to cause at least 128 bits of entropy
    // before 96 other bytes are combined, when run forward or backward
    //   For every input bit,
    //   Two inputs differing in just that input bit
    //   Where "differ" means xor or subtraction
    //   And the base value is random
    //   When run forward or backwards one Mix
    // I tried 3 pairs of each; they all differed by at least 212 bits.
    //
    inline void Mix( const u64* data, u64& s0, u64& s1, u64& s2, u64& s3, u64& s4, u64& s5, u64& s6, u64& s7, u64& s8, u64& s9, u64& s10, u64& s11)
    {
        s0 += data[0];    s2 ^= s10;   s11 ^= s0;   s0 = Rot64<11>(s0);    s11 += s1;
        s1 += data[1];    s3 ^= s11;   s0 ^= s1;    s1 = Rot64<32>(s1);    s0 += s2;
        s2 += data[2];    s4 ^= s0;    s1 ^= s2;    s2 = Rot64<43>(s2);    s1 += s3;
        s3 += data[3];    s5 ^= s1;    s2 ^= s3;    s3 = Rot64<31>(s3);    s2 += s4;
        s4 += data[4];    s6 ^= s2;    s3 ^= s4;    s4 = Rot64<17>(s4);    s3 += s5;
        s5 += data[5];    s7 ^= s3;    s4 ^= s5;    s5 = Rot64<28>(s5);    s4 += s6;
        s6 += data[6];    s8 ^= s4;    s5 ^= s6;    s6 = Rot64<39>(s6);    s5 += s7;
        s7 += data[7];    s9 ^= s5;    s6 ^= s7;    s7 = Rot64<57>(s7);    s6 += s8;
        s8 += data[8];    s10 ^= s6;   s7 ^= s8;    s8 = Rot64<55>(s8);    s7 += s9;
        s9 += data[9];    s11 ^= s7;   s8 ^= s9;    s9 = Rot64<54>(s9);    s8 += s10;
        s10 += data[10];  s0 ^= s8;    s9 ^= s10;   s10 = Rot64<22>(s10);  s9 += s11;
        s11 += data[11];  s1 ^= s9;    s10 ^= s11;  s11 = Rot64<46>(s11);  s10 += s0;
    }

    //
    // Mix all 12 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3%
    // For every pair of input bits,
    // with probability 50 +- 3%
    //
    // This does not rely on the last Mix() call having already mixed some.
    // Two iterations was almost good enough for a 64-bit result, but a
    // 128-bit result is reported, so End() does three iterations.
    //
    inline void EndPartial( u64& h0, u64& h1, u64& h2, u64& h3, u64& h4, u64& h5, u64& h6, u64& h7, u64& h8, u64& h9, u64& h10, u64& h11)
    {
        h11 += h1;   h2 ^= h11;   h1 = Rot64<44>(h1);
        h0 += h2;    h3 ^= h0;    h2 = Rot64<15>(h2);
        h1 += h3;    h4 ^= h1;    h3 = Rot64<34>(h3);
        h2 += h4;    h5 ^= h2;    h4 = Rot64<21>(h4);
        h3 += h5;    h6 ^= h3;    h5 = Rot64<38>(h5);
        h4 += h6;    h7 ^= h4;    h6 = Rot64<33>(h6);
        h5 += h7;    h8 ^= h5;    h7 = Rot64<10>(h7);
        h6 += h8;    h9 ^= h6;    h8 = Rot64<13>(h8);
        h7 += h9;    h10 ^= h7;   h9 = Rot64<38>(h9);
        h8 += h10;   h11 ^= h8;   h10 = Rot64<53>(h10);
        h9 += h11;   h0 ^= h9;    h11 = Rot64<42>(h11);
        h10 += h0;   h1 ^= h10;   h0 = Rot64<54>(h0);
    }
    inline void End( const u64* data, u64& h0, u64& h1, u64& h2, u64& h3, u64& h4, u64& h5, u64& h6, u64& h7, u64& h8, u64& h9, u64& h10, u64& h11)
    {
        h0 += data[0];   h1 += data[1];   h2 += data[2];   h3 += data[3];
        h4 += data[4];   h5 += data[5];   h6 += data[6];   h7 += data[7];
        h8 += data[8];   h9 += data[9];   h10 += data[10]; h11 += data[11];
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
    }

    //
    // SpookyHash: hash a single message in one call, produce 128-bit output
    // message - message to hash
    // length - length of message in bytes
    // hash1 - in/out: in seed 1, out hash value 1
    // hash2 - in/out: in seed 2, out hash value 2
    //
    inline void hash_128(const void* message, size_t length, u64* hash1, u64* hash2)
    {
        if (length < sc_bufSize)
        {
            hash_short(message, length, hash1, hash2);
            return;
        }

        u64 h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
        u64 buf[sc_numVars];
        u64* end;
        union
        {
            const u8* p8;
            u64* p64;
            size_t i;
        } u;
        size_t remainder;

        h0 = h3 = h6 = h9 = *hash1;
        h1 = h4 = h7 = h10 = *hash2;
        h2 = h5 = h8 = h11 = sc_const;

        u.p8 = (const u8*)message;
        end = u.p64 + (length / sc_blockSize) * sc_numVars;

        // handle all whole sc_blockSize blocks of bytes
        if constexpr (ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0))
        {
            while (u.p64 < end)
            {
                Mix(u.p64, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
                u.p64 += sc_numVars;
            }
        }
        else
        {
            while (u.p64 < end)
            {
                memcpy(buf, u.p64, sc_blockSize);
                Mix(buf, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
                u.p64 += sc_numVars;
            }
        }

        // handle the last partial block of sc_blockSize bytes
        remainder = (length - ((const u8*)end - (const u8*)message));
        memcpy(buf, end, remainder);
        memset(((u8*)buf) + remainder, 0, sc_blockSize - remainder);
        ((u8*)buf)[sc_blockSize - 1] = static_cast<u8>(remainder & 0xff);

        // do some final mixing 
        End(buf, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        *hash1 = h0;
        *hash2 = h1;
    }

}



