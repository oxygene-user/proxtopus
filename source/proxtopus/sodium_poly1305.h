#pragma once

#include "botan/mac.h"

class poly1305
{
    template <typename CORE> void update_core(CORE&core, const uint8_t* m, size_t len)
    {
        if (core.leftover)
        {
            size_t want = (CORE::poly1305_block_size - core.leftover);

            if (want > len)
                want = len;

            memcpy(core.buffer + core.leftover, m, want);

            len -= want;
            m += want;
            core.leftover = static_cast<uint8_t>(want + core.leftover);
            if (core.leftover < CORE::poly1305_block_size)
                return;

            core.poly1305_blocks(core.buffer, CORE::poly1305_block_size);
            core.leftover = 0;
        }

        if (len >= CORE::poly1305_block_size) {
            size_t want = (len & ~(CORE::poly1305_block_size - 1));

            core.poly1305_blocks(m, want);
            m += want;
            len -= want;
        }

        if (len) {
            memcpy(core.buffer, m, len);
            core.leftover = static_cast<uint8_t>(len);
        }
    }


    struct internal_sse2
    {
        enum consts {
            poly1305_block_size = 32,

            // flags
            poly1305_started = 1,
            poly1305_final_shift8 = 4,
            poly1305_final_shift16 = 8,
            poly1305_final_r2_r = 16, /* use [r^2,r] for the final block */
            poly1305_final_r_1 = 32  /* use [r,1] for the final block */
        };

        union {
            uint64_t h[3];
            uint32_t hh[10];
        } H;                                         /*  40 bytes */
        uint32_t        R[5];                        /*  20 bytes */
        uint32_t        R2[5];                       /*  20 bytes */
        uint32_t        R4[5];                       /*  20 bytes */
        uint64_t        pad[2];                      /*  16 bytes */
        uint8_t         flags;
        uint8_t         dummy1[3];  // align
        uint8_t         leftover;
        uint8_t         dummy2[3];   // align
        uint8_t         buffer[poly1305_block_size];

        void init(const uint8_t* k);
        void poly1305_blocks(const uint8_t* m, size_t len);
        void fin(uint8_t* tag);
    };

#ifndef SSE2_SUPPORTED
    struct internal_donna
    {
        enum consts {
            poly1305_block_size = 16,
        };

#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__)
        uint64_t    r[3];
        uint64_t    h[3];
        uint64_t    pad[2];
#else
        uint32_t    r[5];
        uint32_t    h[5];
        uint32_t    pad[4];
        uint32_t    dummy[2];
#endif
        uint8_t     buffer[poly1305_block_size];
        uint8_t     leftover;
        bool        final;

        void init(const uint8_t* k);
        void poly1305_blocks(const uint8_t* m, size_t len);
        void fin(uint8_t* tag);
    };

    struct state
    {
        union
        {
            internal_sse2 isse2;
            internal_donna idonna;
        };
    };
    aligned_data<state, 16> internal;
#else
    aligned_data<internal_sse2, 16> internal;
#endif


public:
    void init(const uint8_t* k);
    void update(std::span<const uint8_t> m);
    void fin(uint8_t *tag); // tag must be 16 bytes len (tag_size)
    bool ready() const { return false; }

    enum consts
    {
        tag_size = 16,
        key_size = 32,
    };
};

class BotanPoly1305 final : public Botan::MessageAuthenticationCode {
    poly1305 core;
public:

    std::unique_ptr<MessageAuthenticationCode> new_object() const override { return std::make_unique<BotanPoly1305>(); }

    void clear() override { core.init(nullptr); }

    size_t output_length() const override { return poly1305::tag_size; }

    Botan::Key_Length_Specification key_spec() const override { return Botan::Key_Length_Specification(poly1305::key_size); }

    bool fresh_key_required_per_message() const override { return true; }

    bool has_keying_material() const override
    {
        return core.ready();
    }

private:
    void add_data(std::span<const uint8_t> d) override
    {
        core.update(d);
    }
    void final_result(std::span<uint8_t> r) override
    {
        core.fin(r.data());
    }
    void key_schedule(std::span<const uint8_t> k) override
    {
        core.init(k.data());
    }
};

