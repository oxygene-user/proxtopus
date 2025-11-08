#include "pch.h"

#ifdef _NIX
#ifdef HAVE_GETRANDOM
#define HAVE_LINUX_COMPATIBLE_GETRANDOM
#else
#include <sys/syscall.h>
#if defined(SYS_getrandom) && defined(__NR_getrandom)
#define getrandom(B, S, F) syscall(SYS_getrandom, (B), (int) (S), (F))
#define HAVE_LINUX_COMPATIBLE_GETRANDOM
#endif
#endif

#endif

randomgen& randomgen::get()
{
    static thread_local randomgen rndg;
    return rndg;
}

void randomgen::rnd(void* const buf_, size_t size) // extra rnd
{
    if (!chacha)
    {
        u8 keyiv[64];
        size_t i = 0;
        auto add_entropy = [&](u64 val)
            {
                for (; val && i < sizeof(keyiv); val >>= 8, ++i)
                {
                    keyiv[i] = static_cast<u8>(val & 0xff);
                }
                return i == sizeof(keyiv);
            };

        add_entropy(chrono::tsc());
        add_entropy(chrono::ms().raw());
        add_entropy(reinterpret_cast<size_t>(this));
        add_entropy(spinlock::current_thread_uid());

        chacha.reset(NEW chacha20());
        chacha->set_key(std::span<const u8, chacha20::key_size>(keyiv, chacha20::key_size));
        chacha->set_iv(std::span<const u8>(keyiv+ chacha20::key_size, 12));
        chacha->keystream(keyiv, 64); // skip 1st block
    }
    chacha->keystream((u8*)buf_, size);
}


#ifdef HAVE_LINUX_COMPATIBLE_GETRANDOM
static bool getrandom256(void* const buf, const size_t size)
{
    int readnb;
    do {
        readnb = getrandom(buf, size, 0);
    } while (readnb < 0 && (errno == EINTR || errno == EAGAIN));

    return readnb == (int)size;
}

#endif

void randomgen::randombytes_buf(void* const buf_, size_t size)
{
#ifdef HAVE_LINUX_COMPATIBLE_GETRANDOM

    if (size <= 256)
    {
        if (!getrandom256(buf_, size))
            rnd(buf_, size);
        return;
    }

    u8* buf = (u8*)buf_;
    size_t chunk_size = 256U;

    do {
        if (size < chunk_size) {
            chunk_size = size;
        }
        if (!getrandom256(buf, chunk_size)) {

            rnd(buf_, size);
            return;
        }
        size -= chunk_size;
        buf += chunk_size;
    } while (size > (size_t)0U);
    return;
#elif defined(_WIN32)
    if (!glb.win32random(buf_, (ULONG)size)) // ok ok! if is correct
#endif
        rnd(buf_, size);

}

