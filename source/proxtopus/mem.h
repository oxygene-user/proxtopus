#pragma once

//#define MEMSPY
#define USE_DLMALLOC 1
#define USE_ARENAS 0

#if USE_DLMALLOC
extern "C"
{
    void* dlmalloc(size_t);
    void  dlfree(void*);
    void* dlrealloc(void*, size_t);
    void* dlcalloc(size_t, size_t);
    size_t dlmalloc_usable_size(void*);
};
#endif

#ifdef _NIX
#include <stdint.h>
#include <memory.h>
#endif

namespace ma
{
#ifdef MEMSPY
    void* ma(const char* f, size_t l, size_t size);
    void* rs(const char* f, size_t l, void* p, size_t size);
#else
#if USE_DLMALLOC
    inline void* ma(size_t size)
    {
        return dlmalloc(size);
    }
    inline void* rs(void* p, size_t size, size_t keep_data)
    {
        if (size > dlmalloc_usable_size(p))
        {
            if (keep_data == 0)
            {
                // no need to copy old data to new allocated chunk
                dlfree(p);
                return dlmalloc(size);
            }
            void *new_p = dlmalloc(size);
            memcpy(new_p, p, keep_data);
            dlfree(p);
            return new_p;
        }

        return dlrealloc(p, size);
    }
    inline void mf(void* p)
    {
        dlfree(p);
    }
#else
    void* ma(size_t size);
    void* rs(void* p, size_t size, size_t keep_data);
    void mf(void* p);
#endif
#endif
}


#ifdef MEMSPY
void* operator new(size_t size, const char* f, size_t l);
void operator delete(void *p, const char* f, size_t l);
#define NEW new (__FILE__, __LINE__)
#define MA(sz) ma::ma(__FILE__, __LINE__, sz)
#define MRS(p, sz, kd) ma::rs(__FILE__, __LINE__, p, sz, kd)
#else
#define NEW new
#define MA(sz) ma::ma(sz)
#define MRS(p, sz, kd) ma::rs(p, sz, kd)
#endif
