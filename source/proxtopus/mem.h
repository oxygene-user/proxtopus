#pragma once

//#define MEMSPY
#define USE_ARENAS

namespace ma
{
#ifdef MEMSPY
    void* ma(const char* f, size_t l, size_t size);
    void* rs(const char* f, size_t l, void* p, size_t size);
#else
    void* ma(size_t size);
    void* rs(void* p, size_t size);
#endif
    void mf(void* p);
}


#ifdef MEMSPY
void* operator new(size_t size, const char* f, size_t l);
void operator delete(void *p, const char* f, size_t l);
#define NEW new (__FILE__, __LINE__)
#define MA(sz) ma::ma(__FILE__, __LINE__, sz)
#define MRS(p, sz) ma::rs(__FILE__, __LINE__, p, sz)
#else
#define NEW new
#define MA(sz) ma::ma(sz)
#define MRS(p, sz) ma::rs(p, sz)
#endif
