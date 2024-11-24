#pragma once


// use crt malloc/realloc/free by default
#ifndef MEMSPY_SYS_ALLOC
#define MEMSPY_SYS_ALLOC(sz) malloc(sz)
#endif

#ifndef MEMSPY_SYS_RESIZE
#define MEMSPY_SYS_RESIZE(ptr,sz) realloc(ptr,sz)
#endif

#ifndef MEMSPY_SYS_FREE
#define MEMSPY_SYS_FREE(ptr) free(ptr)
#endif

#ifndef MEMSPY_SYS_SIZE
#ifdef _WIN32
#define MEMSPY_SYS_SIZE(ptr) _msize(ptr)
#endif
#ifdef __linux__
#define MEMSPY_SYS_SIZE(ptr) malloc_usable_size(ptr)
#endif
#endif

void *mspy_malloc(const char *fn, int line, int typ, size_t sz);
void *mspy_realloc(const char *fn, int line, int typ, void *p, size_t sz);
void mspy_free(void *p);
size_t mspy_size(void *p);

typedef void memcb( int typ, int num, size_t size, void *prm );

bool mspy_getallocated_info( memcb *cb, void *prm );
bool mspy_getallocated_info( char *buf, int bufsz ); // call at end of app to get allocated memory info (leaks)
void reset_allocnum();