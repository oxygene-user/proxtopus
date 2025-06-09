#include "pch.h"

#ifdef MEMSPY
#include "../debug/memspy.h"
#endif

namespace ma
{


#if defined _DEBUG && defined COUNT_ALLOCS
	struct aa
	{
		spinlock::long3264 async = 0;

		struct meminfo
		{
			int sz = 0;
			int count = 0;
			int peak = 0;
			int total = 0;

			void up();
			void dn();
		};

		meminfo allocs[22];

		aa()
		{
			spinlock::simple_lock(async);

			for (int i = 0, sz = 2; i < 22; ++i, sz <<= 1)
				allocs[i].sz = sz;

			spinlock::simple_unlock(async);
		}

		void * alloc(size_t sz)
		{
			for (meminfo& mi : allocs)
			{
				if (sz <= mi.sz)
				{
					u8* p = (u8 *)malloc(sz + 16);

					*((size_t*)p) = sz;
					//*((int*)(p + 4)) = _msize;
					mi.up();
					return p + 16;
				}
			}
			DEBUGBREAK();
			UNREACHABLE();
		}
		void* realloc(void *p, size_t sz)
		{
			u8* bp = (u8*)p;
			u8* psz = (u8*)(bp-16);
			size_t asz = *((size_t*)psz);
			u8* np = (u8 *)::realloc(psz, sz + 16);

			for (meminfo& mi : allocs)
			{
				if (asz <= mi.sz)
				{
					mi.dn();
					break;
				}
			}

			for (meminfo& mi : allocs)
			{
				if (sz <= mi.sz)
				{
					*((size_t*)np) = sz;
					mi.up();
					return np + 16;
				}
			}

			DEBUGBREAK();
			UNREACHABLE();
		}
		void free(void *p)
		{
			if (p == nullptr)
				return;
			u8* bp = (u8*)p;
			u8* psz = (u8*)(bp - 16);
			size_t asz = *((size_t*)psz);
			::free(psz);

			for (meminfo& mi : allocs)
			{
				if (asz <= mi.sz)
				{
					mi.dn();
					break;
				}
			}
		}

	};

	u8 aaabuf[sizeof(aa)];
	aa& aaa()
	{
		return ref_cast<aa>(aaabuf);
	}

	void aa::meminfo::up()
	{
		spinlock::simple_lock(aaa().async);

		++total;
		++count;
		if (peak < count)
			peak = count;

		spinlock::simple_unlock(aaa().async);

	}

	void aa::meminfo::dn()
	{
		spinlock::simple_lock(aaa().async);

		--count;

		spinlock::simple_unlock(aaa().async);

	}

#endif

#ifdef MEMSPY
	void* rs(const char* f, size_t l, void* p, size_t size, bool /*allow_discard_old_content*/)
#else
#if USE_DLMALLOC
	void* rs_dummy(void* p, size_t size, size_t keep_data)
#else
    void* rs(void* p, size_t size, size_t keep_data)
#endif
#endif
	{
#ifdef MEMSPY
        if (true)
            return mspy_realloc(f, (int)l, 0, p, size);
#endif

#if USE_ARENAS
		if (glb.arena16.here(p))
		{
			if (size <= 16)
				return p;
			void* np = MA(size);
			memcpy(np, p, keep_data);
			glb.arena16.free(p);
			return np;
		}
		if (glb.arena32.here(p))
		{
			if (size <= 32)
				return p;
			void* np = MA(size);
            memcpy(np, p, keep_data);
			glb.arena32.free(p);
			return np;
		}
		if (glb.arena64.here(p))
		{
			if (size <= 64)
				return p;
			void* np = MA(size);
            memcpy(np, p, keep_data);
			glb.arena64.free(p);
			return np;
		}
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			return aaa().realloc(p, size);
#endif
		if (keep_data == 0)
		{
			// TODO : check that malloc/free will be faster than realloc, since there is no need to copy memory
			//_msize();
		}

		return realloc(p, size);
	}

#ifdef MEMSPY
	void* ma(const char* f, size_t l, size_t size)
#else
#if USE_DLMALLOC
    void* ma_dummy(size_t size)
#else
	void* ma(size_t size)
#endif
#endif
	{
#ifdef MEMSPY
		if (true)
			return mspy_malloc(f, (int)l, 0, size);
#endif

#if USE_ARENAS
		if (size <= 16)
			return glb.arena16.alloc(size);
		if (size <= 32)
			return glb.arena32.alloc(size);
		if (size <= 64)
			return glb.arena64.alloc(size);
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			return aaa().alloc(size);
#endif
		return malloc(size);
	}

#if USE_DLMALLOC
    void mf_dummy(void* p)
#else
	void mf(void* p)
#endif
	{
#ifdef MEMSPY
		if (true)
		{
			mspy_free(p);
			return;
		}
#endif

#if USE_ARENAS
		if (glb.arena16.free(p))
			return;
		if (glb.arena32.free(p))
			return;
		if (glb.arena64.free(p))
			return;
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			aaa().free(p);
		else
#endif
		free(p);
	}
}

global_data::first_init::first_init()
{
#if defined _DEBUG && defined COUNT_ALLOCS
	new (&ma::aaa()) ma::aa();
#endif
}

#ifdef MEMSPY
void* operator new(std::size_t size, const char* f, std::size_t l) {
    return ma::ma(f,l,size);
}
void operator delete(void *ptr, const char*, std::size_t) {
	ma::mf(ptr);
}
#endif


void* operator new(std::size_t size) {
	return MA(size);
}

void* operator new[](std::size_t size) {
	return MA(size);
}

void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
	return MA(size);
}

void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
	return MA(size);
}


void* operator new(std::size_t size, std::align_val_t /*alignment*/) {
	return MA(size);
}

void* operator new[](std::size_t size, std::align_val_t /*alignment*/) {
	return MA(size);
}

void* operator new(std::size_t size, std::align_val_t /*alignment*/, const std::nothrow_t&) noexcept {
	return MA(size);
}

void* operator new[](std::size_t size, std::align_val_t /*alignment*/, const std::nothrow_t&) noexcept {
	return MA(size);
}

void operator delete(void* ptr) noexcept {
	ma::mf(ptr);
}

void operator delete[](void* ptr) noexcept {
	ma::mf(ptr);
}

void operator delete(void* ptr, const std::nothrow_t&) noexcept {
	ma::mf(ptr);
}

void operator delete[](void* ptr, const std::nothrow_t&) noexcept {
	ma::mf(ptr);
}

void operator delete(void* ptr, std::align_val_t) noexcept {
	ma::mf(ptr);
}

void operator delete[](void* ptr, std::align_val_t) noexcept {
	ma::mf(ptr);
}

void operator delete(void* ptr, std::align_val_t, const std::nothrow_t&) noexcept {
	ma::mf(ptr);
}

void operator delete[](void* ptr, std::align_val_t, const std::nothrow_t&) noexcept {
	ma::mf(ptr);
}

void operator delete(void* ptr, std::size_t /*size*/, std::align_val_t /*alignment*/) noexcept {
	ma::mf(ptr);
}

void operator delete[](void* ptr, std::size_t /*size*/, std::align_val_t /*alignment*/) noexcept {
	ma::mf(ptr);
}

// dlmalloc -----------------

#ifdef _MSC_VER
#pragma warning (disable:4559)
#pragma warning (disable:4127)
#pragma warning (disable:4057)
#pragma warning (disable:4702)
#endif // _MSC_VEW

#define MALLOC_ALIGNMENT ((size_t)16U)
#define USE_DL_PREFIX
#define USE_LOCKS 0

static size_t dlmalloc_spinlock = 0;

#define PREACTION(M)  (spinlock::simple_lock_spincount(dlmalloc_spinlock, 10000), 0)
#define POSTACTION(M) spinlock::simple_unlock(dlmalloc_spinlock)

#define _NTOS_
#undef ERROR
#undef M_TRIM_THRESHOLD
#undef M_MMAP_THRESHOLD
#define mallinfo dlmallinfo

#include "dlmalloc/dlmalloc.c"
