#include "pch.h"

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

	void* rs(void* p, size_t size)
	{
#ifdef USE_ARENAS
		if (glb.arena16.here(p))
		{
			if (size <= 16)
				return p;
			void* np = ma(size);
			memcpy(np, p, 16);
			glb.arena16.free(p);
			return np;
		}
		if (glb.arena32.here(p))
		{
			if (size <= 32)
				return p;
			void* np = ma(size);
			memcpy(np, p, 32);
			glb.arena32.free(p);
			return np;
		}
		if (glb.arena64.here(p))
		{
			if (size <= 64)
				return p;
			void* np = ma(size);
			memcpy(np, p, 64);
			glb.arena64.free(p);
			return np;
		}
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			return aaa().realloc(p, size);
#endif

		return realloc(p, size);
	}

	void* ma(size_t size)
	{
#ifdef USE_ARENAS
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
	void mf(void* p)
	{
#ifdef USE_ARENAS
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

global_data::global_data()
{
#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
	cfg.crash_log_file = str::astr(ASTR("imconee.crush.log"));
	cfg.dump_file = str::astr(ASTR("imconee.dmp"));
#endif

}

void* operator new(std::size_t size) {
	return ma::ma(size);
}

void* operator new[](std::size_t size) {
	return ma::ma(size);
}

void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
	return ma::ma(size);
}

void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
	return ma::ma(size);
}


void* operator new(std::size_t size, std::align_val_t /*alignment*/) {
	return ma::ma(size);
}

void* operator new[](std::size_t size, std::align_val_t /*alignment*/) {
	return ma::ma(size);
}

void* operator new(std::size_t size, std::align_val_t /*alignment*/, const std::nothrow_t&) noexcept {
	return ma::ma(size);
}

void* operator new[](std::size_t size, std::align_val_t /*alignment*/, const std::nothrow_t&) noexcept {
	return ma::ma(size);
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

