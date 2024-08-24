#include "pch.h"

namespace ma
{

#define COUNT_ALLOCS
#define USE_ARENAS

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

			void up()
			{
				spinlock::simple_lock(aaa.async);

				++total;
				++count;
				if (peak < count)
					peak = count;

				spinlock::simple_unlock(aaa.async);

			}

			void dn()
			{
				spinlock::simple_lock(aaa.async);

				--count;

				spinlock::simple_unlock(aaa.async);

			}
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

	} aaa;
#endif

	template<size_t elsz, signed_t arsz, typename fallback> struct arena
	{
		volatile spinlock::long3264 ff = 0;
		u8 buf[elsz * arsz];
#ifdef _DEBUG
		signed_t current = 0, peak = 0;
#endif
		arena()
		{
			static_assert(elsz >= sizeof(int));

			for (signed_t i = 0; i < arsz; ++i)
			{
				int* ef = (int*)(buf + (elsz * i));
				*ef = (int)(i + 1);
			}
		}

		bool here(const void* p) const
		{
			const u8* pp = (u8*)p;
			signed_t index = (pp - buf) / elsz;
			if (index < 0 || index >= arsz)
				return false;
			return true;
		}

		void* alloc(size_t sz)
		{
			spinlock::long3264 unlockff = ff & ~(0x80000000ull);
			if (unlockff < arsz)
			{
				spinlock::long3264 lockff;

				for (;;)
				{
					unlockff = ff & ~(0x80000000ull);
					lockff = 0x80000000ull | unlockff;
					if (spinlock::atomic_replace(ff, unlockff, lockff))
						break; // lock success
					_mm_pause();
				}

				int* nf = (int*)(buf + (elsz * unlockff));
				unlockff = *nf;

#ifdef _DEBUG
				++current;
				if (current > peak)
					peak = current;
#endif

				if (unlockff < 0)
					DEBUGBREAK();
				bool ok = spinlock::atomic_replace(ff, lockff, unlockff);
				if (!ok)
					DEBUGBREAK();

				return nf;
			}
			return fallback::alloc(sz);
		}

		bool free(void* p)
		{
			u8* pp = (u8*)p;
			signed_t index = (pp - buf) / elsz;
			if (index < 0 || index >= arsz)
				return false;

			spinlock::long3264 unlockff;
			spinlock::long3264 lockff;
			for (;;)
			{
				unlockff = ff & ~(0x80000000ull);
				lockff = 0x80000000ull | unlockff;
				if (spinlock::atomic_replace(ff, unlockff, lockff))
					break; // lock success
				_mm_pause();
			}

			int* ef = (int*)(buf + (elsz * index));
			*ef = (int)unlockff;
			unlockff = index;

#ifdef _DEBUG
			--current;
#endif

			if (unlockff < 0)
				DEBUGBREAK();
			bool ok = spinlock::atomic_replace(ff, lockff, unlockff);
			if (!ok)
				DEBUGBREAK();

			return true;
		}
	};

#ifdef USE_ARENAS
	struct fb0
	{
		static void* alloc(size_t x)
		{
			return malloc(x);
		}
	};

	arena<64, 2048, fb0> arena64;

	struct fb1
	{
		static void* alloc(size_t x)
		{
			return arena64.alloc(x);
		}
	};

	arena<32, 2048, fb1> arena32;

	struct fb2
	{
		static void* alloc(size_t x)
		{
			return arena32.alloc(x);
		}
	};

	arena<8, 1024, fb2> arena8;
#endif

	void* rs(void* p, size_t size)
	{
#ifdef USE_ARENAS
		if (arena8.here(p))
		{
			if (size <= 8)
				return p;
			void* np = ma(size);
			memcpy(np, p, 8);
			arena8.free(p);
			return np;
		}
		if (arena32.here(p))
		{
			if (size <= 32)
				return p;
			void* np = ma(size);
			memcpy(np, p, 32);
			arena32.free(p);
			return np;
		}
		if (arena64.here(p))
		{
			if (size <= 64)
				return p;
			void* np = ma(size);
			memcpy(np, p, 64);
			arena64.free(p);
			return np;
		}
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			return aaa.realloc(p, size);
#endif

		return realloc(p, size);
	}

	void* ma(size_t size)
	{
#ifdef USE_ARENAS
		if (size <= 8)
			return arena8.alloc(size);
		if (size <= 32)
			return arena32.alloc(size);
		if (size <= 64)
			return arena64.alloc(size);
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			return aaa.alloc(size);
#endif
		return malloc(size);
	}
	void mf(void* p)
	{
#ifdef USE_ARENAS
		if (arena8.free(p))
			return;
		if (arena32.free(p))
			return;
		if (arena64.free(p))
			return;
#endif

#if defined _DEBUG && defined COUNT_ALLOCS
		if (true)
			aaa.free(p);
		else
#endif
		free(p);
	}
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

