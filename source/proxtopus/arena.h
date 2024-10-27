#pragma once

template<size_t elsz, signed_t arsz, typename fallback> struct arena
{
	volatile spinlock::long3264 ff = 0;
	u8 buf[elsz * arsz];
#ifdef _DEBUG
	u64 corrupt_guard = 123456789;
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
#ifdef _DEBUG
		ASSERT(corrupt_guard == 123456789);
#endif

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

#ifdef _DEBUG
			++current;
			if (current > peak)
				peak = current;

			spinlock::long3264 unlockff1 = *nf;

			if (unlockff1 < 0)
				DEBUGBREAK();

#endif

			unlockff = *nf;

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

