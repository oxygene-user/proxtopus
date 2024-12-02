#pragma once

template <typename T> struct has_alloc {
    typedef char one;
    struct two { char x[2]; };

    template <typename C> static one test(decltype(&C::alloc));
    template <typename C> static two test(...);

public:
    enum { value = sizeof(test<T>(0)) == sizeof(char) };
};

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
		while (unlockff < arsz)
		{
			spinlock::long3264 lockff;

            for (spinlock::long3264 spincount = 0;; ++spincount)
			{
				unlockff = ff & ~(0x80000000ull);
				lockff = 0x80000000ull | unlockff;
				if (spinlock::atomic_replace(ff, unlockff, lockff))
					break; // lock success

				if (g_single_core || spincount > 10000)
					spinlock::sleep((spincount >> 17) & 0xff);
                else
                    spinlock::sleep();
			}

			if (unlockff >= arsz)
			{
				spinlock::atomic_replace(ff, lockff, unlockff);
				break;
			}

			int* nf = (int*)(buf + (elsz * unlockff));

#ifdef _DEBUG
			++current;

			if (current > arsz)
				DEBUGBREAK();

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

		if constexpr (has_alloc<fallback>::value)
		{
			return fallback::alloc(sz);
		}
		else
		{
            return fallback()(sz);
		}

	}

	bool free(void* p)
	{
		u8* pp = (u8*)p;
		signed_t index = (pp - buf) / elsz;
		if (index < 0 || index >= arsz)
			return false;

		spinlock::long3264 unlockff;
		spinlock::long3264 lockff;
		for (spinlock::long3264 spincount = 0;;++spincount)
		{
			unlockff = ff & ~(0x80000000ull);
			lockff = 0x80000000ull | unlockff;
			if (spinlock::atomic_replace(ff, unlockff, lockff))
				break; // lock success

            if (g_single_core || spincount > 10000)
                spinlock::sleep((spincount >> 17) & 0xff);
            else
                spinlock::sleep();
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

