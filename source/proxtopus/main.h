#pragma once

struct conf
{
	enum getip_options
	{
		gip_prior4, // any, but 4 first
		gip_prior6, // any, but 6 first
		gip_only4,
		gip_only6,

		gip_log_it = (1 << 8),	// log if cant resolve
		gip_any = (2 << 8),		// don't resolve prior/only if already resolved
	};

	enum dns_options
	{
		dnso_internal, // only internal dns resolver
		dnso_system, // only system dns resolver

		dnso_mask = 0xff,
		dnso_bit_parse_hosts = 0x100, // valid only with internal
		dnso_bit_use_system = 0x200, // valid only with internal

		dnso_internal_with_hosts = dnso_internal | dnso_bit_parse_hosts,
	};


#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
	str::astr crash_log_file;
	str::astr dump_file;
#endif
	getip_options ipstack = gip_prior4;
	dns_options dnso = dnso_internal_with_hosts;

	conf()
	{
	}
};

#ifdef USE_ARENAS
inline void* alloc_arena64(size_t x);
inline void* alloc_arena32(size_t x);
#endif

class dns_resolver;

struct global_data
{
	struct first_init { first_init(); } _finint;

	FN path_config;
	str::astr emptys;


#if LOGGER==2
	bool log_muted = false;
#endif

#ifdef _WIN32
	SERVICE_STATUS_HANDLE hSrv = nullptr;
#endif
	conf cfg;
	std::unique_ptr<dns_resolver> dns;

#ifdef USE_ARENAS
	struct fb0
	{
		static void* alloc(size_t x)
		{
			return malloc(x);
		}
	};

	arena<64, 4096, fb0> arena64;

	struct fb1
	{
		static void* alloc(size_t x)
		{
			return alloc_arena64(x);
		}
	};

	arena<32, 2048, fb1> arena32;

	struct fb2
	{
		static void* alloc(size_t x)
		{
			return alloc_arena32(x);
		}
	};

	arena<16, 512, fb2> arena16;
#endif

#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
	dbg::exceptions_best_friend ebf;
#endif

	spinlock::syncvar<std::vector<str::astr>> prints;
    Botan::HKDF kdf = Botan::HKDF(std::make_unique<Botan::HMAC>(std::make_unique<Botan::SHA_1>()));

private:
	volatile bool exit = false;
public:
	volatile spinlock::long3264 numlisteners = 0;

	void stop() { Print(); exit = true; }
	bool is_stop() { return exit; }

	global_data();
};

extern global_data glb;

#ifdef USE_ARENAS
inline void* alloc_arena64(size_t x)
{
	return glb.arena64.alloc(x);
}
inline void* alloc_arena32(size_t x)
{
	return glb.arena32.alloc(x);
}
#endif

