#pragma once

#define PROXTOPUS_VER "0.8"

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
	FN crash_log_file;
	FN dump_file;
#endif
	FN log_file;
	FN debug_log_file;
	signed_t debug_log_mask = 0;
	getip_options ipstack = gip_prior4;
	dns_options dnso = dnso_internal_with_hosts;

	conf()
	{
	}
};

#if USE_ARENAS
inline void* alloc_arena64(size_t x);
inline void* alloc_arena32(size_t x);
#endif

class dns_resolver;

struct actual_process
{
#ifdef _WIN32
	HANDLE evt = nullptr;
#else
	pid_t pid = 0;
#endif
	void actualize();
	void terminate();
};

struct global_data
{
	struct first_init { first_init(); } _finint;

	engine* e = nullptr;
	FN path_config;
	const str::astr emptys;

	actual_process actual_proc;
	signed_t ppid = 0;

#if LOGGER==2
	bool log_muted = false;
#endif
	bool actual = false;
	bool listeners_need_all = false;
	u8   bind_try_count = 1;

#ifdef _WIN32
	HMODULE module = nullptr;
	SERVICE_STATUS_HANDLE hSrv = nullptr;
#endif
	conf cfg;
	std::unique_ptr<dns_resolver> dns;

#if USE_ARENAS
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

	struct print_line
	{
		char* data = nullptr;
		signed_t data_len = 0;
		u16 color = 0;
		bool use_color = false;
		WINONLY(bool oem_convert = false;)
		print_line(const char *s, signed_t sl, bool nl = false);
		print_line(const print_line&) = delete;
		print_line(print_line&& pl)
		{
            data = pl.data;
			data_len = pl.data_len;
            pl.data = nullptr;
			pl.data_len = 0;
            color = pl.color;
            use_color = pl.use_color;
            WINONLY(oem_convert = pl.oem_convert;)
		}
		void operator=(const print_line&) = delete;
		void operator=(print_line&& pl)
		{
			ma::mf(data);
			data = pl.data;
			data_len = pl.data_len;
			pl.data = nullptr;
			pl.data_len = 0;
			color = pl.color;
			use_color = pl.use_color;
			WINONLY(oem_convert = pl.oem_convert;)
		}
        ~print_line();
		str::astr_view view() const
		{
			return str::astr_view(data, data_len);
		}
	};

	spinlock::syncvar<std::vector<print_line>> prints;
    Botan::HKDF kdf = Botan::HKDF(std::make_unique<Botan::HMAC>(std::make_unique<Botan::SHA_1>()));
	interceptor icpt;

private:
	volatile bool exit = false;
public:
	volatile size_t numlisteners = 0;
	volatile size_t numtcp = 0; // number of tcp processing threads
	volatile size_t numudp = 0; // number of udp processing threads

	void stop();
	bool is_stop() { return exit; }

	//void restart(); // restart current app

	global_data();
};

extern global_data glb;

inline bool log_enabled()
{
    return !glb.log_muted || !glb.cfg.log_file.empty();
}

#if USE_ARENAS
inline void* alloc_arena64(size_t x)
{
	return glb.arena64.alloc(x);
}
inline void* alloc_arena32(size_t x)
{
	return glb.arena32.alloc(x);
}
#endif

