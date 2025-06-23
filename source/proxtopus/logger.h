#pragma once

#if LOGGER==2
class logger
{
	size_t lock = 0;
	bool muted = false;
	//logger& operator <<(const str::astr& s);
	//logger& operator <<(const char* s);
	//logger& operator <<(signed_t x);

public:

    static void mute();
    static void unmute();
	static void newline(int color_, const str::astr_view& s);
    static void log2file(const FN& logfn, const str::astr_view &s);
};

enum severity_e
{
	SEV_NOTE,
	SEV_IMPORTANT,
	SEV_WARNING,
	SEV_ERROR,
	SEV_DEBUG,
};

enum dlchnl_e
{
    DLCH_DNS,
	DLCH_REBOOT,
	DLCH_SOCKET,
};

#define DL(chnl, ...) if (0 != (glb.cfg.debug_log_mask & (1ull << (chnl)))) logger::log2file(glb.cfg.debug_log_file, str::build_string(__VA_ARGS__).c_str())

#define LOG_N(...) if (log_enabled()) logger::newline(SEV_NOTE, str::build_string(__VA_ARGS__))
#define LOG_I(...) if (log_enabled()) logger::newline(SEV_IMPORTANT, str::build_string(__VA_ARGS__))
#define LOG_W(...) if (log_enabled()) logger::newline(SEV_WARNING, str::build_string(__VA_ARGS__))
#define LOG_E(...) if (log_enabled()) logger::newline(SEV_ERROR, str::build_string(__VA_ARGS__))
#define LOG_FATAL(...) logger::unmute(); logger::newline(SEV_ERROR, str::build_string(__VA_ARGS__))
#ifdef _DEBUG
#define LOG_D(...) logger::newline(SEV_DEBUG, str::build_string(__VA_ARGS__))
#else
#define LOG_D(...) do {} while(false)
#endif

#else
#if LOGGER == 1
// simple logging
// not yet supported
#define LOG_N(...) Print(__VA_ARGS__)
#define LOG_I(...) Print(FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY, __VA_ARGS__)
#define LOG_W(...) Print(FOREGROUND_RED | FOREGROUND_GREEN, __VA_ARGS__)
#define LOG_E(...) Print(FOREGROUND_RED, __VA_ARGS__)
#define LOG_D(...) do {} while(false)
#else
#define LOG_N(...) do {} while(false)
#define LOG_I(...) do {} while(false)
#define LOG_E(...) do {} while(false)
#define LOG_W(...) do {} while(false)
#define LOG_D(...) do {} while(false)
#endif

#endif

void debug_print(str::astr_view s);
