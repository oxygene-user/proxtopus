#pragma once

#if LOGGER==2
class logger
{
	spinlock::long3264 lock = 0;
	bool muted = false;
	//logger& operator <<(const str::astr& s);
	//logger& operator <<(const char* s);
	//logger& operator <<(signed_t x);

public:

	void mute() { muted = true; }
	void newline(int color_, const str::astr& s);
};

extern logger lg;

enum severity_e
{
	SEV_NOTE,
	SEV_IMPORTANT,
	SEV_WARNING,
	SEV_ERROR,
};

#define LOG_N(...) lg.newline(SEV_NOTE, str::build_string(__VA_ARGS__))
#define LOG_I(...) lg.newline(SEV_IMPORTANT, str::build_string(__VA_ARGS__))
#define LOG_W(...) lg.newline(SEV_WARNING, str::build_string(__VA_ARGS__))
#define LOG_E(...) lg.newline(SEV_ERROR, str::build_string(__VA_ARGS__))

#else
#if LOGGER == 1
#define LOG_N(...) Print(__VA_ARGS__)
#define LOG_I(...) Print(FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY, __VA_ARGS__)
#define LOG_W(...) Print(FOREGROUND_RED | FOREGROUND_GREEN, __VA_ARGS__)
#define LOG_E(...) Print(FOREGROUND_RED, __VA_ARGS__)
#else
#define LOG_N(...) do {} while(false)
#define LOG_I(...) do {} while(false)
#define LOG_E(...) do {} while(false)
#define LOG_W(...) do {} while(false)
#endif

#endif