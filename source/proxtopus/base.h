#pragma once

#define USE_ARENAS
#ifdef _DEBUG
//#define COUNT_ALLOCS
//#define LOG_TRAFFIC
#endif


#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__)
#define MODE64
#define ARCHBITS 64
#else
#define ARCHBITS 32
#endif

typedef signed short i16;
typedef ptrdiff_t signed_t;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
typedef long i32;

#if defined(_MSC_VER)
typedef signed __int64		i64;
typedef unsigned __int64	u64;
#elif defined(__GNUC__)
typedef int64_t	i64;
typedef uint64_t u64;
using WORD = uint16_t;
#endif


#define SLASSERT ASSERT
#define SLERROR(...) do {ERRORM(__FILE__, __LINE__, ##__VA_ARGS__); DEBUGBREAK(); } while(false)

#define ERRORM(fn, ln, ...) (([&]()->bool { Print(FOREGROUND_RED, "%s\n", str::build_string_d(fn, ln, ##__VA_ARGS__).c_str()); return true; })())
#define ASSERT(expr,...) NOWARNING(4800, ((expr) || (ERRORM(__FILE__, __LINE__, ##__VA_ARGS__) ? (SMART_DEBUG_BREAK, false) : false))) // (...) need to make possible syntax: ASSERT(expr, "Message")

#ifdef _MSC_VER
#define DEBUGBREAK() __debugbreak()
#define NOWARNING(n,...) __pragma(warning(push)) __pragma(warning(disable:n)) __VA_ARGS__ __pragma(warning(pop))
#define NIXONLY(...)
#define UNREACHABLE() __assume(0)
#endif

#ifdef __GNUC__
#define UNREACHABLE() __builtin_unreachable()
#define DEBUGBREAK() __builtin_trap()
#define NOWARNING(n,...) __VA_ARGS__
#endif

#ifdef _NIX
#define NIXONLY(...) __VA_ARGS__

#define MB_OK 1
#define MB_ICONWARNING 2
#define FOREGROUND_RED 4
#define FOREGROUND_GREEN 2
#define FOREGROUND_BLUE 1
#define FOREGROUND_INTENSITY 8
#endif
#define FOREGROUND_WHITE 7

#ifndef _DEBUG
#define SMART_DEBUG_BREAK (is_debugger_present() ? DEBUGBREAK(), false : false)
#else
#define SMART_DEBUG_BREAK DEBUGBREAK() // always break in debug
#endif

inline bool is_debugger_present()
{
#ifdef _WIN32
	return IsDebuggerPresent() != FALSE;
#endif
	return false;
}

void Print(); // print current queue
void Print(const char* format, ...);
void Print(signed_t color, const char* format, ...);
void Print(const std::vector<char>& txt);

