#pragma once

#ifdef _DEBUG
//#define COUNT_ALLOCS
//#define LOG_TRAFFIC
#endif

#include "mem.h"

class Endian
{
public:
    Endian() = delete;

    static constexpr bool little = std::endian::native == std::endian::little;
    static constexpr bool big = std::endian::native == std::endian::big;
};

#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__)
#define MODE64
#define ARCHBITS 64
#else
#define ARCHBITS 32
#endif

using i16 = int16_t;
using signed_t = ptrdiff_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using i32 = int32_t;

static_assert(sizeof(u32) == 4);

#if defined(_MSC_VER)
typedef signed __int64		i64;
typedef unsigned __int64	u64;
#elif defined(__GNUC__)
using i64 = int64_t;
using u64 = uint64_t;
using WORD = uint16_t;
#endif


template<typename Tout, typename Tin> Tout& ref_cast(Tin& t)
{
    static_assert(sizeof(Tout) <= sizeof(Tin), "ref cast fail");
    return (Tout&)t;
}
template<typename Tout, typename Tin> const Tout& ref_cast(const Tin& t) //-V659
{
    static_assert(sizeof(Tout) <= sizeof(Tin), "ref cast fail");
    return *(const Tout*)&t;
}

template<typename Tout, typename Tin> const Tout& ref_cast(const Tin& t1, const Tin& t2)
{
    static_assert(sizeof(Tout) <= (sizeof(Tin) * 2), "ref cast fail");
    ASSERT(((u8*)&t1) + sizeof(Tin) == (u8*)&t2);
    return *(const Tout*)&t1;
}

#ifdef MODE64
struct u128
{
    u64 low;
    u64 hi;

    u128() {}
    u128(u64 v) :low(v), hi(0)
    {
    }

    operator u64() const
    {
        return low;
    }

    bool operator >= (u64 v) const
    {
        return hi > 0 || low >= v;
    }

    u128& operator=(u64 v)
    {
        low = v;
        hi = 0;
        return *this;
    }

    u128& operator-=(u128 v)
    {
        if (low < v.low)
        {
            hi -= v.hi - 1;
            low -= v.low;
        }
        else
        {
            hi -= v.hi;
            low -= v.low;
        }
        return *this;
    }
    u128& operator+=(u64 v)
    {
#ifdef _MSC_VER
        _addcarry_u64(_addcarry_u64(0, low, v, &low), hi, 0, &hi);
#endif
#ifdef __GNUC__
        DEBUGBREAK();
#endif
        return *this;
    }
    u128& operator+=(const u128& v)
    {
#ifdef _MSC_VER
        _addcarry_u64(_addcarry_u64(0, low, v.low, &low), hi, v.hi, &hi);
#endif
#ifdef __GNUC__
        DEBUGBREAK();
#endif
        return *this;
    }
};
#endif

template <> struct std::hash<u128>
{
    std::size_t operator()(const u128& k) const
    {
        return std::hash<u64>()(k.low) ^ std::hash<u64>()(k.hi);
    }
};


namespace tools
{

    template<class T> inline void swap(T& first, T& second)
    {
        T temp = std::move(first);
        first = std::move(second);
        second = std::move(temp);
    }

    u8 inline as_byte(signed_t b) { return static_cast<u8>(b & 0xFF); }
    //u8 inline as_byte(size_t b) { return static_cast<u8>(b & 0xFF); }
    u8 inline as_byte(u64 b) { return static_cast<u8>(b & 0xFF); }
#ifdef MODE64
    u8 inline as_byte(u128 b) { return as_byte((u64)b); }
#endif
//    wchar inline as_wchar(size_t x) { return static_cast<wchar>(x & 0xFFFF); }
    u32 inline as_dword(size_t x) { return static_cast<u32>(x & 0xFFFFFFFF); }
    u16 inline as_word(size_t x) { return static_cast<u16>(x & 0xFFFF); }

    template<typename EL, typename ELC> inline signed_t find(const std::vector<EL>& ar, const ELC& el)
    {
        for (signed_t i = 0, c = ar.size(); i < c; ++i)
            if (ar[i] == el)
                return i;
        return -1;
    }
}



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

#define isizeof(s) ((signed_t)(sizeof(s)))

inline bool is_debugger_present()
{
#ifdef _WIN32
	return IsDebuggerPresent() != FALSE;
#endif
	return false;
}

using printfunc = void(const char* s, size_t l);
void GetPrint(printfunc pf);

void Print(); // print current queue
void Print(const char* format, ...);
void Print(signed_t color, const char* format, ...);
void Print(const std::vector<char>& txt);

