#pragma once

#ifndef PROXTOPUS_PCH
#error "do not include this file without pch.h"
#endif

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

#ifndef ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define ALIGN(x) __declspec(align(x))
# else
#  define ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif

#include "mem.h"
#include <bit>
#ifdef _MSC_VER
#include <intrin.h>
#endif

class Endian
{
public:
    Endian() = delete;

    static constexpr bool little = std::endian::native == std::endian::little;
    static constexpr bool big = std::endian::native == std::endian::big;
};

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
#elif defined(GCC_OR_CLANG)
using i64 = int64_t;
using u64 = unsigned long long;
using WORD = uint16_t;
#endif
#if defined(__SIZEOF_INT128__)
__extension__ typedef unsigned __int128 u128;
#define NATIVE_U128
#endif

static_assert(sizeof(u64) == 8);


template <size_t sz> struct sztype { using type = std::array<u8, sz>; static constexpr bool native = false; };
template <> struct sztype<1> { using type = u8; static constexpr bool native = true; };
template <> struct sztype<2> { using type = u16; static constexpr bool native = true; };
template <> struct sztype<4> { using type = u32; static constexpr bool native = true; };
template <> struct sztype<8> { using type = u64; static constexpr bool native = true; };
#if defined(NATIVE_U128)
template <> struct sztype<16> { using type = u128; static constexpr bool native = true; };
#endif

static_assert(sizeof(sztype<4>::type) == 4);
static_assert(sizeof(sztype<8>::type) == 8);
static_assert(sizeof(sztype<16>::type) == 16);
static_assert(sizeof(sztype<32>::type) == 32);

template<typename T> concept native = sztype<sizeof(T)>::native;
template<typename T> concept not_native = !native<T>;

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

#ifdef _MSC_VER
#define DEBUGBREAK() __debugbreak()
#define NOWARNING(n,...) __pragma(warning(push)) __pragma(warning(disable:n)) __VA_ARGS__ __pragma(warning(pop))
#define NIXONLY(...)
#define WINONLY(...) __VA_ARGS__
#define UNREACHABLE() __assume(0)
#endif

#ifdef GCC_OR_CLANG
#define UNREACHABLE() __builtin_unreachable()
#define DEBUGBREAK() __builtin_trap()
#define NOWARNING(n,...) __VA_ARGS__
#endif
#if !defined(ARCH_X86) || !defined MODE64
inline u8 _addcarry_u64( u8 carry_in, u64 a, u64 b, u64* out)
{
    u32 a0 = static_cast<u32>(a & 0xffffffff);
    u32 a1 = static_cast<u32>(a >> 32);
    u32 b0 = static_cast<u32>(b & 0xffffffff);
    u32 b1 = static_cast<u32>(b >> 32);

    u32 res_lo, res_hi;
    u8 carry_hi = _addcarry_u32(_addcarry_u32(carry_in, a0, b0, &res_lo), a1, b1, &res_hi);
    *out = (static_cast<u64>(res_hi) << 32) | res_lo;
    return carry_hi;
}
inline u8 _subborrow_u64(u8 borrow_in, u64 a, u64 b, u64* out)
{
    u32 a0 = static_cast<u32>(a & 0xffffffff);
    u32 a1 = static_cast<u32>(a >> 32);
    u32 b0 = static_cast<u32>(b & 0xffffffff);
    u32 b1 = static_cast<u32>(b >> 32);

    u32 res_lo, res_hi;
    u8 borrow_hi = _subborrow_u32(_subborrow_u32(borrow_in, a0, b0, &res_lo), a1, b1, &res_hi);

    *out = (static_cast<u64>(res_hi) << 32) | res_lo;
    return borrow_hi;
}
#endif
#if !defined(_MSC_VER) || !defined(MODE64)
inline u64 _umul128(u64 a, u64 b, u64* high)
{
    u32 a0 = static_cast<u32>(a & 0xffffffff);
    u32 a1 = static_cast<u32>(a >> 32);
    u32 b0 = static_cast<u32>(b & 0xffffffff);
    u32 b1 = static_cast<u32>(b >> 32);

    u64 p0 = (u64)a0 * b0;
    u64 p1 = (u64)a0 * b1;
    u64 p2 = (u64)a1 * b0;
    u64 p3 = (u64)a1 * b1;

    // this cannot overflow as (0xffffffff)^2 + 0xffffffff + 0xffffffff = 2^64-1
    const u64 middle = p2 + (p0 >> 32) + (p1 & 0xffffffff);

    // likewise these cannot overflow
    *high = p3 + (middle >> 32) + (p1 >> 32);
    return (middle << 32) + (p0 & 0xffffffff);

}
#endif

#include "uints.h"

#if !defined(NATIVE_U128)
using u128 = uints::uint<128>;
#endif

template <> struct std::hash<u128>
{
    std::size_t operator()(const u128& k) const
    {
        return std::hash<u64>()((const u64&)uints::low(k)) ^ std::hash<u64>()((const u64&)uints::high(k));
    }
};


namespace tools
{
    consteval size_t min_integral_size_for_value(size_t val, size_t minsize)
    {
        if (val < 256)
            return minsize > 1 ? minsize : 1;
        if (val < 65536)
            return minsize > 2 ? minsize : 2;
        if (val < (0xffffffffull + 1ull))
            return minsize > 4 ? minsize : 4;
        return 8;
    }

    template<class T> inline void swap(T& first, T& second)
    {
        T temp = std::move(first);
        first = std::move(second);
        second = std::move(temp);
    }

#if 0
    u8 inline as_byte(signed_t b) { return static_cast<u8>(b & 0xFF); }
    u8 inline as_byte(u64 b) { return static_cast<u8>(b & 0xFF); }
#ifdef MODE64
    u8 inline as_byte(const u128 &b) { return uints::aslow<1>(b); }
#else
    u8 inline as_byte(size_t b) { return static_cast<u8>(b & 0xFF); }
#endif
#endif

    template<uints::flat T> u8 inline as_byte(const T &b) { return uints::aslow<1>(b); }


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
#define SLERROR(...) do {ERRORM(__FILE__, __LINE__, __VA_ARGS__); DEBUGBREAK(); } while(false)

#define ERRORM(fn, ln, ...) (([&]()->bool { debug_print("$($): $\n", filename(fn, strsize(fn)), ln, str::build_string(__VA_ARGS__).c_str()); return true; })())
#define ASSERT(expr,...) NOWARNING(4800, ((expr) || (ERRORM(__FILE__, __LINE__, __VA_ARGS__) ? (SMART_DEBUG_BREAK, false) : false))) // (...) need to make possible syntax: ASSERT(expr, "Message")

#ifdef _NIX
#define NIXONLY(...) __VA_ARGS__
#define WINONLY(...)

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

#ifdef _WIN32
inline bool is_debugger_present()
{
	return IsDebuggerPresent() != FALSE;
}
#else
bool is_debugger_present();
#endif

//using printfunc = void(const char *s, signed_t sl);
//void GetPrint(printfunc pf);

void Print(); // print current queue
void Print(const std::string_view& stroke);
void Print(signed_t color, const std::string_view& stroke);
void Print(const buffer& txt);

