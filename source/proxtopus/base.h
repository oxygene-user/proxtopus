#pragma once

#ifndef PROXTOPUS_PCH
#error "do not include this file without pch.h"
#endif

#ifdef _DEBUG
//#define COUNT_ALLOCS
//#define LOG_TRAFFIC
#endif

#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__) || defined(ARCH_64BIT)
#ifndef ARCH_64BIT
#define ARCH_64BIT
#endif
#else
#ifndef ARCH_32BIT
#define ARCH_32BIT
#endif
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

constexpr size_t next_power_of_two(size_t n) {
    size_t power = 1;
    while (power < n) {
        power *= 2;
    }
    return power;
}

template <size_t sz> struct sztype { using type = std::array<u8, sz>; static constexpr bool native = false; };
template <> struct sztype<1> { using type = u8; static constexpr bool native = true; };
template <> struct sztype<2> { using type = u16; static constexpr bool native = true; };
template <> struct sztype<4> { using type = u32; static constexpr bool native = true; };
template <> struct sztype<8> { using type = u64; static constexpr bool native = true; };
#if defined(NATIVE_U128)
template <> struct sztype<16> { using type = u128; static constexpr bool native = true; };
#endif

template <size_t sz> struct xtype { using type = typename sztype< next_power_of_two(sz) >::type; };

static_assert(sizeof(sztype<4>::type) == 4);
static_assert(sizeof(sztype<8>::type) == 8);
static_assert(sizeof(sztype<16>::type) == 16);
static_assert(sizeof(sztype<32>::type) == 32);

template<typename T> concept native = sztype<sizeof(T)>::native;
template<typename T> concept not_native = !native<T>;

template<typename Tout, typename Tin> Tout& ref_cast(Tin& t)
{
    static_assert(sizeof(Tout) <= sizeof(Tin), "ref cast fail");
    return reinterpret_cast<Tout&>(t);
}
template<typename Tout, typename Tin> const Tout& ref_cast(const Tin& t) //-V659
{
    static_assert(sizeof(Tout) <= sizeof(Tin), "ref cast fail");
    return reinterpret_cast<const Tout&>(t);
}

#if defined(ANDROID) || defined(LIB)
#define APPONLY(...)
#define LIBONLY(...) __VA_ARGS__
#define APP 0
#else
#define APPONLY(...) __VA_ARGS__
#define LIBONLY(...)
#define APP 1
#endif

#ifdef _MSC_VER
#define DEBUGBREAK() __debugbreak()
#define MAYBEUNUSED(...) __pragma(warning(push)) __pragma(warning(disable:4800)) __VA_ARGS__ __pragma(warning(pop))
#define NIXONLY(...)
#define WINONLY(...) __VA_ARGS__
#define UNREACHABLE() __assume(0)
#endif

#ifdef GCC_OR_CLANG
#define UNREACHABLE() __builtin_unreachable()
#define DEBUGBREAK() __builtin_trap()
#ifdef __clang__
#define MAYBEUNUSED(...) _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wunused-value\"") __VA_ARGS__ _Pragma("clang diagnostic pop")
#else
#define MAYBEUNUSED(...) __VA_ARGS__
#endif
#endif


#if !defined(ARCH_X86)
inline u8 _addcarry_u32(u8 carry_in, u32 a, u32 b, u32* sum) {
    u64 result = static_cast<u64>(a) + static_cast<u64>(b) +static_cast<u64>(carry_in);
    *sum = static_cast<u32>(result & 0xffffffff);
    return static_cast<u8>((result >> 32) & 0xff);
}
inline u8 _subborrow_u32(u8 borrow_in, u32 a, u32 b, u32* diff) {
    u64 result = static_cast<u64>(a) - static_cast<u64>(b) - static_cast<u64>(borrow_in);
    *diff = static_cast<u32>(result & 0xffffffff);
    return static_cast<u8>(result >> 32) & 1;
}
#endif
#if !defined(ARCH_X86) || defined(ARCH_32BIT)
#ifdef ARCH_X86
#include <immintrin.h>
#endif
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
#if !defined(_MSC_VER) || defined(ARCH_32BIT)
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
#include "spooky_hash.h"

#define UNSIGNED tools::make_unsigned::get()
#define SIGNED tools::make_signed::get()

namespace tools
{
#ifdef ARCH_64BIT
    size_t inline as_sizet(u64 x) { return x; }
#else
    size_t inline as_sizet(u64 x) { return static_cast<size_t>(x & 0xffffffff); }
#endif

    struct make_unsigned
    {
        static make_unsigned get() { return make_unsigned(); }
        size_t operator %(signed_t v) const { return static_cast<size_t>(v); }
    };
    struct make_signed
    {
        static make_signed get() { return make_signed(); }
        signed_t operator %(size_t v) const { return static_cast<signed_t>(v); }
    };

    template<size_t typesize> requires (typesize >= 2) struct low_part_mask
    {
        consteval static sztype<typesize>::type build_mask()
        {
            typename sztype<typesize>::type rv = 0xff;

            for (size_t b = typesize - 1; b > (typesize / 2); --b)
                rv |= (rv << 8);

            return rv;
        }

        constexpr static const sztype<typesize>::type mask = build_mask();
    };


    template<size_t typesize> requires (typesize >= 2) struct hi_part_mask
    {
        consteval static sztype<typesize>::type build_mask()
        {
            typename sztype<typesize>::type rv = 0xff;

            for (size_t b = typesize - 1; b > 0; --b)
                rv |= (rv << 8);

            return rv ^ low_part_mask<typesize>::mask;
        }

        constexpr static const sztype<typesize>::type mask = build_mask();
    };

}

#if !defined(NATIVE_U128)
using u128 = uints::uint<128>;
template <> struct std::hash<u128>
{
    std::size_t operator()(const u128& k) const
    {
        u64 h1 = (const u64&)uints::low(k);
        u64 h2 = (const u64&)uints::high(k);
        spooky::hash_short(nullptr, 0, &h1, &h2);
        return tools::as_sizet(h1);
    }
};
#endif

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
#ifdef ARCH_64BIT
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

#define ERRORM(fn, ln, ...) (([&]()->bool { debug_print("$($): $\n", filename(fn, strsize(fn)), ln, str::build_string(__VA_ARGS__).c_str()); return true; })())
#ifdef _DEBUG
#define CHECK(expr,...) MAYBEUNUSED( ((expr) || (ERRORM(__FILE__, __LINE__, __VA_ARGS__) ? (SMART_DEBUG_BREAK, false) : false))) // (...) need to make possible syntax: ASSERT(expr, "Message")
#define ASSERT CHECK
#else
#define ASSERT(...) do {} while (false)
#define CHECK(expr,...) (expr)
#endif

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

