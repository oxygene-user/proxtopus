#pragma once

namespace uints {

template<size_t bits> class uint;
#pragma pack(push,1)

template<typename T> struct is_uint : std::false_type {};
template<size_t N> struct is_uint<uint<N>> : std::true_type {};
template<size_t N> struct is_uint<uint<N>&> : std::true_type {};
template<size_t N> struct is_uint<const uint<N>&> : std::true_type {};

template<typename T> struct is_flat : std::bool_constant<is_uint<T>::value || (std::is_integral_v<T> && std::is_trivial_v<T>)> {};
template<size_t N> struct is_flat<sztype<N>> : std::true_type {};
template<size_t N> struct is_flat<sztype<N>&> : std::true_type {};
template<size_t N> struct is_flat<const sztype<N>&> : std::true_type {};
template<size_t N> struct is_flat<std::array<u8, N>> : std::true_type {};
template<size_t N> struct is_flat<std::array<u8, N>&> : std::true_type {};
template<size_t N> struct is_flat<const std::array<u8, N>&> : std::true_type {};
#ifdef NATIVE_U128
template<> struct is_flat<u128> : std::true_type {};
#endif
template<typename T> concept flat = is_flat<T>::value;

template<typename T> struct is_array : std::false_type {};
template<size_t N> struct is_array<std::array<u8, N>> : std::true_type {};

template<typename Tout, typename Tin> static Tout& strong_ref_cast(Tin& t)
{
    static_assert(sizeof(Tout) == sizeof(Tin));
    return (Tout&)t;
}
template<typename Tout, typename Tin> static const Tout& strong_ref_cast(const Tin& t) //-V659
{
    static_assert(sizeof(Tout) == sizeof(Tin));
    return *(const Tout*)&t;
}
template<typename Tout, typename Tin> static Tout& ref_cast_temp(Tin& t)
{
    static_assert(sizeof(Tout) == sizeof(Tin), "temp cast");
    return (Tout&)t;
}
template<typename Tout, typename Tin> static const Tout& ref_cast_temp(const Tin& t) //-V659
{
    static_assert(sizeof(Tout) == sizeof(Tin), "temp cast");
    return *(const Tout*)&t;
}

template<size_t szlo, size_t szhi, bool little> struct pair;
template<size_t szlo, size_t szhi> struct pair<szlo, szhi, true>
{
    static_assert(szlo > 0 && szhi > 0);
    static_assert(std::has_single_bit(szlo + szhi) || ((szlo + szhi) % sizeof(size_t)) == 0);
    typename sztype<szlo>::type lo;
    typename sztype<szhi>::type hi;
};
template<size_t halfsz> using dtype = pair<halfsz, halfsz, Endian::little>;

template<size_t szlo, typename T> auto& aslow(T& t) // asymmetric low
{
    static_assert(szlo < sizeof(T));
    static_assert(sizeof(T) >= 2);
    return strong_ref_cast<pair<szlo, sizeof(T) - szlo, Endian::little>>(t).lo;
}
template<size_t szlo, typename T> auto& ashigh(T& t) // asymmetric high
{
    static_assert(szlo < sizeof(T));
    static_assert(sizeof(T) >= 2);
    return strong_ref_cast<pair<szlo, sizeof(T) - szlo, Endian::little>>(t).hi;
}

template<size_t szlo, size_t sz, typename T> auto& mid(T& t) // middle of type
{
    if constexpr (szlo == 0)
        return aslow<sz>();
    else
    {
        static_assert(szlo <= (sizeof(T)-sz));
        static_assert(sizeof(T) >= 2);

        if constexpr (sizeof(T) - szlo == sz)
            return ashigh<szlo>(t);
        else
            return aslow<sz>(ashigh<szlo>(t));
    }
}

template<typename T> auto& low(T& t)
{
    static_assert(sizeof(T) >= 2);
    return strong_ref_cast<dtype<sizeof(T) / 2>>(t).lo;
}
template<typename T> auto& high(T& t)
{
    static_assert(sizeof(T) >= 2);
    return strong_ref_cast<dtype<sizeof(T) / 2>>(t).hi;
}

template<typename T> u32 make_u32(const T& t)
{
    if constexpr (sizeof(T) == 4)
        return ref_cast<u32>(t);
    else if constexpr (sizeof(T) == 2)
        return static_cast<u32>(ref_cast<u16>(t));
    else if constexpr (sizeof(T) == 1)
        return static_cast<u32>(ref_cast<u8>(t));
}

struct carryop_add
{
    inline static u8 op32(u8 c, u32 a, u32 b, u32* res)
    {
        #ifdef GCC_OR_CLANG
        return __builtin_ia32_addcarryx_u32(c,a,b,res);
        #else
        return _addcarry_u32(c, a, b, res);
        #endif
    }
    inline static u8 op64(u8 c, u64 a, u64 b, u64* res)
    {
        #ifdef GCC_OR_CLANG
        return __builtin_ia32_addcarryx_u64(c,a,b,res);
        #else
        return _addcarry_u64(c, a, b, res);
        #endif
    }
};
struct carryop_sub
{
    inline static u8 op32(u8 c, u32 a, u32 b, u32* res)
    {
        #ifdef GCC_OR_CLANG
        return __builtin_ia32_sbb_u32(c, a, b, res);
        #else
        return _subborrow_u32(c, a, b, res);
        #endif
    }
    inline static u8 op64(u8 c, u64 a, u64 b, u64* res)
    {
        #ifdef GCC_OR_CLANG
        return __builtin_ia32_sbb_u64(c, a, b, res);
        #else
        return _subborrow_u64(c, a, b, res);
        #endif
    }
};

template<size_t x, size_t y> struct maximum_of
{
    constexpr static const size_t value = x >= y ? x : y;
};

#pragma pack(pop)

template<size_t N> std::array<u8, N> operator&(const std::array<u8, N>& ina1, const std::array<u8, N>& ina2)
{
    std::array<u8, N> rslt;

    if constexpr ((N & (sizeof(size_t) - 1)) == 0)
    {
        const size_t* src1 = (const size_t*)ina1.data();
        const size_t* src2 = (const size_t*)ina2.data();
        size_t* tgt = (size_t*)rslt.data();
        for (size_t i = 0; i < (N / sizeof(size_t)); ++i)
        {
            *tgt = *src1 & *src2;
            ++tgt;
            ++src1;
            ++src2;
        }
    }
    else
    {
        static_assert(N == 123123); // static_assert(false); - unconditionally triggers gcc
    }

    return rslt;
}

template<size_t N> std::array<u8, N> operator|(const std::array<u8, N>& ina1, const std::array<u8, N>& ina2)
{
    std::array<u8, N> rslt;

    if constexpr ((N & (sizeof(size_t) - 1)) == 0)
    {
        const size_t* src1 = (const size_t*)ina1.data();
        const size_t* src2 = (const size_t*)ina2.data();
        size_t* tgt = (size_t*)rslt.data();
        for (size_t i = 0; i < (N / sizeof(size_t)); ++i)
        {
            *tgt = *src1 | *src2;
            ++tgt;
            ++src1;
            ++src2;
        }
    }
    else
    {
        static_assert(N == 123123);
    }

    return rslt;
}

template<size_t bits> class uint
{
    static_assert(std::has_single_bit(bits)); // only power of 2 bits allowed

    friend class uint<bits * 2>;
    using type = sztype<bits / 8>::type;
    static constexpr bool native = sztype<bits / 8>::native;
    static constexpr size_t bytes = bits / 8;
    using half_type = uint<bits / 2>;
    type value;

    template<size_t sz> auto& low()
    {
        static_assert(sz < bytes);
        return aslow<sz>(value);
    }
    template<size_t sz> auto& low() const
    {
        static_assert(sz < bytes);
        return aslow<sz>(value);
    }

    template<size_t skip_bytes> auto& high()
    {
        static_assert(skip_bytes < bytes);
        return ashigh<skip_bytes>(value);
    }
    template<size_t skip_bytes> auto& high() const
    {
        static_assert(skip_bytes < bytes);
        return ashigh<skip_bytes>(value);
    }

    half_type& get_low()
    {
        return strong_ref_cast<half_type>(aslow<bytes / 2>(value));
    }
    const half_type& get_low() const
    {
        return strong_ref_cast<half_type>(aslow<bytes / 2>(value));
    }
    half_type& get_high()
    {
        return strong_ref_cast<half_type>(ashigh<bytes / 2>(value));
    }
    const half_type& get_high() const
    {
        return strong_ref_cast<half_type>(ashigh<bytes / 2>(value));
    }

    template<size_t bits2> static void clear(uint<bits2>& v)
    {
        v = 0;
    }
    template<size_t sz> static void clear(std::array<u8, sz>& v)
    {
        memset(&v, 0, sz);
    }
    template<std::integral T> static void clear(T& t)
    {
        t = 0;
    }
#ifdef NATIVE_U128
    static void clear(u128& t)
    {
        t = 0;
    }
#endif


    static const type& getval(const uint<bits>& p)
    {
        return p.value;
    }
    static const type& getval(const decltype(uint<bits>::value)& p)
    {
        return p;
    }
    template<size_t N> static const type& getval(const std::array<u8, N>& p)
    {
        return strong_ref_cast<type>(p);
    }

    template<typename OP, typename T> static u8 carryop(u8 carry_in, const sztype<bytes>::type& a, const T& b, sztype<bytes>::type* result)
    {
        static_assert(sizeof(b) <= sizeof(a));
        static_assert(bytes >= 4);
        if constexpr (bytes == 4)
        {
            return OP::op32(carry_in, make_u32(a), make_u32(b), result);
        }
        else if constexpr (bytes == 8 && sztype<8>::native)
        {
            return OP::op64(carry_in, a, getval(b), result);
        }
        else
        {
            const half_type &a0 = uints::low(a);
            const half_type &a1 = uints::high(a);
            const half_type &b0 = uints::low(getval(b));
            const half_type &b1 = uints::high(getval(b));

            auto* low_res = &uints::low(*result);
            return half_type::template carryop<OP, typename half_type::type>(half_type::template carryop<OP, typename half_type::type>(carry_in, a0.value, b0.value, low_res), a1.value, b1.value, &uints::high(*result));
        }
    }
    template<typename T> static u8 addcarry(u8 carry_in, const sztype<bytes>::type& a, const T& b, sztype<bytes>::type* result)
    {
        return carryop<carryop_add, T>(carry_in, a, b, result);
    }
    template<typename T> static u8 subborrow(u8 borrow_in, const sztype<bytes>::type& a, const T& b, sztype<bytes>::type* result)
    {
        return carryop<carryop_sub, T>(borrow_in, a, b, result);
    }

    static uint<bits> umul(const half_type& a, const half_type& b)
    {
        if constexpr (native)
        {
            return uint<bits>(static_cast<type>(a.value) * b.value);
        }
        else if constexpr (half_type::bytes == 4)
        {
#if defined(ARCH_X86) && defined(_MSC_VER) && !defined(MODE64)
            return strong_ref_cast<u64>(__emulu(a.value, b.value));
#else
            return (u64)a.value * b.value;
#endif
        }
        else
#ifdef MODE64
            if constexpr (half_type::bytes == 8)
            {
#if defined(ARCH_X86) && defined(_MSC_VER)
                uint<bits> rv;
                rv.get_low() = _umul128(strong_ref_cast<u64>(a), strong_ref_cast<u64>(b), &strong_ref_cast<u64>(rv.get_high()));
                return rv;
#else
#ifdef NATIVE_U128
                return (unsigned __int128)a * b;
#else
                static_assert(false, "implement 64x64->128 multiplication yourself");
#endif
#endif
            }
            else
#endif
            {
                using quarter_type = uint<bits / 4>;

                const quarter_type &a0 = uints::low(a);
                const quarter_type &a1 = uints::high(a);
                const quarter_type &b0 = uints::low(b);
                const quarter_type &b1 = uints::high(b);

                half_type p0 = half_type::umul(a0, b0);
                half_type p1 = half_type::umul(a0, b1);
                half_type p2 = half_type::umul(a1, b0);
                half_type p3 = half_type::umul(a1, b1);

                uint<bits> rv;

                half_type middle = p2 + p0.get_high() + p1.get_low();
                half_type middleshift;
                middleshift.get_low() = 0;
                middleshift.get_high() = middle.get_low();
                rv.get_high() = p3 + middle.get_high() + p1.get_high();
                rv.get_low() = middleshift + p0.get_low();

                return rv;

            }

    }

    template<flat T> static const uint<bits> umul3(const uint<bits>& a, const T& b, uint<bits>* high)
    {
        static_assert(sizeof(T) <= bytes);

        if constexpr (sizeof(T) < bytes)
        {
            // second less - hi part of b is 0

            const half_type &a0 = uints::low(a);
            const half_type &a1 = uints::high(a);
            uint<bits> p0 = umul(a0, b);
            uint<bits> p2 = umul(a1, b);

            const uint<bits> middle = p2 + p0.get_high();

            if (high)
                *high = middle.get_high();

            uint<bits> middleshift;
            middleshift.get_low() = 0;
            middleshift.get_high() = middle.get_low();

            return middleshift + p0.get_low();
        }
        else
        {
            //same size

            const auto &a0 = uints::low(a);
            const auto &a1 = uints::high(a);
            const auto &b0 = uints::low(getval(b));
            const auto &b1 = uints::high(getval(b));

            uint<bits> p0 = umul(a0, b0);
            uint<bits> p1 = umul(a0, b1);
            uint<bits> p2 = umul(a1, b0);

            // this cannot overflow as (0xffffffff)^2 + 0xffffffff + 0xffffffff = 2^64-1
            uint<bits> middle = p2 + p0.get_high() + p1.get_low();

            if (high)
            {
                uint<bits> p3 = umul(a1, b1);
                // these cannot overflow too
                *high = strong_ref_cast<typename sztype<bytes>::type>(p3 + middle.get_high() + p1.get_high());
            }

            uint<bits> middleshift;
            middleshift.get_low() = 0;
            middleshift.get_high() = middle.get_low();

            return middleshift + p0.get_low();
        }

    }


    template<flat T> void assign(const T& t)
    {
        if constexpr (sizeof(value) == sizeof(T))
        {
            tools::memcopy<sizeof(T)>(&value, &t);
        }
        else if constexpr (sizeof(value) > sizeof(T))
        {
            if constexpr (native)
            {
                value = static_cast<decltype(value)>(strong_ref_cast<typename sztype<sizeof(T)>::type>(t));
            }
            else
            {
                using low_uint = uint<sizeof(T) * 8>;
                low_uint& lowu = strong_ref_cast<low_uint>(aslow<sizeof(T)>(value));
                lowu = t;
                clear(high<sizeof(T)>());
            }
        }
        else
        {
            value = ref_cast<decltype(value)>(t);
        }
    }

    void shr(uint<bits>& rv, const int shift) const {

        if constexpr (native)
            rv = value >> shift;
        else
        {
            if (shift < 0)
            {
                shl(rv, -shift);
                return;
            }

            constexpr const int halfsize = bits / 2;

            if (shift >= bits)
            {
                rv = 0;
            }
            else if (shift >= bits / 2)
            {
                rv.get_high() = 0;
                get_high().shr(rv.get_low(), shift - halfsize);

            }
            else if (shift == 0)
            {
                rv = *this;
            }
            else {

                half_type r1, r2;
                get_low().shr(r1, shift);
                get_high().shl(r2, halfsize - shift);

                r1.binor(rv.get_low(), r2);
                get_high().shr(rv.get_high(), shift);
            }
        }
    }
    void shl(uint<bits>& rv, const int shift) const {
        if constexpr (native)
            rv = value << shift;
        else
        {
            if (shift < 0)
            {
                shr(rv, -shift);
                return;
            }

            constexpr const int halfsize = bits / 2;

            if (shift >= bits)
            {
                rv = 0;
                return;
            }
            else if (shift >= halfsize)
            {
                rv.get_low() = 0;
                get_low().shl(rv.get_high(), shift - halfsize);
            }
            else if (shift == 0)
            {
                rv = *this;
            }
            else {
                get_low().shl(rv.get_low(), shift);

                half_type r1, r2;
                get_high().shl(r1, shift);
                get_low().shr(r2, halfsize - shift);
                r1.binor(rv.get_high(), r2);
            }
        }
    }

    template<flat T> void binor(uint<bits>& rv, const T& v) const
    {
        if constexpr (bytes == sizeof(T))
        {
            if constexpr (native)
                rv = uint<bits>(value | getval(v));
            else {
                rv = uint<bits>(value | strong_ref_cast<decltype(value)>(v));
            }
        }
        else if constexpr (bytes > sizeof(T))
        {
            constexpr const size_t parsz = sizeof(T);
            aslow<parsz>(rv) = low<parsz>() | v;
            ashigh<parsz>(rv) = high<parsz>();
        }
        else
        {
            rv = *this | ref_cast<uint<bits>>(v);
        }
    }

public:
    uint() {}
    template<flat T> uint(const T& t)
    {
        assign(t);
    }
    template<flat T> uint<bits>& operator=(const T& t)
    {
        assign(t);
        return *this;
    }

    template<flat T> uint<maximum_of<bits, sizeof(T) * 8>::value> operator*(const T& t) const
    {
        using return_type = uint<maximum_of<bits, sizeof(T) * 8>::value>;

        if constexpr (native)
        {
            if constexpr (is_uint<T>::value && sztype<sizeof(T)>::native) {

                return value * strong_ref_cast<typename sztype<sizeof(T)>::type>(t);
            }
            else
            {
                return t * value;
            }
        }
        else
        {
            if constexpr (sizeof(T) <= bytes)
                return umul3(value, t, nullptr);
            else
            {
                return return_type(t) * value;
            }
        }
    }


    template<flat T> uint<bits> operator-(const T& t) const
    {
        if constexpr (native)
        {
            if constexpr (is_uint<T>::value) {
                if constexpr (sizeof(T) <= bytes)
                    return value - t.value;
                else {
                    return value - aslow<bytes>(t);
                }
            } else
            {
                return value - t;
            }
        }
        else
        {
            uint<bits> rv;
            constexpr const size_t halfbytes = bytes / 2;
            if constexpr (is_uint<T>::value)
            {
                if constexpr (sizeof(T) == bytes)
                {
                    rv.get_high() = get_high() - t.get_high() - half_type::subborrow(0, low<halfbytes>(), t.template low<halfbytes>(), &rv.low<halfbytes>());
                }
                else if constexpr (sizeof(T) > bytes)
                {
                    const uint<bits>& second_clamped = ref_cast<uint<bits>>(t);
                    rv.get_high() = get_high() + second_clamped.get_high() + half_type::subborrow(0, low<halfbytes>(), second_clamped.low<halfbytes>(), &rv.low<halfbytes>());
                }
                else
                {
                    static_assert(sizeof(T) * 2 <= bytes);
                    rv.get_high() = get_high() + half_type::subborrow(0, low<halfbytes>(), t, &rv.low<halfbytes>());
                }

            }
            else if constexpr (std::is_integral<T>::value)
            {
                if (t < 0)
                    return (*this) + (-t);

                rv.get_high() = get_high() + half_type::subborrow(0, low<halfbytes>(), t, &rv.low<halfbytes>());
            }
            else
            {
                static_assert(sizeof(T)==123123);
            }

            return rv;
        }
    }

    template<flat T> uint<bits> &operator-=(const T& t)
    {
        if constexpr (native)
        {
            if constexpr (is_uint<T>::value) {
                if constexpr (sizeof(T) <= bytes)
                    value -= t.value;
                else {
                    value -= aslow<bytes>(t);
                }
            }
            else
            {
                value -= t;
            }
        }
        else
        {
            constexpr const size_t halfbytes = bytes / 2;
            if constexpr (is_uint<T>::value)
            {
                if constexpr (sizeof(T) == bytes)
                {
                    get_high() = get_high() - t.get_high() - half_type::subborrow(0, low<halfbytes>(), t.template low<halfbytes>(), &low<halfbytes>());
                }
                else if constexpr (sizeof(T) > bytes)
                {
                    const uint<bits>& second_clamped = ref_cast<uint<bits>>(t);
                    get_high() = get_high() + second_clamped.get_high() + half_type::subborrow(0, low<halfbytes>(), second_clamped.low<halfbytes>(), &low<halfbytes>());
                }
                else
                {
                    static_assert(sizeof(T) * 2 <= bytes);
                    get_high() = get_high() + half_type::subborrow(0, low<halfbytes>(), t, &low<halfbytes>());
                }

            }
            else if constexpr (std::is_integral<T>::value)
            {
                if constexpr (!std::is_unsigned<T>::value)
                {
                    if (t < 0)
                        (*this) += (-t);
                    else
                        get_high() = get_high() + half_type::subborrow(0, low<halfbytes>(), t, &low<halfbytes>());
                }
                else
                {
                    get_high() = get_high() + half_type::subborrow(0, low<halfbytes>(), t, &low<halfbytes>());
                }

            }
            else
            {
                static_assert(sizeof(T)==123123);
            }

        }
        return *this;
    }

    template<flat T> uint<bits> operator+(const T& t) const
    {
        if constexpr (native)
        {
            if constexpr (is_uint<T>::value) {
                if constexpr (sizeof(T) <= bytes)
                    return value + t.value;
                else {
                    return value + aslow<bytes>(t);
                }
            } else
                return value + t;
        }
        else
        {
            uint<bits> rv;
            constexpr const size_t halfbytes = bytes / 2;
            if constexpr (is_uint<T>::value)
            {
                if constexpr (sizeof(T) == bytes)
                {
                    rv.get_high() = get_high() + t.get_high() + half_type::addcarry(0, low<halfbytes>(), t.template low<halfbytes>(), &rv.low<halfbytes>());
                }
                else if constexpr (sizeof(T) > bytes)
                {
                    const uint<bits>& second_clamped = ref_cast<uint<bits>>(t);
                    rv.get_high() = get_high() + second_clamped.get_high() + half_type::addcarry(0, low<halfbytes>(), second_clamped.low<halfbytes>(), &rv.low<halfbytes>());
                }
                else
                {
                    static_assert(sizeof(T) * 2 <= bytes);
                    rv.get_high() = get_high() + half_type::addcarry(0, low<halfbytes>(), t, &rv.low<halfbytes>());
                }

            }
            else if constexpr (std::is_integral<T>::value)
            {
                if constexpr (!std::is_unsigned<T>::value)
                {
                    if (t < 0)
                        return (*this) - (-t);
                }
                else
                {
                    rv.get_high() = get_high() + half_type::addcarry(0, low<halfbytes>(), t, &rv.low<halfbytes>());
                }
            }
            else
            {
                static_assert(sizeof(T) == 123123);
            }

            return rv;
        }
    }
    template<flat T> uint<bits>& operator+=(const T& t)
    {
        if constexpr (native)
        {
            if constexpr (is_uint<T>::value) {
                if constexpr (sizeof(T) <= bytes)
                    value += t.value;
                else {
                    value += aslow<bytes>(t);
                }
            }
            else
                value += t;
        }
        else
        {
            constexpr const size_t halfbytes = bytes / 2;
            if constexpr (is_uint<T>::value)
            {
                if constexpr (sizeof(T) == bytes)
                {
                    get_high() = get_high() + t.get_high() + half_type::addcarry(0, low<halfbytes>(), t.template low<halfbytes>(), &low<halfbytes>());
                }
                else if constexpr (sizeof(T) > bytes)
                {
                    const uint<bits>& second_clamped = ref_cast<uint<bits>>(t);
                    get_high() = get_high() + second_clamped.get_high() + half_type::addcarry(0, low<halfbytes>(), second_clamped.low<halfbytes>(), &low<halfbytes>());
                }
                else
                {
                    static_assert(sizeof(T) * 2 <= bytes);
                    get_high() = get_high() + half_type::addcarry(0, low<halfbytes>(), t, &low<halfbytes>());
                }

            }
            else if constexpr (std::is_integral<T>::value)
            {
                if constexpr (!std::is_unsigned<T>::value)
                {
                    if (t < 0)
                        (*this) -= (-t);
                    else
                        get_high() = get_high() + half_type::addcarry(0, low<halfbytes>(), t, &low<halfbytes>());
                }
                else
                {
                    get_high() = get_high() + half_type::addcarry(0, low<halfbytes>(), t, &low<halfbytes>());
                }

            }
            else
            {
                static_assert(sizeof(T) == 123123);
            }
        }

        return *this;
    }


    template<flat T> uint<bits> operator&(const T& v) const
    {
        if constexpr (bytes == sizeof(T))
        {
            if constexpr (native)
                return uint<bits>(value & v);
            else
                return uint<bits>(value & strong_ref_cast<decltype(value)>(v));
        }
        else if constexpr (bytes > sizeof(T))
        {
            constexpr const size_t parsz = sizeof(T);
            uint<bits> rv;
            aslow<parsz>(rv) = low<parsz>() & v;
            clear(ashigh<parsz>(rv));
            return rv;
        }
        else
        {
            return *this & ref_cast<uint<bits>>(v);
        }
    }

    template<flat T> uint<bits> operator|(const T& v) const
    {
        uint<bits> rv;
        binor(rv, v);
        return rv;
    }


    uint<bits> operator<<(const int shift) const {
        uint<bits> rv;
        shl(rv, shift);
        return rv;
    }
    uint<bits> operator>>(const int shift) const {
        uint<bits> rv;
        shr(rv, shift);
        return rv;
    }

    template<flat T> std::strong_ordering operator<=>(const T& t) const noexcept {
        if constexpr (native)
        {
            if constexpr (std::is_integral<T>::value)
            {
                return value <=> t;
            }
            else
            {
                static_assert(sizeof(T) == 123123); // just not implementet
            }
        }
        else
        {
            static_assert(sizeof(T) == 123123); // just not implementet
        }
    }
    template<flat T> bool operator==(const T& t) const noexcept {
        if constexpr (native)
        {
            if constexpr (std::is_integral<T>::value)
            {
                return value == t;
            }
            else
            {
                static_assert(sizeof(T) == 123123); // just not implementet
            }
        }
        else
        {
            static_assert(sizeof(T) == 123123); // just not implementet
        }
    }
    template<flat T> bool operator!=(const T& t) const noexcept {
        if constexpr (native)
        {
            if constexpr (std::is_integral<T>::value)
            {
                return value != t;
            }
            else
            {
                static_assert(sizeof(T) == 123123); // just not implementet
            }
        }
        else
        {
            if constexpr (bytes == sizeof(T))
                return memcmp(&value, &t, bytes) != 0;
            else if constexpr (bytes > sizeof(T))
            {
                if constexpr (sztype<sizeof(T)>::native)
                {
                    return low<sizeof(T)>() != t;
                }
                else
                {
                    static_assert(sizeof(T) == 123123); // just not implementet
                }
            }
            else
                static_assert(sizeof(T) == 123123); // just not implementet
        }
    }
    template<flat T> friend bool operator!=(const T& t, const uint<bits>& me) noexcept {
        if constexpr (native)
        {
            if constexpr (std::is_integral<T>::value)
            {
                return me.value != t;
            }
            else
            {
                static_assert(sizeof(T) == 123123); // just not implementet
            }
        }
        else
        {
            return me != t;
        }
    }

    explicit operator u32() const
    {
        if constexpr (bytes > 4)
            return low<4>();
        else
            return value;
    }
    explicit operator u64() const
    {
        if constexpr (bytes > 8)
            return (const u64&)low<8>();
        else
            return (const u64&)value;
    }
};

template<bool is_const> struct octets;
template<> struct octets<true>
{
    const u8* p;
    template <typename T> octets(T& t) :p(reinterpret_cast<const u8*>(&t)) {}
};
template<> struct octets<false>
{
    u8* p;
    template <typename T> octets(T& t) :p(reinterpret_cast<u8*>(&t)) {}
};

template<uints::flat T, bool is_little_endian = Endian::little> struct from_low_to_high
{
    octets< std::is_const_v<T> > octet; // point to low byte if num

    from_low_to_high(T& num) :octet(num) {
        if constexpr (!is_little_endian)
        {
            octet.p += sizeof(T) - 1;
        }
    }

    u8 operator[](size_t index) const
    {
        if constexpr (is_little_endian)
        {
            return octet.p[index];
        }
        else
        {
            return octet.p[-index];
        }
    }
    u8& operator[](size_t index)
    {
        if constexpr (std::is_const_v<T>)
        {
            UNREACHABLE();
        }
        else
        {
            if constexpr (is_little_endian)
            {
                return octet.p[index];
            }
            else
            {
                return octet.p[-(signed_t)index];
            }
        }

    }

    from_low_to_high& operator++() {
        if constexpr (is_little_endian)
        {
            ++octet.p;
        }
        else
        {
            --octet.p;
        }
        return *this;
    }
    u8 operator *() const
    {
        return *octet.p;
    }
    u8& operator *()
    {
        return *octet.p;
    }
};


template<flat T, size_t N> u8 divbyconst(T& t)
{
    if constexpr (sztype<sizeof(T)>::native)
    {
        T d = t / N;
        u8 rem = static_cast<u8>(t - d * N);
        t = d;
        return rem;
    }
    else
    {
        from_low_to_high<T, !Endian::little> fromhi(t); // from high to lo bytes

        size_t d = 0;
        for (size_t i = 0; i < sizeof(T); ++i, ++fromhi)
        {
            u8 e = *fromhi;
            if (!e && !d)
                continue;

            d = (d << 8) + e;

            if (d >= N)
            {
                size_t x = d/N;
                *fromhi = static_cast<u8>(x);
                x *= N;
                d -= x;
            }
            else
                *fromhi = 0;
        }
        return static_cast<u8>(d);
    }
}

template<flat T> u8 is_zero(const T& t)
{
    if constexpr (sztype<sizeof(T)>::native)
    {
        return t == 0;
    }
    else
    {
        static_assert(sizeof(T) % sizeof(size_t) == 0);
        const size_t* d = reinterpret_cast<const size_t*>(&t);
        const size_t* e = d + sizeof(T) / sizeof(size_t);
        for (; d < e; ++d)
            if (*d != 0)
                return false;
        return true;
    }
}

} // namespace uints
