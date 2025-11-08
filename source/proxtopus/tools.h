#pragma once

#ifdef ARCH_X86
#include <emmintrin.h>
#include <immintrin.h>
#endif
#ifdef _MSC_VER
#include <intrin.h>
#endif
#include <sstream>
#include <string>
#include <span>
#include <bit>

#ifdef __GNUC__
#define ALLOCA (u8 *)alloca
#endif
#ifdef _MSC_VER
#define ALLOCA (u8 *)_alloca
#endif // _MSC_VER

bool messagebox(const char* s1, const char* s2, int options);

//#define ASSERTS(expr, ...) ASSERTO(expr, (std::stringstream() << ""  __VA_ARGS__).str())

//#define MESSAGE(...) messagebox("#", str::build_string(__VA_ARGS__).c_str(), MB_OK|MB_ICONINFORMATION)
#define WARNING(...) messagebox("!?", str::build_string(__VA_ARGS__).c_str(), MB_OK|MB_ICONWARNING)
template <typename T> inline T* BREAK_ON_NULL(T* ptr, const char* file, int line) { if (ptr == nullptr) { WARNING("nullptr pointer conversion: $:$", file, line); } return ptr; }
#define NOT_NULL( x ) BREAK_ON_NULL(x, __FILE__, __LINE__)
template<typename PTRT, typename TF> inline PTRT ptr_cast(TF* p) { if (!p) return nullptr; return NOT_NULL(dynamic_cast<PTRT>(p)); }
template<typename T> const T* makeptr(const T& t) { return &t; }

#include "logger.h"


#define ONEBIT(x) (static_cast<size_t>(1)<<(x))

template<typename T> constexpr inline size_t array_size(const T&)
{
    static_assert(std::is_array_v<T>, "array_size can only be used with arrays");
    return std::extent_v<T>;
}

namespace secure
{
    inline void scrub_memory(void* mem, size_t size)
    {
#ifdef _DEBUG
        memset(mem, 0xab, size);
#else
        Botan::secure_scrub_memory(mem, size);
#endif
    }

    template<size_t sz> inline bool equals(const void* m1, const void* m2)
    {
        static_assert((sz & (sizeof(size_t) - 1)) == 0);

#ifdef SSE2_SUPPORTED
        if constexpr (sz == 16)
        {
            return _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128((const __m128i*)m1), _mm_loadu_si128((const __m128i*)m2))) == 0xffff;
        }
        else if constexpr (sz == 32)
        {
            return 0xffff == (_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128((const __m128i*)m1), _mm_loadu_si128((const __m128i*)m2))) &
                _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128((const __m128i*)m1 + 1), _mm_loadu_si128((const __m128i*)m2 + 1))));
        }
        else
#endif
        {
            bool noteq = false;
            const size_t* b1 = reinterpret_cast<const size_t*>(m1);
            const size_t* b2 = reinterpret_cast<const size_t*>(m2);
            for (size_t i = 0; i < sz / sizeof(size_t); ++i, ++b1, ++b2)
                noteq |= ((*b1) ^ (*b2)) != 0;

            return !noteq;
        }
    }
}

namespace tools
{
    size_t unique_id();
    double calculate_entropy(std::span<const u8> data);

	template<size_t sz> struct flags
	{
		using type = sztype<sz>::type;
		type f = 0;
		flags() {}
		flags(type x) :f(x) {}

		void clear()
		{
			f = 0;
		}

		type all() const { return f; }
		void operator=(type v)
		{
			f = v;
		}

		template<type mask> consteval static size_t lowbit()
		{
			static_assert(mask != 0);
			type m = 1;
			for (size_t i = 0; i < sizeof(type) * 8; ++i, m <<= 1)
			{
				if (m & mask)
					return i;
			}
			UNREACHABLE();
		}

		template<type mask> bool is() const
		{
			return 0 != (f & mask);
		}
        template<type mask> void set(bool do_set)
        {
            if (do_set)
                f |= mask;
            else
                f &= ~mask;
        }
        template<type mask> void set()
        {
            f |= mask;
        }
        template<type mask> void unset()
        {
            f &= ~mask;
        }
        template<type mask> bool invert() // return prev
        {
			bool prev = is<mask>();
            f ^= mask;
			return prev;
        }
		template<type mask, size_t shiftleft = 0> size_t getn() const
		{
			return ((f & mask) >> lowbit<mask>()) << shiftleft;
		}
        template<type mask> void setn(size_t v)
        {
			f = (f & (~mask)) | ((v << lowbit<mask>()) & mask);
        }
        template<type mask_set, type mask_clear> void setup()
        {
            f = (f & ~mask_clear) | mask_set;
        }
	};

}

namespace chrono
{
	class mils
	{
		u32 value = 0x80000000; // uninitialized (with hi bit set)
	public:
		mils() {}
		explicit mils(u32 raw) :value(raw) {}
		bool is_empty() const { return (value & 0x80000000) != 0; }
        void empty() { value = 0x80000000; }
		u32 raw() const { return value; }
	};
    inline i32 operator-(mils m1, mils m2)
    {
		ASSERT(0 == ((m1.raw() | m2.raw()) & 0x80000000)); // both initialized
		i32 delta = (static_cast<i32>(m1.raw() << 1) - static_cast<i32>(m2.raw() << 1));
		return delta >> 1;
    }
    inline bool operator >= (mils m1, mils m2)
    {
        return (m1 - m2) >= 0;
    }
	inline bool operator > (mils m1, mils m2)
    {
        return (m1 - m2) > 0;
    }

	inline time_t now() // seconds
	{
		time_t t;
#ifdef _WIN32
		_time64(&t);
#else
        time(&t);
#endif
		return t;
	}

#ifdef _WIN32
	inline mils ms() // milliseconds
	{
		return mils( timeGetTime() & 0x7fffffff );
	}
#endif
#ifdef _NIX
    inline mils ms()
    {
        struct timespec monotime;
#if defined(__linux__) && defined(CLOCK_MONOTONIC_RAW)
        clock_gettime(CLOCK_MONOTONIC_RAW, &monotime);
#else
        clock_gettime(CLOCK_MONOTONIC, &monotime);
#endif
        u64 time = 1000ULL * monotime.tv_sec + (monotime.tv_nsec / 1000000ULL);
        return mils(time & 0x7fffffff);
    }
#endif
	inline mils ms(signed_t addms)
	{
		return mils((ms().raw() + addms) & 0x7fffffff);
	}


#if defined(_MSC_VER)
#pragma intrinsic(__rdtsc)
	inline uint64_t tsc() {
		return __rdtsc();
	}
#elif defined(GCC_OR_CLANG) && defined(ARCH_X86)
	inline uint64_t tsc() {
		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
		return ((uint64_t)hi << 32) | lo;
	}
#elif defined(GCC_OR_CLANG) && defined(ARCH_ARM) && defined(ARCH_64BIT)
    inline uint64_t tsc(void) {
        uint64_t val;
        asm volatile("mrs %0, cntvct_el0" : "=r"(val));
        return val;
    }
#elif defined(GCC_OR_CLANG) && defined(ARCH_ARM) && defined(ARCH_32BIT)
    inline uint64_t tsc(void) {
        uint64_t val;
        asm volatile("mrrc p15, 0, %Q0, %R0, c14" : "=r"(val));
        return val;
    }
#else
#error "Unsupported compiler"
#endif
}

namespace math
{
    constexpr size_t log2_floor(size_t x) {
        return x ? std::bit_width(x) - 1 : 0;
    }

	template<size_t numbits> size_t subnum(std::span<const u8> blob, size_t frombit)
	{
		ASSERT(blob.size() % sizeof(size_t) == 0);

		size_t blobbits = blob.size() * 8;

		if (frombit >= blobbits)
			return subnum<numbits>(blob, frombit - blobbits);

        size_t bitwnd = sizeof(size_t) * 8;

		size_t shift = frombit / bitwnd;
		size_t shift1 = (frombit+numbits-1) / bitwnd;
		size_t maxshift = blob.size() / sizeof(size_t);

		auto getw = [&](size_t s) -> size_t
		{
			return *reinterpret_cast<const size_t*>(blob.data() + (s * 8));
		};

        size_t v = getw(shift) >> frombit;

		if (shift1 > shift)
		{
			if (shift1 >= maxshift)
				shift1 = 0;

			v |= getw(shift1) << (bitwnd-frombit);
		}

		return v & ((1 << numbits) - 1);
	}

    template<typename T> struct is_signed { static const bool value = (((T)-1) < 0); };
    template<> struct is_signed<float> { static const bool value = true; };
    template<> struct is_signed < double > { static const bool value = true; };

#ifdef ARCH_X86
	inline long int fround(float x)
    {
        return _mm_cvtss_si32(_mm_load_ss(&x));
    }

	inline long int dround(double x)
    {
        return _mm_cvtsd_si32(_mm_load_sd(&x));
    }
#endif

	template<typename NUM, int shiftval> struct makemaxint
	{
		static const constexpr NUM value = (makemaxint<NUM, shiftval - 1>::value << 8) | 0xFF;
	};
	template<typename NUM> struct makemaxint < NUM, 0 >
	{
		static const constexpr NUM value = 0x7F;
	};
    template<typename NUM, int shiftval> struct makemaxuint
    {
        static const constexpr NUM value = (makemaxuint<NUM, shiftval - 1>::value << 8) | 0xFF;
    };
    template<typename NUM> struct makemaxuint < NUM, 0 >
    {
        static const constexpr NUM value = 0xFF;
    };

	template<typename NUM> struct maximum
	{
		static const constexpr NUM value = is_signed<NUM>::value ? makemaxint<NUM, sizeof(NUM) - 1>::value : makemaxuint<NUM, sizeof(NUM) - 1>::value;
	};
	template<typename NUM> struct minimum
	{
		static const constexpr NUM value = is_signed<NUM>::value ? (-maximum<NUM>::value - 1) : 0;
	};

}

namespace helpers
{
    template<typename IT> u8 inline clamp2byte(IT n)
    {
        return n < 0 ? 0 : (n > 255 ? 255 : (u8)n);
    }

    template<typename IT> u8 inline clamp2byte_u(IT n)
    {
        return n > 255 ? 255 : (u8)n;
    }

#ifdef ARCH_X86
    // TODO: fround and dround not currently defined for non-x86 arch
    template<typename RT, typename IT, bool issigned> struct clamper;

    template<> struct clamper < u8, float, true >
    {
        static u8 dojob(float b)
        {
            return clamp2byte<int>(math::fround(b));
        }
    };

    template<> struct clamper < u8, double, true >
    {
        static u8 dojob(double b)
        {
            return clamp2byte<int>(math::dround(b));
        }
    };

    template<typename IT> struct clamper < u8, IT, true >
    {
        static u8 dojob(IT n)
        {
            return clamp2byte<IT>(n);
        }
    };

    template<typename IT> struct clamper < u8, IT, false >
    {
        static u8 dojob(IT n)
        {
            return clamp2byte_u<IT>(n);
        }
    };

    template<typename RT, typename IT> struct clamper< RT, IT, false>
    {
        static RT dojob(IT b)
        {
            return b > math::maximum<RT>::value ? math::maximum<RT>::value : (RT)b;
        }
    };
    template<typename RT, typename IT> struct clamper < RT, IT, true >
    {
        static RT dojob(IT b)
        {
            return b < math::minimum<RT>::value ? math::minimum<RT>::value : (b > math::maximum<RT>::value ? math::maximum<RT>::value : (RT)b);
        }
    };
#endif

    template<typename T1, typename T2> using bigger_type = typename std::conditional<(sizeof(T1) >= sizeof(T2)), T1, T2>::type;

    template<bool s1, bool s2, typename T1, typename T2> struct getminmax
    {
        typedef bigger_type<T1, T2> type_min;
		typedef bigger_type<T1, T2> type_max;
        static constexpr T1 getmin(T1 t1, T2 t2)
        {
            return t1 < t2 ? t1 : t2;
        }
        static constexpr T1 getmax(T1 t1, T2 t2)
        {
			return t1 > t2 ? t1 : t2;
        }
    };
	template<typename T1, typename T2> struct getminmax<true, false, T1, T2> {

        typedef T1 type_min;
        typedef T2 type_max;
        static constexpr T1 getmin(T1 t1, T2 t2)
		{
			return t1 < 0 || (size_t)t1 < t2 ? t1 : (T1)t2;
		}
        static constexpr T2 getmax(T1 t1, T2 t2)
        {
            return t1 < 0 || static_cast<size_t>(t1) < t2 ? t2 : static_cast<size_t>(t1);
        }
    };
	template<typename T1, typename T2> struct getminmax<false, true, T1, T2> {

        typedef T2 type_min;
        typedef T1 type_max;
		static constexpr T2 getmin(T1 t1, T2 t2)
		{
			return t2 < 0 || (size_t)t2 < t1 ? t2 : (T2)t1;
		}
        static constexpr T1 getmax(T1 t1, T2 t2)
        {
            return t2 < 0 || (size_t)t2 < t1 ? (T1)t1 : t2;
        }
	};


};

namespace math
{
	template<std::unsigned_integral T, u8 flr> consteval T fill()
	{
		T t = flr;
		for (size_t i = 1; i < sizeof(T); ++i)
		{
			t = (t << 8) | flr;
		}
		return t;
	}

#ifdef ARCH_X86
    // TODO: fround not currently defined for non-x86 arch
    template < typename T1, typename T2, typename T3 > inline T1 clamp(const T1 & a, const T2 & vmin, const T3 & vmax)
    {
        return (T1)(((a) > (vmax)) ? (vmax) : (((a) < (vmin)) ? (vmin) : (a)));
    }

    template < typename RT, typename IT > inline RT clamp(IT b)
    {
        return helpers::clamper<RT, IT, is_signed<IT>::value>::dojob(b);
    }
#endif

    template < typename T1 > inline T1 abs(const T1 &x)
    {
        return x >= 0 ? x : (-x);
    }

#ifdef ARCH_X86
    // TODO: fround not currently defined for non-x86 arch
    int inline lerp_int(int a, int b, float t)
    {
        float v = static_cast<float>(a) * (1.0f - (t)) + (t) * static_cast<float>(b);
        return fround(v);
    }
#endif

	template < typename T1, typename T2 > inline constexpr typename helpers::getminmax<is_signed<T1>::value, is_signed<T2>::value, T1, T2>::type_min minv(T1 x1, T2 x2)
	{
        return helpers::getminmax<is_signed<T1>::value, is_signed<T2>::value, T1, T2>::getmin(x1, x2);
	}

    template < typename T1, typename T2 > inline constexpr typename helpers::getminmax<is_signed<T1>::value, is_signed<T2>::value, T1, T2>::type_max maxv(T1 x1, T2 x2)
    {
        return helpers::getminmax<is_signed<T1>::value, is_signed<T2>::value, T1, T2>::getmax(x1, x2);
    }

    /*
	template < typename T > inline T nmin(const T& x, const T& y)
	{
		return x <= y ? x : y;
	}
    */
}


#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)

#define __STR3W__(x) L ## x
#define __STR2W__(x) __STR3W__( #x )
#define __STR1W__(x) __STR2W__(x)

#define LIST_ADD(el,first,last,prev,next) {if((last)!=nullptr) {(last)->next=el;} (el)->prev=(last); (el)->next=nullptr;  last=(el); if(first==nullptr) {first=(el);}}
#define LIST_DEL(el,first,last,prev,next) \
    {if((el)->prev!=0) (el)->prev->next=el->next;\
        if((el)->next!=0) (el)->next->prev=(el)->prev;\
        if((last)==(el)) last=(el)->prev;\
    if((first)==(el)) (first)=(el)->next;}

template<typename CH> inline bool is_letter(CH c)
{
	return (c >= L'a' && c <= 'z') || (c >= L'A' && c <= 'Z');
}

template<typename CH> inline bool is_digit(CH c)
{
	return c >= '0' && c <= '9';
}


namespace str
{
	template<typename CH> str::xstr<CH> replace_all_copy(const str::xstr_view<CH>& source, const str::xstr_view<CH>&what, const str::xstr_view<CH>& to)
	{
		std::string new_string;
        new_string.reserve(source.length());

		std::string::size_type lastPos = 0;
		std::string::size_type findPos;

		while (std::string::npos != (findPos = source.find(what, lastPos)))
		{
            new_string.append(source, lastPos, findPos - lastPos);
            new_string += to;
			lastPos = findPos + what.length();
		}

		// Care for the rest after last occurrence
        new_string += source.substr(lastPos);

        return new_string;
	}
}

namespace tools
{
    static inline void store32_le(uint8_t* dst, u32 w)
    {
        if constexpr (Endian::little)
        {
            *(u32*)dst = w;
		}
        else
        {
			dst[0] = as_byte(w >> 24);
			dst[1] = as_byte(w >> 16);
			dst[2] = as_byte(w >> 8);
			dst[3] = as_byte(w);
        }
    }

    static inline void store64_le(uint8_t* dst, u64 w)
    {
        if constexpr (Endian::little)
        {
            *(u64*)dst = w;
        }
        else
        {
            dst[0] = as_byte(w >> 56);
            dst[1] = as_byte(w >> 48);
            dst[2] = as_byte(w >> 40);
            dst[3] = as_byte(w >> 32);
            dst[4] = as_byte(w >> 24);
            dst[5] = as_byte(w >> 16);
            dst[6] = as_byte(w >> 8);
            dst[7] = as_byte(w);
        }
    }


	template<typename T> class deferred_init
	{
		u8 data[sizeof(T)];

	public:

        deferred_init() {}
        ~deferred_init() {
			get()->~T();
        }

        template <class... _Valty> void init(_Valty&&... _Val)
        {
			new(get())T(std::forward<_Valty>(_Val)...);
        }

		T* get() { return reinterpret_cast<T*>(&data); }
		const T* get() const { return reinterpret_cast<const T*>(&data); }

		T& operator *()
		{
			return ref_cast<T>(data);
		}
        const T& operator *() const
        {
            return ref_cast<T>(data);
        }
        T* operator->() {
            return get();
        }
        const T* operator->() const {
            return get();
        }

	};

    template<typename T> constexpr bool is_plain_old_struct_v =
        std::is_trivially_default_constructible_v<T> &&
        std::is_trivially_copy_constructible_v<T> &&
        std::is_trivially_move_constructible_v<T> &&
        std::is_trivially_destructible_v<T>;

	template<typename T, size_t align> requires(is_plain_old_struct_v<T> && std::has_single_bit(align)) class aligned_data
	{
		u8 data[sizeof(T) + align];
	public:
		aligned_data()
		{
			size_t addr_ok = (reinterpret_cast<size_t>(data + 1) + align - 1) & ~(size_t)(align - 1);
			size_t addr_cur = reinterpret_cast<size_t>(data + 0);
			data[0] = static_cast<u8>(addr_ok - addr_cur); // offset to aligned
		}
		T& operator->() { return *(T*)(data + data[0]); }
		const T& operator->() const { return *(const T*)(data + data[0]); }
	};


    struct skip_buf : public buffer
    {
        size_t skip = 0;
        u8* data() { return buffer::data() + skip; }
        const u8* data() const { return buffer::data() + skip; }
        size_t size() const { return buffer::size() - skip; }
        void clear() {
            buffer::clear();
            skip = 0;
        }
        void erase(size_t szerase)
        {
            skip += szerase;
        }

        skip_buf& operator+=(const std::span<const u8>& d)
        {
            if (skip > 500 * 1024 && sz + d.size() > cap)
            {
                memcpy(buffer::data(), data(), size());
                sz = size();
                skip = 0;
            }
            buffer::operator+=(d);
            return *this;
        }
    };

	struct memory_pair
	{
		std::span<u8> p0, p1;
		template<typename T> memory_pair(T& t)
		{
			p0 = std::span(reinterpret_cast<u8 *>(&t), sizeof(T));
		}
		memory_pair(u8* p, size_t sz) :p0(p, sz) {}
		memory_pair(u8* p0, size_t sz0, u8* p1, size_t sz1) :p0(p0, sz0), p1(p1, sz1) {}

        const u8* get_plain(u8 *buffer, size_t sz) const
        {
            if (sz <= p0.size())
                return p0.data();

            this->copy_out(buffer, sz);
            return buffer;
        }

        u8 operator[](size_t i) const
        {
            if (i < p0.size())
                return p0.data()[i];
            i -= p0.size();
            if (i < p1.size())
                return p1.data()[i];
            return 0;
        }

		str::astr_view view1st() const
		{
			return str::view(p0);
		}
        str::astr_view view2nd() const
        {
            return str::view(p0);
        }

		size_t size() const
		{
			return p0.size() + p1.size();
		}

		void copy_in(size_t offset, const u8* data, size_t sz)
		{
			if (offset < p0.size())
			{
				// some space in 1st buf
				size_t ost = math::minv(p0.size() - offset, sz);
				memcpy(p0.data() + offset, data, ost);
				sz -= ost;
				offset += ost;
				data += ost;
			}
			if (sz > 0)
			{
				offset -= p0.size();
				ASSERT(p1.size() >= (sz+offset));
				memcpy(p1.data() + offset, data, sz);
			}
		}
        void copy_out(u8* data, size_t sz) const
        {
            if (p0.size())
            {
                // some space in 1st buf
                size_t ost = math::minv(p0.size(), sz);
                memcpy(data, p0.data(), ost);
                sz -= ost;
                data += ost;
            }
            if (sz > 0 && p1.size() > 0)
            {
                size_t ost = math::minv(p1.size(), sz);
                memcpy(data, p1.data(), ost);
            }
        }
	};

    struct const_memory_pair
    {
        std::span<const u8> p0, p1;
        const_memory_pair(const u8* p, size_t sz) :p0(p, sz) {}
        const_memory_pair(const u8* p0, size_t sz0, const u8* p1, size_t sz1) :p0(p0, sz0), p1(p1, sz1) {}

        const u8* get_plain(u8* buffer, size_t sz) const
        {
            if (sz <= p0.size())
                return p0.data();

            this->copy_out(buffer, sz);
            return buffer;
        }

        u8 operator[](size_t i) const
        {
            if (i < p0.size())
                return p0.data()[i];
            i -= p0.size();
            if (i < p1.size())
                return p1.data()[i];
            return 0;
        }

        size_t size() const
        {
            return p0.size() + p1.size();
        }

        void copy_out(u8* data, size_t sz) const
        {
            if (p0.size())
            {
                // some space in 1st buf
                size_t ost = math::minv(p0.size(), sz);
                memcpy(data, p0.data(), ost);
                sz -= ost;
                data += ost;
            }
            if (sz > 0 && p1.size() > 0)
            {
                memcpy(data, p1.data(), sz);
            }
        }
    };

	template<signed_t size> class chunk_buffer
	{
	public:
		enum {
			SIZE = size
		};
	private:
		struct chunk
		{
			u8 data[SIZE];
			std::unique_ptr<chunk> next;
		};

		std::unique_ptr<chunk> first;
		chunk* last = nullptr;
		signed_t first_skip = 0;
		signed_t last_size = 0;

		void insert_impl(std::span<const u8> &data)
		{
			if (first_skip > 0)
			{
				signed_t cpy = math::minv(first_skip, data.size());

				memcpy( first->data + first_skip - cpy, data.data() + data.size() - cpy, cpy );
				data = std::span( data.data(), data.size() - cpy );
				first_skip -= cpy;
				return;
			}

            chunk* nch = NEW chunk();
			signed_t cpy = math::minv(SIZE, data.size());
			memcpy(nch->data + SIZE - cpy, data.data() + data.size() - cpy, cpy);
			data = std::span(data.data(), data.size() - cpy);
			first_skip = SIZE - cpy;
			nch->next.reset( first.get() );
			first.release();
			first.reset(nch);
		}

	public:
		chunk_buffer() {}
		chunk_buffer(chunk_buffer&& ab):first(std::move(ab.first)), last(ab.last), first_skip(ab.first_skip), last_size(ab.last_size)
		{
			ab.last = nullptr;
			ab.first_skip = 0;
			ab.last_size = 0;
		}

		void operator=(chunk_buffer&& ab)
		{
			first = std::move(ab.first);
			last = ab.last;
			first_skip = ab.first_skip;
			last_size = ab.last_size;
            ab.last = nullptr;
            ab.first_skip = 0;
            ab.last_size = 0;
		}

		void clear()
		{
            first.reset();
            last = nullptr;
            first_skip = 0;
            last_size = 0;
		}

		void insert(std::span<const u8> data) // insert to beginning
		{
			if (!first)
			{
				assign(data);
				return;
			}

			while (data.size() > 0)
				insert_impl( data );
		}

		void assign(std::span<const u8> data)
		{
			if (data.size() == 0)
			{
				clear();
				return;
			}

			if (!first)
			{
				first.reset(NEW chunk());
				last = first.get();
				last_size = 0;
			}
			else
			{
				first_skip = 0;
			}

			for (chunk *ch = first.get(); data.size() > 0;)
			{
				signed_t cpy = math::minv(SIZE, data.size());
				memcpy(ch->data, data.data(), cpy);
				last_size = cpy;
				data = std::span<const u8>(data.data() + cpy, data.size() - cpy);

				if (data.size() > 0)
				{
					if (!ch->next)
						ch->next.reset(NEW chunk());
					ch = ch->next.get();
					last = ch;
					continue;
				}
				else
				{
					ch->next.reset();
					break;
				}
			}
		}

		memory_pair alloc(signed_t siz)
		{
            if (!first)
            {
                first.reset(NEW chunk());
                last = first.get();
                last_size = 0;
            }
			signed_t ost = SIZE - last_size;
            ASSERT(siz <= SIZE+ost);
			if (siz <= ost)
			{
				u8 *rv = last->data + last_size;
                last_size += siz;
				return memory_pair(rv, siz);
			}

			u8* p0 = last->data + last_size;

            last_size = siz - ost;
            last->next.reset(NEW chunk());
            last = last->next.get();

			return memory_pair(p0, ost, last->data, last_size);
		}

		void append(std::span<const u8> data)
		{
			if (!first)
			{
				first.reset(NEW chunk());
				last = first.get();
				last_size = 0;
			}

			for (;data.size() > 0;)
			{
				signed_t ost = SIZE - last_size;
				signed_t cpy = math::minv(ost, data.size());
				memcpy(last->data + last_size, data.data(), cpy);
				last_size += cpy;
				data = std::span<const u8>( data.data() + cpy, data.size() - cpy );
				if (last_size == SIZE)
				{
					last_size = 0;
					last->next.reset( NEW chunk() );
					last = last->next.get();
				}
			}
		}

		chunk_buffer& operator += (std::span<const u8> data)
		{
			append(data);
			return *this;
		}

		std::span<const u8> get_1st_chunk()
		{
			if (!first)
				return std::span<const u8>();
			return std::span<const u8>(first->data + first_skip, (first.get() == last ? last_size : SIZE) - first_skip);
		}

		void skip(signed_t sv)
		{
			first_skip += sv;
			for (;;)
			{
				signed_t fsz = first.get() == last ? last_size : SIZE;
				if (first_skip < fsz)
					break;

				first_skip -= fsz;
				chunk* next = first->next.get();
				first->next.release();
				first.reset(next);
				if (!next)
				{
					last = nullptr;
					ASSERT(first_skip == 0);
					break;
				}
			}
		}

        signed_t peek(u8* out, signed_t sv) // like skip with data get
        {
            signed_t total_peeked = 0;
            for (; first && sv > 0;)
            {
                auto fc = get_1st_chunk();
                signed_t cpy = math::minv(sv, fc.size());
                memcpy(out, fc.data(), cpy);
                sv -= cpy;
                out += cpy;
                skip(cpy);
                total_peeked += cpy;
            }
            return total_peeked;
        }

		template<typename BUF> signed_t peek(BUF &bufout, signed_t sv) // like skip with data get
        {
            signed_t total_peeked = 0;
            for (; first && sv > 0;)
            {
                auto fc = get_1st_chunk();
                signed_t cpy = math::minv(sv, fc.size());
                bufout += std::span<const u8>(fc.data(), cpy);
                sv -= cpy;
                skip(cpy);
                total_peeked += cpy;
            }
            return total_peeked;
        }

		signed_t peek(u8* out) // peek all
		{
			signed_t total_peeked = 0;
			for (; first;)
			{
				auto fc = get_1st_chunk();
				memcpy(out, fc.data(), fc.size());
				out += fc.size();
				total_peeked += fc.size();

				first_skip = 0;
				chunk* next = first->next.get();
				first->next.release();
				first.reset(next);
				if (!next)
				{
					last = nullptr;
					ASSERT(first_skip == 0);
					break;
				}

			}
			return total_peeked;
		}

        template<typename BUF> signed_t peek(BUF & bufout) // peek all
        {
            signed_t cap = capacity(bufout);
            if (cap == 0)
                cap = math::maximum<signed_t>::value;
            signed_t total_peeked = 0;
            for (; first;)
            {
                auto fc = get_1st_chunk();
                auto cpy = math::minv(cap, fc.size());
                bufout += std::span<const u8>(fc.data(), cpy);
                total_peeked += cpy;
                cap -= cpy;
                if (cap == 0)
                {
                    first_skip += cpy;
                    return total_peeked;
                }

                first_skip = 0;
                chunk* next = first->next.get();
                first->next.release();
                first.reset(next);
                if (!next)
                {
                    last = nullptr;
                    ASSERT(first_skip == 0);
                    break;
                }

            }
            return total_peeked;
        }

		bool is_empty() const
		{
			return first == nullptr || (first.get() == last && last_size == 0);
		}

		bool enough(signed_t sz) const // is buffer contain at least sz bytes
		{
			signed_t csz = -first_skip;
			for (chunk* ch = first.get(); ch; ch = ch->next.get())
			{
				signed_t fcsh = ch == last ? last_size : SIZE;
				csz += fcsh;
				if (csz >= sz)
					return true;
			}
			return csz >= sz;
		}

		bool enough_for(signed_t sz) const // is sz bytes enough to fit whole buffer data
		{
			signed_t csz = -first_skip;
			for (chunk* ch = first.get(); ch; ch = ch->next.get())
			{
				signed_t fcsh = ch == last ? last_size : SIZE;
				csz += fcsh;
				if (csz > sz)
					return false;
			}
			return csz <= sz;
		}

	};

	inline signed_t capacity(const str::astr&)
	{
		return 0;
	}
    template<signed_t size> signed_t capacity(const chunk_buffer<size>&)
    {
        return 0;
    }
    inline signed_t capacity(const buffer&)
    {
        return 0;
    }
	class circular_buffer_extdata;
	signed_t capacity(const circular_buffer_extdata&);

	class circular_buffer_engine
	{
    protected:
        i32 start = 0, end = 0;
	public:
        using tank = std::span<u8>;
		using const_tank = std::span<const u8>;

        void clear()
        {
            start = 0;
            end = 0;
        }

	protected:
		circular_buffer_engine() {}

		bool is_full( size_t size ) const
		{
			return (start == 0 && UNSIGNED % end == size) || (end + 1 == start);
		}

#if 0
		bool insert(const u8* d, signed_t sz, tank storage)
		{
			if (get_free_size(storage.size()) < sz)
				return false;

			i32 dsz = datasize(storage.size());
			u8* temp = ALLOCA(dsz);
			peek(temp, dsz, storage);
			clear();
			auto t = get_1st_free(storage);
			ASSERT((signed_t)t.size() <= (sz + dsz));
			memcpy(t.data(), d, sz);
            memcpy(t.data() + sz, temp, dsz);
			confirm(sz + dsz, storage.size());
			return true;
		}
#endif

		size_t datasize(size_t size) const { return (start <= end) ? (end - start) : ((size - start) + end); }
        size_t get_free_size(size_t size) const
		{
			if (start <= end)
			{
				i32 sz1 = static_cast<i32>(size) - end;
				i32 sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				return sz1 + sz2;
			}
			signed_t sz = start - end - 1; if (sz < 0) sz = 0;
			return sz;
		}

        const u8* plain_data(u8* temp, size_t getsize, const_tank storage) const
        {
            if (getsize > datasize(storage.size()))
                return nullptr;
            return data(getsize, storage).get_plain(temp, getsize);
        }

		memory_pair data(size_t getsize, tank storage)
		{
			if (start <= end)
				return memory_pair(storage.data() + start, math::minv(getsize, end-start));

			size_t sz1 = storage.size() - start;
			if (getsize <= sz1)
				return memory_pair(storage.data() + start, getsize);
			getsize -= sz1;
			return memory_pair(storage.data() + start, sz1, storage.data(), math::minv(getsize, end));
		}

        const_memory_pair data(size_t getsize, const_tank storage) const
        {
            if (start <= end)
                return const_memory_pair(storage.data() + start, math::minv(getsize, end - start));

            size_t sz1 = storage.size() - start;
            if (getsize <= sz1)
                return const_memory_pair(storage.data() + start, getsize);
            getsize -= sz1;
            return const_memory_pair(storage.data() + start, sz1, storage.data(), math::minv(getsize, end));
        }

        tank get_1st_free(tank storage) // it simply returns the 1st free block following the data; after filling you should call confirm method to apply append
		{
			if (start <= end)
			{
				i32 sz1 = static_cast<i32>(storage.size()) - end;
				i32 sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				if (sz1 == 0)
					return tank(storage.data(), sz2);
				return tank(storage.data() + end, sz1); // , tank(data, sz2)
			}
			i32 sz = start - end - 1; if (sz < 0) sz = 0;
			return tank(storage.data() + end, sz); // , tank(nullptr, 0)
		}
        memory_pair get_free(tank storage) // it simply returns the free blocks following the data; after filling you should call confirm method to apply append
        {
            if (start <= end)
            {
                i32 sz1 = static_cast<i32>(storage.size()) - end;
                i32 sz2 = start - 1; if (sz2 < 0) sz2 = 0;
                if (sz1 == 0)
                    return memory_pair(storage.data(), sz2);
                return memory_pair(storage.data() + end, sz1, storage.data(), sz2);
            }
            i32 sz = start - end - 1; if (sz < 0) sz = 0;
            return memory_pair(storage.data() + end, sz); // , tank(nullptr, 0)
        }
		void confirm(signed_t sz, size_t size)
		{
			if (start <= end)
			{
				i32 sz1 = static_cast<i32>(size) - end;
#ifdef _DEBUG
				i32 sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				ASSERT(sz <= (sz1 + sz2));
#endif
				if (sz <= sz1)
				{
					end += static_cast<i32>(sz);
					return;
				}

				end = static_cast<i32>(sz - sz1);
				return;
			}


#ifdef _DEBUG
			i32 sz0 = start - end - 1; if (sz < 0) sz = 0;
			ASSERT(sz <= sz0);
#endif
			end += static_cast<i32>(sz);
		}

        i32 append(const_tank d, tank storage)
        {
            auto cpy = [](tank dst, const_tank src) -> i32
                {
                    size_t cpysz = math::minv(dst.size(), src.size());
                    memcpy(dst.data(), src.data(), cpysz);
                    return static_cast<i32>(cpysz);
                };

            i32 cpyd = 0;
            for (; d.size() > 0;)
            {

                auto csz = cpy(get_1st_free(storage), d);
                if (csz == 0)
                    return cpyd;
                cpyd += csz;
                d = const_tank(d.data() + csz, d.size() - csz);
                confirm(csz, storage.size());
            }
            return cpyd;
        }

        void skip(signed_t skipbytes, size_t size)
        {
            if (start <= end)
            {
                // continuous block
                i32 blocksize = end - start;
                if (skipbytes < blocksize)
                {
                    start += static_cast<i32>(skipbytes);
					return; // static_cast<i32>(skipbytes);
                }
                clear();
				return; // blocksize;

            }

            // two blocks: from start to size and from 0 to end
            i32 sz1 = static_cast<i32>(size) - start;
            i32 sz2 = end;

            if (skipbytes <= sz1)
            {
                start += static_cast<i32>(skipbytes);
                if (UNSIGNED % start == size)
                    start = 0;
				return; // static_cast<i32>(skipbytes);
            }
			skipbytes -= sz1;

            if (skipbytes < sz2)
            {
                start = static_cast<i32>(skipbytes);
				return; // static_cast<i32>(sz1 + outsize);
            }

            clear();
			return; // sz1 + sz2;

        }

		i32 peek(u8* output, signed_t outsize, const_tank storage)
		{
			if (start <= end)
			{
				// continuous block
				i32 blocksize = end - start;
				if (outsize < blocksize)
				{
					memcpy(output, storage.data() + start, outsize);
					start += static_cast<i32>(outsize);
					return static_cast<i32>(outsize);
				}
				memcpy(output, storage.data() + start, blocksize);
				clear();
				return blocksize;

			}

			// two blocks: from start to size and from 0 to end
			i32 sz1 = static_cast<i32>(storage.size()) - start;
			i32 sz2 = end;

			if (outsize <= sz1)
			{
				memcpy(output, storage.data() + start, outsize);
				start += static_cast<i32>(outsize);
				if (UNSIGNED % start == storage.size())
					start = 0;
				return static_cast<i32>(outsize);
			}
			memcpy(output, storage.data() + start, sz1);
			outsize -= sz1;

			if (outsize < sz2)
			{
				memcpy(output + sz1, storage.data(), outsize);
				start = static_cast<i32>(outsize);
				return static_cast<i32>(sz1 + outsize);
			}

			memcpy(output + sz1, storage.data(), sz2);
			clear();
			return sz1 + sz2;

		}
        template<typename BUF> i32 peek(BUF &buf, const_tank storage)
        {
            if (start <= end)
            {
                // continuous block
                i32 blocksize = end - start;
				buf += std::span<const u8>(storage.data() + start, blocksize);
                clear();
                return blocksize;
            }

            // two blocks: from start to size and from 0 to end
            i32 sz1 = static_cast<i32>(storage.size()) - start;
            i32 sz2 = end;

            buf += std::span<const u8>(storage.data() + start, sz1);
			buf += std::span<const u8>(storage.data(), sz2);
            clear();
            return sz1 + sz2;
        }
		template<typename BUF> i32 peek(BUF& buf, signed_t limit, const_tank storage)
		{
			signed_t bufcap = capacity(buf);
			if (limit == 0 && bufcap == 0)
				return peek(buf, storage);

			size_t a = bufcap - 1;
			size_t b = limit - 1;
			limit = math::minv( a, b ) + 1;

            if (start <= end)
            {
                // continuous block
                i32 blocksize = end - start;
                if (limit < blocksize)
                {
					buf += std::span<const u8>(storage.data() + start, limit);
                    start += static_cast<i32>(limit);
                    return static_cast<i32>(limit);
                }
				buf += std::span<const u8>(storage.data() + start, blocksize);
                clear();
                return blocksize;

            }

            // two blocks: from start to size and from 0 to end
            i32 sz1 = static_cast<i32>(storage.size()) - start;
            i32 sz2 = end;

            if (limit <= sz1)
            {
				buf += std::span<const u8>(storage.data() + start, limit);
                start += static_cast<i32>(limit);
                if (UNSIGNED % start == storage.size())
                    start = 0;
                return static_cast<i32>(limit);
            }
			buf += std::span<const u8>(storage.data() + start, sz1);
			limit -= sz1;

            if (limit < sz2)
            {
				buf += std::span<const u8>(storage.data(), limit);
                start = static_cast<i32>(limit);
                return static_cast<i32>(sz1 + limit);
            }

			buf += std::span<const u8>(storage.data(), sz2);
            clear();
            return sz1 + sz2;
		}
	};

	template<size_t desiredsize> class circular_buffer : public circular_buffer_engine
	{
		constexpr const static size_t size = (desiredsize + 3) & (~3);
		u8 bytes[size];

	public:
		circular_buffer() {}
		circular_buffer(circular_buffer&& x) noexcept
		{
			end = x.peek(bytes, size - 1);
		}
		void operator=(circular_buffer&& x) noexcept
		{
			start = 0;
			end = x.peek(bytes, size - 1);
		}

        bool is_full() const { return circular_buffer_engine::is_full(size); }
		//bool insert(const u8* d, signed_t sz) { return circular_buffer_engine::insert(d, sz, std::span(bytes, size)); }
		i32 datasize() const { return circular_buffer_engine::datasize(size); }
        const u8* plain_data(u8* buffer, size_t getsize) const { return circular_buffer_engine::plain_data(buffer, getsize, std::span(bytes, size)); }
        i32 peek(u8* output, signed_t outsize) { return circular_buffer_engine::peek(output, outsize, std::span(bytes, size)); }
		template<typename BUF> i32 peek(BUF &buf, signed_t limit = 0) { return circular_buffer_engine::peek<BUF>(buf, limit, std::span(bytes, size)); }
		void confirm(signed_t sz) { circular_buffer_engine::confirm(sz, size); }
		tank get_1st_free() { return circular_buffer_engine::get_1st_free(std::span(bytes, size)); }
		i32 get_free_size() const { return circular_buffer_engine::get_free_size(size); }

	};

	class circular_buffer_extdata : public circular_buffer_engine
	{
	public:
		std::span<u8> storage;

		circular_buffer_extdata(std::span<u8> s, bool prefill = false) :storage(s) {
			if (prefill)
				end = static_cast<i32>(s.size());
		};
        template<size_t N> circular_buffer_extdata(std::array<u8, N> &s, bool prefill = false) :storage(std::span(s.data(), N)) {
            if (prefill)
                end = static_cast<i32>(s.size());
        };

		bool is_full() const { return circular_buffer_engine::is_full(storage.size()); }
		//bool insert(const u8* d, signed_t sz) { return circular_buffer_engine::insert(d, sz, storage); }
		size_t datasize() const { return circular_buffer_engine::datasize(storage.size()); }
		const u8* plain_data(u8 * buffer, size_t getsize) const { return circular_buffer_engine::plain_data(buffer, getsize, storage); }
		memory_pair data(size_t getsize) { return circular_buffer_engine::data(getsize, storage); }
		i32 peek(u8* output, signed_t outsize) { return circular_buffer_engine::peek(output, outsize, storage); }
		template<typename BUF> i32 peek(BUF& buf, signed_t limit = 0) { return circular_buffer_engine::peek<BUF>(buf, limit, storage); }
		void skip(signed_t skipbytes) { circular_buffer_engine::skip(skipbytes, storage.size()); }
		void confirm(signed_t sz) { circular_buffer_engine::confirm(sz, storage.size()); }
		tank get_1st_free() { return circular_buffer_engine::get_1st_free(storage); }
		memory_pair get_free() { return circular_buffer_engine::get_free(storage); }
		size_t get_free_size() const { return circular_buffer_engine::get_free_size(storage.size()); }

		template<typename T> T getle()
		{
			if constexpr (sizeof(T) == 1)
			{
				T r = static_cast<T>(*(storage.data() + start));
				skip(1);
				return r;
			}
			else
			{
				T r;
				peek(reinterpret_cast<u8*>(&r), sizeof(T));
				return r;
			}

		}

		circular_buffer_extdata& operator+=(const_tank d)
		{
			ASSERT((size_t)get_free_size() >= d.size());
			circular_buffer_engine::append(d, storage);
			return *this;
		}
	};

	inline signed_t capacity(const circular_buffer_extdata& cbed)
	{
		return cbed.get_free_size();
	}

	template<size_t sz> class circular_buffer_preallocated : public circular_buffer_extdata
	{
		u8 buf[sz];
	public:
		circular_buffer_preallocated():circular_buffer_extdata(std::span<u8>(buf, sz)) {}
	};


#ifdef GCC_OR_CLANG
    template<typename T> signed_t lowest_bit_index(T x) {
		if (0 == x)
			return -1;
        return __builtin_ctzll(x);
    }
#endif
#ifdef _MSC_VER
#ifdef ARCH_64BIT
#pragma intrinsic(_BitScanForward64)
	template<typename T> signed_t lowest_bit_index(T x) {

        unsigned long index;
        return _BitScanForward64(&index, x) ? SIGNED % index : -1;
    }
#else
#pragma intrinsic(_BitScanForward)
	template<typename T>  signed_t lowest_bit_index(T x) {

        if constexpr (sizeof(T) == 4)
        {
            unsigned long index;
            return _BitScanForward(&index, x) ? SIGNED % index : -1;
        }
		else {

            unsigned long index;
			if (_BitScanForward(&index, static_cast<u32>(x & 0xffffffff)))
				return SIGNED % index;

			return _BitScanForward(&index, static_cast<u32>(x >> 32)) ? SIGNED % (index + 32) : -1;
		}
    }
#endif
#endif

    template<size_t initial_size> struct fifo_behaviour_base
    {
        using setype = u32;

        size_t size = initial_size;
        setype start = 0;
        setype end = 0;

        size_t get_count(setype s, setype e) const {
            return (s <= e) ? (e - s) : ((static_cast<setype>(size) - s) + e);
        }

        bool allow_shrink()
        {
            return false;
        }

        bool need_shrink(setype, setype) const {
            return false;
        }

        void shrinked() {}


        setype load_start() const { return start; }
        setype load_end() const { return end; }
        void store_start(setype t) { start = t; }

        template<bool locked> void store_end(setype t)
        {
            if constexpr (locked)
            {
            }
            else
            {
                end = t;
            }
        }

        void unlock_end(setype)
        {
        }

        setype lock_end()
        {
            return end;
        }

        static setype lock_start(setype expected_start)
        {
            return expected_start;
        }

    };

#if 0
    template<size_t initial_size> struct fifo_behaviour_shrinkable : public fifo_behaviour_base<initial_size>
    {
        using super_type = fifo_behaviour_base<initial_size>;

        enum consts
        {
            SHRINK_DISABLED = 100,
        };

        int shrink_disabled = SHRINK_DISABLED;

        bool allow_shrink()
        {
            return (--shrink_disabled) <= 0;
        }

        bool need_shrink(super_type::setype s, super_type::setype e) const {
            if (super_type::size == initial_size)
                return false;

            return super_type::get_count(s, e) < super_type::size / 4;
        }

        void shrinked() {}


        template<bool locked> void store_end(super_type::setype t)
        {
            if constexpr (locked)
            {
            }
            else
            {
                if (super_type::get_count(super_type::load_start(), t) >= super_type::size / 2)
                    shrink_disabled = SHRINK_DISABLED;

                super_type::end = t;
            }
        }
    };
#endif

    // timebased shrinkable
    template<size_t initial_size> struct fifo_behaviour_shrinkable : public fifo_behaviour_base<initial_size>
    {
        using super_type = fifo_behaviour_base<initial_size>;

        enum consts
        {
            SHRINK_DISABLED_TIME = 10000,
        };

        chrono::mils next_shrink;

        void shrinked()
        {
            next_shrink = chrono::ms(SHRINK_DISABLED_TIME);
        }

        bool allow_shrink()
        {
            return next_shrink.is_empty() || chrono::ms() > next_shrink;
        }

        bool need_shrink(super_type::setype s, super_type::setype e) const {
            if (super_type::size == initial_size)
                return false;

            return super_type::get_count(s, e) < super_type::size / 4;
        }
    };



    template<size_t initial_size> struct fifo_behaviour_sync
    {
        using setype = u32;

        volatile size_t size = initial_size;
        volatile setype start = 0;
        volatile setype end = 0;

        enum consts : setype
        {
            LOCKBIT = setype(1) << (31),
        };

        size_t get_count(setype s, setype e) const {
            return (s <= e) ? (e - s) : ((static_cast<setype>(size) - s) + e);
        }

        bool allow_shrink()
        {
            return false;
        }

        bool need_shrink(setype, setype) const
        {
            return false;
        }

        void shrinked()
        {

        }

        setype load_start() const
        {
            return spinlock::atomic_load(start) & (~LOCKBIT);
        }
        setype load_end() const
        {
            return spinlock::atomic_load(end) & (~LOCKBIT);
        }

        void store_start(setype t)
        {
            spinlock::atomic_set(start, t);
        }
        template<bool locked> void store_end(setype t)
        {
            if constexpr (locked)
                spinlock::atomic_set(end, t | LOCKBIT);
            else
            {
                spinlock::atomic_set(end, t);
            }
        }

        void unlock_end(setype t)
        {
            spinlock::atomic_set(end, t);
        }

        setype lock_end()
        {
            setype expected_end = load_end();

            // lock end index (for write)
            for (size_t spincount = 0;; ++spincount)
            {
                expected_end &= ~LOCKBIT;
                setype val = expected_end | LOCKBIT;

                if (spinlock::atomic_cas_update_expected(end, expected_end, val))
                    return val & (~LOCKBIT);

                SPINCOUNT_SLEEP(spincount, expected_end = load_end());
            }
            UNREACHABLE();
        }

        setype lock_start(setype expected_start)
        {
            for (size_t spincount = 0;; ++spincount)
            {
                expected_start &= ~LOCKBIT; // expected unlocked [start]
                setype val = expected_start | LOCKBIT;

                if (spinlock::atomic_cas_update_expected(start, expected_start, val))
                    return val & (~LOCKBIT);

                SPINCOUNT_SLEEP(spincount, expected_start = load_start());
            }
            UNREACHABLE();
        }

    };

    template<size_t initial_size> struct fifo_behaviour_sync_shrinkable : public fifo_behaviour_sync<initial_size>
    {
        using super_type = fifo_behaviour_sync<initial_size>;

        enum consts
        {
            SHRINK_DISABLED_TIME = 10000,
        };

        chrono::mils next_shrink;

        void shrinked()
        {
            next_shrink = chrono::ms(SHRINK_DISABLED_TIME);
        }

        bool allow_shrink()
        {
            return next_shrink.is_empty() || chrono::ms() > next_shrink;
        }

        bool need_shrink(super_type::setype s, super_type::setype e) const {
            if (super_type::size == initial_size)
                return false;

            return super_type::get_count(s, e) < super_type::size / 4;
        }

    };

    // Circular based fixed-size queue with separated (enqueue|dequeue) spinlock synchronization
    template<typename T, size_t initial_size = 4, size_t max_size = 2147483648, typename beh = fifo_behaviour_sync_shrinkable<initial_size> >
        requires(std::has_single_bit(initial_size) && std::has_single_bit(max_size)) class fifo : public beh
    {
        T* items;

        bool is_full(beh::setype s, beh::setype e) const
        {
            return ((e + 1) & (beh::size - 1)) == s;
        }

        void init(size_t s, size_t e)
        {
            if constexpr (!std::is_trivially_default_constructible_v<T>)
            {
                for (size_t i = s; i < e; ++i)
                    new (items + i) T();
            }
        }

        void del(size_t s, size_t e)
        {
            if constexpr (!std::is_trivially_default_constructible_v<T>)
            {
                for (size_t i = s; i < e; ++i)
                    items[i].~T();
            }
        }

    public:

        fifo()
        {
            items = (T*)MA(initial_size * sizeof(T));
            init(0, beh::size);
        }
        ~fifo()
        {
            del(0, beh::size);
            ma::mf(items);
        }

        size_t get_max_size() const { return beh::size; }
        size_t get_count() const {
            typename beh::setype s = beh::load_start();
            typename beh::setype e = beh::load_end();
            return beh::get_count(s, e);
        }
        bool is_full() const
        {
            return is_full(beh::load_start(), beh::load_end());
        }

        template<typename INITOR> bool enqueue(INITOR initor)
        {
            typename beh::setype locked_end = beh::lock_end();

            typename beh::setype current_start = beh::load_start();

            if (beh::need_shrink(current_start, locked_end))
            {
                typename beh::setype locked_start = beh::lock_start(current_start);
                if (beh::need_shrink(locked_start, locked_end) && beh::allow_shrink())
                {
                    // still shrink
                    typename beh::setype si = locked_start;
                    typename beh::setype ei = locked_end;
                    typename beh::setype sz = static_cast<beh::setype>(beh::size); // cache size in register due size is volatile

                    if (si == ei)
                    {
                        // empty
                        if constexpr (is_relocatable<T>::value)
                        {
                            del(initial_size, sz);
                            items = (T*)MRS(items, initial_size * sizeof(T), initial_size * sizeof(T));
                        }
                        else
                        {
                            del(0, sz);
                            ma::mf(items);
                            items = (T*)MA(initial_size * sizeof(T));
                            init(0, initial_size);
                        }
                        si = 0;
                        ei = 0;
                        beh::size = initial_size;
                        beh::shrinked();
                    }
                    else
                    {
                        size_t newsize = sz / 2;

                        if constexpr (is_relocatable<T>::value)
                        {
                            if (si < ei)
                            {
                                typename beh::setype cnt = ei - si;
                                // one range
                                if (ei < newsize)
                                {
                                    // simple case
                                    del(newsize, sz);
                                    items = (T*)MRS(items, newsize * sizeof(T), newsize * sizeof(T));
                                }
                                else {

                                    // 0123456789ABCDEF0123456789ABCDEF : 32 items
                                    //                 ^ - cut here
                                    // eeeeeeeDDDDDDDDDDDDDeeeeeeeeeeee : si == 7, ei = 20

                                    del(0, si);

                                    // .......DDDDDDDDDDDDDeeeeeeeeeeee : (0..7) deleted

                                    tools::memcopy(items, items + si, cnt * sizeof(T));

                                    // DDDDDDDDDDDDD.......eeeeeeeeeeee : data copied; (13..20) garbage

                                    init(cnt, newsize);

                                    // DDDDDDDDDDDDDeee....eeeeeeeeeeee : (13..16) created; (16..20) garbage

                                    del(ei, sz);

                                    // DDDDDDDDDDDDDeee................ : (20..32) deleted

                                    items = (T*)MRS(items, newsize * sizeof(T), newsize * sizeof(T));

                                    si = 0;
                                    ei = cnt;
                                }
                            }
                            else
                            {
                                // DDDDeeeeeeeeeeeeeeeeeeeDDDDDDDDD : si == 23, ei = 4

                                T* newitems = (T*)MA(newsize * sizeof(T));
                                size_t tailsize = (sz - si);
                                tools::memcopy(newitems, items + si, tailsize * sizeof(T));
                                tools::memcopy(newitems + tailsize, items, ei * sizeof(T));

                                del(ei, si);

                                ma::mf(items);
                                items = newitems;

                                typename beh::setype cnt = static_cast<beh::setype>(tailsize + ei);

                                init(cnt, newsize);

                                si = 0;
                                ei = cnt;
                            }
                        }
                        else
                        {
                            T* newitems = (T*)MA(newsize * sizeof(T));
                            typename beh::setype cnt = 0;

                            if (si < ei)
                            {
                                del(0, si);
                                del(ei, sz);
                            }
                            else
                            {
                                del(ei, si);
                            }

                            for (; si != ei; si = (si + 1) & (beh::size - 1), ++cnt)
                                new (newitems + cnt) T(std::move(items[si]));

                            ma::mf(items);
                            items = newitems;

                            init(cnt, newsize);

                            si = 0;
                            ei = cnt;
                        }

                        beh::size = newsize;

                    }

                    beh::template store_end<true>(ei); // update end and keep locked
                    beh::store_start(si); // now unlock start; // readers can read
                    locked_end = ei;
                    current_start = beh::load_start();
                    beh::shrinked();
                }
                else
                {
                    // do nothing for now
                    beh::store_start(locked_start);
                }
            }

            if (is_full(current_start, locked_end))
            {
                if (beh::size >= max_size)
                {
                    beh::unlock_end(locked_end); // unlock end
                    return false;
                }

                // so, we can expand space
                // have to lock [start] index ([end] already locked)
                typename beh::setype locked_start = beh::lock_start(current_start);

                if (is_full(locked_start, locked_end))
                {
                    size_t newsize = beh::size * 2;

                    typename beh::setype si = locked_start;
                    typename beh::setype ei = locked_end;
                    typename beh::setype sz = static_cast<beh::setype>(beh::size);

                    if constexpr (is_relocatable<T>::value)
                    {
                        if (si < ei)
                        {
                            items = (T*)MRS(items, newsize * sizeof(T), beh::size * sizeof(T));
                            init(sz, newsize);
                        }
                        else
                        {
                            items = (T*)MRS(items, newsize * sizeof(T), beh::size * sizeof(T));

                            // DDDDeeeeeeeeeeeeeeeeeeeDDDDDDDDD................................ : si == 23, ei = 4

                            tools::memcopy(items + sz, items, ei * sizeof(T));

                            // ....eeeeeeeeeeeeeeeeeeeDDDDDDDDDDDDD............................ : si == 23, ei = 4

                            init(0, ei);
                            init(beh::size + ei, newsize);

                            // eeeeeeeeeeeeeeeeeeeeeeeDDDDDDDDDDDDDeeeeeeeeeeeeeeeeeeeeeeeeeeee : si == 23, ei = 4

                            ei += sz;
                        }
                    }
                    else
                    {
                        T* newitems = (T*)MA(newsize * sizeof(T));
                        typename beh::setype cnt = 0;

                        if (si < ei)
                        {
                            del(0, si);
                            del(ei, sz);
                        }
                        else
                        {
                            del(ei, si);
                        }

                        for (; si != ei; si = (si + 1) & (sz - 1), ++cnt)
                            new (newitems + cnt) T(std::move(items[si]));

                        ma::mf(items);
                        items = newitems;

                        init(cnt, newsize);

                        si = 0;
                        ei = cnt;

                    }

                    beh::size = newsize;

                    beh::template store_end<true>(ei); // update [end] and keep locked
                    beh::store_start(si); // now unlock start; // readers can read
                    locked_end = ei;
                }
                else
                {
                    // just unlock start, no change, keep [end] locked
                    beh::store_start(locked_start);
                }

            }

            initor(items[locked_end]); // init slot with value
            typename beh::setype new_end = (locked_end + 1) & (beh::size - 1);

            // update and unlock end index
            beh::template store_end<false>(new_end);

            return true;
        }

        template <typename READER> bool dequeue(READER r)
        {
            typename beh::setype current_start = beh::load_start();

            if (current_start == beh::load_end())
                return false;

            typename beh::setype locked_start = beh::lock_start(current_start);

            if (locked_start == beh::load_end())
            {
                // oops
                // no items after lock (many concurrent readers)
                // unlock and exit
                beh::store_start(locked_start);
                return false;
            }

            T rv = std::move(items[locked_start]);
            typename beh::setype newstart = (locked_start + 1) & (beh::size - 1);

            // update start index and unlock
            beh::store_start(newstart);

            r(rv); // return value

            return true;
        }
    };

    template<typename T> using fifo_shrinkable = fifo<T, 4, 65536, fifo_behaviour_shrinkable<4> >;
    template<typename T> using sync_fifo_shrinkable = fifo<T, 4, 65536, fifo_behaviour_sync_shrinkable<4> >;

	// bucket for maximum 32 slots with separated (lock free) spinlock synchronization
	// THIS IS NOT FIFO or LIFO buffer:
	// get() returns any exist item (not necessary newest or oldest)
	template<typename T> requires(is_plain_old_struct_v<T>) class bucket
	{
		volatile u64 lockmask = 0xffffffffffffffffull; // each 0..31 bit: 0 - locked; 1 - unlocked / each 32..63 bit: 0 - not empty; 1 - empty (free)
		u8 buf[sizeof(T) * 32];

		signed_t lockempty()
        {
			size_t spincount = 0;
            for (u64 m = spinlock::atomic_load(lockmask);;++spincount)
            {
                signed_t indx = lowest_bit_index(static_cast<u32>(m & (m>>32)));
                if (indx < 0)
                    return -1;
                u64 newmask = m & (~(1ull << indx));
                if (spinlock::atomic_cas_update_expected(lockmask, m, newmask))
                    return indx;

				SPINCOUNT_SLEEP(spincount, m = spinlock::atomic_load(lockmask));
            }
		}

        signed_t lockvalue()
        {
			size_t spincount = 0;
            for (u64 m = spinlock::atomic_load(lockmask);;++spincount)
            {
                signed_t indx = lowest_bit_index(static_cast<u32>(m & ((~m)>>32)));
                if (indx < 0)
                    return -1;
                u64 newmask = m & (~(1ull << indx));
                if (spinlock::atomic_cas_update_expected(lockmask, m, newmask))
                    return indx;

				SPINCOUNT_SLEEP(spincount, m = spinlock::atomic_load(lockmask));
            }
        }

		void unlock(u64 bitmask_set, u64 bitmask_clear)
		{
			size_t spincount = 0;
            for (u64 m = lockmask;; ++spincount)
            {
				ASSERT( (m & bitmask_set) == 0 );
                u64 newmask = (m | bitmask_set) & (~bitmask_clear);
                if (spinlock::atomic_cas_update_expected(lockmask, m, newmask))
                    return;

				SPINCOUNT_SLEEP(spincount, m = spinlock::atomic_load(lockmask));
            }
		}

	public:

		bool empty() const
		{
			return (lockmask >> 32) == 0xffffffff; // no need spinlock::atomic_load(lockmask) because we need only 32 bits of lockmask: 32 bit always read atomically
		}

		template<typename SETER> bool put(SETER s)
		{
			if (signed_t idx = lockempty(); idx >= 0)
			{
                // indx bit is locked
				// now set data
                s(*(((T*)buf) + idx));
                u64 maskbit = (1ull << idx);
                unlock(maskbit, maskbit << 32);
				return true;
			}
			return false;
		}
        template<typename GETER> bool get(GETER g)
        {
            if (signed_t idx = lockvalue(); idx >= 0)
            {
                // indx bit is locked
                // now get data
				g(*(((T*)buf) + idx));
                u64 maskbit = (1ull << idx);
                unlock(maskbit|(maskbit<<32), 0);
                return true;
            }
            return false;
        }

	};

    class keep_buffer
    {
        u8* buf = nullptr;
    public:
        keep_buffer() {}
        keep_buffer(keep_buffer&& ob) noexcept :buf(ob.buf)  { ob.buf = nullptr; }
        keep_buffer(size_t sz) :buf((u8*)MA(sz + sizeof(size_t))) { *reinterpret_cast<size_t*>(buf) = sz; }
        ~keep_buffer() { ma::mf(buf); }

        keep_buffer& operator=(keep_buffer&& ob) noexcept
        {
            ma::mf(buf);
            buf = ob.buf;
            ob.buf = nullptr;
            return *this;
        }

        template<typename T> const T* tdata(size_t &count) const
        {
            count = size() / sizeof(T);
            ASSERT(size() == count * sizeof(T));
            return reinterpret_cast<const T *>(buf ? buf + sizeof(size_t) : nullptr);
        }


        u8* data()
        {
            return buf ? buf + sizeof(size_t) : nullptr;
        }
        const u8* data() const
        {
            return buf ? buf + sizeof(size_t) : nullptr;
        }
        size_t size() const
        {
            return buf ? *reinterpret_cast<size_t*>(buf) : 0;
        }
        u8 * resize(size_t sz, size_t keep_data)
        {
            buf = (u8 *)MRS( buf, sz + sizeof(size_t), keep_data );
            *reinterpret_cast<size_t*>(buf) = sz;
            return buf + sizeof(size_t);
        }
        std::span<const u8> span() const { return std::span(data(), size()); }
        std::span<u8> span() { return std::span(data(), size()); }

        bool is_empty() const
        {
            return buf == nullptr || *reinterpret_cast<size_t*>(buf) == 0;
        }

        void clear()
        {
            ma::mf(buf);
            buf = nullptr;
        }
    };


#if 0
	template<typename T> class fifo
	{
		std::vector<T> buf;
		size_t head = 0;
		size_t tail = 0;

	public:
		template <class... _Valty> void emplace(_Valty&&... _Val)
		{
			if (tail == buf.size())
			{
				if (head <= 1)
				{
					// full
					buf.emplace_back(std::forward<_Valty>(_Val)...);
					++tail;
					return;
				}
				buf[0] = T(std::forward<_Valty>(_Val)...);
				tail = 1;
				return;
			}
			if (tail == head - 1)
			{
				buf.emplace(buf.begin() + tail, std::forward<_Valty>(_Val)...);
				++head;
				++tail;
				return;
			}
			buf[tail++] = T(std::forward<_Valty>(_Val)...);
		}

		bool empty() const
		{
			return tail == head;
		}

		bool get(T &t)
		{
			if (tail == head)
				return false;
			t = std::move(buf[head++]);
			if (head == tail)
			{
				// now empty
				head = 0;
				tail = 0;
			}
			else if (head == buf.size())
				head = 0;
			return true;
		}
	};
#endif

	template<typename EL> void remove_fast(std::vector<EL>& arr, signed_t eli)
	{
		if (eli < (signed_t)arr.size() - 1)
		{
			arr[eli] = std::move( arr[arr.size()-1] );
		}
		arr.resize(arr.size()-1);
	}

    template <typename T> struct array_element_type {
        using type = typename std::remove_extent<T>::type;
    };
    template <typename T, typename Alloc> struct array_element_type<std::vector<T, Alloc>> {
        using type = T;
    };
    template <typename T> using element_type_t = typename array_element_type<T>::type;
    template <typename T, size_t N> struct array_element_type<std::array<T, N>> {
        using type = T;
    };

    template<typename ARR, typename KEY> bool find_sorted(const ARR &arr, signed_t& index, const KEY& key, signed_t maxcount = -1)
    {
        if (maxcount < 0) maxcount = std::size(arr);

        if (maxcount == 0)
        {
            index = 0;
            return false;
        }
        if (maxcount == 1)
        {
            auto cmp = arr[0] <=> key;
            index = cmp == std::strong_ordering::less ? 1 : 0;
            return cmp == std::strong_ordering::equal;
        }


		signed_t left = 0;
		signed_t rite = maxcount;

		signed_t test;
        do
        {
            test = (rite + left) >> 1;

            auto cmp = arr[test] <=> key;
            if (cmp == std::strong_ordering::equal)
            {
                index = test;
                return true;
            }
            if (cmp == std::strong_ordering::greater)
            {
                // do left
                rite = test;
            }
            else
            {
                // do rite
                left = test + 1;
            }
        } while (left < (rite - 1));

        if (left >= maxcount)
        {
            index = left;
            return false;
        }

        auto cmp = arr[left] <=> key;
        index = cmp == std::strong_ordering::less ? left + 1 : left;
        return cmp == std::strong_ordering::equal;
    }


	template<size_t size, size_t numh> class bloom_filter
	{
		static_assert( std::has_single_bit(size) );

		static constexpr const size_t bitsperhash = math::log2_floor(size);

		u8 bitmap[size / 8] = {0};

		bool is_set(size_t bi) const
		{
            if (bi >= size) return false;
            return 0 != (bitmap[bi >> 3] & (1 << (bi & 7)));
		}

        void set_bit(size_t bi)
        {
			if (bi >= size)
				return;

            bitmap[bi >> 3] |= (1 << (bi & 7));
        }


	public:

		static void build_indices(std::span<size_t, numh> inds, std::span<const u8> blob)
		{
			memset(inds.data(), 0, sizeof(size_t) * numh);
            size_t blobbits = blob.size() * 8;
            size_t i = 0;
            bool loop = false;
            for (size_t bi0 = 0; bi0 < blobbits || !loop; bi0 += bitsperhash)
            {
                inds.data()[i] ^= math::subnum<bitsperhash>(blob, bi0);
                ++i;
                if (i >= numh)
                {
                    i = 0;
                    loop = true;
                }
            }
		}


        void add(std::span<const size_t, numh> inds)
        {
            for (size_t i = 0; i < numh; ++i)
                set_bit(inds.data()[i]);
        }

		/*
		* return true if blob not present (blob will be present after call of this function)
		*/
		bool test_and_add(std::span<const size_t, numh> inds)
		{
			for(size_t i = 0; i<numh; ++i)
			{
				if (!is_set(inds[i]))
				{
					// not present, so set and return false
					for (size_t j = i; j < numh; ++j)
						set_bit(inds.data()[j]);

					return true; // pass
				}
			}

			return false; // not pass
		}
		bool test(std::span<const size_t, numh> inds) const
        {
            for (size_t i = 0; i < numh; ++i)
            {
                if (!is_set(inds.data()[i]))
                    return true; // pass
            }

            return false; // not pass
        }

		void clear()
		{
			memset(bitmap, 0, sizeof(bitmap));
		}
	};

	template<size_t size, size_t numh, size_t keep_full = 3600> class bloom_filter_set
	{
		volatile size_t lock = 0;

		struct bf : public bloom_filter<size, numh>
		{
			time_t delete_time = 0;
			size_t count = size/10; // average capacity
			std::unique_ptr<bf> next;
			bf(time_t delete_time, std::span<const size_t, numh> inds):delete_time(delete_time)
			{
				bloom_filter<size, numh>::add(inds);
			}
			void reuse(time_t delete_time1, std::span<const size_t, numh> inds)
			{
				delete_time = delete_time1;
				bloom_filter<size, numh>::clear();
				bloom_filter<size, numh>::add(inds);
				ASSERT(next.get() == nullptr);
			}
		};
		std::unique_ptr<bf> first;
	public:
		template<size_t blobsize> bool test_and_add(std::span<const u8, blobsize> blob)
		{
            size_t inds[numh];
            bloom_filter<size, numh>::build_indices(inds, blob);

            time_t ct = chrono::now();

			spinlock::auto_simple_lock l(lock);

            if (!first)
            {
                first.reset(NEW bf(ct + keep_full, inds));
                return true;
            }

			std::unique_ptr<bf> freefb;
            while (first->count == 0 && ct > first->delete_time)
            {
				bf* n = first->next.release();
				if (nullptr == n)
				{
                    first->reuse(ct + keep_full, inds);
					l.unlock(); // unlock first
                    return true;
				}
				first->next = std::move(freefb);
				freefb = std::move(first);
                first.reset(n);
            }

			bf* last = nullptr;
			for (bf* x = first.get(); x; x = x->next.get())
			{
				last = x;
				if (x->count == 0)
				{
					if (!x->test(inds))
					{
						x->delete_time = ct + keep_full;
						l.unlock();
						return false;
					}
				}
				else {
                    x->delete_time = ct + keep_full;
					if (x->test_and_add(inds))
					{
						--x->count;
						l.unlock();
                        return true;
					}
					l.unlock();
					return false;
				}
			}
			if (freefb)
			{
				auto x = std::move(freefb->next);
				freefb->reuse(ct + keep_full, inds);
				last->next = std::move(freefb);
				l.unlock();
			}
			else
            {
                last->next.reset(NEW bf(ct + keep_full, inds));
			}
			return true;
		}
	};


} // namespace tools

namespace str
{
#pragma pack(push)
#pragma pack(1)
	class shared_str : public ptr::shared_object_t<ptr::intref<i16>, ptr::FREER>
	{
		u8 len;
		shared_str() = delete;
		shared_str(const shared_str &) = delete;
		shared_str(shared_str &&) = delete;
		void operator=(const shared_str&) = delete;
		void operator=(shared_str &&) = delete;
	public:
		using ptr = ptr::shared_ptr<shared_str>;
		static ptr build(const astr_view& s)
		{
			shared_str* x = (shared_str*)MA( s.length() + sizeof(shared_str) );
			*(u16*)x = 0;
			x->len = tools::as_byte(s.length());
			memcpy((void *)(x + 1), s.data(), s.length());
			return ptr(x);
		}
		void secure_erase()
        {
            secure::scrub_memory(this, len + sizeof(shared_str)); // zeroise including length
		}

		str::astr_view cstr() const
		{
			return str::astr_view( (const char *)(this+1), len );
		}
		str::astr to_string() const
		{
			return str::astr((const char*)(this + 1), len);
		}
		bool equals(const str::astr_view& name) const
		{
			return name == cstr();
		}
		bool equals(const str::shared_str::ptr& name) const
		{
			return name->cstr() == cstr();
		}
	};
#pragma pack(pop)
	static_assert(sizeof(shared_str) == 3);

	inline void __append(str::astr& sout, const str::shared_str::ptr& p)
	{
		sout.append(p->cstr());
	}

    inline std::span<const u8> span(const str::shared_str::ptr& s)
    {
        return str::span(s->cstr());
    }

}

