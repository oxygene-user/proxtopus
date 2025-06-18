#pragma once


#include <emmintrin.h>
#include <immintrin.h>
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

#define PTR_TO_UNSIGNED( p ) ((size_t)p)

#ifdef _NIX
inline int timeGetTime()
{
	struct timespec monotime;
#if defined(__linux__) && defined(CLOCK_MONOTONIC_RAW)
	clock_gettime(CLOCK_MONOTONIC_RAW, &monotime);
#else
	clock_gettime(CLOCK_MONOTONIC, &monotime);
#endif
	uint64_t time = 1000ULL * monotime.tv_sec + (monotime.tv_nsec / 1000000ULL);
	return time & 0xffffffff;
}
#define _time64 time
#endif

namespace tools
{
    size_t unique_id();

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
		template<type mask> size_t getn() const
		{
			return (f & mask) >> lowbit<mask>();
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
	inline time_t now() // seconds
	{
		time_t t;
		_time64(&t);
		return t;
	}

	inline signed_t ms() // milliseconds
	{
		return (signed_t)timeGetTime();
	}

#if defined(_MSC_VER)
#pragma intrinsic(__rdtsc)
	inline uint64_t tsc() {
		return __rdtsc();
	}
#elif defined(GCC_OR_CLANG)
	inline uint64_t tsc() {
		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
		return ((uint64_t)hi << 32) | lo;
	}
#else
#error "Unsupported compiler"
#endif
}

namespace math
{
    template<typename T> struct is_signed { static const bool value = (((T)-1) < 0); };
    template<> struct is_signed<float> { static const bool value = true; };
    template<> struct is_signed < double > { static const bool value = true; };

	inline long int fround(float x)
    {
        return _mm_cvtss_si32(_mm_load_ss(&x));
    }

	inline long int dround(double x)
    {
        return _mm_cvtsd_si32(_mm_load_sd(&x));
    }

	template<typename NUM, int shiftval> struct makemaxint
	{
		static const NUM value = (makemaxint<NUM, shiftval - 1>::value << 8) | 0xFF;
	};
	template<typename NUM> struct makemaxint < NUM, 0 >
	{
		static const NUM value = 0x7F;
	};
    template<typename NUM, int shiftval> struct makemaxuint
    {
        static const NUM value = (makemaxuint<NUM, shiftval - 1>::value << 8) | 0xFF;
    };
    template<typename NUM> struct makemaxuint < NUM, 0 >
    {
        static const NUM value = 0xFF;
    };

	template<typename NUM> struct maximum
	{
		static const NUM value = is_signed<NUM>::value ? makemaxint<NUM, sizeof(NUM) - 1>::value : makemaxuint<NUM, sizeof(NUM) - 1>::value;
	};
	template<typename NUM> struct minimum
	{
		static const NUM value = is_signed<NUM>::value ? (-maximum<NUM>::value - 1) : 0;
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

    template<typename T1, typename T2> using bigger_type = typename std::conditional<(sizeof(T1) >= sizeof(T2)), T1, T2>::type;

    template<bool s1, bool s2, typename T1, typename T2> struct getminmax
    {
        typedef bigger_type<T1, T2> type_min;
		typedef bigger_type<T1, T2> type_max;
        static T1 getmin(T1 t1, T2 t2)
        {
            return t1 < t2 ? t1 : t2;
        }
        static T1 getmax(T1 t1, T2 t2)
        {
			return t1 > t2 ? t1 : t2;
        }
    };
	template<typename T1, typename T2> struct getminmax<true, false, T1, T2> {

        typedef T1 type_min;
        typedef T2 type_max;
        static T1 getmin(T1 t1, T2 t2)
		{
			return t1 < 0 || (size_t)t1 < t2 ? t1 : (T1)t2;
		}
        static T2 getmax(T1 t1, T2 t2)
        {
            return t1 < 0 || static_cast<size_t>(t1) < t2 ? t2 : static_cast<size_t>(t1);
        }
    };
	template<typename T1, typename T2> struct getminmax<false, true, T1, T2> {

        typedef T2 type_min;
        typedef T1 type_max;
		static T2 getmin(T1 t1, T2 t2)
		{
			return t2 < 0 || (size_t)t2 < t1 ? t2 : (T2)t1;
		}
        static T1 getmax(T1 t1, T2 t2)
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


    template < typename T1, typename T2, typename T3 > inline T1 clamp(const T1 & a, const T2 & vmin, const T3 & vmax)
    {
        return (T1)(((a) > (vmax)) ? (vmax) : (((a) < (vmin)) ? (vmin) : (a)));
    }

    template < typename RT, typename IT > inline RT clamp(IT b)
    {
        return helpers::clamper<RT, IT, is_signed<IT>::value>::dojob(b);
    }

    template < typename T1 > inline T1 abs(const T1 &x)
    {
        return x >= 0 ? x : (-x);
    }

    int inline lerp_int(int a, int b, float t)
    {
        float v = static_cast<float>(a) * (1.0f - (t)) + (t) * static_cast<float>(b);
        return fround(v);
    }

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
	return c >= L'0' && c <= '9';
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
    static inline u32 load32_le(const u8* src)
    {
		if constexpr (Endian::little)
        {
            return *(u32*)src;
		}
        else
		{
			return (static_cast<u32>(src[0]) << 24) | (static_cast<u32>(src[1]) << 16) | (static_cast<u32>(src[2]) << 8) | static_cast<u32>(src[3]);
        }
    }
    static inline u64 load64_le(const u8* src)
    {
        if constexpr (Endian::little)
        {
            return *(u64*)src;
        }
        else
        {
            return (static_cast<u64>(src[0]) << 56) | (static_cast<u64>(src[1]) << 48) | (static_cast<u64>(src[2]) << 40) | (static_cast<u64>(src[3]) << 32) |
				(static_cast<u64>(src[4]) << 24) | (static_cast<u64>(src[5]) << 16) | (static_cast<u64>(src[6]) << 8) | static_cast<u64>(src[7]);
        }
    }
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
			p0 = std::span(reinterpret_cast<uint8_t *>(&t), sizeof(T));
		}
		memory_pair(uint8_t* p, size_t sz) :p0(p, sz) {}
		memory_pair(uint8_t* p0, size_t sz0, uint8_t* p1, size_t sz1) :p0(p0, sz0), p1(p1, sz1) {}

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

		void copy(size_t offset, const u8* data, size_t sz)
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
			return (start == 0 && (size_t)end == size) || (end + 1 == start);
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

		i32 datasize(size_t size) const { return (start <= end) ? (end - start) : ((static_cast<i32>(size) - start) + end); }
		i32 get_free_size(size_t size) const
		{
			if (start <= end)
			{
				i32 sz1 = static_cast<i32>(size) - end;
				i32 sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				return sz1 + sz2;
			}
			i32 sz = start - end - 1; if (sz < 0) sz = 0;
			return sz;
		}

		const u8* data1st(size_t getsize, const_tank storage) const
		{
            auto available = (start <= end) ? (end - start) : (storage.size() - start);
			ASSERT(getsize <= available);
			//return getsize <= available ? storage.data() + start : nullptr;
			return storage.data() + start;
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

        tank get_1st_free(tank storage) // it simply returns the free block following the data; after filling you should call confirm method to apply append
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
                if ((size_t)start == size)
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
				if ((size_t)start == storage.size())
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
                if ((size_t)start == storage.size())
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
		circular_buffer(circular_buffer&& x)
		{
			end = x.peek(bytes, size - 1);
		}
		void operator=(circular_buffer&& x)
		{
			start = 0;
			end = x.peek(bytes, size - 1);
		}

        bool is_full() const { return circular_buffer_engine::is_full(size); }
		//bool insert(const u8* d, signed_t sz) { return circular_buffer_engine::insert(d, sz, std::span(bytes, size)); }
		i32 datasize() const { return circular_buffer_engine::datasize(size); }
		const u8* data1st(size_t getsize) const { return circular_buffer_engine::data(getsize, std::span(bytes, size)); }
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
		i32 datasize() const { return circular_buffer_engine::datasize(storage.size()); }
		const u8* data1st(size_t getsize) const { return circular_buffer_engine::data1st(getsize, storage); }
		memory_pair data(size_t getsize) { return circular_buffer_engine::data(getsize, storage); }
		i32 peek(u8* output, signed_t outsize) { return circular_buffer_engine::peek(output, outsize, storage); }
		template<typename BUF> i32 peek(BUF& buf, signed_t limit = 0) { return circular_buffer_engine::peek<BUF>(buf, limit, storage); }
		void skip(signed_t skipbytes) { circular_buffer_engine::skip(skipbytes, storage.size()); }
		void confirm(signed_t sz) { circular_buffer_engine::confirm(sz, storage.size()); }
		tank get_1st_free() { return circular_buffer_engine::get_1st_free(storage); }
		i32 get_free_size() const { return circular_buffer_engine::get_free_size(storage.size()); }
		
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
#ifdef MODE64
#pragma intrinsic(_BitScanForward64)
	template<typename T> signed_t lowest_bit_index(T x) {

        unsigned long index;
        return _BitScanForward64(&index, x) ? (signed_t)index : -1;
    }
#else
#pragma intrinsic(_BitScanForward)
	template<typename T>  signed_t lowest_bit_index(T x) {
        
        if constexpr (sizeof(T) == 4)
        {
            unsigned long index;
            return _BitScanForward(&index, x) ? (signed_t)index : -1;
        }
		else {

            unsigned long index;
			if (_BitScanForward(&index, static_cast<u32>(x & 0xffffffff)))
				return (signed_t)index;

			return _BitScanForward(&index, static_cast<u32>(x >> 32)) ? (signed_t)(index + 32) : -1;
		}
    }
#endif
#endif

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
				DASSERT( (m & bitmask_set) == 0 );
                u64 newmask = (m | bitmask_set) & (~bitmask_clear);
                if (spinlock::atomic_cas_update_expected(lockmask, m, newmask))
                    return;

				SPINCOUNT_SLEEP(spincount, m = spinlock::atomic_load(lockmask));
            }
		}

	public:

		bool empty() const
		{
			return (lockmask >> 32) == 0xffffffff;
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
            Botan::secure_scrub_memory(this, len + sizeof(shared_str)); // zeroise including length
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

namespace stats
{
    struct tick_collector
    {
		str::astr_view tag;
        signed_t start_ms = 0;
        signed_t collect_start_ms = 0;

        std::vector<std::pair<u16, u16>> mss;

		tick_collector(str::astr_view tag);
		~tick_collector();

		void collect();

    };

}
