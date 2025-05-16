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
#define ALIGN(n) __declspec( align( n ) )



#ifdef MODE64
typedef u64 usingle;
typedef u128 udouble;
typedef u32 uhalf;
#else
typedef u16 uhalf;
typedef u32 usingle;
typedef u64 udouble;
#endif

template<signed_t N> struct vbv;
template<> struct vbv<1> { u8 v; };
template<> struct vbv<2> { u16 v; };
template<> struct vbv<4> { u32 v; };

typedef unsigned long Color;


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
	template<typename NUM> struct maximum
	{
		static const NUM value = is_signed<NUM>::value ? makemaxint<NUM, sizeof(NUM) - 1>::value : (NUM)(-1);
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

    template<bool s1, bool s2, typename T1, typename T2> struct getminmax
    {
        typedef T1 type_min;
		typedef T1 type_max;
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

		signed_t peek(u8 * out, signed_t sv) // like skip with data get
		{
			signed_t total_peeked = 0;
			for (;first && sv > 0;)
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

		bool enough_for(signed_t sz) const // is sz bytes enough to fit current buffer data
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

	template<signed_t size> class circular_buffer
	{
		u8 data[(size + 15) & (~15)];
		signed_t start = 0, end = 0;
	public:
		circular_buffer() {}
		circular_buffer(circular_buffer&& x)
		{
			end = x.peek(data, size);
		}
		void operator=(circular_buffer&& x)
		{
			start = 0;
			end = x.peek(data, size);
		}

		bool is_full() const
		{
			return (start == 0 && end == size) || (end + 1 == start);
		}

		bool insert(const u8* d, signed_t sz)
		{
			if (get_free_size() < sz)
				return false;

			signed_t dsz = datasize();
			u8* temp = ALLOCA(dsz);
			peek(temp, dsz);
			clear();
			auto t = get_1st_free();
			ASSERT((signed_t)t.size() <= (sz + dsz));
			memcpy(t.data(), d, sz);
            memcpy(t.data() + sz, temp, dsz);
			confirm(sz + dsz);
			return true;
		}

		void clear()
		{
			start = 0;
			end = 0;
		}
		signed_t datasize() const { return (start <= end) ? (end - start) : ((size - start) + end); }
		signed_t get_free_size() const
		{
			if (start <= end)
			{
				signed_t sz1 = size - end;
				signed_t sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				return sz1 + sz2;
			}
			signed_t sz = start - end - 1; if (sz < 0) sz = 0;
			return sz;
		}

		using tank = std::span<u8>;

		tank get_1st_free()
		{
			if (start <= end)
			{
				signed_t sz1 = size - end;
				signed_t sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				if (sz1 == 0)
					return tank(data, sz2);
				return tank(data + end, sz1); // , tank(data, sz2)
			}
			signed_t sz = start - end - 1; if (sz < 0) sz = 0;
			return tank(data + end, sz); // , tank(nullptr, 0)
		}
		void confirm(signed_t sz)
		{
			if (start <= end)
			{
				signed_t sz1 = size - end;
#ifdef _DEBUG
				signed_t sz2 = start - 1; if (sz2 < 0) sz2 = 0;
				ASSERT(sz <= (sz1 + sz2));
#endif
				if (sz <= sz1)
				{
					end += sz;
					return;
				}

				end = sz - sz1;
				return;
			}


#ifdef _DEBUG
			signed_t sz0 = start - end - 1; if (sz < 0) sz = 0;
			ASSERT(sz <= sz0);
#endif
			end += sz;
		}

		signed_t peek(u8* output, signed_t outsize)
		{
			if (start <= end)
			{
				// continuous block
				signed_t blocksize = end - start;
				if (outsize <= blocksize)
				{
					memcpy(output, data + start, outsize);
					start += outsize;
					if (start == end)
						clear();
					return outsize;
				}
				memcpy(output, data + start, blocksize);
				start += blocksize;
				if (start == end)
					clear();
				return blocksize;

			}

			// two blocks: from start to size and from 0 to end
			signed_t sz1 = size - start;
			signed_t sz2 = end;

			if (outsize <= sz1)
			{
				memcpy(output, data + start, outsize);
				start += outsize;
				if (start == size)
					start = 0;
				return outsize;
			}
			memcpy(output, data + start, sz1);
			outsize -= sz1;

			if (outsize < sz2)
			{
				memcpy(output + sz1, data, outsize);
				start = outsize;
				return sz1 + outsize;
			}

			memcpy(output + sz1, data, sz2);
			start = sz2;
			return sz1 + sz2;

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

	template<typename T, bool is_little_endian = Endian::little> struct from_low_to_high
	{
		octets< std::is_const_v<T> > octet; // point to low byte if num

		from_low_to_high(T& num):octet(num) {
            if constexpr (!is_little_endian)
            {
				octet.p += sizeof(T)-1;
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
        u8 &operator *()
        {
            return *octet.p;
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
			shared_str* x = (shared_str*)malloc( s.length() + sizeof(shared_str) );
			*(u16*)x = 0;
			x->len = tools::as_byte(s.length());
			memcpy((void *)(x + 1), s.data(), s.length());
			return ptr(x);
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
