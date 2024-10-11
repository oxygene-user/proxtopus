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

class Endian
{
public:
	Endian() = delete;

	static constexpr bool little = std::endian::native == std::endian::little;
	static constexpr bool big = std::endian::native == std::endian::big;
};


bool messagebox(const char* s1, const char* s2, int options);

//#define ASSERTS(expr, ...) ASSERTO(expr, (std::stringstream() << ""  __VA_ARGS__).str())

//#define MESSAGE(...) messagebox("#", str::build_string(__VA_ARGS__).c_str(), MB_OK|MB_ICONINFORMATION)
#define WARNING(...) messagebox("!?", str::build_string(__VA_ARGS__).c_str(), MB_OK|MB_ICONWARNING)
template <typename T> inline T* BREAK_ON_NULL(T* ptr, const char* file, int line) { if (ptr == nullptr) { WARNING("nullptr pointer conversion: %s:%i", file, line); } return ptr; }
#define NOT_NULL( x ) BREAK_ON_NULL(x, __FILE__, __LINE__)
template<typename PTRT, typename TF> inline PTRT ptr_cast(TF* p) { if (!p) return nullptr; return NOT_NULL(dynamic_cast<PTRT>(p)); }
template<typename T> const T* makeptr(const T& t) { return &t; }

#include "logger.h"



#define ONEBIT(x) (static_cast<size_t>(1)<<(x))

#define PTR_TO_UNSIGNED( p ) ((size_t)p)
#define ALIGN(n) __declspec( align( n ) )

#ifdef MODE64
struct u128
{
	u64 low;
	u64 hi;

    u128() {}
	u128(u64 v):low(v), hi(0)
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
	u128& operator+=(const u128 &v)
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

}

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
    wchar inline as_wchar(size_t x) { return static_cast<wchar>(x & 0xFFFF); }
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


namespace math
{

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

namespace ptr
{
    /*
        intrusive shared pointer

        example:
        shared_ptr<MyClass> p(new MyClass(...)), p2(p), p3=p;
        . . .
    */

    template <class T> class shared_ptr // T must be public child of shared_object
    {
        T *object = nullptr;

        void unconnect()
        {
            if (object) T::dec_ref(object);
        }

        void connect(T *p)
        {
            object = p;
            if (object) object->add_ref();
        }

    public:
        shared_ptr() {}
        //shared_ptr(const T &obj):object(new T (obj)) {object->ref = 1;}
        shared_ptr(T *p) { connect(p); } // now safe todo: shared_ptr p1(obj), p2(obj);
        shared_ptr(const shared_ptr &p) { connect(p.object); }
        shared_ptr(shared_ptr &&p) :object(p.object) { p.object = nullptr; }

        shared_ptr &operator=(T *p)
        {
            if (p) p->add_ref(); // ref up - to correct self assign
            unconnect();
            object = p;
            return *this;
        }
        shared_ptr &operator=(const shared_ptr &p)
        {
            return *this = p.object;
        }

		shared_ptr& operator=(shared_ptr&& p)
		{
            unconnect();
            object = p.object;
            p.object = nullptr;
            return *this;
		}

        ~shared_ptr() { unconnect(); }

        void swap(shared_ptr &p) { tools::swap(*this, p); }

        operator T *() const { return object; }
        T *operator->() const { return object; }

        T *get() { return object; }
        const T *get() const { return object; }
    };

    template<typename N = int> struct intref
    {
        N value = 0;

        intref& operator++()
        {
            ++value;
            return *this;
        }
		intref& operator--()
		{
			--value;
			return *this;
		}

		bool operator()()
		{
			auto nv = --value;
			ASSERT(nv >= 0);
			return nv == 0;
		}
		bool operator *() const
        {
            return value > 1;
        }
    };

	using intref_sync = intref<std::atomic<signed_t>>;

	struct DELETER
    {
        template<typename T> static void kill(T* o)
        {
            delete o;
        }
    };

	struct FREER
	{
		template<typename T> static void kill(T* o)
		{
			free(o);
		}
	};

	struct RELEASER
	{
		template<typename T> static void kill(T* o)
		{
			o->release();
		}
	};

    template<typename REF, typename OKILLER = DELETER> class shared_object_t
    {
        mutable REF ref;

        shared_object_t(const shared_object_t &) = delete;
        void operator=(const shared_object_t &) = delete;
    public:
        shared_object_t() {}

        bool is_multi_ref() const { return *ref; }
        void add_ref() const { ++ref; }
		void dec_ref_no_check() const { --ref; }
        template <class T> static void dec_ref(T *object)
        {
            if (object->ref())
                OKILLER::kill(object);
        }
    };

    using shared_object = shared_object_t<intref<int>>;
	using sync_shared_object = shared_object_t<intref_sync>;
    template <typename KILLER> using sync_shared_object_ck = shared_object_t<intref_sync, KILLER>; // with custom killer

	// intrusive UNMOVABLE weak pointer
    // UNMOVABLE means that you cannot use memcpy to copy this pointer

	template<class OO> struct eyelet_s;
	template<class OO, class OO1 = OO> struct iweak_ptr
	{
		friend struct eyelet_s<OO>;
	private:
		iweak_ptr* prev = nullptr;
		iweak_ptr* next = nullptr;
		OO* oobject = nullptr;

	public:

		iweak_ptr() {}
		iweak_ptr(const iweak_ptr& hook)
		{
			if (hook.get()) const_cast<OO*>(static_cast<const OO*>(hook.get()))->hook_connect(this);
		}

		iweak_ptr(OO1* ob)
		{
			if (ob) ((OO*)ob)->OO::hook_connect(this);
		}
		~iweak_ptr()
		{
			unconnect();
		}

		void unconnect()
		{
			if (oobject) oobject->hook_unconnect(this);
		}

		iweak_ptr& operator = (const iweak_ptr& hook)
		{
			if (hook.get() != get())
			{
				unconnect();
				if (hook.get()) const_cast<OO*>(hook.get())->hook_connect(this);
			}
			return *this;
		}

		iweak_ptr& operator = (OO1* obj)
		{
			if (obj != get())
			{
				unconnect();
				if (obj) obj->OO::hook_connect(this);
			}
			return *this;
		}

		explicit operator bool() { return get() != nullptr; }

		template<typename OO2> bool operator==(const OO2* obj) const { return oobject == ptr_cast<const OO2*>(obj); }

		OO1* operator()() { return static_cast<OO1*>(oobject); }
		const OO1* operator()() const { return static_cast<const OO1*>(oobject); }

		operator OO1* () const { return static_cast<OO1*>(oobject); }
		OO1* operator->() const { return static_cast<OO1*>(oobject); }

		OO1* get() { return static_cast<OO1*>(oobject); }
		const OO1* get() const { return static_cast<OO1*>(oobject); }

		bool expired() const { return get() == nullptr; }
	};

	template<class OO> struct eyelet_s
	{
		iweak_ptr<OO>* first = nullptr;

		eyelet_s() {}
		~eyelet_s()
		{
			iweak_ptr<OO>* f = first;
			for (; f;)
			{
				iweak_ptr<OO>* next = f->next;

				f->oobject = nullptr;
				f->prev = nullptr;
				f->next = nullptr;

				f = next;
			}
		}

		void connect(OO* object, iweak_ptr<OO, OO>* hook)
		{
			if (hook->get()) hook->get()->hook_unconnect(hook);
			hook->oobject = object;
			hook->prev = nullptr;
			hook->next = first;
			if (first) first->prev = hook;
			first = hook;
		}

		void    unconnect(iweak_ptr<OO, OO>* hook)
		{
#ifdef _DEBUG
			iweak_ptr<OO>* f = first;
			for (; f; f = f->next)
			{
				if (f == hook) break;
			}
			ASSERT(f == hook, "foreigner hook!!!");

#endif
			if (first == hook)
			{
				ASSERT(first->prev == nullptr);
				first = hook->next;
				if (first)
				{
					first->prev = nullptr;
				}
				hook->next = nullptr;
			}
			else
			{
				ASSERT(hook->prev != nullptr);
				hook->prev->next = hook->next;
				if (hook->next) { hook->next->prev = hook->prev; hook->next = nullptr; };
				hook->prev = nullptr;
			}
			hook->oobject = nullptr;
		}
	};

}

#define DECLARE_EYELET( obj ) private: ptr::eyelet_s<obj> _ptr_eyelet; public: \
	template<class OO1> void hook_connect( ptr::iweak_ptr<obj, OO1> * hook ) { _ptr_eyelet.connect(this, reinterpret_cast<ptr::iweak_ptr<obj>*>(hook)); } \
	template<class OO1> void hook_unconnect( ptr::iweak_ptr<obj, OO1> * hook ) { _ptr_eyelet.unconnect(reinterpret_cast<ptr::iweak_ptr<obj>*>(hook)); } private:


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


#ifdef _RELEASE
#define USELIB(ln) comment(lib, #ln LIBSUFFIX)
#else
#define USELIB(ln) comment(lib, #ln "d" LIBSUFFIX)
#endif


template<typename CH> inline bool is_letter(CH c)
{
	return c >= L'a' && c <= 'z';
}

template<typename CH> inline bool is_digit(CH c)
{
	return c >= L'0' && c <= '9';
}


#include "sts.h"

namespace str
{
	template<typename CH> std::basic_string<CH> replace_all_copy(const std::basic_string<CH>& source, const std::basic_string_view<CH>&what, const std::basic_string_view<CH>& to)
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

	public:

		void assign(std::span<const u8> data)
		{
			if (data.size() == 0)
			{
				first.reset();
				last = nullptr;
				first_skip = 0;
				last_size = 0;
				return;
			}

			if (!first)
			{
				first.reset(new chunk());
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
						ch->next.reset(new chunk());
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
				first.reset(new chunk());
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
					last->next.reset( new chunk() );
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
			memcpy(x + 1, s.data(), s.length());
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

}

#ifdef _NIX
void Sleep(int ms);
#endif

