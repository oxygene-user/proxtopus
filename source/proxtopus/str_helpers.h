#pragma once

#include <string>

#ifdef _MSC_VER
typedef wchar_t wchar;
#elif defined __GNUC__
typedef char16_t wchar;
#endif

template <size_t _Size> consteval inline size_t strsize(const char(&)[_Size]) noexcept {
    return _Size - 1;
}
template <size_t _Size> consteval inline size_t strsize(const wchar(&)[_Size]) noexcept {
    return _Size - 1;
}

#define ASTR( s ) str::astr_view(s,strsize(s))

#if defined _MSC_VER
#define WSTR( s ) str::wstr_view(L##s,strsize(s))
#define XSTR( tc, s ) str::_const_str_build<tc, strsize(s)>::get( s, L##s )
#define WIDE2(s) L##s
#elif defined __GNUC__
#define WSTR( s ) str::wstr_view(u##s,strsize(s))
#define XSTR( tc, s ) str::_const_str_build<tc, strsize(s)>::get( s, u##s )
#define WIDE2(s) u##s
#endif

#define DEC(d,n) dec<d, std::decay_t<decltype(n)>>(n)
#define HEX(d,n) hex<d, std::decay_t<decltype(n)>>(n)

struct PTR
{
	uintptr_t val;
	PTR(const void* p) :val(reinterpret_cast<uintptr_t>(p)) {}
};

template<int min_digits, typename N> struct dec;
template<int min_digits, native N> struct dec<min_digits, N>
{
	constexpr const static bool native1 = true;
    N n;
    dec(N n) :n(n) {}
};
template<int min_digits, not_native N> struct dec<min_digits, N>
{
    constexpr const static bool native1 = false;
    const N &n;
    dec(const N &n) :n(n) {}
};

template<int min_digits, typename N> struct hex;
template<int min_digits, native N> struct hex<min_digits, N>
{
    constexpr const static bool native = true;
    N n;
    hex(N n) :n(n) {}
};
template<int min_digits, not_native N> struct hex<min_digits, N>
{
	constexpr const static bool native = false;
	const N &n;
    hex(const N& n) :n(n) {}
};

struct filename {
	const char* fn; size_t csz; filename(const char* s, size_t ss) :fn(s), csz(ss) {}
};

template <typename S> struct crlf
{
    const S& s;
    crlf(const S& s) :s(s) {}
};


namespace str
{
    template <typename CC> using xstr = std::basic_string<CC>;
    template <typename CC> using xstr_view = std::basic_string_view<CC>;
    using astr = xstr<char>;
    using wstr = xstr<wchar>;
    using astr_view = xstr_view<char>;
    using wstr_view = xstr_view<wchar>;

    struct hollow_flusher
    {
        template<typename T> bool operator()(const T*, size_t) const { return false; }
    };

    namespace xsstr_core
    {
        template<typename CC, size_t maxchars, typename flusher> struct core
        {
            using sizetype = sztype<tools::min_integral_size_for_value(maxchars, sizeof(CC))>::type;
            enum {
			    maxsize = maxchars - 1 // keep one char for zero end
		    };

			core() { buf[0] = 0; }
			core(flusher&& f) :fl(std::move(f)) { buf[0] = 0; }
			~core()
			{
				flush();
			}
			[[no_unique_address]] flusher fl;
            sizetype len = 0;
            CC buf[maxchars];
			bool flush_if()
            {
				if (len == maxsize && fl(buf, len))
                {
                    len = 0;
                    buf[0] = 0;
                    return true;
                }
				return false;
			}
			void flush()
			{
				if (len > 0)
					fl(buf, len);
			}
			static constexpr bool will_flush() { return true; }
			flusher* get_flusher() {
				if constexpr (sizeof(flusher) > 0)
					return &fl;
				else
					return nullptr;
			}
		};
		template <typename CC, size_t maxchars> struct core<CC, maxchars, hollow_flusher> {
            using sizetype = sztype<tools::min_integral_size_for_value(maxchars, sizeof(CC))>::type;
            enum {
			    maxsize = maxchars - 1 // keep one char for zero end
		    };

			template<typename... Args> core(Args&&...) { buf[0] = 0; buf[maxsize] = 0; }
			sizetype len = 0;
			CC buf[maxchars];
			bool flush_if()
			{
				return false;
			}
			static constexpr bool will_flush() { return false; }
			hollow_flusher* get_flusher() { return nullptr; }
		};

    }

	template<typename CC, size_t maxchars, typename flusher = hollow_flusher> class xsstr
	{
	public:
		using sizetype = sztype<tools::min_integral_size_for_value(maxchars, sizeof(CC))>::type;
		enum {
			maxsize = maxchars - 1 // keep one char for zero end
		};
	private:

		xsstr_core::core<CC, maxchars, flusher> cor;

	public:
		xsstr() {}
		template<typename Ts> xsstr(Ts&& arg) :cor(std::move(arg)) {}
		sizetype length() const { return cor.len; };

		flusher* get_flusher() { return cor.get_flusher(); }

		const CC* data() const { return cor.buf; }
		CC* data() { return cor.buf; }
		void clear() { cor.len = 0; cor.buf[0] = 0; }
        void push_back(CC c) {
			if (cor.len < maxsize)
			{
				cor.buf[cor.len] = c;
				cor.buf[cor.len+1] = 0;
				++cor.len;
			}
			cor.flush_if();
        }
		xsstr& append(const xstr_view<CC>& s)
		{
			size_t len = s.length();
			const char* data = s.data();

			if constexpr (cor.will_flush())
            {
                if (cor.len > maxsize / 2 && len > maxsize / 2)
                {
					// so, just do two flushes
					cor.flush();
					cor.fl(data,len);
					clear();
					return *this;
                }
			}

            for(;len > 0;)
			{
				size_t free_space = maxsize - cor.len;
                size_t copychars = len <= free_space ? len : free_space;
                memcpy(cor.buf + cor.len, data, copychars * sizeof(CC));
                cor.len = static_cast<sizetype>(cor.len + copychars);

				if (cor.flush_if())
				{
					len -= copychars;
					data += copychars;
					continue;
				}
				else
				{
					break;
				}
			}
            cor.buf[cor.len] = 0;

			return *this;
		}
		xsstr& operator += (CC c)
		{
			push_back(c);
			return *this;
		}
        xsstr& operator += (const xstr_view<CC> &s)
        {
			return append(s);
        }
		void resize(size_t sz)
		{
			cor.len = static_cast<sizetype>(sz <= maxsize ? sz : maxsize);
			cor.buf[cor.len] = 0;
		}
	};

	template <size_t maxchars> using asstr = xsstr<char, maxchars, hollow_flusher>;
	template <size_t maxchars> using wsstr = xsstr<wchar, maxchars, hollow_flusher>;

	template<typename T, size_t sz> struct _const_str_build
	{
	};
	template<size_t sz> struct _const_str_build<char, sz>
	{
		consteval static astr_view get(const char* sa, const wchar*) { return str::astr_view(sa, sz); }
	};
	template<size_t sz> struct _const_str_build<wchar, sz>
	{
		consteval static wstr_view get(const char*, const wchar* sw) { return wstr_view(sw, sz); }
	};

    inline const astr_view& view(const astr_view& s)
    {
        return s;
    }
    template<size_t ssz> astr_view view(const asstr<ssz>& s)
    {
        return astr_view(s.data(), s.length());
    }
	inline astr_view view(const astr& s)
	{
		return astr_view(s.c_str(), s.length());
	}
    inline astr_view view(const astr& s, signed_t skip_chars)
    {
        return astr_view(s.c_str() + skip_chars, s.length() - skip_chars);
    }
	inline wstr_view view(const wstr& s)
	{
		return wstr_view(s.c_str(), s.length());
	}

    inline astr_view view(const buffer& s)
    {
        return astr_view(reinterpret_cast<const char*>(s.data()), s.size());
    }
    inline astr_view view(const std::span<const u8>& s)
    {
        return astr_view(reinterpret_cast<const char*>(s.data()), s.size());
    }

    template<typename STR> struct chartype;
    template<> struct chartype<astr> { using type = char; };
    template<> struct chartype<buffer> { using type = char; };
    template<> struct chartype<std::span<char>> { using type = char; };
    template<size_t ssz, typename flusher> struct chartype<xsstr<char,ssz,flusher>> { using type = char; };
    template<> struct chartype<wstr> { using type = wchar; };
	template<size_t ssz, typename flusher> struct chartype<xsstr<wchar, ssz, flusher>> { using type = wchar; };

	template <typename TCH> TCH get_last_char(const xstr<TCH>& s)
	{
		size_t l = s.length();
		if (l > 0)
			return s[l - 1];
		return 0;
	}
	template <typename TCH> TCH get_last_char(const xstr_view<TCH>& s)
	{
		size_t l = s.length();
		if (l > 0)
			return s[l - 1];
		return 0;
	}

	template <typename TCH> TCH starts_with(const xstr_view<TCH>& s, const xstr_view<TCH>& ss)
	{
		if (s.length() < ss.length())
			return false;
		return s.substr(0, ss.length()) == ss;
	}
	template <typename TCH> TCH starts_with(const xstr<TCH>& s, const xstr_view<TCH>& ss)
	{
		if (s.length() < ss.length())
			return false;
		return xstr_view<TCH>(s).substr(0, ss.length()) == ss;
	}

	template <typename TCH> void trunc_len(xstr<TCH>& s, size_t numchars = 1)
	{
		size_t l = s.length();
		if (l >= numchars)
			s.resize(l - numchars);
	}

    template <typename TCH> xstr<TCH>& replace_one(xstr<TCH>& s, const xstr_view<TCH>& s1, const xstr_view<TCH>& s2)
	{
		for (size_t f = 0;;)
		{
			f = s.find(s1, f);
			if (f == s.npos)
				break;

			s.replace(f, s1.size(), s2);
			break;
		}
		return s;
	}

	template <typename TCH> xstr<TCH>& replace_all(xstr<TCH>& s, TCH c1, TCH c2)
	{
		for (size_t f = 0;;)
		{
			f = s.find(c1, f);
			if (f == s.npos)
				break;

			s[f] = c2;
			++f;
		}
		return s;
	}

	template <class CH> bool is_hollow(CH c)
	{
		return c == ' ' || c == 0x9 || c == 0x0d || c == 0x0a;
	}

	template <class CH> signed_t strz_find(const CH* const s, const CH c)
	{
		signed_t l = -1;
		CH temp;
		do { l++; temp = *(s + l); } while (temp && (temp ^ c));
		return temp ? l : -1;
	}

	template <typename CH> signed_t strz_findn(const CH* const s, const CH c, signed_t slen)
	{
		signed_t l = -1;
		CH temp;
		do { ++l; temp = *(s + l); } while ((temp ^ c) && l < slen);
		return (temp == c && l < slen) ? l : -1;
	}

	template<typename CC> inline void ltrim(xstr<CC>& s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](CC ch) {
			return !is_hollow(ch);
		}));
	}

	template<typename CC> inline xstr_view<CC> ltrim(xstr_view<CC> s) {
		signed_t i = 0;
		for (signed_t c = s.length(); i < c && is_hollow(s[i]); ++i);
		if (i > 0)
			return xstr_view<CC>(s.data() + i, s.length() - i);
		return s;
	}

	// trim from end (in place)
	template<typename CC> inline void rtrim(xstr<CC>& s) {
		//s.erase(std::find_if(s.rbegin(), s.rend(), [](CC ch) {
			//return !is_space(ch);
		//}).base(), s.end());

		signed_t i = s.length() - 1;
		for (; i >= 0 && is_hollow(s[i]); --i);
		++i;
		if ((size_t)i < s.length())
			s.resize(i);
	}

	template<typename CC> inline xstr_view<CC> rtrim(xstr_view<CC> s) {

		signed_t i = s.length() - 1;
		for (; i >= 0 && is_hollow(s[i]); --i);
		++i;
		if ((size_t)i < s.length())
			return xstr_view<CC>(s.data(), i);
		return s;
	}


	// trim from both ends (in place)
	template<typename CC> inline void trim(xstr<CC>& s) {
		rtrim(s);
		ltrim(s);
	}

	template<typename CC> inline xstr_view<CC> trim(xstr_view<CC> s) {
		return ltrim(rtrim(s));
	}


	template <class CH> xstr_view<CH> trime(const xstr_view<CH>& s, const CH* addition_hollow_chars = nullptr)
	{
		auto __is_hollow = [&](CH c)
			{
				if (is_hollow(c)) return true;
				if (addition_hollow_chars)
					return strz_find(addition_hollow_chars, c) >= 0;
				return false;
			};

		signed_t tlen = s.length();
		signed_t i0 = 0, i1 = tlen - 1;
		for (; i0 < tlen && __is_hollow(s[i0]); ++i0);
		for (; i1 >= 0 && __is_hollow(s[i1]); --i1);
		return s.substr(i0, i1 + 1);
	}

    inline std::span<u8> span(str::astr& s)
    {
        return std::span<u8>(reinterpret_cast<u8*>(s.data()), s.length());
    }

    inline std::span<const u8> span(const str::astr& s)
    {
        return std::span<const u8>(reinterpret_cast<const u8*>(s.data()), s.length());
    }
    inline std::span<const u8> span(const str::astr_view& s)
    {
        return std::span<const u8>(reinterpret_cast<const u8*>(s.data()), s.length());
    }

    inline void operator += (std::span<char>& s, char c)
    {
        s.data()[s.size()] = c;
        s = std::span(s.data(), s.size() + 1);
    }

    inline void operator += (buffer& s, const astr_view& a)
    {
        s += span(a);
    }

    inline bool __ends(const astr_view& s, const astr_view& se)
    {
        return s.ends_with(se);
    }
    inline bool __ends(const astr_view& s, char se)
    {
        if (s.length() == 0)
            return false;
        return s[s.length() - 1] == se;
    }

    inline str::astr_view __cut_tail(const astr_view& s, size_t num_chars)
    {
        if (s.length() <= num_chars)
            return astr_view();

        return astr_view(s.data(), s.length() - num_chars);
    }

    template<typename SS> SS& __append(SS& s, const xstr_view<typename chartype<SS>::type>& a)
    {
        s += a;
        return s;
    }

	inline void __append(astr& sout, const wstr& s);

	inline void __append(astr& sout, const astr& s) {
		sout.append(s);
	}
    template<typename CC> void __append(xstr<CC>& sout, const CC * s) {
        sout.append(s);
    }
    template<typename CC, size_t sssz, typename flusher> void __append(xsstr<CC, sssz, flusher>& sout, const CC* s) {
        sout.append(xstr_view<CC>(s,strlen(s)));
    }
    inline void __append(astr& sout, const std::exception& e) {
        sout.append(e.what());
    }

    inline void __append(astr& sout, std::floating_point auto e) {
        sout.append(std::to_string(e));
    }

	template<typename SS, std::integral N> void __append(SS& sout, N x);
	template<typename SS> void __append(SS& sout, const PTR& x);
	template<typename SS, int MD, uints::flat N> void __append(SS& sout, const hex<MD, N>& x);
	template<typename SS, int MD, uints::flat N> void __append(SS& sout, const dec<MD, N>& x);
	inline void __append(astr& sout, const filename& x)
	{
		for (size_t i = 0; i < x.csz; ++i)
		{
			char fnc = x.fn[i];
			sout.push_back(fnc);
			if (fnc == '\\')
				sout.push_back('\\');
		}
	}

	template<typename SS, typename S> SS& __append(SS& sout, const crlf<S>& x)
	{
        if (__ends(x.s, ASTR("\r\n")))
            __append(sout, x.s);
        if (__ends(x.s, '\n'))
        {
            __append(sout, __cut_tail(x.s, 1));
            __append(sout, ASTR("\r\n"));
		} else {
            __append(sout, x.s);
            __append(sout, ASTR("\r\n"));
		}
		return sout;
	}

    template<typename SS> void impl_build_string(SS& sout, const char* format) {
		__append(sout, format);
    }

    template <typename SS, typename T, typename... Ts> void impl_build_string(SS& sout, const char* format, const T& val, const Ts&... rest) {

        while (*format)
		{
			char fchar = *format;
			++format;
            if (fchar == '$') {
				__append(sout, val);
				impl_build_string(sout, format, rest...);
				return;
            }
            else {
				sout += fchar;
            }
        }
    }

    template <typename... T> astr build_string(const char* s, const T&... args) {

		astr sout;
		impl_build_string(sout, s, args...);
		return sout;
    }

    inline astr build_string() {

		return astr();
    }

	enum class codepage_e
	{
		ANSI,
		OEM,
		UTF8,
	};

	size_t  _text_from_ucs2(char* out, size_t maxlen, const wstr_view& from, codepage_e cp);
	size_t  _text_to_ucs2(wchar* out, size_t maxlen, const astr_view& from, codepage_e cp);

	inline str::astr to_str(const wstr_view& s, codepage_e cp)
	{
		astr sout; sout.resize(s.length());

		_text_from_ucs2(sout.data(), sout.capacity(), s, cp);
		return sout;
	}

	inline astr to_str(const wstr_view& s)
	{
		return to_str(s, codepage_e::ANSI);
	}

	inline astr to_utf8(const astr_view& s)
	{
		return astr(s);
	}

	inline astr to_utf8(const wstr_view& s)
	{
		astr  sout; sout.resize(s.length() * 3); // hint: char at utf8 can be 6 bytes length, but ucs2 maximum code is 0xffff encoding to utf8 has 3 bytes len
		size_t nl = _text_from_ucs2(sout.data(), sout.capacity(), s, codepage_e::UTF8);
		sout.resize(nl);
		return sout;
	}

	inline wstr from_utf8(const str::astr_view& s)
	{
		wstr   sout; sout.resize(s.length());
		size_t nl = _text_to_ucs2(sout.data(), sout.capacity(), s, codepage_e::UTF8);
		sout.resize(nl);
		return sout;
	}

    template<typename SS, typename CCFROM> SS& __assign(SS& s, const xstr_view<CCFROM>& a)
    {
        if constexpr (std::is_same_v<typename chartype<SS>::type, CCFROM>)
        {
            s = a;
        }
        else if constexpr (std::is_same_v<typename chartype<SS>::type, char>)
        {
            s = to_utf8(a);
        }
        else if constexpr (std::is_same_v<typename chartype<SS>::type, wchar>)
        {
            s = from_utf8(a);
        }
		return s;
    }
    template<typename SS, typename CCFROM> SS& __assign(SS& s, const xstr<CCFROM>& a)
    {
        if constexpr (!std::is_same_v<typename chartype<SS>::type, CCFROM>)
            return __assign(s, view(a));
		else
		{
            s = a;
			return s;
		}
    }
	template<typename SS, typename CCFROM> SS& __assign(SS& s, std::floating_point auto v)
	{
		return __assign(s, std::to_string(v));
	}
    template<typename SS, typename CCFROM> SS& __assign(SS& s, std::integral auto v)
    {
		s.clear();
        return append_num(s, v, 0);
    }

    inline void __append(astr& sout, const wstr& s) {
        sout.append(to_utf8(s));
    }

	template <typename TCH> void qsplit(std::vector<xstr<TCH>>& splar, const xstr_view<TCH>& str, TCH spltr = ' ')
	{
		splar.clear();
		if (str.length() == 0)  return;
		int i = 0;
		int bg = -1;
		bool quote = false;
		for (signed_t l = str.length(); l > 0; ++i, --l)
		{
			wchar ch = str[i];
			if (bg < 0)
			{
				if (ch == spltr) continue;
				bg = i;
				quote = ch == '\"';

			}
			else
			{
				if (quote)
				{
					if (ch == '\"')
					{
						splar.emplace_back(str.substr(bg + 1, i - bg - 1));
						bg = -1;
					}
				}
				else
				{
					if (ch == spltr)
					{
						splar.emplace_back(str.substr(bg, i - bg));
						bg = -1;
					}
				}
			}
		}
		if (bg >= 0)
		{
			if (quote)
			{
				splar.emplace_back(str.substr(bg + 1, i - bg - 1));
			}
			else
			{
				splar.emplace_back(str.substr(bg, i - bg));
			}
		}
	}

	template<typename CH> xstr<CH> quoter(const xstr_view<CH> &s)
	{
		if (s.find(' ') == s.npos)
			return xstr<CH>(s);

		if (s[0] == '\"') // already quoted
			return xstr<CH>(s);

		xstr<CH> rv; rv.reserve(s.length() + 2);
		rv.push_back('\"');
		rv.append(s);
		rv.push_back('\"');
		return rv;
	}

	template<typename CH> xstr<CH> qjoin(const std::vector<xstr<CH>>& splar)
	{
		xstr<CH> rv;
		for (const auto& s : splar)
		{
			if (!rv.empty())
				rv.push_back(' ');
			rv.append(quoter(view(s)));
		}
		return rv;
	}

	template<typename CH> struct sep_base
	{
		xstr_view<CH> s;
		signed_t pos = -1;
		sep_base(xstr_view<CH> s) :s(s) {}
		operator bool() const
		{
			bool working = pos <= slen();
			return working;
		}
		signed_t slen() const
		{
			return s.length();
		}
	};

	template<typename CH, CH ch> struct sep_onechar : public sep_base<CH>
	{
		sep_onechar(xstr_view<CH> s) :sep_base<CH>(s) {}
		xstr_view<CH> operator()()
		{
			if (this->pos < 0)
			{
				size_t x = this->s.find(ch);
                if (x == this->s.npos)
                {
                    this->pos = this->s.length();
                    return this->s;
                }
                xstr_view<CH> r = this->s.substr(0, x);
                this->pos = x;
                return r;
			}

			if (this->pos >= this->slen())
			{
				++this->pos;
				return this->s.substr(0, 0);
			}

			size_t x = this->s.find(ch, this->pos + 1);
			if (x == this->s.npos)
			{
				xstr_view<CH> r = this->s.substr(this->pos + 1, this->s.length() - this->pos - 1);
				this->pos = this->s.length();
				return r;
			}
			xstr_view<CH> r = this->s.substr(this->pos + 1, x- this->pos - 1);
			this->pos = x;
			return r;
		}
	};
	template<typename CH, CH ch> struct sep_onechar_rev : public sep_base<CH>
	{
		sep_onechar_rev(xstr_view<CH> s) :sep_base<CH>(s) {}
		xstr_view<CH> operator()()
		{
            if (this->pos < 0)
            {
                size_t x = this->s.rfind(ch);
                if (x == this->s.npos)
                {
                    this->pos = this->s.length();
                    return this->s;
                }
                xstr_view<CH> r = this->s.substr(x+1);
                this->pos = x;
                return r;
            }

            if (this->pos >= this->slen())
            {
                ++this->pos;
                return this->s.substr(0, 0);
            }

            size_t x = this->s.substr(0,this->pos).rfind(ch);
            if (x == this->s.npos)
            {
                xstr_view<CH> r = this->s.substr(0, this->pos);
                this->pos = this->s.length();
                return r;
            }
            xstr_view<CH> r = this->s.substr(x+1, this->pos - x - 1);
            this->pos = x;
            return r;
		}
        xstr_view<CH> operator* () const
		{
			if (this->pos >= this->slen())
				return this->s.substr(0, 0);
			return this->pos < 0 ? this->s : this->s.substr(0, this->pos);
		}

	};
	template<typename CH> struct sep_line : public sep_base<CH>
	{
		xstr_view<CH> crlf = XSTR(CH, "\r\n");
		sep_line(xstr_view<CH> s) :sep_base<CH>(s) {}
		xstr_view<CH> operator()()
		{
            if (this->pos < 0)
            {
                size_t x = this->s.find_first_of(crlf);
                if (x == this->s.npos)
                {
                    this->pos = this->s.length();
                    return this->s;
                }
                xstr_view<CH> r = this->s.substr(0, x);

				if (this->s[x + 1] == crlf[1])
				{
					// keep crlf
				}
				else
				{
					crlf = this->s.substr(x, 1); // use found character (cr or lf)
				}

                this->pos = x + crlf.length() - 1;
                return r;
            }

            if (this->pos >= this->slen())
            {
                ++this->pos;
                return this->s.substr(0, 0);
            }

            size_t x = this->s.find(crlf, this->pos + 1);
            if (x == this->s.npos)
            {
                xstr_view<CH> r = this->s.substr(this->pos + 1, this->s.length() - this->pos - 1);
                this->pos = this->s.length();
                return r;
            }
            xstr_view<CH> r = this->s.substr(this->pos + 1, x - this->pos - 1);
            this->pos = x + crlf.length() - 1;
            return r;

		}
	};

	template<typename CH> struct sep_hollow : public sep_base<CH>
	{
		sep_hollow(xstr_view<CH> s) :sep_base<CH>(trim(s)) {}
		xstr_view<CH> operator()()
		{
            if (this->pos < 0)
            {
                size_t x = this->s.find_first_of(XSTR(CH, " \t\r\n"));
                if (x == this->s.npos)
                {
                    this->pos = this->s.length();
                    return this->s;
                }
                xstr_view<CH> r = this->s.substr(0, x);
                this->pos = x;
				for (; this->pos + 1 < this->slen() && is_hollow(this->s[this->pos + 1]); ++this->pos);
                return r;
            }

            if (this->pos >= this->slen())
            {
                ++this->pos;
                return this->s.substr(0, 0);
            }

            size_t x = this->s.find_first_of(XSTR(CH, " \t\r\n"), this->pos + 1);
            if (x == this->s.npos)
            {
                xstr_view<CH> r = this->s.substr(this->pos + 1, this->s.length() - this->pos - 1);
                this->pos = this->s.length();
                return r;
            }
            xstr_view<CH> r = this->s.substr(this->pos + 1, x - this->pos - 1);
            this->pos = x;
			for (; this->pos + 1 < this->slen() && is_hollow(this->s[this->pos + 1]); ++this->pos);
            return r;

		}
	};

#define enum_tokens_a(tkn, s, c) for (str::token<char, str::sep_onechar<char, c>> tkn(str::view(s)); tkn; tkn())
#define enum_tokens_w(tkn, s, c) for (str::token<wchar, str::sep_onechar<wchar, c>> tkn(s); tkn; tkn())

	template<typename CH, typename TE = sep_onechar<CH, ','>> class token // tokenizer, for (token t(str); t; t()) if (*t=="...") ...
	{
		TE te;
		xstr_view<CH> tkn;

	public:

		typedef decltype(tkn) tokentype;

		token(const xstr_view<CH>& s) : te(s) { tkn = te(); }
		token(const xstr<CH>& s) : te(view(s)) { tkn = te(); }
		token(const CH* s, size_t count) :te(xstr_view<CH>(s, count)) { tkn = te(); }
		explicit token(const CH* s) = delete;
		token(const token &s) = delete;
		token(token&& s) = delete;
		token() {}

		void operator=(const token& s) = delete;
		void operator=(token&& s) = delete;

		xstr_view<CH> remained() const
		{
			return *te;
		}

		operator bool() const { return !!te; }

		const xstr_view<CH>& operator* () const { return  tkn; }
		const xstr_view<CH>* operator->() const { return &tkn; }

		void trim(size_t x)
		{
			tkn = tkn.substr(0, x);
		}

		void operator()()
		{
			tkn = te();
		}
	};

}

namespace str
{
	template <size_t typesz> consteval inline size_t decimal_str_size()
	{
		return (typesz*3+4) & ~(3u); // at least 3 characters per byte
	}

	template <class CH, uints::flat T> size_t fill_str_unsigned(CH* buf, size_t idx, T& t)
	{
		if constexpr (sztype<sizeof(T)>::native)
		{
            T i = t;
            while (i >= 10)
            {
                u8 remainder = uints::divbyconst<T,10>(i);
                buf[idx--] = static_cast<CH>(remainder + '0');
            }
            buf[idx] = static_cast<CH>(i + '0');
			return idx;
		}
		else
        {
            if (uints::is_zero(uints::high(t)))
                return fill_str_unsigned<CH>(buf, idx, uints::low(t));

            do
            {
                u8 remainder = uints::divbyconst<T, 10>(t);
                buf[idx--] = static_cast<CH>(remainder + '0');
            } while (!uints::is_zero(uints::high(t)));

			return fill_str_unsigned<CH>(buf, idx, uints::low(t));
		}

	}

    template <class CH, uints::flat T> CH* make_str_unsigned(CH* buf, size_t& szbyte, const T &t)
    {
        signed_t idx = (decimal_str_size<sizeof(T)>() - 1);
        buf[idx--] = 0;
		T tt = t;
		idx = fill_str_unsigned<CH, T>(buf, idx, tt);
        szbyte = static_cast<size_t>((decimal_str_size<sizeof(T)>() - idx) * sizeof(CH));
        return buf + idx;
    }

	inline size_t __size(const buffer& b)
	{
		return b.size();
	}
    template<typename CC> size_t __size(const xstr<CC>& s)
    {
        return s.length();
    }
    template<typename CC, size_t ssz, typename flusher> size_t __size(const xsstr<CC, ssz, flusher>& s)
    {
        return s.length();
    }

    inline void __resize(buffer& b, size_t newsize)
    {
		b.resize(newsize, true);
    }
    template<typename CC> void __resize(xstr<CC>& s, size_t newsize)
    {
		s.resize(newsize);
    }
    template<typename CC, size_t ssz, typename flusher> void __resize(xsstr<CC, ssz, flusher>& s, size_t newsize)
    {
		s.resize(newsize);
    }

	template<typename SS> void append(SS& s, signed_t n, typename chartype<SS>::type filler)
    {
        signed_t l = __size(s), nl = l + n;
        __resize(s, nl);
        for (signed_t i = l; i < nl; ++i)
            s.data()[i] = filler;
    }

	template<typename SS, uints::flat T> SS& append_num(SS& s, const T &n, size_t minimum_digits)
	{
        using CH = typename chartype<SS>::type;
        CH buf[decimal_str_size<sizeof(T)>()];

        if constexpr (sztype<sizeof(T)>::native && std::is_signed_v<T>)
        {
			if (n < 0)
			{
				s += '-';
				T nn = -n;
				return append_num(s, nn, minimum_digits);
			}
        }

		size_t szbyte;
        CH* tcalced = make_str_unsigned(buf, szbyte, n);
		size_t digits = szbyte / sizeof(CH)-1;
        if (digits < minimum_digits)
            append(s, minimum_digits - digits, '0');
        return __append(s, xstr_view<CH>(tcalced, digits));
	}

	template<size_t typesize> requires (typesize >= 2) struct low_part_mask
	{
		consteval static sztype<typesize>::type build_mask()
		{
			typename sztype<typesize>::type rv = 0xff;

			for (size_t b = typesize - 1; b > (typesize/2); --b)
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

	template<size_t skip, uints::flat T> size_t calc_high_zeros_impl(const T& t)
	{
        if constexpr (sizeof(T) == 1)
        {
            if (t == 0) return 2;
            if ((t & 0xf0) == 0) return 1;
            return 0;
        }
        else if constexpr (sztype<sizeof(T)>::native)
        {
            if ((t & hi_part_mask<sizeof(T)>::mask) == 0)
                return sizeof(T) + calc_high_zeros_impl<0>(uints::aslow<sizeof(T) / 2>(t));
            return calc_high_zeros_impl<0>(uints::ashigh<sizeof(T) / 2>(t));
        }
		else
		{
			if constexpr (skip == 0)
			{
				return calc_high_zeros_impl<0>(uints::aslow<sizeof(size_t)>(t));
			}
			else
            {
                size_t mp = (const size_t&)uints::mid<skip, sizeof(size_t)>(t);
                if (mp == 0)
                    return sizeof(size_t) * 2 + calc_high_zeros_impl<skip - sizeof(size_t)>(t);
                return calc_high_zeros_impl<0>(mp);
			}
		}

	}

	template<uints::flat T> size_t calc_high_zeros(const T&t)
	{
		static_assert(sztype<sizeof(T)>::native || (sizeof(T) % sizeof(size_t)) == 0 );
		return calc_high_zeros_impl<sizeof(T) - sizeof(size_t)>(t);
	}

	template<typename T> u8 extract_hex(const T& t, signed_t index)
	{
		if constexpr (Endian::little)
		{
            bool hipart = (index & 1) != 0;
			const std::array<u8, sizeof(T)>& bytes = ref_cast<const std::array<u8, sizeof(T)>>(t);
			u8 hexi = bytes[index >> 1];
			return hipart ? (hexi >> 4) : (hexi & 0xf);
		}
		else {
			static_assert(sizeof(T) == 123123, "Implement big endian yourself");
		}
	}

    template<typename SS, uints::flat V, int min_digits = -1> inline void append_hex(SS& s, const V &v) {

        static char cc[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        constexpr const unsigned N = 2 * sizeof(v);
        size_t fromd = 0;
        if constexpr (min_digits > 0)
        {
            size_t digits = N - calc_high_zeros(v);
            if (digits < min_digits)
                append(s, min_digits - digits, '0');
            fromd = N - digits;
        }

        bool skipz = min_digits < 0;
        for (size_t i = fromd; i < N; ++i)
        {
            u8 hexi = extract_hex<V>(v, N - i - 1);
            if (skipz && hexi == 0)
                continue;
            s += cc[hexi];
            skipz = false;
        }
        if (skipz)
            s += cc[0];
    }

	template <typename SS> inline size_t __find(const SS& s, const xstr_view<typename chartype<SS>::type>& ss, size_t offs)
	{
		return s.find(ss, offs);
	}
    template <> inline size_t __find<buffer>(const buffer& s, const xstr_view<char>& ss, size_t offs)
    {
		return view(s).find(ss, offs);
    }

	template<typename SS> inline size_t __npos(const SS &s)
	{
		return s.npos;
	}
    template<> inline size_t __npos(const buffer&)
    {
        return astr_view::npos;
    }

    template <typename SS> inline void __replace(SS& s, size_t off, size_t cnt, const xstr_view<typename chartype<SS>::type>& ss)
    {
        s.replace(off, cnt, ss);
    }
    template <> inline void __replace(buffer& s, size_t off, size_t cnt, const astr_view& ss)
    {
        s.replace(off, cnt, std::span((const u8 *)ss.data(), ss.length()));
    }

    template <typename SS> SS& replace_all(SS& s, const xstr_view<typename chartype<SS>::type>& s1, const xstr_view<typename chartype<SS>::type>& s2)
    {
        for (size_t f = 0;;)
        {
            f = __find(s, s1, f);
            if (f == __npos(s))
                break;

            __replace(s, f, s1.size(), s2);
            f += s2.size();
        }
        return s;
    }

	struct lazy_cleanup_string
	{
		astr_view s;
		astr_view disabled_chars;
		lazy_cleanup_string(const astr& s, astr_view disabled_chars) :s(view(s)), disabled_chars(disabled_chars) {}
		lazy_cleanup_string(const astr_view &s, astr_view disabled_chars) :s(s), disabled_chars(disabled_chars) {}
		void append_to(str::astr& sout) const
        {
            for (char cc : s)
                if (disabled_chars.find(cc) != disabled_chars.npos)
					sout.push_back('?');
				else
					sout.push_back(cc);
        }
	};

	inline void __append(astr& sout, const lazy_cleanup_string& s) {
        s.append_to(sout);
    }

    template<typename SS, std::integral N> void __append(SS& sout, N x) {
        append_num(sout, x, 0);
    }
	template<typename SS> void __append(SS& sout, const PTR& x)
	{
		//__append(sout, ASTR("0x"));
		append_hex<SS, decltype(x.val), 0>(sout, x.val);
	}
	template<typename SS, int MD, uints::flat N> void __append(SS& sout, const hex<MD, N>& x)
	{
		append_hex<SS, N, MD>(sout, x.n);
	}
	template<typename SS, int MD, uints::flat N> void __append(SS& sout, const dec<MD, N>& x)
	{
		append_num(sout, x.n, MD);
	}

	inline lazy_cleanup_string clean(const astr& s, astr_view disabled_chars = ASTR("{}[]`\"\'\\/?&"))
	{
		return lazy_cleanup_string(s, disabled_chars);
	}
    inline lazy_cleanup_string clean(astr_view s, astr_view disabled_chars = ASTR("{}[]`\"\'\\/?&"))
    {
        return lazy_cleanup_string(s, disabled_chars);
    }

	inline char base64(signed_t index)
	{
		static char base64_encoding_table[64] = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
			'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
			'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
		};
		return base64_encoding_table[index];
	}


	inline void encode_base64(astr& s, const void* data, signed_t size)
	{
		const uint8_t* b = (const uint8_t*)data;

		size_t blockcount = size / 3;
		size_t padding = size - (blockcount * 3);
		if (padding) { padding = 3 - padding; ++blockcount; }

		for (size_t x = 0; x < blockcount; x++)
		{
			signed_t indx = x * 3;

			uint8_t b1 = indx < size ? b[indx] : 0;
			++indx;
			uint8_t b2 = indx < size ? b[indx] : 0;
			++indx;
			uint8_t b3 = indx < size ? b[indx] : 0;

			uint8_t temp, temp1, temp2, temp3, temp4;
			temp1 = (uint8_t)((b1 & 252) >> 2);//first


			temp = (uint8_t)((b1 & 3) << 4);
			temp2 = (uint8_t)((b2 & 240) >> 4);
			temp2 += temp; //second


			temp = (uint8_t)((b2 & 15) << 2);
			temp3 = (uint8_t)((b3 & 192) >> 6);
			temp3 += temp; //third


			temp4 = (uint8_t)(b3 & 63); //fourth

			s.push_back(base64(temp1));
			s.push_back(base64(temp2));
			s.push_back(base64(temp3));
			s.push_back(base64(temp4));

		}

		switch (padding)
		{
		case 2: s[s.length() - 2] = '=';
		case 1: s[s.length() - 1] = '=';
		}

	}

	inline signed_t base64_len(const astr_view& s, signed_t from = 0, signed_t ilen = -1)
	{
		const char* ss = s.data() + from;
		signed_t sl = ilen < 0 ? (s.length() - from) : ilen;
		if (sl > 1 && ss[sl - 2] == '=') sl -= 2;
		else if (sl > 0 && ss[sl - 1] == '=') --sl;
		return (sl * 6) / 8;
	}
	inline signed_t decode_base64(const astr_view& s, void* data, signed_t datasize, signed_t from = 0, signed_t ilen = -1)
	{
		uint8_t* d = (uint8_t*)data;
		const char* ss = s.data() + from;
		signed_t sl = ilen < 0 ? (s.length() - from) : ilen;

		signed_t bszlen = base64_len(s, from, ilen);
		static const char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
		uint8_t inb[4]; //-V112
		if (datasize > bszlen) datasize = bszlen;
		for (; sl>0 && datasize;)
		{
			bool inbb = false;
			for (signed_t i = 0; i < isizeof(inb) && (sl > 0); ++i)
			{
				uint8_t v = 0;
				while ((sl>0) && v == 0)
				{
					char bch = *ss; ++ss; --sl;
					if (bch < 43 || v > 122)
						continue; // just ignore all non-base64 chars

					v = (uint8_t)(cd64[bch - 43]);
					v = (uint8_t)((v == '$') ? 0 : v - 61);
				}
				if (v)
					inb[i] = (uint8_t)(v - 1), inbb = true;
			}
			if (inbb)
			{
				if (datasize) { *d = (uint8_t)((inb[0] << 2 | inb[1] >> 4) & 0xFF); ++d; --datasize; }
				if (datasize) { *d = (uint8_t)((inb[1] << 4 | inb[2] >> 2) & 0xFF); ++d; --datasize; }
				if (datasize) { *d = (uint8_t)((((inb[2] << 6) & 0xc0) | inb[3]) & 0xFF); ++d; --datasize; }
			}
		}
		return (signed_t)(d - (uint8_t*)data);
	}

	template<typename CH> signed_t parse_int(const xstr_view<CH>& x, signed_t max_valid, signed_t if_failed)
	{
		signed_t v = 0;
		for (CH c : x)
		{
			size_t y = c - 48;
			if (y >= 10)
				return if_failed;
			v = v * 10 + y;
			if (v > max_valid)
				return if_failed;
		}
		return v;
	}
	template<typename CH> signed_t parse_int(const xstr_view<CH>& x, signed_t if_failed)
    {
        signed_t v = 0;
        for (CH c : x)
        {
            size_t y = c - 48;
            if (y >= 10)
                return if_failed;
            v = v * 10 + y;
        }
        return v;
    }


	template<typename CH> signed_t find_pos_t(const xstr_view<CH>& in, signed_t idx, const xstr_view<CH>& subs, CH c = '?') // find substring. c is any char // find_pos_t("abc5abc",0,"c?a",'?') == 2
	{
		if (in.length() == 0) return ((idx == 0) && (subs.length() == 0)) ? 0 : -1;

		xstr_view<CH> s = subs;
		for (; s.length() && s.data()[0] == c; s = s.substr(1));
		signed_t skip = subs.length() - s.length();
		idx += skip;
		for (;;)
		{
			signed_t left = in.length() - idx;
			if (left < (signed_t)s.length()) return -1;
			signed_t temp = strz_findn(in.data() + idx, *s.data(), left);
			if (temp < 0) return -1;
			idx += temp;
			if ((idx + s.length()) > in.length()) return -1;

			bool gotcha = true;
			for (signed_t i = 0; i < (signed_t)s.length(); ++i)
			{
				if (s.data()[i] == c) continue;
				if (*(in.data() + idx + i) != s.data()[i]) { gotcha = false; break; }
			}

			if (gotcha) return idx - skip;
			++idx;
		}
		UNREACHABLE();
	};


	template<typename CH> bool mask_match(const xstr_view<CH>& s, const xstr_view<CH>& mask)
	{
		if (xstr_view<CH>(mask) == XSTR(CH, "*"))
			return true;

		signed_t index = 0;
		bool left = true;
		bool last_e = false;
		for (str::token<char, str::sep_onechar<char, '*'>> mp(mask); mp; mp())
		{
			last_e = mp->length() == 0;
			signed_t i = last_e ? index : find_pos_t(s, index, *mp);
			if (i < 0) return false;
			if (left && i != 0) return false;
			left = false;
			index = i + mp->length();
		}
		if (last_e)
			return true;

		return index == (signed_t)s.length();
	}
}

namespace tools
{
	template <typename CH> struct string_hash
	{
		using hash_type = std::hash<str::xstr_view<CH>>;
		using is_transparent = void;

		std::size_t operator()(const CH* s) const { return hash_type{}(s); }
		std::size_t operator()(str::xstr_view<CH> s) const { return hash_type{}(s); }
		std::size_t operator()(str::xstr<CH> const& s) const { return hash_type{}(s); }
	};

	template <typename TCH, typename VALT> using shashmap = std::unordered_map<str::xstr<TCH>, VALT, string_hash<TCH>, std::equal_to<>>;

} // namespace tools


void debug_print(str::astr_view s);
template <typename... T> void debug_print(const char* s, const T&... args) {

    str::astr sout;
	str::impl_build_string(sout, s, args...);
	debug_print(str::view(sout));
}

