#pragma once

#ifdef _MSC_VER
typedef wchar_t wchar;
#elif defined __GNUC__
typedef char16_t wchar;
#endif

#define BUILD_ASTRVIEW(x,y) str::astr_view(x,y)

#if defined _MSC_VER
#define BUILD_WSTRVIEW(x,y) str::wstr_view(L##x,y)
#define XSTR( tc, s ) str::_const_str_build<tc>::get( s, L##s, sizeof(s)-1 )
#define WIDE2(s) L##s
#elif defined __GNUC__
#define BUILD_WSTRVIEW(x,y) str::wstr_view(u##x,y)
#define XSTR( tc, s ) str::_const_str_build<tc>::get( s, u##s, sizeof(s)-1 )
#define WIDE2(s) u##s
#endif

namespace str
{
	template <typename TCH> using xstr = std::basic_string<TCH>;
	template <typename TCH> using xstr_view = std::basic_string_view<TCH>;
	using astr = xstr<char>;
	using wstr = xstr<wchar>;
	using astr_view = xstr_view<char>;
	using wstr_view = xstr_view<wchar>;

	template<typename T> struct _const_str_build
	{
	};
	template<> struct _const_str_build<char>
	{
		constexpr static str::astr_view get(const char* sa, const wchar*, signed_t len) { return str::astr_view(sa, len); }
	};
	template<> struct _const_str_build<wchar>
	{
		constexpr static str::wstr_view get(const char*, const wchar* sw, signed_t len) { return str::wstr_view(sw, len); }
	};

	inline astr_view view(const str::astr& s)
	{
		return astr_view(s.c_str(), s.length());
	}
	inline wstr_view view(const str::wstr& s)
	{
		return wstr_view(s.c_str(), s.length());
	}

    inline str::astr_view view(const buffer& s)
    {
        return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
    }
    inline str::astr_view view(const std::span<const u8>& s)
    {
        return str::astr_view(reinterpret_cast<const char*>(s.data()), s.size());
    }

    template<typename STR> struct chartype;
    template<> struct chartype<astr> { using type = char; };
    template<> struct chartype<buffer> { using type = char; };
    template<> struct chartype<std::span<char>> { using type = char; };
    template<> struct chartype<wstr> { using type = wchar; };


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
		return (c == ' ' || c == 0x9 || c == 0x0d || c == 0x0a);
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

	inline str::astr build_string(const char* s, ...)
	{
		char b[1024];

		va_list args;
		va_start(args, s);
		int t = vsnprintf(b, sizeof(b), s, args);
		va_end(args);
		return str::astr(b, t);
	}

	inline str::astr build_string_d(const char* fn, int ln, const char* s, ...)
	{
		char b[1024];

		int t = snprintf(b, sizeof(b), "%s(%i): ", fn, ln);

		for (signed_t i = t - 1; i >= 0; --i)
		{
			if (b[i] == '\\')
			{
				memmove(b + i + 1, b + i, t-i);
				++t;
			}
		}

		va_list args;
		va_start(args, s);
		t += vsnprintf(b + t, sizeof(b) - t, s, args);
		va_end(args);

		return str::astr(b, t);
	}

	inline str::astr build_string_d(const char* fn, int ln)
	{
		return build_string_d(fn, ln, "---");
	}


	enum class codepage_e
	{
		ANSI,
		OEM,
		UTF8,
	};

	size_t  _text_from_ucs2(char* out, size_t maxlen, const str::wstr_view& from, codepage_e cp);
	size_t  _text_to_ucs2(wchar* out, size_t maxlen, const str::astr_view& from, codepage_e cp);

	inline str::astr to_str(const str::wstr_view& s, codepage_e cp)
	{
		str::astr   sout; sout.resize(s.length());

		_text_from_ucs2(sout.data(), sout.capacity(), s, cp);
		return sout;
	}

	inline str::astr to_str(const str::wstr_view& s)
	{
		return to_str(s, codepage_e::ANSI);
	}

	inline str::astr to_utf8(const str::astr_view& s)
	{
		return str::astr(s);
	}

	inline str::astr to_utf8(const str::wstr_view& s)
	{
		str::astr  sout; sout.resize(s.length() * 3); // hint: char at utf8 can be 6 bytes length, but ucs2 maximum code is 0xffff encoding to utf8 has 3 bytes len
		size_t nl = _text_from_ucs2(sout.data(), sout.capacity(), s, codepage_e::UTF8);
		sout.resize(nl);
		return sout;
	}

	inline str::wstr from_utf8(const str::astr_view& s)
	{
		str::wstr   sout; sout.resize(s.length());
		size_t nl = _text_to_ucs2(sout.data(), sout.capacity(), s, codepage_e::UTF8);
		sout.resize(nl);
		return sout;
	}

	template <typename TCH> void qsplit(std::vector<xstr<TCH>>& splar, const xstr_view<TCH>& str)
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
				if (ch == ' ') continue;
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
					if (ch == ' ')
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
		const xstr_view<CH>& operator* () const { return s; }
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

#define TFORa(tkn, s, c) for (str::token<char, str::sep_onechar<char, c>> tkn(s); tkn; tkn())
#define TFORw(tkn, s, c) for (str::token<wchar, str::sep_onechar<wchar, c>> tkn(s); tkn; tkn())

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

		const xstr_view<CH>& remaind() const
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








#define ASTR( s ) BUILD_ASTRVIEW( s, sizeof(s)-1 )
#define WSTR( s ) BUILD_WSTRVIEW( s, sizeof(s)-1 )


namespace str
{
    template<typename T> struct is_signed
    {
        static const bool value = (((T)-1) < 0);
    };

    template<typename T, bool s = is_signed<T>::value, bool too_huge = (sizeof(T) > sizeof(size_t)) > struct as_native_1
    {
        typedef T type;
    };

    template<typename T, bool sgn = is_signed<T>::value > struct invert
    {
        void operator()(T&) { UNREACHABLE(); }
    };
    template<typename T> struct invert<T, true>
    {
        void operator()(T& t) { t = -t; }
    };

	inline void operator += (std::span<char>& s, char c)
	{
        s.data()[s.size()] = c;
        s = std::span(s.data(), s.size() + 1);
	}

    inline void operator += (buffer& s, const astr_view& a)
    {
        s += span(a);
    }

    template <class CH, typename I> __inline CH* make_str_unsigned(CH* buf, signed_t& szbyte, I i)
    {
		signed_t idx = (sizeof(I) * 4 - 1);
        buf[idx--] = 0;
        while (i >= 10)
        {
            I d = i / 10;
            buf[idx--] = (CH)(i - ((d << 3) + (d << 1)) + 48);
            i = d;
        }
        buf[idx] = (CH)((CH)i + 48);
        szbyte = static_cast<signed_t>(((sizeof(I) * 4) - idx) * sizeof(CH));
        return buf + idx;
    }

	template<typename SS> struct strop
    {
		using CH = typename chartype<SS>::type;

        static void append_chars(SS& s, signed_t n, CH filler)
        {
            signed_t l = s.size(), nl = l + n;
            s.resize(nl);
            for (signed_t i = l; i < nl; ++i)
                s.data()[i] = filler;
        }
        static void append_char(SS& s, char cha)
        {
            s += cha;
        }
        static void append(SS& s, const xstr_view<CH>& a)
        {
			s += a;
        }
	};

	template<typename SS, typename N> struct strap
	{
		static void append_num(SS& s, N n, signed_t minimum_digits)
		{
            using CH = typename chartype<SS>::type;
            CH buf[sizeof(N) * 4];

            if constexpr (is_signed<N>::value)
            {
				if (n < 0)
				{
					strop<SS>::append_char(s, '-');
					invert<N>()(n);
				}
            }

            signed_t szbyte;
            CH* tcalced = make_str_unsigned(buf, szbyte, n);
            signed_t digits = szbyte / sizeof(CH)-1;
            if (digits < minimum_digits)
                strop<SS>::append_chars(s, minimum_digits - digits, '0');
            strop<SS>::append(s, xstr_view<CH>(tcalced, digits));

		}
	};
	template<> struct strap<astr, float> { static void append_num(astr& s, float n, signed_t) { s.append( std::to_string(n) ); } };
	template<> struct strap<astr, double> { static void append_num(astr& s, double n, signed_t) { s.append(std::to_string(n)); } };
    //template<> struct strap<wstr, float> { static void append_num(wstr& s, float n, signed_t) { s.append(std::to_wstring(n)); } };
    //template<> struct strap<wstr, double> { static void append_num(wstr& s, double n, signed_t) { s.append(std::to_wstring(n)); } };

    template<typename SS, typename V, bool skipzeros = true> inline void append_hex(SS& s, V v) {

        static char cc[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        const unsigned N = 2 * sizeof(v);
        bool skipz = skipzeros;
        for (unsigned i = 0; i < N; ++i)
        {
            unsigned shiftr = 4 * (N - i - 1);
            V hex = (v >> shiftr) & 0xf;
            if (skipz && hex == 0)
                continue;
            strop<SS>::append_char(s, cc[hex]);
            skipz = false;
        }
        if (skipz)
            strop<SS>::append_char(s, cc[0]);
    }

    template <class SS, typename N> void append_num(SS& s, N n, signed_t minimum_digits)
    {
		strap<SS, N>::append_num(s,n,minimum_digits);
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



	const char* printable(const str::astr& name, str::astr_view disabled_chars = ASTR("{}[]`\"\'\\/?&"));

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


	inline void encode_base64(str::astr& s, const void* data, signed_t size)
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

	inline signed_t base64_len(const str::astr_view& s, signed_t from = 0, signed_t ilen = -1)
	{
		const char* ss = s.data() + from;
		signed_t sl = ilen < 0 ? (s.length() - from) : ilen;
		if (sl > 1 && ss[sl - 2] == '=') sl -= 2;
		else if (sl > 0 && ss[sl - 1] == '=') --sl;
		return (sl * 6) / 8;
	}
	inline signed_t decode_base64(const str::astr_view& s, void* data, signed_t datasize, signed_t from = 0, signed_t ilen = -1)
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
					v = (uint8_t)ss[0]; ++ss; --sl;
					v = (uint8_t)((v < 43 || v > 122) ? 0 : cd64[v - 43]);
					if (v)
					{
						v = (uint8_t)((v == '$') ? 0 : v - 61);
					}
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

	inline signed_t parse_int(const astr_view& x, signed_t max_valid, signed_t if_failed)
	{
		signed_t v = 0;
		for (char c : x)
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
    inline signed_t parse_int(const astr_view& x, signed_t if_failed)
    {
        signed_t v = 0;
        for (char c : x)
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
