#pragma once

#ifdef _MSC_VER
typedef wchar_t wchar;
#elif defined __GNUC__
typedef char16_t wchar;
#endif


namespace str
{
	template <typename TCH> using xstr = std::basic_string<TCH>;
	template <typename TCH> using xstr_view = std::basic_string_view<TCH>;
	using astr = xstr<char>;
	using wstr = xstr<wchar>;
	using astr_view = xstr_view<char>;
	using wstr_view = xstr_view<wchar>;

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


	template <typename TCH> xstr<TCH>& replace_all(xstr<TCH>& s, const xstr_view<TCH>& s1, const xstr_view<TCH>& s2)
	{
		for (size_t f = 0;;)
		{
			f = s.find(s1, f);
			if (f == s.npos)
				break;

			s.replace(f, s1.size(), s2);
			f += s2.size();
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

	template<typename CC> INLINE bool is_space(CC c)
	{
		return c == 32 || c == '\n' || c == '\r' || c == '\t';
	}

	template<typename CC> INLINE void ltrim(xstr<CC>& s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](CC ch) {
			return !is_space(ch);
		}));
	}

	template<typename CC> INLINE xstr_view<CC> ltrim(xstr_view<CC> s) {
		signed_t i = 0;
		for (signed_t c = s.length(); i < c && is_space(s[i]); ++i);
		--i;
		if (i >= 0)
			return xstr_view<CC>(s.data() + i, s.length() - i);
		return s;
	}

	// trim from end (in place)
	template<typename CC> INLINE void rtrim(xstr<CC>& s) {
		//s.erase(std::find_if(s.rbegin(), s.rend(), [](CC ch) {
			//return !is_space(ch);
		//}).base(), s.end());

		signed_t i = s.length() - 1;
		for (; i >= 0 && is_space(s[i]); --i);
		++i;
		if ((size_t)i < s.length())
			s.resize(i);
	}

	template<typename CC> INLINE xstr_view<CC> rtrim(xstr_view<CC> s) {

		signed_t i = s.length() - 1;
		for (; i >= 0 && is_space(s[i]); --i);
		++i;
		if ((size_t)i < s.length())
			return xstr_view<CC>(s.data(), i);
		return s;
	}


	// trim from both ends (in place)
	template<typename CC> INLINE void trim(xstr<CC>& s) {
		rtrim(s);
		ltrim(s);
	}

	template<typename CC> INLINE xstr_view<CC> trim(xstr_view<CC> s) {
		return ltrim(rtrim(s));
	}


	inline str::astr build_string(const char* s, ...)
	{
		char str[1024];

		va_list args;
		va_start(args, s);
		vsnprintf(str, sizeof(str), s, args);
		va_end(args);
		str[sizeof(str) - 1] = 0;
		return str::astr(str);
	}

	inline str::astr build_string_d(const char* fn, int ln, const char* s, ...)
	{
		char str[1024];

		int t = snprintf(str, sizeof(str), "%s(%i): ", fn, ln);

		va_list args;
		va_start(args, s);
		vsnprintf(str + t, sizeof(str) - t, s, args);
		va_end(args);

		str[sizeof(str) - 1] = 0;

		return str::astr(str);
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


	template<typename TCHARACTER, bool quoted = false> class token // tokenizer, for (token t(str); t; t++) if (*t=="...") ...
	{
		xstr_view<TCHARACTER> str;
		xstr_view<TCHARACTER> tkn;
		TCHARACTER separator;
		bool eos;

	public:

		typedef decltype(tkn) tokentype;

		//token(const xstr<TCHARACTER>& str, TCHARACTER separator = TCHARACTER(',')) : str(str), separator(separator), eos(false) { ++(*this); }
		token(const xstr_view<TCHARACTER>& str, TCHARACTER separator = TCHARACTER(',')) : str(str), separator(separator), eos(false) { ++(*this); }
		token() : eos(true) {}

		TCHARACTER sep() const { return separator; }

		operator bool() const { return !eos; }

		const xstr_view<TCHARACTER>& tail() const { return str; }

		const xstr_view<TCHARACTER>& operator* () const { return  tkn; }
		const xstr_view<TCHARACTER>* operator->() const { return &tkn; }

		token& begin() { return *this; }
		token end() { return token(); }
		bool operator!=(const token& t) { return eos != t.eos; }

		void operator++()
		{
			if (str.empty())
			{
				eos = true;
				tkn = str.substr(0, 0);
				return;
			}
			const TCHARACTER* begin = str.data();
			bool q = false;
			for (; !str.empty(); str = str.substr(1))
			{
				if (quoted)
				{
					if (str[0] == '\"')
						q = !q;
				}

				if (!q && str[0] == separator)
				{
					tkn = xstr_view<TCHARACTER>(begin, (signed_t)(str.data() - begin));
					str = str.substr(1);
					return;
				}
			}
			tkn = xstr_view<TCHARACTER>(begin, (signed_t)(str.data() - begin));
		}
		void operator++(int) { ++(*this); }
	};

}







#define BUILD_ASTRVIEW(x,y) str::astr_view(x,y)
#define BUILD_WSTRVIEW(x,y) str::wstr_view(L##x,y)

#if defined _MSC_VER
#define BUILD_WSTRVIEW(x,y) str::wstr_view(L##x,y)
#define CONST_STR_BUILD( tc, s ) _const_str_build<tc>::get( s, L##s, sizeof(s)-1 )
#define WIDE2(s) L##s
#elif defined __GNUC__
#define WSPTR_MACRO(x,y) str::wstr_view(u##x,y)
#define CONST_STR_BUILD( tc, s ) _const_str_build<tc>::get( s, u##s, sizeof(s)-1 )
#define WIDE2(s) u##s
#endif


template<typename T> struct _const_str_build
{
};
template<> struct _const_str_build<char>
{
	static str::astr_view get(const char* sa, const wchar*, signed_t len) { return str::astr_view(sa, len); }
};
template<> struct _const_str_build<wchar>
{
	static str::wstr_view get(const char*, const wchar* sw, signed_t len) { return str::wstr_view(sw, len); }
};


#define ASTR( s ) BUILD_ASTRVIEW( s, sizeof(s)-1 )
#define WSTR( s ) BUILD_WSTRVIEW( s, sizeof(s)-1 )


namespace str
{
	const char* printable(const str::astr& name, str::astr_view disabled_chars = ASTR("{}[]`\"\'\\/?&"));
}