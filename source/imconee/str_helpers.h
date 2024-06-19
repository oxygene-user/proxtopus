#pragma once



namespace str
{

	template <typename TCH> TCH get_last_char(const std::basic_string<TCH>& s)
	{
		size_t l = s.length();
		if (l > 0)
			return s[l - 1];
		return 0;
	}
	template <typename TCH> TCH get_last_char(const std::basic_string_view<TCH>& s)
	{
		size_t l = s.length();
		if (l > 0)
			return s[l - 1];
		return 0;
	}

	template <typename TCH> TCH starts_with(const std::basic_string_view<TCH>& s, const std::basic_string_view<TCH>& ss)
	{
		if (s.length() < ss.length())
			return false;
		return s.substr(0, ss.length()) == ss;
	}
	template <typename TCH> TCH starts_with(const std::basic_string<TCH>& s, const std::basic_string_view<TCH>& ss)
	{
		if (s.length() < ss.length())
			return false;
		return std::basic_string_view<TCH>(s).substr(0, ss.length()) == ss;
	}

	template <typename TCH> void trunc_len(std::basic_string<TCH>& s, size_t numchars = 1)
	{
		size_t l = s.length();
		if (l >= numchars)
			s.resize(l - numchars);
	}

	template <typename TCH> std::basic_string<TCH>& replace_all(std::basic_string<TCH>& s, const std::basic_string_view<TCH>& s1, const std::basic_string_view<TCH>& s2)
	{
		for (size_t f = 0;;)
		{
			f = s.find(s1, f);
			if (f == s.npos)
				break;

			s.replace(f, s.size(), s2);
			f += s2.size();
		}
		return s;
	}

	template <typename TCH> std::basic_string<TCH>& replace_all(std::basic_string<TCH>& s, TCH c1, TCH c2)
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

	template<typename CC> INLINE void ltrim(std::basic_string<CC>& s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](CC ch) {
			return !is_space(ch);
		}));
	}

	template<typename CC> INLINE std::basic_string_view<CC> ltrim(std::basic_string_view<CC> s) {
		signed_t i = 0;
		for (signed_t c = s.length(); i < c && is_space(s[i]); ++i);
		--i;
		if (i >= 0)
			return std::basic_string_view(s.data() + i, s.length() - i);
		return s;
	}

	// trim from end (in place)
	template<typename CC> INLINE void rtrim(std::basic_string<CC>& s) {
		//s.erase(std::find_if(s.rbegin(), s.rend(), [](CC ch) {
			//return !is_space(ch);
		//}).base(), s.end());

		signed_t i = s.length() - 1;
		for (; i >= 0 && is_space(s[i]); --i);
		++i;
		if ((size_t)i < s.length())
			s.resize(i);
	}

	template<typename CC> INLINE std::basic_string_view<CC> rtrim(std::basic_string_view<CC> s) {

		signed_t i = s.length() - 1;
		for (; i >= 0 && is_space(s[i]); --i);
		++i;
		if ((size_t)i < s.length())
			return std::basic_string_view(s.data(), i);
		return s;
	}


	// trim from both ends (in place)
	template<typename CC> INLINE void trim(std::basic_string<CC>& s) {
		rtrim(s);
		ltrim(s);
	}

	template<typename CC> INLINE std::basic_string_view<CC> trim(std::basic_string_view<CC> s) {
		return ltrim(rtrim(s));
	}


	inline std::string build_string(const char* s, ...)
	{
		char str[1024];

		va_list args;
		va_start(args, s);
		vsnprintf(str, sizeof(str), s, args);
		va_end(args);
		str[sizeof(str) - 1] = 0;
		return std::string(str);
	}

	inline std::string build_string_d(const char* fn, int ln, const char* s, ...)
	{
		char str[1024];

		int t = sprintf_s(str, sizeof(str), "%s(%i): ", fn, ln);

		va_list args;
		va_start(args, s);
		vsnprintf(str + t, sizeof(str) - t, s, args);
		va_end(args);

		str[sizeof(str) - 1] = 0;

		return std::string(str);
	}

	inline std::string build_string_d(const char* fn, int ln)
	{
		return build_string_d(fn, ln, "---");
	}


	enum class codepage_e
	{
		ANSI,
		OEM,
		UTF8,
	};

	size_t  _text_from_ucs2(char* out, size_t maxlen, const std::wstring_view& from, codepage_e cp);
	size_t  _text_to_ucs2(wchar_t* out, size_t maxlen, const std::string_view& from, codepage_e cp);

	inline std::string to_str(const std::wstring_view& s, codepage_e cp)
	{
		std::string   sout; sout.reserve(s.length());

		_text_from_ucs2(sout.data(), sout.capacity(), s, cp);
		return sout;
	}

	inline std::string to_str(const std::wstring_view& s)
	{
		return to_str(s, codepage_e::ANSI);
	}

	inline std::string to_utf8(const std::wstring_view& s)
	{
		std::string  sout; sout.reserve(s.length() * 3); // hint: char at utf8 can be 6 bytes length, but ucs2 maximum code is 0xffff encoding to utf8 has 3 bytes len
		size_t nl = _text_from_ucs2(sout.data(), sout.capacity(), s, codepage_e::UTF8);
		sout.resize(nl);
		return sout;
	}

	inline std::wstring from_utf8(const std::string_view& s)
	{
		std::wstring   sout; sout.reserve(s.length());
		size_t nl = _text_to_ucs2(sout.data(), sout.capacity(), s, codepage_e::UTF8);
		sout.resize(nl);
		return sout;
	}

	template <typename TCH> void qsplit(std::vector<std::basic_string<TCH>>& splar, const std::basic_string_view<TCH>& str)
	{
		splar.clear();
		if (str.length() == 0)  return;
		int i = 0;
		int bg = -1;
		bool quote = false;
		for (signed_t l = str.length(); l > 0; ++i, --l)
		{
			wchar_t ch = str[i];
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
		std::basic_string_view<TCHARACTER> str;
		std::basic_string_view<TCHARACTER> tkn;
		TCHARACTER separator;
		bool eos;

	public:

		typedef decltype(tkn) tokentype;

		//token(const std::basic_string<TCHARACTER>& str, TCHARACTER separator = TCHARACTER(',')) : str(str), separator(separator), eos(false) { ++(*this); }
		token(const std::basic_string_view<TCHARACTER>& str, TCHARACTER separator = TCHARACTER(',')) : str(str), separator(separator), eos(false) { ++(*this); }
		token() : eos(true) {}

		TCHARACTER sep() const { return separator; }

		operator bool() const { return !eos; }

		const std::basic_string_view<TCHARACTER>& tail() const { return str; }

		const std::basic_string_view<TCHARACTER>& operator* () const { return  tkn; }
		const std::basic_string_view<TCHARACTER>* operator->() const { return &tkn; }

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
					tkn = std::basic_string_view<TCHARACTER>(begin, (signed_t)(str.data() - begin));
					str = str.substr(1);
					return;
				}
			}
			tkn = std::basic_string_view<TCHARACTER>(begin, (signed_t)(str.data() - begin));
		}
		void operator++(int) { ++(*this); }
	};

}







#define BUILD_ASTRVIEW(x,y) std::string_view(x,y)

#if defined _MSC_VER
#define BUILD_WSTRVIEW(x,y) std::wstring_view(L##x,y)
#define CONST_STR_BUILD( tc, s ) _const_str_build<tc>::get( s, L##s, sizeof(s)-1 )
#define WIDE2(s) L##s
#elif defined __GNUC__
#define WSPTR_MACRO(x,y) std::wstring_view(u##x,y)
#define CONST_STR_BUILD( tc, s ) _const_str_build<tc>::get( s, u##s, sizeof(s)-1 )
#define WIDE2(s) u##s
#endif


template<typename T> struct _const_str_build
{
};
template<> struct _const_str_build<char>
{
	static std::string_view get(const char* sa, const wchar_t*, signed_t len) { return std::string_view(sa, len); }
};
template<> struct _const_str_build<wchar_t>
{
	static std::wstring_view get(const char*, const wchar_t* sw, signed_t len) { return std::wstring_view(sw, len); }
};


#define ASTR( s ) BUILD_ASTRVIEW( s, sizeof(s)-1 )
#define WSTR( s ) BUILD_WSTRVIEW( s, sizeof(s)-1 )


namespace str
{
	const char* printable(const std::string& name, std::string_view disabled_chars = ASTR("{}[]`\"\'\\/?&"));
}