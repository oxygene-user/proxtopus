#include "pch.h"

namespace
{
	class tools_init
	{
	public:
		RWLOCK lockp = 0;
		std::unique_ptr<std::map<std::string, std::string>> printables;
		tools_init()
		{
		}
		~tools_init()
		{
			spinlock::auto_lock_write alw(lockp);
			printables.reset(nullptr);
		}
	};

	static tools_init ti;


	struct console_buffer
	{
		HANDLE hout;
		WORD restorea = 0;
		console_buffer()
		{
			hout = GetStdHandle(STD_OUTPUT_HANDLE);
			restorea = get_attr();
		}
		WORD get_attr()
		{
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			GetConsoleScreenBufferInfo(hout, &csbi);
			return csbi.wAttributes;
		}

		void write(const char* s, signed_t sl)
		{
			DWORD x;
			WriteConsoleA(hout, s, tools::as_dword(sl), &x, nullptr);
		}

		void set_text_color(signed_t c)
		{
			SetConsoleTextAttribute(hout, tools::as_word((c | (restorea & 0xF0))));
		}
		void set_attr(WORD c)
		{
			SetConsoleTextAttribute(hout, c);
		}

	};


	class set_console_color : public console_buffer
	{

	public:
		set_console_color(signed_t color)
		{
			set_text_color(color);
		}
		~set_console_color()
		{
			set_attr(restorea);
		}
	};

	struct cpair
	{
		WORD color;
		char left, right;
	};

}


static void cprintf(console_buffer *cb, const char* s, signed_t sl)
{
	int curca = -1;

	cpair cols[] = {
		{ FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY, '{', '}'},
		{ FOREGROUND_GREEN | FOREGROUND_INTENSITY, '\"', '\"' }
	};

	signed_t p = 0;
	for (signed_t i = 0; i < sl; ++i)
	{
		char c = s[i];

		for (const cpair& cp : cols)
		{
			if (c == cp.left)
			{
				if (curca < 0)
					curca = cb->get_attr();

				if (p < i)
				{
					cb->write(s + p, i - p);
				}
				++i;
				signed_t j = i;
				for (; i < sl && s[i] != cp.right; ++i);
				cb->set_text_color(cp.color);
				cb->write(s + j, i - j);
				cb->set_attr(curca & 0xffff);
				p = i + 1;
				i = p;
			}
		}
	}
	if (p < sl)
	{
		cb->write(s + p, sl - p);
	}
}

void Print(signed_t color, const char* format, ...)
{
	set_console_color cc(color);
	char buf[2048];
	va_list arglist;
	va_start(arglist, format);
	signed_t sl = vsprintf_s(buf, sizeof(buf), format, arglist);
	CharToOemBuffA(buf, buf, tools::as_dword(sl));
	cprintf(&cc, buf, sl);
}

void Print(const char* format, ...)
{
	va_list arglist;
	char buf[2048];
	va_start(arglist, format);
	signed_t sl = vsprintf_s(buf, sizeof(buf), format, arglist);
	CharToOemBuffA(buf, buf, tools::as_dword(sl));
	console_buffer cb;
	cprintf(&cb, buf, sl);
}

namespace tools
{

}

namespace str
{
	const char* printable(const std::string& s, std::string_view disabled_chars)
	{
		for(char c : s)
			if (disabled_chars.find(c) != disabled_chars.npos)
			{
				{
					spinlock::auto_lock_read alr(ti.lockp);
					if (ti.printables)
					{
						auto it = ti.printables->find(s);
						if (it != ti.printables->end())
							return it->second.c_str();
					}
				}

				std::string corrs;
				for (char cc : s)
					if (disabled_chars.find(cc) != disabled_chars.npos)
						corrs.push_back('?');
					else
						corrs.push_back(cc);

				spinlock::auto_lock_write alr(ti.lockp);
				if (!ti.printables)
					ti.printables = std::make_unique<std::map<std::string, std::string>>();
				(*ti.printables)[s] = corrs;
				return (*ti.printables)[s].c_str();
			}
		return s.c_str();
	}

	size_t  _text_from_ucs2(char* out, size_t maxlen, const std::wstring_view &from, codepage_e cp)
	{
		if ((maxlen == 0) || (from.length() == 0)) return 0;

		UINT CodePage = CP_ACP;
		switch (cp)
		{
		case codepage_e::OEM:
			CodePage = CP_OEMCP;
			break;
		case codepage_e::UTF8:
			CodePage = CP_UTF8;
			break;
		}

		signed_t l = WideCharToMultiByte(CodePage, WC_COMPOSITECHECK | WC_DEFAULTCHAR, from.data(), (int)from.length(), out, (int)maxlen, nullptr, nullptr);
		out[l] = 0;
		return l;
	}

	size_t   _text_to_ucs2(wchar_t * out, size_t maxlen, const std::string_view& from, codepage_e cp)
	{
		if ((maxlen == 0) || (from.length() == 0)) return 0;

		UINT CodePage = CP_ACP;
		switch (cp)
		{
		case codepage_e::OEM:
			CodePage = CP_OEMCP;
			break;
		case codepage_e::UTF8:
			CodePage = CP_UTF8;
			break;
		}

		signed_t res = MultiByteToWideChar(CodePage, 0, from.data(), (int)from.length(), out, (int)maxlen);
		if (res == 0)
		{
			//DWORD err = GetLastError();
			//const char *err_txt = "unknown error";
			//if (err == ERROR_INSUFFICIENT_BUFFER) err_txt = "ERROR_INSUFFICIENT_BUFFER";
			//else if (err == ERROR_INVALID_FLAGS) err_txt = "ERROR_INVALID_FLAGS";
			//else if (err == ERROR_INVALID_PARAMETER) err_txt = "ERROR_INVALID_PARAMETER";
			//else if (err == ERROR_NO_UNICODE_TRANSLATION) err_txt = "ERROR_NO_UNICODE_TRANSLATION";

			//printf(err_txt);
		}
		else
		{
			out[res] = 0;
		}
		return res;
	}

}


bool messagebox(const char* /*s1*/, const char* /*s2*/, int /*options*/)
{
    // TODO : show message box for main thread

    return true;
}

