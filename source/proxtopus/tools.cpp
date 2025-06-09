#include "pch.h"
#ifdef _NIX
#include <iconv.h>
#include <iostream>
#endif

namespace spinlock
{
	size_t current_thread_uid()
	{
		static size_t counter = 0;
		static thread_local size_t tid = atomic_increment(counter);
		return tid;
	}
}

namespace
{
	class tools_init
	{
	public:
		tools_init()
		{
			// TODO : init tools here
		}
		~tools_init()
		{
		}
	};

	static tools_init ti;

	struct console_buffer
	{
#ifdef _WIN32
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
		void restore_attr()
		{
			set_attr(restorea);
		}
#endif
#ifdef _NIX

		const str::astr_view get_textcolor_code(const int textcolor) {
			switch (textcolor) {
			case  0: return str::astr_view("\033[30m"); // color_black      0
			case  1: return str::astr_view("\033[34m"); // color_dark_blue  1
			case  2: return str::astr_view("\033[32m"); // color_dark_green 2
			case  3: return str::astr_view("\033[36m"); // color_light_blue 3
			case  4: return str::astr_view("\033[31m"); // color_dark_red   4
			case  5: return str::astr_view("\033[35m"); // color_magenta    5
			case  6: return str::astr_view("\033[33m"); // color_orange     6
			case  7: return str::astr_view("\033[37m"); // color_light_gray 7
			case  8: return str::astr_view("\033[90m"); // color_gray       8
			case  9: return str::astr_view("\033[94m"); // color_blue       9
			case 10: return str::astr_view("\033[92m"); // color_green     10
			case 11: return str::astr_view("\033[96m"); // color_cyan      11
			case 12: return str::astr_view("\033[91m"); // color_red       12
			case 13: return str::astr_view("\033[95m"); // color_pink      13
			case 14: return str::astr_view("\033[93m"); // color_yellow    14
			case 15: return str::astr_view("\033[97m"); // color_white     15
			default: return str::astr_view("\033[37m");
			}
		}

		WORD current = FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE;
		console_buffer()
		{
		    std::cout << get_textcolor_code(current);
		}
		WORD get_attr()
		{
			return current;
		}

		void write(const char* s, signed_t sl)
		{
			std::cout << std::string_view(s, sl);
		}

		void set_text_color(signed_t c)
		{
			current = tools::as_word((c | (current & 0xF0)));
			std::cout << get_textcolor_code(current&0xf);
		}
		void set_attr(WORD c)
		{
			current = c;
			std::cout << get_textcolor_code(current & 0xf); // todo background
		}
		void restore_attr()
		{
			std::cout << "\033[0m";
		}
#endif

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
			restore_attr();
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
	bool prev_esc = false;
	for (signed_t i = 0; i < sl; ++i)
	{
		char c = s[i];
		if (c != '\\' && !prev_esc)
		{
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
		prev_esc = c == '\\';
		if (prev_esc)
		{
			if (p < i)
			{
				cb->write(s + p, i - p);
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

/*
void GetPrint(printfunc pf)
{
	glb.prints.lock_read([&](const std::vector<global_data::print_line>& cp) {
        for (auto &s : cp)
        {
            pf(s.data, s.data_len);
        }
	});

}
*/

void Print()
{
	std::vector<global_data::print_line> cp;
	cp = std::move(glb.prints.lock_write()());
	
	static volatile size_t lock = 0;
	spinlock::auto_simple_lock slock(lock);

	for(auto &s : cp)
	{
        if (!glb.cfg.log_file.empty())
            logger::log2file(glb.cfg.log_file, s.view());

		if (glb.log_muted)
			continue;

#ifdef _WIN32
        if (s.oem_convert)
        {
            s.oem_convert = false;
            CharToOemBuffA(s.data, s.data, tools::as_dword(s.data_len));
        }
#endif

		if (s.use_color)
		{
			set_console_color cc(s.color);
			cprintf(&cc, s.data, s.data_len);
		}
		else
		{
			set_console_color cc(FOREGROUND_WHITE);
            cprintf(&cc, s.data, s.data_len);
		}
	}

}

void Print(signed_t color, const std::string_view& stroke)
{
#ifdef _WIN32
    bool oem_convert = false;
	for(auto c : stroke)
		if (c > 127)
		{
			oem_convert = true;
			break;
		}
#endif

	auto wr = glb.prints.lock_write();
	auto &ln = wr().emplace_back(stroke.data(), stroke.length());
	ln.use_color = true;
	ln.color = tools::as_word(color);
#ifdef _WIN32
	ln.oem_convert = oem_convert;
#endif

}

void Print(const std::string_view& stroke)
{
	glb.prints.lock_write()().emplace_back(stroke.data(), stroke.length());
}

void Println(const char* s, signed_t slen)
{
	glb.prints.lock_write()().emplace_back(s, slen, true);
}

void Print(const buffer &txt)
{
	enum_tokens_a(t, txt, '\n')
	{
		Println( t->data(), t->size() );
	}
}

namespace tools
{

}

namespace str
{

#ifdef _NIX
	struct inconv_stuff_s
	{
		iconv_t ucs2_to_ansi = (iconv_t)-1;
		iconv_t ansi_to_ucs2 = (iconv_t)-1;
		iconv_t utf8_to_ucs2 = (iconv_t)-1;
		iconv_t ucs2_to_utf8 = (iconv_t)-1;
		//iconv_t utf8_to_ansi = (iconv_t)-1;
		//iconv_t ansi_to_utf8 = (iconv_t)-1;

		~inconv_stuff_s()
		{
			if (ucs2_to_ansi != (iconv_t)-1)
				iconv_close(ucs2_to_ansi);
			if (ansi_to_ucs2 != (iconv_t)-1)
				iconv_close(ansi_to_ucs2);
			if (utf8_to_ucs2 != (iconv_t)-1)
				iconv_close(utf8_to_ucs2);
			if (ucs2_to_utf8 != (iconv_t)-1)
				iconv_close(ucs2_to_utf8);
			//if (utf8_to_ansi != (iconv_t)-1)
				//iconv_close(utf8_to_ucs2);
			//if (ansi_to_utf8 != (iconv_t)-1)
				//iconv_close(ucs2_to_utf8);

		}

	} iconvs;

#endif

	size_t  _text_from_ucs2(char* out, size_t maxlen, const str::wstr_view &from, codepage_e cp)
	{
		if ((maxlen == 0) || (from.length() == 0)) return 0;

#ifdef _WIN32
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
#endif
#ifdef _NIX
		iconv_t func = (iconv_t) - 1;
		switch (cp)
		{
		case codepage_e::OEM:
			if (iconvs.ucs2_to_ansi <= (iconv_t)-1)
				iconvs.ucs2_to_ansi = iconv_open("cp1251//IGNORE", "UCS-2");
			func = iconvs.ucs2_to_ansi;
			break;
		case codepage_e::UTF8:
			if (iconvs.ucs2_to_utf8 <= (iconv_t)-1)
				iconvs.ucs2_to_utf8 = iconv_open("UTF-8//IGNORE", "UCS-2");
			func = iconvs.ucs2_to_utf8;
			break;
		}

		if (func != (iconv_t)-1)
		{
			size_t isz = from.length() * sizeof(wchar);
			size_t osz = maxlen;
			char* f = (char*)from.data();
			iconv(func, &f, &isz, &out, &osz);
			if (isz == 0)
				return maxlen - osz;
		}
		return 0;

#endif

	}

	size_t   _text_to_ucs2(wchar * out, size_t maxlen, const str::astr_view& from, codepage_e cp)
	{
		if ((maxlen == 0) || (from.length() == 0)) return 0;

#ifdef _WIN32
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
#endif
#ifdef _NIX
		iconv_t func = (iconv_t)-1;
		switch (cp)
		{
		case codepage_e::OEM:
			if (iconvs.ansi_to_ucs2 <= (iconv_t)-1)
				iconvs.ansi_to_ucs2 = iconv_open("UCS-2//IGNORE", "cp1251");
			func = iconvs.ansi_to_ucs2;
			break;
		case codepage_e::UTF8:
			if (iconvs.utf8_to_ucs2 <= (iconv_t)-1)
				iconvs.utf8_to_ucs2 = iconv_open("UCS-2//IGNORE", "UTF-8");
			func = iconvs.utf8_to_ucs2;
			break;
		}

		if (func != (iconv_t)-1)
		{
			size_t isz = from.length();
			size_t osz = maxlen * sizeof(wchar);
			char* f = (char*)from.data();
			char* o = (char*)out;
			iconv(func, &f, &isz, &o, &osz);
			if (isz == 0)
				return maxlen - osz / sizeof(wchar);
		}
		return 0;
#endif
	}

}


bool messagebox(const char* /*s1*/, const char* /*s2*/, int /*options*/)
{
    // TODO : show message box for main thread

    return true;
}


namespace stats
{
	tick_collector::tick_collector(str::astr_view tag):tag(tag)
	{
		DL(DLCH_THREADS, "start collector $", tag);
	}
    tick_collector::~tick_collector()
    {
        DL(DLCH_THREADS, "stop collector $", tag);
    }

	void tick_collector::collect()
	{
		if (0 == (glb.cfg.debug_log_mask & (1ull << DLCH_THREADS)))
			return;

		signed_t ct = chrono::ms();
		if (start_ms == 0)
		{
			start_ms = ct;
			return;
		}

		signed_t dt = (ct - start_ms);
		start_ms = ct;
		if (collect_start_ms == 0)
			collect_start_ms = ct;

		if (dt > 65535)
			dt = 65535;

		u16 dt16 = (u16)dt;
		if (mss.empty())
		{
			mss.push_back(std::pair(dt16, (u16)1));
		}
		else
		{
			if (mss[mss.size() - 1].first == dt16)
				++mss[mss.size() - 1].second;
			else
				mss.push_back(std::pair(dt16, (u16)1));
		}

		if ((ct - collect_start_ms) > 5000)
		{
			collect_start_ms = ct;

			str::astr mssc;
			for (auto& x : mss)
			{
				if (!mssc.empty())
					mssc.push_back(',');
				str::append_num(mssc, x.first, 0);
				if (x.second > 1)
				{
					mssc.push_back('(');
					str::append_num(mssc, x.second, 0);
					mssc.push_back(')');
				}
			}
			mss.clear();
			DL(DLCH_THREADS, "collected for $ : $", tag, mssc);
		}
	}
}
