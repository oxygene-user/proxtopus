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

#ifdef ANDROID
void android_prepare_env();
void android_release_env();
void android_log(global_data::print_line &s);
#endif

void Print()
{
	std::vector<global_data::print_line> cp;
	cp = std::move(glb.prints.lock_write()());

#ifdef ANDROID
    if (cp.size() > 0)
        android_prepare_env();
#endif

    static volatile size_t lock = 0;
	spinlock::simple_lock(lock);

	for(auto &s : cp)
	{
#if FEATURE_FILELOG
        if (!glb.cfg.log_file.empty())
            logger::log2file(glb.cfg.log_file, s.view());
#endif

#if LOGGER==2 && !defined(ANDROID)
        if (glb.log_muted)
			continue;
#endif
#ifdef ANDROID
        android_log(s);
#endif

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

    spinlock::simple_unlock(lock);

#ifdef ANDROID
    if (cp.size() > 0)
        android_release_env();
#endif

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
	size_t unique_id()
	{
		static size_t idpool = 0;
		return spinlock::atomic_increment(idpool);
	}

    double calculate_entropy(std::span<const u8> data)
    {
        if (data.empty())
            return 0.0;

        std::array<size_t, 256> frequency = {};

        for (u8 byte : data)
            ++frequency[byte];

        double entropy = 0.0;
        const double inv_data_size = 1.0 / static_cast<double>(data.size());

        for (size_t count : frequency) {
            if (count > 0) {
                double probability = static_cast<double>(count) * inv_data_size;
                entropy += probability * std::log2(probability);
            }
        }

        return std::max(-entropy, 0.0) * 100 / log2(static_cast<double>(data.size()));
    }

}

namespace str
{

#if defined(_NIX) && !defined(ANDROID)
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

    // UCS-2 → UTF-8
    size_t ucs2_to_utf8(const wchar *in, size_t in_len, char *out, size_t out_len) {
        size_t i = 0, j = 0;
        while (i < in_len && j < out_len) {
            uint16_t ch = in[i++];
            if (ch < 0x80) {
                out[j++] = tools::as_byte(ch);
            } else if (ch < 0x800) {
                if (j + 1 >= out_len) break;
                out[j++] = tools::as_byte(0xC0 | (ch >> 6));
                out[j++] = tools::as_byte(0x80 | (ch & 0x3F));
            } else {
                if (j + 2 >= out_len) break;
                out[j++] = tools::as_byte(0xE0 | (ch >> 12));
                out[j++] = tools::as_byte(0x80 | ((ch >> 6) & 0x3F));
                out[j++] = tools::as_byte(0x80 | (ch & 0x3F));
            }
        }
        if (j < out_len) out[j] = '\0';
        return j; // number of bytes of UTF-8
    }
    size_t ucs2_to_ansi(const wchar *in, size_t in_len, char *out, size_t out_len) {
        size_t i = 0, j = 0;
        while (i < in_len && j < out_len) {
            uint16_t ch = in[i++];
            if (ch < 0x80) {
                out[j++] = tools::as_byte(ch);
            } else {
                out[j++] = '_';
            }
        }
        if (j < out_len) out[j] = '\0';
        return j; // number of bytes
    }

	size_t  _text_from_ucs2(char* out, size_t maxlen, const str::wstr_view &from, codepage_e cp)
	{
		if ((maxlen == 0) || (from.length() == 0)) return 0;

#ifdef ANDROID
        if (codepage_e::UTF8 == cp)
        {
            size_t l = ucs2_to_utf8(from.data(), from.size(), out, maxlen);
            out[l] = 0;
            return l;
        }

        size_t l = ucs2_to_ansi(from.data(), from.size(), out, maxlen);
        out[l] = 0;
        return l;
#else
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
#endif

	}

    // UTF-8 → UCS-2
    size_t utf8_to_ucs2(const char *in, size_t in_len, wchar *out, size_t out_len) {
        size_t i = 0, j = 0;
        while (i < in_len && j < out_len) {
            u8 c = in[i];
            if (c < 0x80) {
                if (c == 0)
                    break;
                out[j++] = c;
                ++i;
            } else if ((c & 0xE0) == 0xC0) {
                if (i+1 < in_len) {
                    out[j++] = ((c & 0x1F) << 6) | (in[i + 1] & 0x3F);
                    i += 2;
                }
            } else if ((c & 0xF0) == 0xE0) {
                if (i + 3 < in_len) {
                    out[j++] = ((c & 0x0F) << 12) | ((in[i + 1] & 0x3F) << 6) | (in[i + 2] & 0x3F);
                    i += 3;
                }
            } else if ((c & 0xF8) == 0xF0) {
                if (i + 4 < in_len ||
                    (in[1] & 0xC0) != 0x80 ||
                    (in[2] & 0xC0) != 0x80 ||
                    (in[3] & 0xC0) != 0x80) {
                    out[j++] = 0xFFFDu;
                    ++i;
                    continue;
                }
                out[j++] = '_';
                i += 4;
            }
        }
        return j; // number of UCS-2 chars
    }

	size_t   _text_to_ucs2(wchar * out, size_t maxlen, const str::astr_view& from, codepage_e cp)
	{
		if ((maxlen == 0) || (from.length() == 0)) return 0;

#ifdef ANDROID
        size_t l = utf8_to_ucs2(from.data(), from.length(), out, maxlen);
        out[l] = 0;
        return l;
#else
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
#endif
	}

}


bool messagebox(const char* /*s1*/, const char* /*s2*/, int /*options*/)
{
    // TODO : show message box for main thread

    return true;
}


