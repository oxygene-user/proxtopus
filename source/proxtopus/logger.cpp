#include "pch.h"


#if LOGGER==2

void logger::log2file(const FN &logfn, const str::astr_view& msg)
{
	if (file_appender apndr(logfn); apndr)
	{
        time_t curtime;
        time(&curtime);
        const tm& t = *localtime(&curtime);

        str::astr sout;
        str::impl_build_string(sout, "$-$-$ $:$:$ : $", t.tm_year + 1900, dec<2, int>(t.tm_mon + 1), dec<2, int>(t.tm_mday), dec<2, int>(t.tm_hour), dec<2, int>(t.tm_min), (t.tm_sec), crlf(msg));
		apndr << sout;
	}

}

#include <codecvt>

/*
logger &logger::operator<<(const std::string& s)
{
	char pc = length() > 0 ? (*this)[length() - 1] : ' ';
	if (pc != ' ' && pc != '[' && s.length() > 0 && s[0] != ',' && s[0] != ' ' && s[0] != ']')
		this->push_back(' ');
	this->append(s);

	return *this;
}

logger& logger::operator<<(const char* s)
{
	char pc = length() > 0 ? (*this)[length() - 1] : ' ';
	if (pc != ' ' && pc != '[' && s[0] != ',' && s[0] != ' ' && s[0] != ']')
		this->push_back(' ');
	this->append(s);
	return *this;
}
logger& logger::operator<<(signed_t x)
{
	*this << std::to_string(x).c_str();
	return *this;
}
*/

void logger::unmute()
{
	glb.log_muted = false;
}

void logger::mute()
{
    glb.log_muted = true;
}

void logger::newline(int sev, const str::astr_view& s)
{
	auto tid = []() -> const char*
		{
			static thread_local std::array<char, 8> tids;
			if (tids[0] == 0)
			{
				tids[0] = '[';
				tids[5] = ']';
				std::span<char> t(tids.data()+1, 0);
				str::append_hex<std::span<char>, u16, false>(t, tools::as_word(spinlock::tid_self()));
			}
			return tids.data();
		};

    str::astr sout;
	switch (sev)
	{
	case SEV_WARNING:
		if (!glb.log_muted || !glb.cfg.log_file.empty())
		{
			str::impl_build_string(sout, "warning: $\n", s);
			Print(FOREGROUND_RED | FOREGROUND_GREEN, str::view(sout));
		}
		break;
    case SEV_IMPORTANT:
		if (!glb.log_muted || !glb.cfg.log_file.empty())
		{
			str::impl_build_string(sout, "beep: $\n", s);
			Print(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY, str::view(sout));
		}
		break;
	case SEV_ERROR:
        
		if (!glb.log_muted || !glb.cfg.log_file.empty())
        {
            if (s[s.length() - 1] == '^')
                str::impl_build_string(sout, "error: $\b; see help for more information\n", s);
            else
                str::impl_build_string(sout, "error: $\n", s);
            Print(FOREGROUND_RED | FOREGROUND_INTENSITY, str::view(sout));
		}
		break;
	case SEV_DEBUG:
		str::impl_build_string(sout, "$ $\n", tid(), s);
		Print(str::view(sout));
		break;
	default:
		if (!glb.log_muted || !glb.cfg.log_file.empty())
		{
			str::impl_build_string(sout, "note: $\n", s);
			Print(str::view(sout));
		}
		break;
	}
}

void debug_print(str::astr_view s)
{
	logger::newline(SEV_DEBUG, s);
}

#endif