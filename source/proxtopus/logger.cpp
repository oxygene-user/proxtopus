#include "pch.h"


#if LOGGER==2

void logger::dstr(const char* msg)
{
    FILE* f = fopen(glb.cfg.debug_log_file.c_str(), "ab");
    if (f)
    {
		size_t cur = (size_t)ftell(f);

        fseek(f, 0, SEEK_END);
		size_t len = (size_t)ftell(f);
		if (len > 1024 * 128) // moar 1 mb
		{
			fclose(f);
			f = fopen(glb.cfg.debug_log_file.c_str(), "w");
		}
		else
		{
			fseek(f, 0, (int)cur);
		}

        time_t curtime;
        time(&curtime);
        const tm& t = *localtime(&curtime);
        fprintf(f, "[%u] (%i-%02i-%02i %02i:%02i:%02i) : %s\r\n", spinlock::tid_self(), t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, msg);
        fclose(f);
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

void logger::mute()
{
	glb.log_muted = true;
}


void logger::newline(int sev, const str::astr& s)
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

	switch (sev)
	{
	case SEV_WARNING:
        if (glb.log_muted)
            return;
		Print(FOREGROUND_RED | FOREGROUND_GREEN, "warning: %s\n", s.c_str());
		break;
    case SEV_IMPORTANT:
        if (glb.log_muted)
            return;
		Print(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY, "beep: %s\n", s.c_str());
		break;
	case SEV_ERROR:
		Print(FOREGROUND_RED | FOREGROUND_INTENSITY, "error: %s\n", s.c_str());
		break;
	case SEV_DEBUG:
		Print("%s %s\n", tid(), s.c_str());
		break;
	default:
        if (glb.log_muted)
            return;
		Print("note: %s\n", s.c_str());
		break;
	}
}

#endif