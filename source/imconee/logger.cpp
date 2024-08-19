#include "pch.h"

#if LOGGER==2
#include <codecvt>

logger lg;

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

void logger::newline(int sev, const std::string& s)
{
	if (muted)
		return;

	SIMPLELOCK(lock);

	switch (sev)
	{
	case SEV_WARNING:
		Print(FOREGROUND_RED | FOREGROUND_GREEN, "warning: %s\n", s.c_str());
		break;
    case SEV_IMPORTANT:
		Print(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY, "beep: %s\n", s.c_str());
		break;
	case SEV_ERROR:
		Print(FOREGROUND_RED | FOREGROUND_INTENSITY, "error: %s\n", s.c_str());
		break;
	default:
		Print("note: %s\n", s.c_str());
		break;
	}
}

#endif