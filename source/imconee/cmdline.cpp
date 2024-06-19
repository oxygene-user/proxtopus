#include "pch.h"

commandline::commandline()
{
	wchar_t* cmdlb = GetCommandLineW();
	str::qsplit(parar_, std::wstring_view(cmdlb));
}

bool commandline::help() const
{
	if (parar_.size() > 1 ? parar_[1] == WSTR("help") : false)
	{
		if (parar_.size() == 2)
		{
			Print("Type {imconee help <topic>} for more information.\n");
			Print(" <topic> can be:\n");
			Print("  {listener} - information about listener settings\n");
			Print("  {handler} - information about handler settings\n");
			Print("  {proxy} - information about proxy settings\n");
			return true;
		}

		Print("We are very sorry, but this help is under construction.\n");

		return true;
	}
	return false;
}

std::wstring commandline::path_config() const
{
	signed_t ci = tools::find(parar_, WSTR("conf"));

	if (ci > 0 && (size_t)(ci + 1) < parar_.size())
	{
		std::wstring pc(parar_[ci+1]);
		path_simplify(pc);
		return pc;
	}

	std::wstring cp = parar_[0];
	signed_t i = cp.find_last_of(WSTR("\\/"));
	cp.resize(i + 1);
	cp.append(WSTR("config.txt"));
	return cp;
}


