#include "pch.h"

#define MAX_PATH_LENGTH 4096

#ifdef _WIN32
#define NATIVE_SLASH '\\'
#define NATIVE_SLASH_S "\\"
#define ENEMY_SLASH '/'
#endif
#ifdef _NIX
#define NATIVE_SLASH '/'
#define NATIVE_SLASH_S "/"
#define ENEMY_SLASH '\\'
#endif

inline bool __is_slash(const wchar_t c)
{
	return c == NATIVE_SLASH || c == ENEMY_SLASH;
}

inline bool __ending_slash(const std::wstring_view& path)
{
	return path.size() > 0 && __is_slash(path[path.size() - 1]);
}

void __append_slash_if_not(wchar_t *path, size_t len) // unsafe! be sure buf has enough space
{
	if (len == 0 || !__is_slash(path[len - 1]))
	{
		path[len] = NATIVE_SLASH;
		path[len+1] = 0;
	}
}
void __append_slash_if_not(std::wstring &path)
{
	if (!__ending_slash(path))
		path.push_back(NATIVE_SLASH);
}


void  __build_full_path(std::wstring& path)
{
#ifdef _WIN32
	std::wstring disk;

	if (path.length() > 1 && (path[1] == ':'))
	{
		disk = path.substr(0, 2);
		path.erase(0, 2);
	}

	if (!__is_slash(path[0]))
	{
		wchar_t buf[MAX_PATH_LENGTH];
		if (disk.empty())
		{
			size_t len = GetCurrentDirectoryW(MAX_PATH_LENGTH - 8, buf);
			buf[len] = 0;
			__append_slash_if_not(buf, len);
			path.insert(0, buf, len);
		}
		else
		{
			size_t len = GetFullPathNameW(disk.c_str(), MAX_PATH_LENGTH - 8, buf, nullptr);
			buf[len] = 0;
			__append_slash_if_not(buf, len);
			path.insert(0, buf, len);
		}
	}
	else
		path.insert(0, disk);
#endif // _WIN32
#ifdef _NIX
	if (!__is_slash(path[0]))
	{
		char wd[MAX_PATH_LENGTH];
		if (const char* d = getcwd(wd, sizeof(wd) - 1))
		{
			std::wstring dd = str::from_utf8(d);
			__append_slash_if_not(dd);
			path.insert(0, dd);
		}
	}
#endif //_NIX
}

void __remove_crap(std::wstring& path)
{
	signed_t prev_prev_slash = str::get_last_char(path) == '.' ? path.length() : -1;
	signed_t prev_slash = prev_prev_slash;
	signed_t cch = path.length() - 1;
	signed_t to = -1;
	signed_t doubledot = 0;
	if (str::starts_with(path, WSTR("\\\\"))) to = path.find_first_of(WSTR("/\\"), 2); // UNC path
	for (; cch >= to; --cch)
	{
		wchar_t c = cch >= 0 ? path[cch] : NATIVE_SLASH;
		if (__is_slash(c))
		{
			if (prev_slash - 1 == cch)
			{
				if (cch < 0) break;

				// remove double slash
				if (c != ENEMY_SLASH || path[prev_slash] == ENEMY_SLASH)
				{
					ASSERT(prev_slash < (signed_t)path.length());
					path.erase(prev_slash, 1);
				}
				else
					path.erase(cch, 1);
				--prev_prev_slash;
				prev_slash = cch;
				continue;
			}
			if (prev_slash - 2 == cch && path[cch + 1] == '.')
			{
				// remove /./

				if (prev_slash < (signed_t)path.length() && (c != ENEMY_SLASH || path[prev_slash] == ENEMY_SLASH))
					path.erase(prev_slash - 1, 2);
				else
					path.erase(cch, 2);
				prev_prev_slash -= 2;
				prev_slash = cch;
				continue;
			}
			if (prev_prev_slash - 3 == prev_slash && prev_slash > cch && path[prev_prev_slash - 1] == '.' && path[prev_prev_slash - 2] == '.')
			{
				// remove /subfolder/..

				if (prev_slash - 3 == cch && path[prev_slash - 1] == '.' && path[prev_slash - 2] == '.')
				{
					++doubledot;
					prev_prev_slash = prev_slash;
					prev_slash = cch;
					continue;
				}

				signed_t n = prev_prev_slash - cch;
				if (prev_prev_slash < (signed_t)path.length() && (c != ENEMY_SLASH || path[prev_prev_slash] == ENEMY_SLASH))
					path.erase(cch + 1, n);
				else
					path.erase(cch, n);
				prev_prev_slash = cch;
				prev_slash = cch;
				if (doubledot)
				{
					--doubledot;
					prev_prev_slash += 3; // "/../"
					ASSERT(__is_slash(path[prev_prev_slash]) && path[prev_prev_slash - 1] == '.' && path[prev_prev_slash - 2] == '.');
				}
				continue;
			}

			prev_prev_slash = prev_slash;
			prev_slash = cch;
		}

	}
}


std::wstring  get_exec_full_name()
{
	std::wstring wd;
#ifdef _WIN32
	wd.resize(MAX_PATH_LENGTH - 8);
	size_t len = GetModuleFileNameW(nullptr, wd.data(), MAX_PATH_LENGTH - 8);
	wd.resize(len);
#endif // _WIN32
#ifdef _NIX
	char tmp[PATH_MAX];
	int len = readlink("/proc/self/exe", tmp, PATH_MAX - 1);
	if (len == -1) { std::wstring(); }
	wd = str::from_utf8(std::string_view(tmp, len));
#endif //_NIX

	if (wd[0] == '\"')
	{
		signed_t s = wd.find('\"', 1);
		wd.resize(s);
		wd.erase(0, 1);
	}

	str::replace_all<wchar_t>(wd, ENEMY_SLASH, NATIVE_SLASH);
	__remove_crap(wd);

	return wd;
}

void  set_start_path(std::wstring& wd, std::wstring* exename)
{
	wd = get_exec_full_name();

	signed_t idx = wd.find_last_of(WSTR("/\\"));
	if (idx == wd.npos)
	{
		//while(true) Sleep(0);
		DEBUG_BREAK(); // OPA!
	}
	if (nullptr != exename)
	{
		exename->assign(wd.c_str() + idx + 1);
	}

	wd.resize(idx + 1);

#ifdef _WIN32
	SetCurrentDirectoryW(wd.c_str());
#endif // _WIN32
#ifdef _NIX
	chdir(str::to_utf8(wd));
#endif //_NIX
}


std::wstring get_start_path()
{
	wchar_t buf[MAX_PATH_LENGTH];
	signed_t len = GetModuleFileNameW(nullptr, buf, sizeof(buf)-1);

	std::wstring p(buf, len);
	signed_t z = p.find_last_of(WSTR("\\/"));
	p.resize(z);
	return p;
}

std::wstring get_path(const std::wstring& full_file_path)
{
	std::wstring p(full_file_path);
	signed_t z = p.find_last_of(WSTR("\\/"));
	if (z == std::wstring::npos)
		return std::wstring();
	p.resize(z);
	return p;
}

void path_simplify(std::wstring& path)
{
	str::replace_all<wchar_t>(path, ENEMY_SLASH, NATIVE_SLASH);
	__remove_crap(path);
	__build_full_path(path);
}

std::wstring path_fix(const std::wstring& path)
{
	if (path.size() >= 2 && path[0] == '.' && path[1] == '\\')
	{
		// replace '.' with path of exe file
		return path_concat(get_start_path(), std::wstring_view(path).substr(2));
	}
	return path;
}

std::wstring path_concat(const std::wstring_view &path, const std::wstring_view &fn)
{
	std::wstring c(path);
	if (c[c.length() - 1] != '\\')
		c.push_back('\\');
	c.append(fn);
	return c;
}

bool load_buf(const std::wstring& fn, std::vector<u8>& b)
{
	HANDLE h = CreateFileW(fn.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (INVALID_HANDLE_VALUE == h)
	{
		b.clear();
		return false;
	}
	signed_t fnl = GetFileSize(h, nullptr);
	b.resize(fnl);
	DWORD r;
	ReadFile(h, b.data(), (DWORD)fnl, &r, nullptr);
	CloseHandle(h);
	if (r != fnl)
	{
		b.clear();
		return false;
	}
	return true;
}

void save_buf(const std::wstring& fn, const std::string& b)
{
	HANDLE h = CreateFileW(fn.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (INVALID_HANDLE_VALUE == h)
		return;
	DWORD w;
	WriteFile(h, b.data(), (int)b.length(), &w, nullptr);
	CloseHandle(h);
}
