#include "pch.h"

#ifdef _WIN32
#define NATIVE_SLASH '\\'
#define NATIVE_SLASH_S "\\"
#define ENEMY_SLASH '/'
#endif
#ifdef _NIX
#define NATIVE_SLASH '/'
#define NATIVE_SLASH_S "/"
#define ENEMY_SLASH '\\'

#pragma GCC diagnostic ignored "-Wunused-result"
#endif

inline bool __is_slash(const FNc c)
{
	return c == NATIVE_SLASH || c == ENEMY_SLASH;
}

inline bool __ending_slash(const FNview& path)
{
	return path.size() > 0 && __is_slash(path[path.size() - 1]);
}

void __append_slash_if_not(FNc *path, size_t len) // unsafe! be sure buf has enough space
{
	if (len == 0 || !__is_slash(path[len - 1]))
	{
		path[len] = NATIVE_SLASH;
		path[len+1] = 0;
	}
}
void __append_slash_if_not(FN &path)
{
	if (!__ending_slash(path))
		path.push_back(NATIVE_SLASH);
}


void  __build_full_path(FN& path)
{
#ifdef _WIN32
	FN disk;

	if (path.length() > 1 && (path[1] == ':'))
	{
		disk = path.substr(0, 2);
		path.erase(0, 2);
	}

	if (!__is_slash(path[0]))
	{
		FNc buf[MAX_PATH_LENGTH];
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
		FNc wd[MAX_PATH_LENGTH];
		if (const FNc* d = getcwd(wd, sizeof(wd) - 1))
		{
			FN dd(d);
			__append_slash_if_not(dd);
			path.insert(0, dd);
		}
	}
#endif //_NIX
}

void __remove_crap(FN& path)
{
	signed_t prev_prev_slash = str::get_last_char(path) == '.' ? path.length() : -1;
	signed_t prev_slash = prev_prev_slash;
	signed_t cch = path.length() - 1;
	signed_t to = -1;
	signed_t doubledot = 0;
	if (str::starts_with(path, MAKEFN("\\\\"))) to = path.find_first_of(MAKEFN("/\\"), 2); // UNC path
	for (; cch >= to; --cch)
	{
		FNc c = cch >= 0 ? path[cch] : NATIVE_SLASH;
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


FN  get_exec_full_name()
{
	FN wd;
#ifdef _WIN32
	wd.resize(MAX_PATH_LENGTH - 8);
	size_t len = GetModuleFileNameW(nullptr, wd.data(), MAX_PATH_LENGTH - 8);
	wd.resize(len);
#endif // _WIN32
#ifdef _NIX
	FNc tmp[PATH_MAX];
	int len = readlink("/proc/self/exe", tmp, PATH_MAX - 1);
	if (len == -1) { FN(); }
	wd = FNview(tmp, len);
#endif //_NIX

	if (wd[0] == '\"')
	{
		signed_t s = wd.find('\"', 1);
		wd.resize(s);
		wd.erase(0, 1);
	}

	str::replace_all<FNc>(wd, ENEMY_SLASH, NATIVE_SLASH);
	__remove_crap(wd);

	return wd;
}

void  set_start_path(FN& wd, FN* exename)
{
	wd = get_exec_full_name();

	size_t idx = wd.find_last_of(MAKEFN("/\\"));
	if (idx == wd.npos)
	{
		//while(true) Sleep(0);
		DEBUGBREAK(); // OPA!
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
	chdir(wd.c_str());
#endif //_NIX
}


FN get_start_path()
{
	FN p = get_exec_full_name();
	signed_t z = p.find_last_of(MAKEFN("\\/"));
	p.resize(z);
	return p;
}

FN get_path(const FN& full_file_path)
{
	FN p(full_file_path);
	size_t z = p.find_last_of(MAKEFN("\\/"));
	if (z == FN::npos)
		return FN();
	p.resize(z);
	return p;
}

FN get_name(const FN& full_file_path)
{
	size_t z = full_file_path.find_last_of(MAKEFN("\\/"));
	if (z == FN::npos)
		return full_file_path;
	return full_file_path.substr(z+1);
}

void path_simplify(FN& path)
{
	str::replace_all<FNc>(path, ENEMY_SLASH, NATIVE_SLASH);
	__remove_crap(path);
	__build_full_path(path);
}

FN path_fix(const FN& path)
{
	if (path.size() >= 2 && path[0] == '.' && path[1] == '\\')
	{
		// replace '.' with path of exe file
		return path_concat(get_start_path(), FNview(path).substr(2));
	}
	return path;
}

FN path_concat(const FNview &path, const FNview &fn)
{
	FN c(path);
	if (c.length() > 0 && c[c.length() - 1] != '\\')
		c.push_back('\\');
	c.append(fn);
	return c;
}

void path_append(FN& path, const FNview& fn)
{
	if (path.length() > 0 && path[path.length() - 1] != '\\')
		path.push_back('\\');
	path.append(fn);
}

bool load_buf(const FN& fn, buffer& b)
{
#ifdef _WIN32
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
#endif
#ifdef _NIX
	int mode = O_RDONLY;
	int h = open(fn.c_str(), mode);
	if (h < 0)
	{
		b.clear();
		return false;
	}

	struct stat s;
	if (fstat(h, &s) < 0)
	{
		b.clear();
		return false;
	}
	signed_t fnl = s.st_size;
	b.resize(s.st_size);
	int r = ::read(h, b.data(), s.st_size);
	close(h);
#endif

	if (r != fnl)
	{
		b.clear();
		return false;
	}
	return true;
}

void save_buf(const FN& fn, const str::astr& b)
{
#ifdef _WIN32
	HANDLE h = CreateFileW(fn.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (INVALID_HANDLE_VALUE == h)
		return;
	DWORD w;
	WriteFile(h, b.data(), (int)b.length(), &w, nullptr);
	CloseHandle(h);
#endif

#ifdef _NIX
	int h = open(fn.c_str(), O_TRUNC | O_CREAT | O_RDWR, 0666);
	if (h < 0)
		return;
	write(h, b.data(), b.size());
	close(h);
#endif

}
