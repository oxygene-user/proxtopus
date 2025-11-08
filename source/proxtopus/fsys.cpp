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

inline bool __starts_with_slash(const FNview& path)
{
    if (path.length() == 0)
        return false;
    return __is_slash(path[0]);
}


inline bool __ends_with_slash(const FNview& path)
{
	return path.size() > 0 && __is_slash(path[path.size() - 1]);
}

bool __append_slash_if_not(FNc *path, size_t len) // unsafe! be sure buf has enough space
{
	if (len == 0 || !__is_slash(path[len - 1]))
	{
		path[len] = NATIVE_SLASH;
		path[len+1] = 0;
		return true;
	}
	return false;
}
void __append_slash_if_not(FN &path)
{
	if (!__ends_with_slash(path))
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
			if (__append_slash_if_not(buf, len))
				++len;
			path.insert(0, buf, len);
		}
		else
		{
			size_t len = GetFullPathNameW(disk.c_str(), MAX_PATH_LENGTH - 8, buf, nullptr);
			buf[len] = 0;
            if (__append_slash_if_not(buf, len))
                ++len;
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
					ASSERT(prev_slash < SIGNED%path.length());
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

				if (prev_slash < SIGNED % path.length() && (c != ENEMY_SLASH || path[prev_slash] == ENEMY_SLASH))
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
				if (prev_prev_slash < SIGNED % path.length() && (c != ENEMY_SLASH || path[prev_prev_slash] == ENEMY_SLASH))
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

void get_exec_full_commandline(FNARR& args)
{
#ifdef _WIN32
    FNc* cmdlb = GetCommandLineW();
    str::qsplit(args, FNview(cmdlb));
#else

	FN fn(MAKEFN("/proc/"));
	str::append_num(fn, getpid(), 0);
	fn.append(MAKEFN("/cmdline"));

    auto fd = open(fn.c_str(), O_RDONLY);
	if (fd == -1)
		return;

	char cmdline[4096];
	ssize_t bytes_read = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);
    if (bytes_read > 0)
    {
        auto cmdlm = FNview(cmdline, bytes_read);
        while(cmdlm.data()[cmdlm.size()-1] == '\0')
            cmdlm = cmdlm.substr(0, cmdlm.size()-1);
        str::qsplit(args, cmdlm, '\0');
    }
#endif

}

void  set_start_path(FN& wd, FN* exename)
{
	wd = get_exec_full_name();

	size_t idx = wd.find_last_of(MAKEFN("/\\"));
	if (idx == wd.npos)
	{
		//while(true) spinlock::sleep(0);
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

void path_simplify(FN& path, bool make_full)
{
	str::replace_all<FNc>(path, ENEMY_SLASH, NATIVE_SLASH);
	__remove_crap(path);
	if (make_full)
		__build_full_path(path);
}

bool is_path_exists(const FNview& path)
{
#ifdef _WIN32
    WIN32_FIND_DATAW find_data;
	FN p(path);

    if (__ends_with_slash(p)) p.resize(p.length()-1);
    if (p.length() == 2 && p[p.length() - 1] == ':')
    {
		p.push_back(NATIVE_SLASH);
        UINT r = GetDriveTypeW(p.c_str());
        return (r != DRIVE_NO_ROOT_DIR);
    }

    HANDLE fh = FindFirstFileW(p.c_str(), &find_data);
    if (fh == INVALID_HANDLE_VALUE) return false;
    FindClose(fh);

    return (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#endif // _WIN32
#ifdef _NIX
    struct stat st = {};
	FN p(path);
    return 0 == stat(p.c_str(), &st) && (st.st_mode & S_IFDIR) != 0;
#endif //_NIX
}

bool is_file_exists(const FN& fname)
{
#ifdef _WIN32

	DWORD a = GetFileAttributesW(fname.c_str());
	if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY) != 0)
		return false;
	return true;

#endif // _WIN32
#ifdef _NIX
    struct stat st = {};
    return 0 == stat(fname.c_str(), &st) && (st.st_mode & S_IFREG) != 0;
#endif //_NIX

}

/*
FN path_fix(const FN& path)
{
	if (path.size() >= 2 && path[0] == '.' && path[1] == NATIVE_SLASH)
	{
		// replace '.' with path of exe file
		return path_concat(get_start_path(), FNview(path).substr(2));
	}
	return path;
}
*/

FN path_concat(const FNview &path, const FNview &fn)
{
	FN c(path);
	__append_slash_if_not(c);
	c.append(__starts_with_slash(fn) ? fn.substr(1) : fn);
	return c;
}

FN path_concat(const FNview& path1, const FNview& path2, const FNview& fn)
{
    FN c(path1);
    __append_slash_if_not(c);
    c.append(__starts_with_slash(path2) ? path2.substr(1) : path2);
    __append_slash_if_not(c);
	c.append(__starts_with_slash(fn) ? fn.substr(1) : fn);
    return c;
}

void path_append(FN& path, const FNview& fn)
{
    __append_slash_if_not(path);
	path.append(__starts_with_slash(fn) ? fn.substr(1) : fn);
}

str::astr path_print_str(const FN& path)
{
	str::astr p = str::to_utf8(path);
	#ifdef _WIN32
	for (signed_t i = p.length() - 1; i >= 0; --i)
	{
		if (__is_slash(p[i]))
			p.insert(p.begin() + i, NATIVE_SLASH);
	}
	#endif
	return p;
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
	size_t fnl = GetFileSize(h, nullptr);
	b.resize(fnl, true);
	DWORD r;
	ReadFile(h, b.data(), static_cast<DWORD>(fnl), &r, nullptr);

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

file_appender::file_appender(const FN& fn)
{
#ifdef _WIN32
	handler = CreateFileW(fn.c_str(), FILE_APPEND_DATA | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (INVALID_HANDLE_VALUE == handler)
	{
		handler = nullptr;
		return;
	}
	SetFilePointer(handler, 0, nullptr, FILE_END);
#endif
#ifdef _NIX
    int fd = open(fn.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0666) + 1;
	if (fd == 0)
	{
		handler = nullptr;
		return;
	}
	handler = reinterpret_cast<void*>(fd);
#endif
}

file_appender& file_appender::operator<<(const str::astr_view& s)
{
#ifdef _WIN32
	if (handler)
	{
        DWORD w;
        WriteFile(handler, s.data(), static_cast<DWORD>(s.length()), &w, nullptr);
	}
#endif
#ifdef _NIX
	int fd = reinterpret_cast<ptrdiff_t>(handler) - 1;
    write(fd, s.data(), s.size());
#endif

	return *this;
}

file_appender::~file_appender()
{
#ifdef _WIN32
	if (handler)
		CloseHandle(handler);
#endif
#ifdef _NIX
    int fd = reinterpret_cast<ptrdiff_t>(handler) - 1;
    close(fd);
#endif
}

