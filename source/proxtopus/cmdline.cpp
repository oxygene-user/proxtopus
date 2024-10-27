#include "pch.h"

commandline::commandline(NIXONLY(std::vector<FN>&& mas)) NIXONLY(:parar_(std::move(mas)))
{
#ifdef _WIN32
	FNc* cmdlb = GetCommandLineW();
	str::qsplit(parar_, FNview(cmdlb));
#endif
}

#ifdef _WIN32

str::astr read_reg(const wchar *n)
{
	HKEY k;
	if (RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", &k) != ERROR_SUCCESS)
		return str::astr();

	DWORD lt = REG_SZ;
	DWORD sz;
	int rz = RegQueryValueExW(k, n, 0, &lt, nullptr, &sz);
	if (rz != ERROR_SUCCESS)
	{
		RegCloseKey(k);
		return str::astr();
	}
	if (sz > 0)
	{
		str::wstr s;
		s.resize(sz / sizeof(wchar) - 1);
		RegQueryValueExW(k, n, 0, &lt, (LPBYTE)s.data(), &sz);
		RegCloseKey(k);
		return str::to_utf8(s);
	}
	RegCloseKey(k);
	return str::astr();
}

#endif

#ifdef _NIX
extern char _binary_res_help_txt_start;
extern char _binary_res_help_txt_end;
extern char _binary_res_help_listener_txt_start;
extern char _binary_res_help_listener_txt_end;
extern char _binary_res_help_nix_txt_start;
extern char _binary_res_help_nix_txt_end;
#include <sys/utsname.h>
#include <sys/wait.h>

#pragma GCC diagnostic ignored "-Wunused-result"

str::astr get_system_output(const char* cmd)
{
    char buff[32];
    str::astr str;

    int fd[2];
    int old_fd[3];
    pipe(fd);


    old_fd[0] = dup(STDIN_FILENO);
    old_fd[1] = dup(STDOUT_FILENO);
    old_fd[2] = dup(STDERR_FILENO);

    int pid = fork();
    switch(pid){
        case 0:
            close(fd[0]);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            dup2(fd[1], STDOUT_FILENO);
            dup2(fd[1], STDERR_FILENO);
            system(cmd);
            close (fd[1]);
            exit(0);
            break;
        case -1:
            exit(1);
        default:
            close(fd[1]);
            dup2(fd[0], STDIN_FILENO);

            int rc = 1;
            while (rc > 0){
                rc = read(fd[0], buff, sizeof(buff));
                str.append(buff, rc);
            }

            waitpid(pid, NULL, 0);
            close(fd[0]);
    }

    dup2(STDIN_FILENO, old_fd[0]);
    dup2(STDOUT_FILENO, old_fd[1]);
    dup2(STDERR_FILENO, old_fd[2]);

    return str;
}

#endif

str::astr lazy_os_desc()
{
#ifdef _WIN32
	str::astr product = read_reg(L"ProductName");

	product.push_back(' ');
	product.append(read_reg(L"ReleaseId"));
	product.append(ASTR(" v"));
	product.append(read_reg(L"CurrentVersion"));
	product.append(ASTR(" build "));
	product.append(read_reg(L"CurrentBuild"));

#endif

#ifdef _NIX
    auto product = get_system_output("lsb_release -dsc");
    str::replace_one(product, ASTR("\n"), ASTR(" ("));
    str::replace_one(product, ASTR("\n"), ASTR(") "));


    utsname n = {};
    uname(&n);

	product.append(n.release);
	product.push_back(' ');
	product.append(n.version);
	product.push_back(' ');
	product.append(n.machine);
#endif
	return product;
}

str::astr lazy_exe()
{
	return str::to_utf8(get_name(get_exec_full_name()));
	
}

void rpl(std::vector<char>& file, const str::astr_view& var, std::function<str::astr()> lazyrepl)
{
	str::astr lrs;
	for (;;)
	{
		str::astr_view fv(file.data(), file.size());
		size_t x = fv.find(var);
		if (x == fv.npos)
			return;
		if (lrs.empty())
			lrs = lazyrepl();
		file.erase(file.begin() + x, file.begin() + x + var.length());
		file.insert(file.begin() + x, lrs.begin(), lrs.end());
	}
}

std::vector<char> load_res(int idr)
{
	std::vector<char> file;

#ifdef _WIN32
	HMODULE me = GetModuleHandleW(nullptr);
	HRSRC hRes = FindResourceW(me, MAKEINTRESOURCE(idr), L"HELP");
	HGLOBAL resh = LoadResource(me, hRes);
	void * data = LockResource(resh);
	signed_t datasize = SizeofResource(me, hRes);
	std::span<const char> d((const char*)data, datasize);
	file.insert(file.begin(), d.begin(), d.end());
	FreeResource(resh);
#endif

#ifdef _NIX
    switch(idr)
    {
        case IDR_HELP:
        {
            std::span<const char> data(&_binary_res_help_txt_start, &_binary_res_help_txt_end-&_binary_res_help_txt_start);
            file.insert(file.begin(), data.begin(), data.end());
        }
        break;
        case IDR_HELP_LISTENER:
        {
            std::span<const char> data(&_binary_res_help_listener_txt_start, &_binary_res_help_listener_txt_end-&_binary_res_help_listener_txt_start);
            file.insert(file.begin(), data.begin(), data.end());
        }
        break;
		case IDR_HELP_HANDLER:
		{
			std::span<const char> data(&_binary_res_help_handler_txt_start, &_binary_res_help_handler_txt_end - &_binary_res_help_handler_txt_start);
			file.insert(file.begin(), data.begin(), data.end());
		}
		break;
        case IDR_HELP_PROXY:
        {
            std::span<const char> data(&_binary_res_help_proxy_txt_start, &_binary_res_help_proxy_txt_end - &_binary_res_help_proxy_txt_start);
            file.insert(file.begin(), data.begin(), data.end());
        }
        break;
		case IDR_HELP_PLATFORM:
        {
            std::span<const char> data(&_binary_res_help_nix_txt_start, &_binary_res_help_nix_txt_end-&_binary_res_help_nix_txt_start);
            file.insert(file.begin(), data.begin(), data.end());
        }
        break;
    }
#endif

	if (idr == IDR_HELP)
	{
		std::vector<char> h2part = load_res(IDR_HELP_PLATFORM);
		file.insert(file.end(), h2part.begin(), h2part.end());
		rpl(file, ASTR("$(OS_DESC)"), lazy_os_desc);
	}

	rpl(file, ASTR("$(EXE)"), lazy_exe);

	return file;
}

bool commandline::help() const
{
	if (parar_.size() > 1 ? parar_[1] == MAKEFN("help") : false)
	{
		if (parar_.size() == 2)
		{
			Print(load_res(IDR_HELP));
			return true;
		}

		if (parar_.size() == 3)
		{
			if (parar_[2] == MAKEFN("listener"))
			{
				Print(load_res(IDR_HELP_LISTENER));
				return true;
			}
			if (parar_[2] == MAKEFN("handler"))
			{
				Print(load_res(IDR_HELP_HANDLER));
				return true;
			}
            if (parar_[2] == MAKEFN("proxy"))
            {
                Print(load_res(IDR_HELP_PROXY));
                return true;
            }

		}


		Print("We are very sorry, but this help is under construction.\n");

		return true;
	}
	return false;
}

FN commandline::path_config() const
{
	if (signed_t ci = tools::find(parar_, MAKEFN("conf")); ci > 0 && (size_t)(ci + 1) < parar_.size())
	{
		FN pc(parar_[ci+1]);
		path_simplify(pc);
		return pc;
	}

	FN cp = parar_[0];
	signed_t i = cp.find_last_of(MAKEFN("\\/"));
	cp.resize(i + 1);
	cp.append(MAKEFN("config.txt"));
	return cp;
}


