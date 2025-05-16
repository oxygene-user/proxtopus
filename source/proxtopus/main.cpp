#include "pch.h"

global_data glb;


global_data::global_data()
{
#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
    cfg.crash_log_file = FN(MAKEFN("proxtopus.crush.log"));
    cfg.dump_file = FN(MAKEFN("proxtopus.dmp"));
#endif
}

void global_data::stop()
{
    logger::unmute();
    Print();
    exit = true;
    if (!actual)
        actual_proc.terminate();
}

#ifdef _WIN32

#ifdef MEMSPY
#include "../debug/memspy.h"
#endif


#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "Ws2_32.lib")

#define SERVICENAME WSTR("proxtopus")

#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
void set_unhandled_exception_filter();
#endif

static BOOL WINAPI consoleHandler(DWORD signal)
{
	if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT)
	{
		if (!glb.is_stop())
		{
			logger::unmute();
			LOG_I("proxtopus has been received stop signal");
			glb.stop();
		}
	}
	return TRUE;
}

void actual_process::terminate()
{
	SetEvent(evt);
}
void actual_process::actualize()
{
    str::wstr evn(str::wstr_view(PROXTOPUS_EVT, strsize(PROXTOPUS_EVT)));
    str::append_hex(evn, glb.ppid);

    evt = OpenEvent(
        EVENT_MODIFY_STATE | SYNCHRONIZE,  // desired access
        FALSE,                             // inherit handle
		evn.c_str()
    );
	if (nullptr != evt)
	{
        std::thread th([this]() {

			// wait parent process or close event

			HANDLE pproc[2] = { OpenProcess(SYNCHRONIZE, FALSE, tools::as_dword(glb.ppid)), evt };
            DWORD dwWaitResult = WaitForMultipleObjects(2, pproc+0, FALSE, INFINITE);

            switch (dwWaitResult) {
            case WAIT_OBJECT_0:
			case WAIT_OBJECT_0+1:
				glb.stop();
                break;
			default:;
            }
			CloseHandle(evt);
			CloseHandle(pproc);
			evt = nullptr;
        });
        th.detach();
	}
}

#endif
#ifdef _NIX
#include <signal.h>
#include <termios.h>

#ifdef _DEBUG
#endif

static void handle_signal(int sig) {
    switch(sig)
    {
        case SIGINT:
        case SIGTERM:
        logger::unmute();
		LOG_I("proxtopus has been received stop signal");
		glb.stop();

        struct termios t;
        tcgetattr(STDIN_FILENO,&t);
        t.c_lflag |= ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);

        break;
    }
}

void actual_process::terminate()
{
	kill(pid, SIGTERM);
}
void actual_process::actualize()
{
	// nothing to do in Linux
}

#endif // _NIX

global_data::print_line::print_line(const char* s, signed_t sl, bool nl)
{
	data = (char *)MA(sl+(nl ? 2 : 1));
	memcpy(data, s, sl);
	if (nl)
		data[sl++] = '\n';
	data[sl] = 0;
	data_len = sl;
}

global_data::print_line::~print_line()
{
	ma::mf(data);
}

#ifdef DO_SPEED_TESTS
void do_perf_tests();
#endif
#ifdef _DEBUG
void do_tests();
void do_pretests();
#endif // _DEBUG

void shapka()
{
	auto numcores = ostools::get_cores();

	LOG_N("proxtopus v" PROXTOPUS_VER " (build " __DATE__ " " __TIME__ ")");
	LOG_N("cores count: $", numcores);
	LOG_D("debug mode");
	Print();

#ifdef DO_SPEED_TESTS
	do_perf_tests();
#endif
#if defined _DEBUG && !defined _NIX
    do_pretests();
#endif

}

int run_engine(WINONLY(bool as_service = false))
{
	engine e;

#ifdef _WIN32
	if (as_service)
	{
		logger::mute();
	} else
	{
		if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
			LOG_E("could not set control handler");
			return EXIT_FAIL_CTLHANDLE;
		}
	}
#endif
#ifdef _NIX

    struct sigaction sa = { 0 };

    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, nullptr) == -1 || sigaction(SIGTERM, &sa, nullptr) == -1) {
        LOG_E("could not set control handler");
        return EXIT_FAIL_CTLHANDLE;
    }

#endif // _NIX

#if defined _DEBUG && !defined _NIX
	do_tests();
#endif

	if (glb.actual)
	{
		// role: work process

		glb.actual_proc.actualize();

		watchdog wd;

		for (; wd();)
		{
			signed_t ms = e.working();
			if (ms < 0)
				break;
			Print();

			spinlock::sleep((int)ms);
		}
	}
	else
	{
		// role: watchdog process

		LOG_N("watchdog mode...");
		Print();

        FNARR fa;
		fa.push_back(get_exec_full_name());
        fa.push_back(FN(MAKEFN("--actual")));
        #ifdef _WIN32
        if (as_service)
            fa.push_back(FN(MAKEFN("--mute")));
        #endif
		fa.push_back(FN(MAKEFN("--ppid")));
		FN pid;
        str::append_num(pid, ostools::process_id(), 0);
        fa.push_back(pid);

		auto need_exit = [](signed_t code) -> bool
			{
				switch (code)
				{
				case EXIT_FAIL_OVERLOAD:
                case EXIT_TERMINATED: // presumably
					return false;
				default:
					break;
				}
                return code < 100; // assume that all codes over 100 are passed through the TerminateProcess function, which means that the process has been terminated
			};

		for (;!glb.is_stop();)
		{
			signed_t ec = ostools::execute(fa WINONLY(, as_service));
			if (need_exit(ec))
			{
                e.exit_code = static_cast<int>(ec);
				break;
			}
		}
	}

	return e.exit_code;

}

#ifdef _WIN32

#include <shellapi.h>

static int elevate(const std::vector<str::wstr>& parar)
{
	LOG_N("elevating...");

	FN exe = get_exec_full_name();

	str::wstr prms;
	for (signed_t i = 1, cnt = parar.size(); i < cnt; ++i)
	{
		if (!prms.empty())
			prms.push_back(' ');
		if (parar[i].find(' ') != str::wstr::npos)
		{
			prms.push_back('\"');
			prms.append(parar[i]);
			prms.push_back('\"');
		}
		else
			prms.append(parar[i]);
	}


	FN path = get_path(exe);

	SHELLEXECUTEINFOW shExInfo = {};
	shExInfo.cbSize = sizeof(shExInfo);
	shExInfo.fMask = 0;
	shExInfo.hwnd = 0;
	shExInfo.lpVerb = L"runas";
	shExInfo.lpFile = exe.c_str();
	shExInfo.lpParameters = prms.c_str();
	shExInfo.lpDirectory = path.c_str();
	shExInfo.nShow = SW_NORMAL;
	shExInfo.hInstApp = 0;

	if (0 != ShellExecuteExW(&shExInfo))
	{
		LOG_N("elevation successful; exit lower process");
		return EXIT_OK_EXIT;
	}

	LOG_E("elevation failed");
	return EXIT_FAIL_ELEVATION;
}

static int SetStatus(DWORD dwState, int dwExitCode, DWORD dwProgress)
{
	SERVICE_STATUS srvStatus;
	srvStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	srvStatus.dwCurrentState = dwState;
	srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	srvStatus.dwWin32ExitCode = dwExitCode > 0 ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
	srvStatus.dwServiceSpecificExitCode = dwExitCode;
	srvStatus.dwCheckPoint = dwProgress;
	srvStatus.dwWaitHint = 3000;
	return SetServiceStatus(glb.hSrv, &srvStatus);
}


static void __stdcall CommandHandler(DWORD dwCommand)
{
	switch (dwCommand)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		SetStatus(SERVICE_STOP_PENDING, 0, 1);
		glb.stop();
		break;
		/*
	case SERVICE_CONTROL_PAUSE:
		SetStatus(SERVICE_PAUSE_PENDING, 0, 1);
		//conf.paused++;
		SetStatus(SERVICE_PAUSED, 0, 0);
		break;
	case SERVICE_CONTROL_CONTINUE:
		SetStatus(SERVICE_CONTINUE_PENDING, 0, 1);
		//conf.needreload = 1;
		SetStatus(SERVICE_RUNNING, 0, 0);
		break;
		*/
	default:;
	}
}


void __stdcall ServiceMain(DWORD /*dwNumServicesArgs*/, LPWSTR* /*lpServiceArgVectors*/)
{
#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
	set_unhandled_exception_filter();
#endif

	str::wstr sn(SERVICENAME);
	glb.hSrv = RegisterServiceCtrlHandlerW(sn.c_str(), (LPHANDLER_FUNCTION)CommandHandler);
	if (glb.hSrv == nullptr) return;

	LOG_N("pending start");
	SetStatus(SERVICE_START_PENDING, 0, 1);
	LOG_N("start");
	SetStatus(SERVICE_RUNNING, 0, 0);
	int ecode = run_engine(true);
	SetStatus(SERVICE_STOPPED, ecode, 0);
}

static int error_openservice()
{
	LOG_E("failed to open service");
	return EXIT_FAIL_OPENSERVICE;
}

static int error_openmgr()
{
	LOG_E("failed to open Service Manager");
	return EXIT_FAIL_OPENMGR;
}

static int error_startservice()
{
	LOG_E("failed to start service");
	return EXIT_FAIL_STARTSERVICE;

}

void compile_oids(const FN& cppfile);
#endif

static int handle_command_line()
{
	commandline cmdl;

	cmdl.handle_options();

	shapka();

	if (cmdl.help())
		return EXIT_OK_EXIT;

	glb.path_config = cmdl.path_config();

#ifdef _WIN32

#ifdef _DEBUG
	FN cppfile;
	if (cmdl.compile_oids(cppfile))
	{
		compile_oids(cppfile);
		return EXIT_OK_EXIT;
	}
#endif

    if (auto pid = cmdl.wait())
    {
        LOG_N("waiting for process end (pid:$)", pid);
        Print();
        ostools::wait_process(pid);
        LOG_N("process ended (pid:$); continue", pid);
        Print();
    }

	str::wstr sn(SERVICENAME);

	if (cmdl.service())
	{
		SERVICE_TABLE_ENTRYW ste[] =
		{
			{ sn.data(), (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
			{ nullptr, nullptr }
		};

		if (StartServiceCtrlDispatcherW(ste))
			return error_startservice();

		return EXIT_OK_EXIT;
	}


	if (cmdl.install())
	{
		SC_HANDLE sch = OpenSCManager(nullptr, nullptr, GENERIC_WRITE | SERVICE_START);

		if (!sch) {

			if (GetLastError() == ERROR_ACCESS_DENIED)
				return elevate(cmdl.parar());

			return error_openmgr();
		}

		str::wstr dn(WSTR("proxtopus service"));
		FN snas(MAKEFN("\"")); snas.append(get_exec_full_name()); snas.append(MAKEFN("\" service"));

		sch = CreateServiceW(sch, sn.c_str(), dn.c_str(), GENERIC_EXECUTE, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, snas.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
		if (!sch)
		{
			LOG_E("failed to create service");
			return EXIT_FAIL_CREATESERVICE;
		}

		if (!StartService(sch, 0, nullptr))
			return error_startservice();

		return EXIT_OK_EXIT;
	}

	if (cmdl.remove())
	{
		SC_HANDLE sch = OpenSCManager(nullptr, nullptr, GENERIC_WRITE);
		if (!sch) {

			if (GetLastError() == ERROR_ACCESS_DENIED)
				return elevate(cmdl.parar());

			return error_openmgr();
		}

		sch = OpenServiceW(sch, sn.c_str(), DELETE | SERVICE_STOP);
		if (!sch)
			return error_openservice();

		SERVICE_STATUS ss;
		QueryServiceStatus(sch, &ss);
		if (ss.dwCurrentState != SERVICE_STOPPED)
		{
			LOG_N("stoping...");
			ControlService(sch, SERVICE_CONTROL_STOP, &ss);
		}

		if (!DeleteService(sch)) {
			LOG_E("failed to delete service");
			return EXIT_FAIL_DELETESERVICE;
		}

		return EXIT_OK_EXIT;
	}

	if (cmdl.stop())
	{
		SC_HANDLE sch = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
		if (!sch) {

			if (GetLastError() == ERROR_ACCESS_DENIED)
				return elevate(cmdl.parar());

			return error_openmgr();
		}

		sch = OpenServiceW(sch, sn.c_str(), SERVICE_STOP);
		if (!sch) {

			if (GetLastError() == ERROR_ACCESS_DENIED)
				return elevate(cmdl.parar());

			return error_openservice();
		}

		SERVICE_STATUS ss = {};
		ControlService(sch, SERVICE_CONTROL_STOP, &ss);

		return EXIT_OK_EXIT;
	}
	if (cmdl.start())
	{
		SC_HANDLE sch = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
		if (!sch) {

			if (GetLastError() == ERROR_ACCESS_DENIED)
				return elevate(cmdl.parar());

			return error_openmgr();
		}

		sch = OpenServiceW(sch, sn.c_str(), SERVICE_START);
		if (!sch) {

			if (GetLastError() == ERROR_ACCESS_DENIED)
				return elevate(cmdl.parar());


			return error_openservice();
		}

		if (!StartService(sch, 0, nullptr))
			return error_startservice();

		return EXIT_OK_EXIT;
	}
#endif

#if defined _NIX && LOGGER==2
    logger::mute(); // mute by default on nix
#endif

	cmdl.handle_options();

	return EXIT_OK;
}

int main(NIXONLY(int /*argc*/, char* argv[]))
{
    g_single_core = ostools::get_cores() == 1;

#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
	set_unhandled_exception_filter();
#endif
#ifdef _NIX
#ifdef _DEBUG
#endif

    struct on_shutdown
	{
		on_shutdown()
		{
            struct termios t;
            tcgetattr(STDIN_FILENO, &t);
            t.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &t);
		}
        ~on_shutdown()
        {
            struct termios t;
            tcgetattr(STDIN_FILENO,&t);
            t.c_lflag |= ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &t);
        };

    } onsh;
#endif // _NIX

	set_start_path();

	int ercode = handle_command_line();
	if (ercode > 0)
	{
		Print();
		return ercode;
	}

	if (ercode < 0)
	{
		Print();
		return EXIT_OK;
	}

	return run_engine();
}


#if 0
void global_data::restart()
{
	stop();

	// start FORCE SELF KILLER
	std::thread th([]() {
		spinlock::sleep(10000);
		ostools::terminate();
	});
    th.detach();

   	FNARR fa;
	get_exec_full_commandline(fa);

    auto w = MAKEFN("--wait");
    auto b = MAKEFN("--btc");
    for (signed_t i = fa.size() - 1; i >= 0; --i)
    {
        if (fa[i] == w || fa[i] == b)
        {
            fa.erase(fa.begin() + i);
            if (i < (signed_t)fa.size())
                fa.erase(fa.begin() + i);
        }
    }
    fa.push_back(FN(w));
    FN pid;
    str::append_num(pid, ostools::process_id(), 0);
    fa.push_back(pid);

    fa.push_back(FN(b));
    fa.push_back(FN(MAKEFN("5")));

	ostools::execute(fa);

}
#endif