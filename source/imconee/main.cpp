#include "pch.h"

global_data glb;

#ifdef _WIN32

#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "Ws2_32.lib")

#define SERVICENAME WSTR("imconee")

#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
void set_unhandled_exception_filter();
#endif

static BOOL WINAPI consoleHandler(DWORD signal)
{
	if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT)
	{
		LOG_I("imconeee has been received stop signal");
		glb.stop();
	}
	return TRUE;
}
#endif
#ifdef _NIX
#include <signal.h>
#include <termios.h>

static void handle_signal(int sig) {
    switch(sig)
    {
        case SIGINT:
        case SIGTERM:
		LOG_I("imconeee has been received stop signal");
		engine::stop();

        struct termios t;
        tcgetattr(STDIN_FILENO,&t);
        t.c_lflag |= ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);

        break;
    }
}
#endif // _NIX

static void shapka()
{

#ifdef _NIX
    struct termios t;
    tcgetattr(STDIN_FILENO,&t);
    t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
#endif


	Print("Imconee v0.4 (build " __DATE__ " " __TIME__ ")\n");
	Print();
}

#ifdef _DEBUG
void dns_test();
void fifo_test();
#endif // _DEBUG

int run_engine(bool as_service)
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

#ifdef _DEBUG
	dns_test();
	fifo_test();
#endif

	for (;;)
	{
		signed_t ms = e.working();
		if (ms < 0)
			break;
		Print();
		Sleep((int)ms);
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
#endif

static int handle_command_line(NIXONLY(std::vector<FN> &&args))
{
	commandline cmdl NIXONLY((std::move(args)));

	if (cmdl.help())
		return EXIT_OK_EXIT;

	glb.path_config = cmdl.path_config();

#ifdef _WIN32
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

		str::wstr dn(WSTR("Imconee service"));
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

	return EXIT_OK;
}

#ifdef _NIX
std::vector<FN> makepa(int argc, char* argv[])
{
	std::vector<FN> pa;
	for (int i = 0; i < argc; ++i)
		pa.push_back(argv[i]);
	return pa;
}
#endif

int main(NIXONLY(int argc, char* argv[]))
{
#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
	set_unhandled_exception_filter();
#endif

	set_start_path();
	shapka();

	int ercode = handle_command_line(NIXONLY(std::move(makepa(argc, argv))));
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

	return run_engine(false);
}
