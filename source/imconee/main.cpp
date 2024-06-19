#include "pch.h"

#ifdef _WIN32
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "Ws2_32.lib")

#define SERVICENAME WSTR("imconee")
static SERVICE_STATUS_HANDLE hSrv = nullptr;
static std::wstring path_config;

static BOOL WINAPI consoleHandler(DWORD signal)
{
	if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT)
	{
		LOG_N("Stop machine");
		engine::stop();
	}
	return TRUE;
}

#endif

static void shapka()
{
	Print("Imconee v0.0\n");

	//([]()->bool { Print(FOREGROUND_RED, "%s\n", "zzz"); return false; })();
}


int run_engine(bool as_service)
{
	engine e(std::move(path_config));

#ifdef _WIN32
	if (as_service)
	{
		lg.mute();
	} else
	{
		if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
			LOG_E("Could not set control handler");
			return EXIT_FAIL_CTLHANDLE;
		}
	}
#endif

	for (;;)
	{
		signed_t ms = e.working();
		if (ms < 0)
			break;

		Sleep((DWORD)ms);
	}

	return e.exit_code;

}

#ifdef _WIN32

#include <shellapi.h>

static int elevate(const std::vector<std::wstring>& parar)
{
	LOG_N("Elevating...");

	std::wstring exe = get_exec_full_name();

	std::wstring prms;
	for (signed_t i = 1, cnt = parar.size(); i < cnt; ++i)
	{
		if (!prms.empty())
			prms.push_back(' ');
		if (parar[i].find(' ') != std::wstring::npos)
		{
			prms.push_back('\"');
			prms.append(parar[i]);
			prms.push_back('\"');
		}
		else
			prms.append(parar[i]);
	}


	std::wstring path = get_path(exe);

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
		LOG_N("Elevation successful. Exit lower process.");
		return EXIT_OK_EXIT;
	}

	LOG_E("Elevation failed. Exit lower process.");
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
	return SetServiceStatus(hSrv, &srvStatus);
}


static void __stdcall CommandHandler(DWORD dwCommand)
{
	switch (dwCommand)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		SetStatus(SERVICE_STOP_PENDING, 0, 1);
		engine::stop();
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
	std::wstring sn(SERVICENAME);
	hSrv = RegisterServiceCtrlHandlerW(sn.c_str(), (LPHANDLER_FUNCTION)CommandHandler);
	if (hSrv == nullptr) return;

	LOG_N("Pending start");
	SetStatus(SERVICE_START_PENDING, 0, 1);
	LOG_N("Start");
	SetStatus(SERVICE_RUNNING, 0, 0);
	int ecode = run_engine(true);
	SetStatus(SERVICE_STOPPED, ecode, 0);
}

#endif

static int error_openservice()
{
	LOG_E("Failed to open service");
	return EXIT_FAIL_OPENSERVICE;
}

static int error_openmgr()
{
	LOG_E("Failed to open Service Manager");
	return EXIT_FAIL_OPENMGR;
}

static int error_startservice()
{
	LOG_E("Failed to start service");
	return EXIT_FAIL_STARTSERVICE;

}

static int handle_command_line()
{
	commandline cmdl;

	if (cmdl.help())
		return EXIT_OK_EXIT;

	path_config = cmdl.path_config();

	std::wstring sn(SERVICENAME);

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

		std::wstring dn(WSTR("Imconee service"));
		std::wstring snas(WSTR("\"")); snas.append(get_exec_full_name()); snas.append(WSTR("\" service"));

		sch = CreateServiceW(sch, sn.c_str(), dn.c_str(), GENERIC_EXECUTE, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, snas.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
		if (!sch)
		{
			LOG_E("Failed to create service");
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
			LOG_N("Stoping...");
			ControlService(sch, SERVICE_CONTROL_STOP, &ss);
		}

		if (!DeleteService(sch)) {
			LOG_E("Failed to delete service");
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


	return EXIT_OK;
}


int main()
{
	set_start_path();
	shapka();

	int ercode = handle_command_line();
	if (ercode > 0)
		return ercode;

	if (ercode < 0)
		return EXIT_OK;

	return run_engine(false);
}
