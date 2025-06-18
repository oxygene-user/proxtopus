#include "pch.h"
#include <botan/internal/os_utils.h>
#ifdef _WIN32
#include <processthreadsapi.h>
#endif
#ifdef _NIX
#include <sys/wait.h>
#include <spawn.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
bool is_debugger_present()
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1)
        return true; // under debugging: ptrace failed
    ptrace(PTRACE_DETACH, 0, NULL, 0); // no need self debugging
    return false;
}
#endif // _NIX

namespace ostools
{
    void wait_process(signed_t pid)
    {
#ifdef _WIN32
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, tools::as_dword(pid));
        if (hProcess == nullptr)
            return;
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
#else
        str::astr proc_path(ASTR("/proc/"));
        str::append_num(proc_path, pid, 0);

        auto is_process_alive = [&]() ->bool {
            return access(proc_path.c_str(), F_OK) == 0;
        };

        for (;is_process_alive();) {
            spinlock::sleep(1000);
        }
#endif
    }

    signed_t process_id()
    {
        return Botan::OS::get_process_id();
    }

    signed_t get_cores()
    {
        return Botan::OS::get_cpu_available();
    }

    void terminate()
    {
#ifdef _WIN32
        HANDLE hProcess = GetCurrentProcess();
        TerminateProcess(hProcess, 1);
        ExitProcess(1);
#else
        syscall(SYS_exit_group, 1);
        _exit(1);
        kill(getpid(), SIGKILL);
#endif
    }

    signed_t execute(const FNARR &cmdl WINONLY(, bool from_service)) // with arguments
    {
        signed_t exit_code = EXIT_OK;
#ifdef _WIN32

        if (glb.actual_proc.evt == nullptr)
        {
            str::wstr evn(str::wstr_view(PROXTOPUS_EVT, strsize(PROXTOPUS_EVT)));
            str::append_hex( evn, GetCurrentProcessId() );

            glb.actual_proc.evt = CreateEvent(
                nullptr,            // default security attributes
                FALSE,              // auto-reset event
                FALSE,              // initial state is nonsignaled
                evn.c_str()
            );
        }

        if (glb.actual_proc.evt == nullptr)
            return EXIT_FAIL_EVNT_CREATE;


        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        auto path = str::qjoin(cmdl);
        if (CreateProcessW(
            nullptr,
            path.data(),
            nullptr,
            nullptr,
            FALSE,
            from_service ? CREATE_NO_WINDOW : 0,
            nullptr,
            nullptr,
            &si,
            &pi)) {


            DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE);

            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode;
                GetExitCodeProcess(pi.hProcess, &exitCode);
                LOG_I("Child process has been terminated with code $", exitCode);
                Print();
                exit_code = exitCode;
            }
            else {

            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else
        {
            exit_code = EXIT_FAIL_CHILD_CREATE;
        }
#else
        signed_t pcnt = cmdl.size();
        const char ** argv = (const char **)alloca( sizeof(char *) * (pcnt + 1) );
        for(int i=0;i<pcnt;++i)
            argv[i] = cmdl[i].c_str();
        argv[pcnt] = nullptr;

        posix_spawn(&glb.actual_proc.pid, argv[0], nullptr, nullptr, (char * const*)argv, nullptr);


        pid_t r;
        int status = 0;
        do
        {
            r = waitpid(glb.actual_proc.pid, &status, 0);
        } while (r == -1 && errno == EINTR);

        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            LOG_I("Child process has been terminated with code $", exit_code);
        } else if (WIFSIGNALED(status)) {
            exit_code = EXIT_OK_EXIT_SIGNAL;
            int s = WTERMSIG(status);
            LOG_I("Child process has been terminated by signal $", s);
        }
        Print();

#endif
        return exit_code;
    }

    void set_current_thread_name(const str::astr_view& name)
    {
#ifdef _WIN32

        typedef HRESULT(WINAPI* SetThreadDescriptionFunc)( HANDLE hThread, PCWSTR lpThreadDescription );
        static SetThreadDescriptionFunc pSetThreadDescription = nullptr;
        static bool tried = false;
        if (!tried)
        {
            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            if (hKernel32)
                pSetThreadDescription = (SetThreadDescriptionFunc) GetProcAddress(hKernel32, "SetThreadDescription");
            if (!pSetThreadDescription)
            {
                hKernel32 = GetModuleHandleW(L"KernelBase.dll");
                if (hKernel32)
                    pSetThreadDescription = (SetThreadDescriptionFunc)GetProcAddress(hKernel32, "SetThreadDescription");
            }
            tried = true;
        }
        if (pSetThreadDescription)
            pSetThreadDescription(GetCurrentThread(), str::from_utf8(name).c_str());
#endif
#if defined(__linux__)
        char buf[16] = {0};
        size_t sl = math::minv(sizeof(buf),name.length());
        memcpy(buf, name.data(), sl);
        buf[15] = 0;
        static_cast<void>(pthread_setname_np(pthread_self(), buf));
#endif

    }

    dynlib::dynlib(str::astr_view library)
    {
#ifdef _NIX
        lib_handler = ::dlopen(str::astr(library).c_str(), RTLD_LAZY);
#elif defined (_WIN32)
        lib_handler = ::LoadLibraryW(str::from_utf8(library).c_str());
#endif
    }

    dynlib::~dynlib() {
#ifdef _NIX
        ::dlclose(lib_handler);
#elif defined (_WIN32)
        ::FreeLibrary(reinterpret_cast<HMODULE>(lib_handler));
#endif
    }

    void* dynlib::resolve_symbol(const str::astr& symbol)
    {
        void* addr = nullptr;

#ifdef _NIX
        addr = ::dlsym(lib_handler, symbol.c_str());
#elif defined (_WIN32)
        addr = reinterpret_cast<void*>(::GetProcAddress(reinterpret_cast<HMODULE>(lib_handler), symbol.c_str()));
#endif
        return addr;
    }


} // namespace ostools