#include "pch.h"

#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
#include "excpn.h"

#include "../imconee/spinlock.h"

#define self glb.ebf

namespace dbg
{
	void LogMessage(const char* caption, const char* msg)
	{
		FILE* f = fopen(glb.cfg.crash_log_file.c_str(), "ab");
		if (f)
		{
			time_t curtime;
			time(&curtime);
			const tm& t = *localtime(&curtime);
			if (caption)
				fprintf(f, "-------------------------\r\nDATETIME: %i-%02i-%02i %02i:%02i\r\nCAPTION: %s\r\nMESSAGE: %s\r\n\r\n", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, caption, msg);
			else
				fprintf(f, "(%i-%02i-%02i %02i:%02i) : %s\r\n", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, msg);
			fclose(f);
		}
	}

	void Log(const char* s, ...)
	{
		char str[65535];

		va_list args;
		va_start(args, s);
		vsnprintf(str, sizeof(str), s, args);
		va_end(args);

		LogMessage(nullptr, str);
	}


char* strerror_r(int errnum, char *buf, size_t n)
{
    static char unn[] = "Unknown error.";
    BOOL fOk = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errnum,
                              //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf,
                              MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf,
                              (DWORD)n, NULL);

    if (!fOk) {
        fOk = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errnum,
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf,
                             (DWORD)n, NULL);

        if (!fOk){
            // Is it a network-related error?
            HMODULE hDll = LoadLibraryEx(TEXT("netmsg.dll"), NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (hDll != NULL) {
                if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errnum,
                    MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf,
                    (DWORD)n, NULL)) strncpy_s(buf, n, unn, n);
                FreeLibrary(hDll);
            }
            else strncpy_s(buf, n, unn, n);
        };
    };

    //CharToOem(buf,buf);

    return (buf);
};


const char* ExceptionCodeToStr(DWORD exceptioncode)
{
	switch (exceptioncode)
	{
	case EXCEPTION_ACCESS_VIOLATION         : return("EXCEPTION_ACCESS_VIOLATION");
	case EXCEPTION_DATATYPE_MISALIGNMENT    : return("EXCEPTION_DATATYPE_MISALIGNMENT");
	case EXCEPTION_BREAKPOINT               : return("EXCEPTION_BREAKPOINT");
	case EXCEPTION_SINGLE_STEP              : return("EXCEPTION_SINGLE_STEP");
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED    : return("EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
	case EXCEPTION_FLT_DENORMAL_OPERAND     : return("EXCEPTION_FLT_DENORMAL_OPERAND");
	case EXCEPTION_FLT_DIVIDE_BY_ZERO       : return("EXCEPTION_FLT_DIVIDE_BY_ZERO");
	case EXCEPTION_FLT_INEXACT_RESULT       : return("EXCEPTION_FLT_INEXACT_RESULT");
	case EXCEPTION_FLT_INVALID_OPERATION    : return("EXCEPTION_FLT_INVALID_OPERATION");
	case EXCEPTION_FLT_OVERFLOW             : return("EXCEPTION_FLT_OVERFLOW");
	case EXCEPTION_FLT_STACK_CHECK          : return("EXCEPTION_FLT_STACK_CHECK");
	case EXCEPTION_FLT_UNDERFLOW            : return("EXCEPTION_FLT_UNDERFLOW");
	case EXCEPTION_INT_DIVIDE_BY_ZERO       : return("EXCEPTION_INT_DIVIDE_BY_ZERO");
	case EXCEPTION_INT_OVERFLOW             : return("EXCEPTION_INT_OVERFLOW");
	case EXCEPTION_PRIV_INSTRUCTION         : return("EXCEPTION_PRIV_INSTRUCTION");
	case EXCEPTION_IN_PAGE_ERROR            : return("EXCEPTION_IN_PAGE_ERROR");
	case EXCEPTION_ILLEGAL_INSTRUCTION      : return("EXCEPTION_ILLEGAL_INSTRUCTION");
	case EXCEPTION_NONCONTINUABLE_EXCEPTION : return("EXCEPTION_NONCONTINUABLE_EXCEPTION");
	case EXCEPTION_STACK_OVERFLOW           : return("EXCEPTION_STACK_OVERFLOW");
	case EXCEPTION_INVALID_DISPOSITION      : return("EXCEPTION_INVALID_DISPOSITION");
	case EXCEPTION_GUARD_PAGE               : return("EXCEPTION_GUARD_PAGE");
	case EXCEPTION_INVALID_HANDLE           : return("EXCEPTION_INVALID_HANDLE");
	default:
		return("EXCEPTION_UNKNOWN");
	}
}

void exceptions_best_friend::trace_info(EXCEPTION_POINTERS* pExp)
{
	// generate exception text and out

	char modulename[256];
	GetModuleFileNameA(NULL, modulename, 256);

	char* name=strrchr(modulename,'\\');
	if (name)
	{
		name++;
		int len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Exception info [%04X]:\r\n\r\n%s caused a %s at %04X:%p\r\n\r\n", (int)GetCurrentThreadId(), name, ExceptionCodeToStr(pExp->ExceptionRecord->ExceptionCode), pExp->ContextRecord->SegCs, (LPVOID)pExp->ExceptionRecord->ExceptionAddress);
		OnOutput(outBuffer, len);

		unsigned char* code = NULL;

		__try{
#ifdef _M_IX86
		if (pExp->ContextRecord-> Eip && !pExp->ExceptionRecord->ExceptionRecord)
		{
			code = (unsigned char*)(pExp->ContextRecord-> Eip); //-V204
			len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Bytes at CS::EIP:\r\n%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n\r\n",
				code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7],
				code[8], code[9], code[10], code[11], code[12], code[13], code[14], code[15]);
		}
		else len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Bytes at CS::EIP:\r\n<NULL>\r\n\r\n");
#elif _M_X64
		if (pExp->ContextRecord-> Rip && !pExp->ExceptionRecord->ExceptionRecord)
		{
			code = (unsigned char*)(pExp->ContextRecord-> Rip);
			len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Bytes at CS::RIP:\r\n%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
				code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7],
				code[8], code[9], code[10], code[11], code[12], code[13], code[14], code[15]);
		}
		else len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Bytes at CS::RIP:\r\n<NULL>\r\n\r\n");
#endif
		}__except(EXCEPTION_EXECUTE_HANDLER){
			len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Bytes at CS::RIP(inavlid):\r\n %p\r\n\r\n", code);
		};

		OnOutput(outBuffer, len);

		void** stack =NULL;

		__try{
#ifdef _M_IX86
		if (pExp->ContextRecord -> Esp && !pExp->ExceptionRecord->ExceptionRecord)
		{
			stack = (void**)(pExp->ContextRecord -> Esp); //-V204
			len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "nStack dump:\r\n%p %p %p %p %p %p %p %p\r\n%p %p %p %p %p %p %p %p\r\n%p %p %p %p %p %p %p %p\r\n%p %p %p %p %p %p %p %p\r\n\r\n",
				stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7],
				stack[8], stack[9], stack[10], stack[11], stack[12], stack[13], stack[14], stack[15],
				stack[16], stack[17], stack[18], stack[19], stack[20], stack[21], stack[22], stack[23],
				stack[24], stack[25], stack[26], stack[27], stack[28], stack[29], stack[30], stack[31]);
		}
		else len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "nStack dump:\r\n<NULL>");
#elif _M_X64
		if (pExp->ContextRecord -> Rsp && !pExp->ExceptionRecord->ExceptionRecord)
		{
			stack = (void**)(pExp->ContextRecord -> Rsp);
			len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "nStack dump:\r\n%p %p %p %p %p %p %p %p\r\n%p %p %p %p %p %p %p %p\r\n%p %p %p %p %p %p %p %p\r\n%p %p %p %p %p %p %p %p\r\n\r\n",
				stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7],
				stack[8], stack[9], stack[10], stack[11], stack[12], stack[13], stack[14], stack[15],
				stack[16], stack[17], stack[18], stack[19], stack[20], stack[21], stack[22], stack[23],
				stack[24], stack[25], stack[26], stack[27], stack[28], stack[29], stack[30], stack[31]);
		}
		else len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "nStack dump:\r\n<NULL>\r\n\r\n");
#endif
		}__except(EXCEPTION_EXECUTE_HANDLER){
			len =_snprintf_s(outBuffer, STACKWALK_MAX_NAMELEN, "Stack dump:(inavlid):\r\n %p\r\n\r\n", stack);
		};

		OnOutput(outBuffer, len);
	}
}

void (*CheckMemCorrupt)() = NULL;

LONG WINAPI exceptions_best_friend::exception_filter(EXCEPTION_POINTERS* pExp)
{
	Log("crush!"); 
	Print(FOREGROUND_RED | FOREGROUND_INTENSITY, "crush! (See config.txt -> settings -> crash_log_file for stack trace)\n");

	if (pExp->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW){
		self.trace_info(pExp);
		Sleep(1000000);
	}

    SIMPLELOCK(self.lock);
	self.output[0] = 0;
	self.OnOutput1("\n=====================================================================\n");
    self.trace_info(pExp);
    self.TraceRegisters(GetCurrentThread(), pExp->ContextRecord);
    self.ShowCallstack(GetCurrentThread(), pExp->ContextRecord);
	self.OnOutput1("=====================================================================\n");

	if (CheckMemCorrupt)
		CheckMemCorrupt();

	Log(self.output.data());

    create_dump(pExp);
	return self.TraceFinal(pExp);
}

void WINAPI exceptions_best_friend::show_callstack(HANDLE hThread, const char* name)
{
    SIMPLELOCK(self.lock);
	self.output[0] = 0;
	self.OnOutput1("\n=====================================================================\n");
	std::array<char,256> stamp;
	int len = sprintf_s(stamp.data(), stamp.max_size(), "%s [%04X]\n", name, ((unsigned int)(size_t)hThread));
	self.OnOutput(stamp.data(), len);
	self.ShowCallstack(hThread, NULL);
	self.OnOutput1("=====================================================================");
	Log(self.output.data());
}

LONG exceptions_best_friend::TraceFinal(EXCEPTION_POINTERS* pExp)
{
	if (pExp->ExceptionRecord->ExceptionCode == 0x2000FFFF) 
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
}

void exceptions_best_friend::OnOutput(LPCSTR szText, size_t len) const
{
	size_t maxlen = output.max_size() - output_len - 1;
    if (len > maxlen) len = maxlen;
    memcpy(output.data() + output_len, szText, len);
	output_len += len;
	output[output_len] = 0;
}

exceptions_best_friend::exceptions_best_friend()
{
    dump_type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory /*| MiniDumpWithProcessThreadData*/ | MiniDumpWithDataSegs | MiniDumpWithHandleData /*| MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo*/ );
    LoadModules();
}

void exceptions_best_friend::set_dump_type(MINIDUMP_TYPE minidumpType)
{
	self.dump_type = minidumpType;
}


void exceptions_best_friend::create_dump(EXCEPTION_POINTERS* pExp/*=NULL*/, bool needExcept/*=true*/)
{
    static spinlock::long3264 lock=0;
    static int err;
    static std::array<char, 256> tmperror;

    spinlock::simple_lock(lock);

    MINIDUMPWRITEDUMP pDump = (MINIDUMPWRITEDUMP)::GetProcAddress(self.DBGDLL(), "MiniDumpWriteDump");

    if (pDump)
    {
        if (glb.cfg.dump_file.empty())
        {
			Log("Dump not created due config.txt->settings->dump_file is empty");
			spinlock::simple_unlock(lock);
			return;
		}

        HANDLE hFile = ::CreateFileA(glb.cfg.dump_file.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile!=INVALID_HANDLE_VALUE)
        {
			if (pExp)
			{
				DUMP(hFile, pDump, pExp);
			}
			else
            {
                if (needExcept)
                {
                    __try{
                        RaiseException(0x2000FFFE, 0, 0, NULL);
                    }__except(DUMP(hFile, pDump, GetExceptionInformation())){}
                }
                else DUMP(hFile, pDump, NULL);
            }

            ::CloseHandle(hFile);
        } else
        {
            err=GetLastError();
            Log("CreateFile dump error: (%d) %s", err, strerror_r(err, tmperror.data(), tmperror.max_size()));
			
        }
    }
    else
    {
        err=GetLastError();
        Log("MiniDumpWriteDump didn't find in DBGHELP.DLL. Error: (%d) %s", err, strerror_r(err, tmperror.data(), tmperror.max_size()));
    }

    spinlock::simple_unlock(lock);
}

LONG WINAPI exceptions_best_friend::DUMP(HANDLE hFile, MINIDUMPWRITEDUMP pDump, EXCEPTION_POINTERS* pExp)
{
    _MINIDUMP_EXCEPTION_INFORMATION ExInfo;

    ExInfo.ThreadId = ::GetCurrentThreadId();
    ExInfo.ExceptionPointers = pExp;
    ExInfo.ClientPointers = NULL;

    if (!pDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, self.dump_type, &ExInfo, NULL, NULL))
    {
        static int err=GetLastError();
        static char tmperror[256];
        Log("MiniDumpWriteDump error: (%d) %s", err, strerror_r(err, tmperror, 256));
    }

    return(EXCEPTION_EXECUTE_HANDLER);
}

}


long __stdcall crash_exception_filter( _EXCEPTION_POINTERS* pExp )
{
    return dbg::exceptions_best_friend::exception_filter( pExp );
}

#endif

void set_unhandled_exception_filter()
{
#ifdef _WIN32
    ::SetUnhandledExceptionFilter(&dbg::exceptions_best_friend::exception_filter);
#endif
}

void set_dump_type(bool full)
{
#ifdef _WIN32
    MINIDUMP_TYPE dump_type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory /*| MiniDumpWithProcessThreadData*/ | MiniDumpWithDataSegs | MiniDumpWithHandleData /*| MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo*/);
    if (!full)
        dump_type = (MINIDUMP_TYPE)(MiniDumpWithDataSegs | MiniDumpWithHandleData);
	dbg::exceptions_best_friend::set_dump_type(dump_type);
#endif
}

