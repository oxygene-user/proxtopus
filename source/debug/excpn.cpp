#include "pch.h"

#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
#include "excpn.h"

#include "../proxtopus/spinlock.h"

#define self glb.ebf

namespace dbg
{
	void append_crash_log(const str::astr_view& msg)
	{
		if (file_appender fa(glb.cfg.crash_log_file); fa)
		{
            time_t curtime;
            time(&curtime);
            const tm& t = *localtime(&curtime);

            auto flush_to_file = [&fa](const char* data, size_t size) -> bool {
                fa << str::astr_view(data, size);
				return true;
            };

			str::xsstr<char, 4096, decltype(flush_to_file)> buf(flush_to_file);
            str::impl_build_string(buf, "$-$-$ $:$:$ : $", t.tm_year + 1900, dec<2, int>(t.tm_mon + 1), DEC(2, t.tm_mday), DEC(2, t.tm_hour), DEC(2, t.tm_min), DEC(2, t.tm_sec), crlf(msg));
		}
	}

    template <typename... T> void Log(const char* s, const T&... args) {

        str::asstr<2048> sout;
        str::impl_build_string(sout, s, args...);
		append_crash_log(str::view(sout));
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


str::astr_view ExceptionCodeToStr(DWORD exceptioncode)
{
	switch (exceptioncode)
	{
	case EXCEPTION_ACCESS_VIOLATION         : return ASTR("EXCEPTION_ACCESS_VIOLATION");
	case EXCEPTION_DATATYPE_MISALIGNMENT    : return ASTR("EXCEPTION_DATATYPE_MISALIGNMENT");
	case EXCEPTION_BREAKPOINT               : return ASTR("EXCEPTION_BREAKPOINT");
	case EXCEPTION_SINGLE_STEP              : return ASTR("EXCEPTION_SINGLE_STEP");
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED    : return ASTR("EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
	case EXCEPTION_FLT_DENORMAL_OPERAND     : return ASTR("EXCEPTION_FLT_DENORMAL_OPERAND");
	case EXCEPTION_FLT_DIVIDE_BY_ZERO       : return ASTR("EXCEPTION_FLT_DIVIDE_BY_ZERO");
	case EXCEPTION_FLT_INEXACT_RESULT       : return ASTR("EXCEPTION_FLT_INEXACT_RESULT");
	case EXCEPTION_FLT_INVALID_OPERATION    : return ASTR("EXCEPTION_FLT_INVALID_OPERATION");
	case EXCEPTION_FLT_OVERFLOW             : return ASTR("EXCEPTION_FLT_OVERFLOW");
	case EXCEPTION_FLT_STACK_CHECK          : return ASTR("EXCEPTION_FLT_STACK_CHECK");
	case EXCEPTION_FLT_UNDERFLOW            : return ASTR("EXCEPTION_FLT_UNDERFLOW");
	case EXCEPTION_INT_DIVIDE_BY_ZERO       : return ASTR("EXCEPTION_INT_DIVIDE_BY_ZERO");
	case EXCEPTION_INT_OVERFLOW             : return ASTR("EXCEPTION_INT_OVERFLOW");
	case EXCEPTION_PRIV_INSTRUCTION         : return ASTR("EXCEPTION_PRIV_INSTRUCTION");
	case EXCEPTION_IN_PAGE_ERROR            : return ASTR("EXCEPTION_IN_PAGE_ERROR");
	case EXCEPTION_ILLEGAL_INSTRUCTION      : return ASTR("EXCEPTION_ILLEGAL_INSTRUCTION");
	case EXCEPTION_NONCONTINUABLE_EXCEPTION : return ASTR("EXCEPTION_NONCONTINUABLE_EXCEPTION");
	case EXCEPTION_STACK_OVERFLOW           : return ASTR("EXCEPTION_STACK_OVERFLOW");
	case EXCEPTION_INVALID_DISPOSITION      : return ASTR("EXCEPTION_INVALID_DISPOSITION");
	case EXCEPTION_GUARD_PAGE               : return ASTR("EXCEPTION_GUARD_PAGE");
	case EXCEPTION_INVALID_HANDLE           : return ASTR("EXCEPTION_INVALID_HANDLE");
	default:
		return ASTR("EXCEPTION_UNKNOWN");
	}
}

#ifdef _M_IX86
#define CODE_REG Eip
#define CODE_REG_S "EIP"
#define STACK_REG Esp
#elif _M_X64
#define CODE_REG Rip
#define CODE_REG_S "RIP"
#define STACK_REG Rsp
#endif

void exceptions_best_friend::trace_info(EXCEPTION_POINTERS* pExp)
{
	// generate exception text and out

	str::asstr<255> modulename;
	modulename.resize(GetModuleFileNameA(nullptr, modulename.data(), modulename.maxsize));
	size_t ni = str::view(modulename).rfind('\\');
	if (ni != str::astr::npos)
	{
		str::astr_view name = str::view(modulename).substr(ni + 1);
		
		str::impl_build_string(m_buf, "Exception info [$]:\r\n\r\n$ caused a $ at $:$\r\n\r\n",
			HEX(4, GetCurrentThreadId()),
			name,
			ExceptionCodeToStr(pExp->ExceptionRecord->ExceptionCode),
			HEX(4, pExp->ContextRecord->SegCs),
			PTR(pExp->ExceptionRecord->ExceptionAddress)
			);

		unsigned char* code = nullptr;

		__try {
			if (pExp->ContextRecord->CODE_REG && !pExp->ExceptionRecord->ExceptionRecord)
			{
				code = (unsigned char*)(pExp->ContextRecord->CODE_REG);

				m_buf.append(ASTR("Bytes at CS::" CODE_REG_S ":\r\n"));
				for (int i = 0; i < 16; ++i, ++code)
				{
					if (i > 0) m_buf += ' ';
					str::append_hex<decltype(m_buf), u8, 2>(m_buf, *code);
				}
				m_buf.append(ASTR("\r\n\r\n"));
			}
			else {
				m_buf.append(ASTR("Bytes at CS::" CODE_REG_S ":\r\n<NULL>\r\n\r\n"));
			}
		}__except(EXCEPTION_EXECUTE_HANDLER){
            str::impl_build_string(m_buf, "Bytes at CS::" CODE_REG_S "(inavlid):\r\n $\r\n\r\n", PTR(code));
		};

		void** stack =nullptr;

		__try{
			if (pExp->ContextRecord ->STACK_REG && !pExp->ExceptionRecord->ExceptionRecord)
			{
				stack = (void**)(pExp->ContextRecord ->STACK_REG);
				m_buf.append(ASTR("Stack dump:\r\n"));
                for (int i = 0; i < 32; ++i, ++stack)
                {
					if (i > 0)
					{
						if (i & 7)
							m_buf += ' ';
						else
							m_buf.append(ASTR("\r\n"));
					}
                    str::append_hex<decltype(m_buf), uintptr_t, 0>(m_buf, reinterpret_cast<uintptr_t>(*stack));
                }
                m_buf.append(ASTR("\r\n\r\n"));

			}
			else {
				m_buf.append(ASTR("Stack dump:\r\n<NULL>\r\n\r\n"));
			}
		}__except(EXCEPTION_EXECUTE_HANDLER){
			str::impl_build_string(m_buf, "Stack dump:(inavlid):\r\n $\r\n\r\n", PTR(stack));
		};
	}
}

void (*CheckMemCorrupt)() = nullptr;

LONG WINAPI exceptions_best_friend::exception_filter(EXCEPTION_POINTERS* pExp)
{
    Print(FOREGROUND_RED | FOREGROUND_INTENSITY, "crash! (See config.txt -> settings -> crash_log_file for stack trace)\n");
	Print();
    
	spinlock::auto_simple_lock slock(self.lock);
    self.m_buf.clear();
	self.m_buf.append(ASTR("crash!\r\n"));

	if (pExp->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW){
		self.trace_info(pExp);
		spinlock::sleep(1000000);
	}

	if (file_appender fa(glb.cfg.crash_log_file); fa)
	{
		if (flusher* f = self.m_buf.get_flusher())
		{
			f->m_fa = &fa;

			self.m_buf += ASTR("\n=====================================================================\n");
			self.trace_info(pExp);
			self.TraceRegisters(GetCurrentThread(), pExp->ContextRecord);
			self.ShowCallstack(GetCurrentThread(), pExp->ContextRecord);
			self.m_buf += ASTR("=====================================================================\n");

			if (CheckMemCorrupt)
				CheckMemCorrupt();

			(*f)(self.m_buf.data(), self.m_buf.length());
			f->m_fa = nullptr;
			self.m_buf.clear();
		}

	}

    create_dump(pExp);
	return self.TraceFinal(pExp);
}

LONG exceptions_best_friend::TraceFinal(EXCEPTION_POINTERS* pExp)
{
	if (pExp->ExceptionRecord->ExceptionCode == 0x2000FFFF) 
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
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
    static size_t lock=0;
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

        HANDLE hFile = ::CreateFileW(glb.cfg.dump_file.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

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
            Log("CreateFile dump error: ($) $", err, strerror_r(err, tmperror.data(), tmperror.max_size()));
			
        }
    }
    else
    {
        err=GetLastError();
        Log("MiniDumpWriteDump didn't find in DBGHELP.DLL. Error: ($) $", err, strerror_r(err, tmperror.data(), tmperror.max_size()));
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
        Log("MiniDumpWriteDump error: ($) $", err, strerror_r(err, tmperror, 256));
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

