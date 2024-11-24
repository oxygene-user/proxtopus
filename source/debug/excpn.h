#pragma once
#include "stkwlk.h"

#ifdef _WIN32

namespace dbg
{
typedef BOOL (WINAPI * MINIDUMPWRITEDUMP)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

class exceptions_best_friend : public StackWalker
{
private:
    spinlock::long3264 lock;
    MINIDUMP_TYPE dump_type;
	mutable std::array<char, 32768> output;
    mutable signed_t output_len = 0;

	//static exceptions_best_friend self;

	void trace_info(EXCEPTION_POINTERS* pExp);
    static LONG WINAPI DUMP(HANDLE hFile, MINIDUMPWRITEDUMP pDump, EXCEPTION_POINTERS* pExp);
protected:
	virtual LONG TraceFinal(EXCEPTION_POINTERS* pExp);
    virtual void OnOutput(const char *szText, size_t len) const override;

    static void glpp(const char* s, size_t l);
public:
	exceptions_best_friend();

	static LONG WINAPI exception_filter(EXCEPTION_POINTERS* pExp);
    static void WINAPI show_callstack(HANDLE hThread, const char* name);

    static void create_dump(EXCEPTION_POINTERS* pExp=nullptr, bool needExcept=true);
    static void set_dump_type(MINIDUMP_TYPE minidumpType);

};

#define EXCEPTIONFILTER() dbg::exceptions_best_friend::exception_filter(GetExceptionInformation())
#define SHOW_CALL_STACK() dbg::exceptions_best_friend::show_callstack(GetCurrentThread(), "CallStack")

}

#endif