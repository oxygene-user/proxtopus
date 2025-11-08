#pragma once
#if FEATURE_FILELOG
#include "stkwlk.h"

#ifdef _WIN32

namespace dbg
{
typedef BOOL (WINAPI * MINIDUMPWRITEDUMP)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

class exceptions_best_friend : public StackWalker
{
private:
    size_t lock;
    MINIDUMP_TYPE dump_type;

	void trace_info(EXCEPTION_POINTERS* pExp);
    static LONG WINAPI DUMP(HANDLE hFile, MINIDUMPWRITEDUMP pDump, EXCEPTION_POINTERS* pExp);
protected:
	virtual LONG TraceFinal(EXCEPTION_POINTERS* pExp);

public:
	exceptions_best_friend();

	static LONG WINAPI exception_filter(EXCEPTION_POINTERS* pExp);

    static void create_dump(EXCEPTION_POINTERS* pExp=nullptr, bool needExcept=true);
    static void set_dump_type(MINIDUMP_TYPE minidumpType);

};

#define EXCEPTIONFILTER() dbg::exceptions_best_friend::exception_filter(GetExceptionInformation())

}

#endif
#endif