#pragma once

#ifdef _NIX
#include <sys/times.h>
#endif

class watchdog
{
    signed_t next_time_query = 0;
    signed_t overload_event = 0;
#ifdef _WIN32
    ULARGE_INTEGER lastTotalTimeInt = { 0, 0 };
    ULARGE_INTEGER lastNowInt = { 0, 0 };
#else

    struct cpustats 
    {
        unsigned long utime;
        unsigned long stime;
    };

    cpustats last_stats = { 0 };
    struct timespec last_time = { 0 };
    FN request;
#endif

public:
    watchdog();
    ~watchdog();

    bool operator()();
};
