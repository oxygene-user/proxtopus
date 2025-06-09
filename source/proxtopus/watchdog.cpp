#include "pch.h"

#define DEBUG_OVERLOADER 0 // overload in (DEBUG_OVERLOADER * 5) secs, zero - disable

watchdog::watchdog()
{
#ifdef _WIN32
#else
    request = MAKEFN("/proc/");
    str::append_num(request, getpid(), 0);
    request.append(MAKEFN("/stat"));
#endif
}
watchdog::~watchdog()
{
}

#if DEBUG_OVERLOADER
static int freez_run = DEBUG_OVERLOADER;
#endif

bool watchdog::operator()()
{
    --next_query_countdown;
    if (next_query_countdown > 0)
        return true;
    next_query_countdown = 5;

#if DEBUG_OVERLOADER
    --freez_run;
    if (freez_run < 0)
    {
        freez_run = 10000;
        std::thread th1([] { for (;;) { Print(); } });
        th1.detach();

        std::thread th2([] { for (;;) { Print(); } });
        th2.detach();
    }
#endif

    signed_t cpu_usage = 0;

#ifdef _WIN32

    FILETIME dummy, kernelTime, userTime;
    FILETIME now1;
    ULARGE_INTEGER kernelTimeInt, userTimeInt;
    ULARGE_INTEGER nowInt;

    GetSystemTimeAsFileTime(&now1);
    nowInt.LowPart = now1.dwLowDateTime;
    nowInt.HighPart = now1.dwHighDateTime;

    GetProcessTimes(GetCurrentProcess(), &dummy, &dummy, &kernelTime, &userTime);

    kernelTimeInt.LowPart = kernelTime.dwLowDateTime;
    kernelTimeInt.HighPart = kernelTime.dwHighDateTime;
    userTimeInt.LowPart = userTime.dwLowDateTime;
    userTimeInt.HighPart = userTime.dwHighDateTime;

    ULARGE_INTEGER totalTimeInt;
    totalTimeInt.QuadPart = kernelTimeInt.QuadPart + userTimeInt.QuadPart;

    if (lastTotalTimeInt.QuadPart != 0 && lastNowInt.QuadPart != 0)
    {
        ULONGLONG timeDiff = totalTimeInt.QuadPart - lastTotalTimeInt.QuadPart;
        ULONGLONG nowDiff = nowInt.QuadPart - lastNowInt.QuadPart;

        if (nowDiff > 0)
        {
            cpu_usage = static_cast<signed_t>(100 * timeDiff / nowDiff);
        }
        else
            cpu_usage = 100;
    }

    lastTotalTimeInt = totalTimeInt;
    lastNowInt = nowInt;

#else

    auto fd = open(request.c_str(), O_RDONLY);
    if (fd == -1)
        return false;

    cpustats curstats = {0};
    char buf[4096];
    ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (bytes_read > 0) {

        auto s1 = str::astr_view(buf, bytes_read).find('(');
        auto s2 = str::astr_view(buf, bytes_read).find(')', s1);
        if (s1 != str::astr_view::npos && s2 != str::astr_view::npos && s1 < s2)
            memset(buf+s1, '-', s2-s1);

        signed_t field = 1;
        enum_tokens_a(t, str::astr_view(buf, bytes_read), ' ')
        {
            if (field == 14)  // utime (14th field)
                curstats.utime = str::parse_int(*t, 0);
            else if (field == 15) // stime (15th field)
                curstats.stime = str::parse_int(*t, 0);
            else if (field >= 16)
                break;
            ++field;
        }
    }

    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);

    if (last_stats.utime != 0 || last_stats.stime != 0) {
        unsigned long delta_time = (curstats.utime + curstats.stime) - (last_stats.utime + last_stats.stime);
        double delta_sec = (current_time.tv_sec - last_time.tv_sec) +
            (current_time.tv_nsec - last_time.tv_nsec) / 1e9;

        if (delta_sec > 0) {
            long ticks_per_sec = sysconf(_SC_CLK_TCK);
            cpu_usage = delta_time * 100 / (delta_sec * ticks_per_sec);
        }
    }

    last_stats = curstats;
    last_time = current_time;

#endif

    if (prev_cpu_usage != cpu_usage)
    {
        if (cpu_usage > 0)
            ostools::set_current_thread_name(str::build_string("cpu load $%", cpu_usage));
        else
            ostools::set_current_thread_name(ASTR("cpu load ok"));
        prev_cpu_usage = cpu_usage;
    }

    if (cpu_usage >= 95)
    {
        --overload_event_countdown;

        // too high load
        if (overload_event_countdown < 0)
        {
            LOG_I("too high CPU usage detected!!!");
            overload_event_countdown = 10; // do not pay attention to the overload of 10 seconds
        } else
        if (overload_event_countdown == 0)
        {
#ifdef _DEBUG
            if (!is_debugger_present()) {
#endif
                // so, watchdog is activated
                LOG_I("it seems that one or more threads are freeze; proxtopus is now exit");
                //glb.restart();

                glb.e->exit_code = EXIT_FAIL_OVERLOAD;
                glb.stop();

                // start FORCE SELF KILLER
                std::thread th([]() {
                    spinlock::sleep(10000);
                    ostools::terminate();
                    });
                th.detach();
#ifdef _DEBUG
            }
#endif

        }
        else
        {
            LOG_I("the CPU remains heavily loaded!!! proxtopus is about to exit");
        }
    }
    else
    {
        overload_event_countdown = -1;
    }


    return true;
}