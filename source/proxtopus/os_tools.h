#pragma once

#ifdef _WIN32
#define PROXTOPUS_EVT L"Local\\proxtopus_signal_"
#endif

namespace ostools
{
    void wait_process(signed_t pid);
    signed_t process_id();
    signed_t get_cores();

    signed_t execute(const FNARR &cmdl WINONLY(, bool from_sevice)); // and wait; also modified glb.actual_proc; [0] - executable path
    void terminate(); // force terminate self
}
