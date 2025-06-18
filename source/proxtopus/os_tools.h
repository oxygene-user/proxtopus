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

    void set_current_thread_name(const str::astr_view& name);


    class dynlib
    {
        dynlib(const dynlib&) = delete;
        dynlib& operator=(const dynlib&) = delete;

        void* lib_handler = nullptr;
    public:
        dynlib(str::astr_view lib_name);
        ~dynlib();
        void* resolve_symbol(const str::astr& symbol);
        template <typename T> T resolve(const str::astr& symbol) {
            return reinterpret_cast<T>(resolve_symbol(symbol));
        }
    };

}
