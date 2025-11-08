#pragma once

#ifdef _WIN32
#define PROXTOPUS_EVT L"Local\\proxtopus_signal_"
#endif

namespace ostools
{
    void wait_process(signed_t pid);
    signed_t process_id();
    signed_t get_cores();

#if APP && FEATURE_WATCHDOG
    signed_t silent_execute(const FNview& cmdl); // and wait
    signed_t execute(const FNARR& cmdl WINONLY(, bool from_sevice)); // and wait; also modified glb.actual_proc; [0] - executable path
    void terminate(); // force terminate self
#endif

    void set_current_thread_name(const str::astr_view& name);

    netkit::ipap get_best_route( const netkit::ipap &ipa );
    bool add_route( const netkit::ipap& dst /*port used as prefix size (mask)*/, const netkit::ipap& ifc, signed_t ifci);

    class dynlib
    {
        dynlib(const dynlib&) = delete;
        dynlib& operator=(const dynlib&) = delete;

        void* lib_handler = nullptr;
    public:
        dynlib(const FN &lib_name);
        ~dynlib();
        void* resolve_symbol(const str::astr& symbol);
        template <typename T> T resolve(const str::astr& symbol) {
            return reinterpret_cast<T>(resolve_symbol(symbol));
        }
        void unload();
        operator bool() const
        {
            return lib_handler != nullptr;
        }
    };

}
