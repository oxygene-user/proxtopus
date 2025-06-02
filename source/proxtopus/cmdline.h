#pragma once

enum AppExitCode
{
	EXIT_OK = 0,
	EXIT_OK_EXIT = -1,
	EXIT_TERMINATED = 1,

	EXIT_FAIL_NOCONFIG = 2,				// no config.txt found
	EXIT_FAIL_NOLISTENERS = 3,			// config has no \"listeners\" block
	// "empty (or not loaded) \"listeners\" block
	EXIT_FAIL_NOHANDLER = 4,			// handler not defined for listener [$]
	EXIT_FAIL_PROXY_NOTFOUND = 5,		// unknown {proxy} [$] for handler of listener [$].
	EXIT_FAIL_INCOMPATIBLE_HANDLER = 6,	// handler not compatible

	EXIT_FAIL_PORT_UNDEFINED = 10,		// port not defined for listener [$]
	EXIT_FAIL_TYPE_UNDEFINED = 11,      // {type} not defined for listener / handler / transport
	// unknown {type} [$] for listener [$].
	// {type} not defined for handler of listener [$]
	// unknown {type} [$] for handler of listener [$].
	// {type} not defined for proxy [$].
	// unknown {type} [$] for proxy [$].
	EXIT_FAIL_ADDR_UNDEFINED = 12,		// addr not defined for proxy [$]
	EXIT_FAIL_METHOD_UNDEFINED = 13,	// {method} not defined for proxy [$]
	// {to} field of direct handler not defined or invalid (listener: [$]). Valid format of {to} field is: domain_or_ipv4:port
	EXIT_FAIL_IPV46_VALS = 14,
	EXIT_FAIL_SOCKET_TYPE = 15,

	EXIT_FAIL_ICPT_NOT_SUPPORTED = 16,
	EXIT_FAIL_ICPT_INIT_ERROR = 17,

	EXIT_FAIL_MODE_UNDEFINED = 18,
	EXIT_FAIL_NEED_ALL_LISTENERS = 19,
	EXIT_FAIL_NO_PASSWORDS_DEFINED = 20,

	EXIT_FAIL_KEY_MISSED = 40,
	EXIT_FAIL_CRT_MISSED = 41,

	EXIT_FAIL_DUP_NAME = 50,
	EXIT_FAIL_EVNT_CREATE = 51,
	EXIT_FAIL_CHILD_CREATE = 52,

	EXIT_FAIL_OVERLOAD = 53,
	EXIT_FAIL_WATCHDOG = 96,
	EXIT_FAIL_ELEVATION = 97,
	EXIT_FAIL_CTLHANDLE = 98,

	EXIT_OK_EXIT_SIGNAL = 99,

#ifdef _WIN32
	EXIT_FAIL_OPENMGR = 100,
	EXIT_FAIL_OPENSERVICE = 101,
	EXIT_FAIL_CREATESERVICE = 102,
	EXIT_FAIL_STARTSERVICE = 103,
	EXIT_FAIL_DELETESERVICE = 104,
#endif

};

class commandline
{
	FNARR parar_;
public:
	commandline();
    commandline(FNARR&& mas);
	~commandline() {}

	void handle_options();

	const std::vector<FN>& parar() const
	{
		return parar_;
	}

	bool have_option(const FNview &opt) const
	{
		return std::find(parar_.begin(), parar_.end(), opt) != parar_.end();
	}

    FN get_option_par(const FNview& opt) const
    {
        auto fr = std::find(parar_.begin(), parar_.end(), opt);
		if (parar_.end() == fr)
			return FN();

		return *(++fr);
    }

	bool help() const;

#ifdef _WIN32
	bool install() const
	{
		return parar_.size() > 1 ? parar_[1] == MAKEFN("install") : false;
	}
	bool remove() const
	{
		return parar_.size() > 1 ? parar_[1] == MAKEFN("remove") : false;
	}
	bool start() const
	{
		return parar_.size() > 1 ? parar_[1] == MAKEFN("start") : false;
	}
	bool stop() const
	{
		return parar_.size() > 1 ? parar_[1] == MAKEFN("stop") : false;
	}
	bool service() const
	{
		return parar_.size() > 1 ? parar_[1] == MAKEFN("service") : false;
	}
#endif
    bool mute() const
    {
        return have_option(MAKEFN("--mute"));
    }

	bool unmute() const
    {
        return have_option(MAKEFN("--unmute"));
    }

    bool lna() const // listeners need all
    {
        return have_option(MAKEFN("--lna"));
    }

    bool actual() const // actual run (not through watchdog)
    {
        return have_option(MAKEFN("--actual"));
    }

    signed_t wait() const // wait pid end before work
    {
        return str::parse_int(str::view(get_option_par(MAKEFN("--wait"))), 0);
    }

    signed_t ppid() const // parent pid
    {
        return str::parse_int(str::view(get_option_par(MAKEFN("--ppid"))), 0);
    }

    u8 btc() const // bind try count
    {
        return tools::as_byte(str::parse_int(str::view(get_option_par(MAKEFN("--btc"))), 0));
    }

#if defined _DEBUG && defined _WIN32
    bool compile_oids(FN &cppfile) const
    {
		if (parar_.size() > 2 && parar_[1] == MAKEFN("oids"))
		{
			cppfile = parar_[2];
			return true;
		}
		return false;
    }
#endif

	FN path_config() const;
};