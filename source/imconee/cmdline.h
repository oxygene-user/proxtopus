#pragma once

enum AppExitCode
{
	EXIT_OK = 0,
	EXIT_OK_EXIT = -1,

	EXIT_FAIL_NOCONFIG = 1,				// no config.txt found
	EXIT_FAIL_NOLISTENERS = 2,			// config has no \"listeners\" block
										// "empty (or not loaded) \"listeners\" block
	EXIT_FAIL_NOHANDLER = 3,			// handler not defined for listener [%s]
	EXIT_FAIL_PROXY_NOTFOUND = 4,		// unknown {proxy} [%s] for handler of lisnener [%s].

	EXIT_FAIL_PORT_UNDEFINED = 10,		// port not defined for listener [%s]
	EXIT_FAIL_TYPE_UNDEFINED = 11,      // {type} not defined for lisnener [%s]. Type {imconee help listener} for more information.
										// unknown {type} [%s] for lisnener [%s]. Type {imconee help listener} for more information.
										// {type} not defined for handler of listener [%s]
										// unknown {type} [%s] for handler of lisnener [%s]. Type {imconee --help handler} for more information.
										// {type} not defined for proxy [%s]. Type {imconee help proxy} for more information. 
										// unknown {type} [%s] for proxy [%s]. Type {imconee help proxy} for more information.
	EXIT_FAIL_ADDR_UNDEFINED = 12,		// addr not defined for proxy [%s]
	EXIT_FAIL_METHOD_UNDEFINED = 13,	// {method} not defined for proxy [%s]
										// {to} field of direct handler not defined or invalid (listener: [%s]). Valid format of {to} field is: domain_or_ipv4:port

	EXIT_FAIL_IPV46_VALS = 14,

	EXIT_FAIL_ELEVATION = 98,
	EXIT_FAIL_CTLHANDLE = 99,

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
	std::vector<FN> parar_;
public:
	commandline(NIXONLY(std::vector<FN>&& mas));
	~commandline() {}

	const std::vector<FN>& parar() const
	{
		return parar_;
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
	

	FN path_config() const;
};