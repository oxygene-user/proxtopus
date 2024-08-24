#include "pch.h"

bool loader::load_conf(const FN& cfp)
{
	buffer cb;
	if (!load_buf(cfp, cb))
	{
		LOG_E("no %s found", str::to_utf8(cfp.c_str()).c_str());
		exit_code = EXIT_FAIL_NOCONFIG;
		return false;
	}

	cfg.load(str::astr_view((const char*)cb.data(), cb.size()));

	// parse config file here

	listeners = cfg.get(ASTR("listeners"));
	prox = cfg.get(ASTR("proxy"));

	if (nullptr == listeners)
	{
		LOG_E("config has no \"listeners\" block");
		exit_code = EXIT_FAIL_NOLISTENERS;
		return false;
	}

	settings = cfg.get(ASTR("settings"));

	if (settings)
	{
		signed_t ipv4 = settings->get_int("ipv4", 1);
		signed_t ipv6 = settings->get_int("ipv6", 0);
		if (ipv4 < 0) ipv4 = 0;
		if (ipv6 < 0) ipv6 = 0;
		if (ipv4 == ipv6)
		{
			LOG_E("value of \"ipv4\" equal to value of \"ipv6\" (==%i) (see \"settings\" block); these values must be different and greater/equal zero", ipv4);
			exit_code = EXIT_FAIL_IPV46_VALS;
			return false;
		}
		if (ipv4 == 0)
			netkit::getip_def = netkit::GIP_ONLY6;
		else if (ipv6 == 0)
			netkit::getip_def = netkit::GIP_ONLY4;
		else if (ipv4 > ipv6)
			netkit::getip_def = netkit::GIP_PRIOR4;
		else
			netkit::getip_def = netkit::GIP_PRIOR6;
	}

	return true;
}

bool loader::iterate_l(listener_loader ll)
{
	if (!ASSERT(listeners))
		return false;

	for (auto it = listeners->begin(); it; ++it)
	{
		if (it.is_comment())
			continue;
		if (it.name()[0] == '!')
		{
			LOG_N("listener {%s} has been skipped", it.name().c_str()+1);
			continue;
		}
		if (!ll(it.name(), *it))
			return false;
	}
	return true;
}

bool loader::iterate_p(proxy_loader pl)
{
	if (nullptr == prox)
		return true;

	for (auto it = prox->begin(); it; ++it)
	{
		if (it.is_comment())
			continue;
		if (it.name()[0] == '!')
		{
			LOG_N("proxy {%s} has been skipped", it.name().c_str() + 1);
			continue;
		}
		if (!pl(it.name(), *it))
			return false;
	}
	return true;
}

