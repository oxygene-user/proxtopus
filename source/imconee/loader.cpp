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
		LOG_W("config has no \"listeners\" block");
		exit_code = EXIT_FAIL_NOLISTENERS;
		return false;
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
			LOG_N("Listener {%s} has been skipped", it.name().c_str()+1);
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
			LOG_N("Proxy {%s} has been skipped", it.name().c_str() + 1);
			continue;
		}
		if (!pl(it.name(), *it))
			return false;
	}
	return true;
}

