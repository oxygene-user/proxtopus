#include "pch.h"

volatile bool engine::exit = false;

engine::engine(std::wstring &&path_config)
{
	std::wstring x = std::move(path_config);

	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);


	loader ldr(this);

	if (!ldr.load_conf(x))
	{
		exit_code = ldr.exit_code;
		exit = true;
		return;
	}

	ldr.iterate_p([&](const std::string& name, const asts& lb) {

		if (name.empty())
		{
			LOG_W("Proxy with no name skipped");
			return true;
		}

		proxy* p = proxy::build(ldr, name, lb);
		if (nullptr == p)
			return false;
		
		prox.emplace_back(p);
		return true;
	});

	if (ldr.exit_code != 0)
	{
		exit_code = ldr.exit_code;
		exit = true;
		return;
	}

	ldr.iterate_l([&](const std::string& name, const asts& lb) {

		if (name.empty())
		{
			LOG_W("Listener with no name skipped");
			return true;
		}

		listener* ls = listener::build(ldr, name, lb);
		if (nullptr == ls)
			return false;
		
		listners.emplace_back(ls);
		return true;
	});

	if (exit_code != 0)
	{
		exit_code = ldr.exit_code;
		exit = true;
		return;
	}

	if (listners.empty())
	{
		LOG_W("empty (or not loaded) \"listeners\" block");
		exit_code = EXIT_FAIL_NOLISTENERS;
		exit = true;
		return;
	}

	for (auto &l : listners)
		l->open();

}

engine::~engine()
{
	WSACleanup();
}

signed_t engine::working()
{
	if (exit)
	{
		for (std::unique_ptr<listener> & l : listners)
			l->stop();

		return -1;
	}


	return 1000;
}
