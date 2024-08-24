#include "pch.h"

volatile bool engine::exit = false;
volatile spinlock::long3264 engine::numlisteners = 0;

engine::engine(FN && path_config)
{
	FN x = std::move(path_config);

#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif


	loader ldr(this);

	if (!ldr.load_conf(x))
	{
		exit_code = ldr.exit_code;
		exit = true;
		return;
	}

	ldr.iterate_p([&](const str::astr& name, const asts& lb) {

		if (name.empty())
		{
			LOG_W("proxy with no name skipped");
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

	ldr.iterate_l([&](const str::astr& name, const asts& lb) {

		if (name.empty())
		{
			LOG_W("listener with no name skipped");
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
#ifdef _WIN32
	WSACleanup();
#endif
}

signed_t engine::working()
{
	if (exit)
	{
		for (std::unique_ptr<listener> & l : listners)
			l->stop();

		return -1;
	}

	if (numlisteners <= 0)
	{
		LOG_E("there are no active listeners");
		return -1;
	}

	return 1000;
}
