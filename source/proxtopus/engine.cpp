#include "pch.h"

engine::engine()
{
	glb.e = this;
#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif


	loader ldr(this);

	if (!ldr.load_conf(glb.path_config))
	{
		exit_code = ldr.exit_code;
		glb.stop();
		return;
	}

	glb.path_config = FN();

	if (!glb.actual)
		return;

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
		glb.stop();
		return;
	}

	ldr.iterate_l([&](const str::astr& name, const asts& lb) {

		if (name.empty())
		{
			if (glb.listeners_need_all)
			{
				ldr.exit_code = EXIT_FAIL_NEED_ALL_LISTENERS;
				return false;
			}

			LOG_W("listener with no name skipped");
			return true;
		}

		listener::build(listners, ldr, name, lb);
		if (ldr.exit_code != EXIT_OK)
			return false;

		return true;
	});

	if (ldr.exit_code != 0)
	{
		exit_code = ldr.exit_code;
		glb.stop();
		return;
	}

	if (listners.empty())
	{
		LOG_E("empty (or not loaded) \"listeners\" block");
		exit_code = EXIT_FAIL_NOLISTENERS;
		glb.stop();
		return;
	}

    for (signed_t idpool = 1; auto & p : prox)
    {
        p->id = idpool++;
    }

	for (signed_t idpool = 1; auto &l : listners)
	{
		l->id = idpool++;
	}

	if (ldr.nameservers && glb.dns != nullptr)
	{
		glb.dns->load_serves(this, ldr.nameservers);
	}

	if (ldr.icpt)
	{
		if (!glb.icpt.load(this, ldr.icpt))
		{
			exit_code = ldr.exit_code;
            glb.stop();
            return;
		}
	}

	for (auto &l : listners)
		l->open();

}

engine::~engine()
{
	glb.e = nullptr;
#ifdef _WIN32
	WSACleanup();
#endif
}

signed_t engine::working()
{
	if (glb.is_stop())
	{
	    LOG_I("stoping...");
	    Print();
		for (std::unique_ptr<listener> & l : listners)
			l->stop();

		return -1;
	}

	if (glb.numlisteners <= 0)
	{
		LOG_E("there are no active listeners");
		Print();
		return -1;
	}

	return glb.log_muted || glb.prints.lock_read()().empty() ? 1000 : 1;
}
