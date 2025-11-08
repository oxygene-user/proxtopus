#include "pch.h"


bool loader::load_conf(APPONLY(const FN& cfp) LIBONLY(const str::astr_view &cfg))
{
#if APP
	buffer cb;
	if (!load_buf(cfp, cb))
	{
		LOG_FATAL("no $ found", path_print_str(cfp));
		exit_code = EXIT_FAIL_NOCONFIG;
		return false;
	}

	cfgsts.load(str::astr_view((const char*)cb.data(), cb.size()));
#else
    cfgsts.load(cfg);
#endif

	// parse config file here

	if (IS_ACTUAL)
    {
        listeners = cfgsts.get(ASTR("listeners"));
        prox = cfgsts.get(ASTR("proxy"));
        nameservers = cfgsts.get(ASTR("nameservers"));
#if FEATURE_ADAPTER
        adapters = cfgsts.get(ASTR("adapters"));
#endif

        if (nullptr == listeners)
        {
			LOG_FATAL("config has no \"listeners\" block");
            exit_code = EXIT_FAIL_NOLISTENERS;
            return false;
        }
	}

	settings = cfgsts.get(ASTR("settings"));
	if (settings)
	{
        macro_context ctx(settings);

		if (IS_ACTUAL)
		{
			glb.cfg.connect_timeout = settings->get_int(ASTR("connect-timeout"), DEFAULT_CONNECT_TIMEOUT * 1000);

			signed_t ipv4 = settings->get_int(ASTR("ipv4"), 1);
			signed_t ipv6 = settings->get_int(ASTR("ipv6"), 0);
			if (ipv4 < 0) ipv4 = 0;
			if (ipv6 < 0) ipv6 = 0;
			if (ipv4 == ipv6)
			{
				LOG_FATAL("value of \"ipv4\" equal to value of \"ipv6\" (==$) (see \"settings\" block); these values must be different and greater/equal zero", ipv4);
				exit_code = EXIT_FAIL_IPV46_VALS;
				return false;
			}
			if (ipv4 == 0)
				glb.cfg.ipstack = conf::gip_only6;
			else if (ipv6 == 0)
				glb.cfg.ipstack = conf::gip_only4;
			else if (ipv4 > ipv6)
				glb.cfg.ipstack = conf::gip_prior4;
			else
				glb.cfg.ipstack = conf::gip_prior6;

			const str::astr &dnso = settings->get_string(ASTR("dns"), glb.emptys);
			if (dnso.starts_with(ASTR("int")))
			{
				glb.cfg.dnso = conf::dnso_internal;
				if (dnso.find(ASTR("|hosts"), 3) != dnso.npos)
					glb.cfg.dnso = (conf::dns_options)(glb.cfg.dnso | conf::dnso_bit_parse_hosts);
				if (dnso.find(ASTR("|sys")) != dnso.npos)
					glb.cfg.dnso = (conf::dns_options)(glb.cfg.dnso | conf::dnso_bit_use_system);
			}
			else if (dnso.starts_with(ASTR("sys")))
				glb.cfg.dnso = conf::dnso_system;


#if FEATURE_FILELOG
	#if (defined _DEBUG || defined _CRASH_HANDLER) && defined _WIN32
			glb.cfg.crash_log_file = tofn(settings->get_string(ASTR("crash_log_file"), glb.emptys));
			glb.cfg.dump_file = tofn(settings->get_string(ASTR("dump_file"), glb.emptys));
			macro_expand(&ctx, glb.cfg.crash_log_file);
			macro_expand(&ctx, glb.cfg.dump_file);
	#endif

            glb.cfg.log_file = tofn(settings->get_string(ASTR("log_file"), glb.emptys));
            macro_expand(&ctx, glb.cfg.log_file);
#endif

        }

#if FEATURE_FILELOG
		glb.cfg.debug_log_file = tofn(settings->get_string(ASTR("debug_log_file"), glb.emptys));
        macro_expand(&ctx, glb.cfg.debug_log_file);

		const str::astr& dlm = settings->get_string(ASTR("debug_log_mask"), glb.emptys);
        enum_tokens_a(tkn, dlm, '|')
        {
            if (ASTR("dns") == *tkn)
                glb.cfg.debug_log_mask |= 1ull << DLCH_DNS;
            if (ASTR("reboot") == *tkn)
                glb.cfg.debug_log_mask |= 1ull << DLCH_REBOOT;
            if (ASTR("socket") == *tkn)
                glb.cfg.debug_log_mask |= 1ull << DLCH_SOCKET;
        }
#endif

#if APP
        const str::astr& opts = settings->get_string(ASTR("options"), glb.emptys);
        if (!opts.empty())
        {
            FNARR aops;
            str::qsplit(aops, FNview(tofn(opts)));
            aops.insert(aops.begin(), FN());
            commandline cmds(std::move(aops));
            cmds.handle_options();
			LOG_N("applying of additional options from the config ($)...", opts);
        }
#endif
	}

	return true;
}

bool loader::iterate_l(listener_loader ll)
{
	if (!CHECK(listeners))
		return false;

	for (auto it = listeners->begin_skip_comments(); it; ++it)
	{
		if (it.name()[0] == '!')
		{
			LOG_N("listener {$} has been skipped", str::view(it.name(), 1));
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

	for (auto it = prox->begin_skip_comments(); it; ++it)
	{
		if (it.name()[0] == '!')
		{
			LOG_N("proxy {$} has been skipped", str::view(it.name(),1));
			continue;
		}
		if (!pl(it.name(), *it))
			return false;
	}
	return true;
}

