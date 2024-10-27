#pragma once

class engine;
class proxy;

class loader
{
	asts cfgsts;
	engine* e;
	const asts* listeners = nullptr;
	const asts* prox = nullptr;
	const asts* settings = nullptr;

public:
	const asts* nameservers = nullptr;

	using listener_loader = std::function< bool(const str::astr&, const asts&) >;
	using proxy_loader = std::function< bool(const str::astr&, const asts&) >;

	loader(engine *eng):e(eng) {}
	~loader() {}

	int exit_code = EXIT_OK;

	bool load_conf(const FN& cfp);


	bool iterate_l(listener_loader ll);
	bool iterate_p(proxy_loader pl);

	const proxy* find_proxy(const str::astr_view& pn) const;

};

