#pragma once

class engine;
class proxy;

class loader
{
	asts cfg;
	engine* e;
	const asts* listeners = nullptr;
	const asts* prox = nullptr;

public:

	using listener_loader = std::function< bool(const std::string&, const asts&) >;
	using proxy_loader = std::function< bool(const std::string&, const asts&) >;

	loader(engine *eng):e(eng) {}
	~loader() {}

	int exit_code = EXIT_OK;

	bool load_conf(const std::wstring& cfp);


	bool iterate_l(listener_loader ll);
	bool iterate_p(proxy_loader pl);

	const proxy* find_proxy(const std::string_view& pn) const;

};
