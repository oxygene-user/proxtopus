#pragma once


class engine
{

	std::vector<std::unique_ptr<listener>> listners;
	std::vector<std::unique_ptr<proxy>> prox;

public:

	int exit_code = EXIT_OK;

	engine();
	~engine();

	signed_t working();

	const proxy* find_proxy(const str::astr_view& pn) const
	{
		for (auto& p : prox)
			if (p->get_name() == pn)
				return p.get();
		return nullptr;
	}

};

inline const proxy* loader::find_proxy(const str::astr_view& pn) const
{
	return e->find_proxy(pn);
}
