#pragma once

class engine
{
	lcoll listners;
	api_collection_uptr<proxy> prox;

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

	const lcoll& l() const { return listners; }
	const api_collection_uptr<proxy>& p() const { return prox; }
};

inline const proxy* loader::find_proxy(const str::astr_view& pn) const
{
	return e->find_proxy(pn);
}
