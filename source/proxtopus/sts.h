/*
    simple text storage
*/
#pragma once

#include <string>
#include <unordered_map>

template<class T> inline void SWAP(T& first, T& second)
{
	T temp = std::move(first);
	first = std::move(second);
	second = std::move(temp);
}

template <typename CH=char> class sts_t
{
    typedef str::xstr<CH> string_type;
	typedef str::xstr_view<CH> string_view_type;

	static string_type static_name_comment;

    struct element;
	sts_t *parent = nullptr;
    element *first_element = nullptr, *last_element = nullptr; // list with original order
	mutable double double_value_cache = -DBL_MAX;
    string_type value;
	tools::shashmap<CH, sts_t*> elements;
#ifdef _DEBUG
	const CH* source_basis = nullptr;
#endif

	int get_current_line(const CH *s);

	template<typename T> void _to_string(str::astr& v, T t)
	{
		v = std::to_string(t);
	}
	template<typename T> void _to_string(str::wstr& v, T t)
	{
		v = std::to_wstring(t);
	}

public:

    sts_t(sts_t *parent) : parent(parent) {}
	sts_t() {}

    sts_t(sts_t *parent, const sts_t &oth): parent(parent), double_value_cache(oth.double_value_cache), value(oth.value)
    {
        for (auto it = oth.begin(); it; ++it)
            add_block(it.name(), *it);
    }

	~sts_t()
	{
		for (element *e=first_element, *next; e; e=next)
		{
			next = e->next;
			delete e;
		}
	}

	bool has_comment(string_type *comment = nullptr) const
	{
		auto sss = get(static_name_comment);
		if (sss && comment)
			(*comment) = sss->as_string();
		return sss != nullptr;
	}


    sts_t& operator=(sts_t &&oth) noexcept
    {
        value = oth.value;
        SWAP(double_value_cache, oth.double_value_cache);
        SWAP(first_element, oth.first_element);
        SWAP(last_element, oth.last_element);
        elements = std::move(oth.elements);
        return *this;
    }

    sts_t& operator=(const sts_t &oth)
    {
        clear();
        value = oth.value;
		double_value_cache = oth.double_value_cache;

        for (auto it = oth.begin(); it; ++it)
            add_block(it.name(), *it);

        return *this;
    }

    template<typename RNMR> sts_t& copy(const sts_t &oth, const RNMR& rnmr)
    {
        clear();
        value = oth.value;
        double_value_cache = oth.double_value_cache;

        for (auto it = oth.begin(); it; ++it)
            add_block(rnmr(it.name()), *it);

        return *this;
    }

    bool value_not_specified() const
    {
        return double_value_cache == DBL_MAX; //-V550
    }
	bool is_empty() const {return first_element == nullptr;}
    bool has_elements() const { return first_element != nullptr; }

	void clear()
	{
		for (element *e=first_element, *next; e; e=next)
		{
			next = e->next;
			delete e;
		}
		first_element = last_element = nullptr;
		value.clear();
		double_value_cache = DBL_MAX;
		elements.clear();
	}

	class iterator
	{
		friend class sts_t;
		element *el;
	public:
		const string_type name() const {return el ? *el->name : string_type();}
		bool is_comment() const { return el ? (el->name == &static_name_comment) : false; }
		operator sts_t*() {return el ? &el->sts : nullptr;}
		sts_t *operator->() {ASSERT(el); return &el->sts;}
		void operator++() {el = el->next;}
        bool operator!=(const iterator &it) const {return el != it.el;}
	};
	iterator begin() const {iterator it; it.el=first_element; return it;}
    iterator end() const {iterator it; it.el = nullptr; return it;}

    bool present( const sts_t * sts ) const
    {
        for (auto it = begin(); it; ++it)
            if (it == sts) return true;
        return false;
    }

    bool present_r(const sts_t * sts) const
    {
        for (auto it = begin(); it; ++it)
            if (it == sts)
                return true;
            else
                if (it->present_r(sts))
                    return true;
        return false;
    }

	sts_t *get(const string_view_type &name)
	{
		auto it = elements.find(name);
		if (it != elements.end())
		{
#ifdef _DEBUG
			if (it->second) return it->second;

			//WARNING("duplicate block get attempt");
			__debugbreak();

			for (element *e=first_element; e; e=e->next)
				if (*e->name == name) return &e->sts;
#else
			return it->second;
#endif
		}
		return nullptr;
	}
	const sts_t *get(const string_view_type &name) const {return const_cast<sts_t*>(this)->get(name);}

    sts_t *get(signed_t index)
    {
        for (auto it = begin(); it; ++it, --index)
            if (index == 0)
                return it;
        return nullptr;
    }

	sts_t &get_safe(const string_view_type &name)
	{
		if (sts_t *sts = get(name)) return *sts;
		static sts_t defsts;
		return defsts;
	}
	const sts_t &get_safe(const string_view_type &name) const {return const_cast<sts_t*>(this)->get_safe(name);}

	sts_t &set(const string_view_type &name)
	{
		if (sts_t *sts = get(name)) return *sts;
		return add_block( string_type(name) );
	}

	const string_type& as_string(const string_type &def) const
	{
		if (value_not_specified()) return def;
		return value;
	}

    string_type as_string(const string_view_type &def = string_view_type()) const
    {
        if (value_not_specified())
			return string_type(def);
        return value;
    }

	double as_double(double def = 0.0) const
	{
		if (value_not_specified()) return def;
		if (double_value_cache == -DBL_MAX) double_value_cache = std::stod(value); //-V550
		return double_value_cache;
	}
	int as_int(int def = 0) const {return (int)as_double(def);}

	const string_type& get_string(const string_view_type &name, const string_type &def = string_type()) const
	{
		if (const sts_t *sts = get(name))
			return sts->as_string(def);
		return def;
	}

	template <typename CR> void get_comments(const CR& cr) const
	{
		const str::xstr<CH> *c = nullptr;
		for (element* e = first_element; e; e = e->next)
		{
			if (e->sts.value.length() >= 2 && e->sts.value[0] == '/' && e->sts.value[1] == '/')
			{
				// comment
				if (c)
					cr(*c, e->sts.value);
				c = nullptr;
			}
			c = e->name;
		}
	}

	double get_double(const string_view_type &name, double def = 0.0) const
	{
		if (const sts_t *sts = get(name))
			return sts->as_double(def);
		return def;
	}
	signed_t get_int(const string_view_type &name, signed_t def = 0) const {return (signed_t)get_double(name, (double)def);}
	bool get_bool(const string_view_type& name, bool def = false) const { return (signed_t)get_double(name, def) != 0; }

    void get_value( string_type &val, const string_type &name, const string_type &def )
    {
        val = get_string( name, def );
    }
    template <class T> void get_value( T &val, const string_type &name, const T &def = T() )
	{
		val = (T)get_double(name, def);
	}

    void as_value( string_type &val, const string_type &def )
    {
        val = as_string( def );
    }
    template <class T> void as_value( T &val, const T &def = T() )
	{
		val = (T)as_double(def);
	}

	sts_t&set_value(const string_view_type &val)
	{
		value = val;
		double_value_cache = -DBL_MAX;
		return *this;
	}
	sts_t& set_value(const string_type &val)
	{
		value = val;
		double_value_cache = -DBL_MAX;
		return *this;
	}
	sts_t& set_value(double val)
	{
		_to_string(value, val);
		double_value_cache = val;
		return *this;
	}
	sts_t& set_value(float val)
	{
		_to_string(value, val);
		double_value_cache = val;
		return *this;
	}
	template<typename T> sts_t& set_value(T val)
	{
		_to_string(value, val);
		double_value_cache = (double)val;
		return *this;
	}

    sts_t *get_parent() { return parent; }
    const sts_t *get_parent() const { return parent; }

	sts_t& add_comment(const string_view_type& comment); // return *this
	sts_t& add_block();
    sts_t &add_block(const string_view_type &name);
	sts_t &add_block(const string_type &name);
    sts_t &add_block(const string_type &name, const sts_t &oth); // create copy

	bool read_sts(const CH *&s, const CH *end);
	const CH *load(const CH *data, const CH *end);
	const CH *load(const string_view_type &data) {return load(data.data(), data.data() + data.length()); }
	const CH *load(const string_type &str) {return load(string_view_type(str));}
	const string_type store(int=0) const;
};

template <typename CH> struct sts_t<CH>::element
{
    const string_type *name = nullptr; // if name == &static_name_comment, then comment
    sts_t<CH> sts;
    element *next = nullptr;
    element(sts_t<CH> *parnt):sts(parnt) {}
    element(sts_t<CH> *parnt, const sts_t<CH> &oth):sts(parnt, oth) {}
};

template <typename CH> class stsreader
{
	const CH *data, *end;
	sts_t<CH> sts;
public:

	stsreader(const CH *data, const CH *end) : data(data), end(end) {operator++();}
	stsreader(const CH *data, int size)  : data(data), end(data+size) {operator++();}
	explicit operator bool() const {return !sts.empty();}
	const str::xstr<CH> name() const {return sts.begin().name();}
	operator   sts_t<CH>*() {return sts.begin();}
	sts_t<CH> *operator->() {return sts.begin();}
	void operator++()
	{
		sts.clear();
		if (data) while (sts.read_sts(data, end))
		{
			if (!ASSERT(&*sts.begin())) continue;
			break;
		}
	}
};

typedef sts_t<char> asts;
// no need
//typedef sts_t<wchar> wsts;
