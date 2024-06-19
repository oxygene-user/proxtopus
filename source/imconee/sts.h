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

template <typename TCHARACTER=char> class sts_t
{
    typedef std::basic_string<TCHARACTER> string_type;
	typedef std::basic_string_view<TCHARACTER> string_view_type;

	static string_type static_name_comment;

    struct element;
	sts_t *parent = nullptr;
    element *first_element = nullptr, *last_element = nullptr; // list with original order
	mutable double double_value_cache = -DBL_MAX;
    string_type value;
	std::unordered_map<string_type, sts_t*> elements;
#ifdef _DEBUG
	const TCHARACTER* source_basis = nullptr;
#endif

	int get_current_line(const TCHARACTER *s);

	template<typename T> void _to_string(std::string& v, T t)
	{
		v = std::to_string(t);
	}
	template<typename T> void _to_string(std::wstring& v, T t)
	{
		v = std::to_wstring(t);
	}

public:

    sts_t(sts_t *parent) : parent(parent) {}
	sts_t() {}

    sts_t(sts_t *parent, const sts_t &oth): parent(parent), value(oth.value), double_value_cache(oth.double_value_cache)
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

	sts_t *get(const std::basic_string_view<TCHARACTER> &name)
	{
		auto it = elements.find(std::basic_string<TCHARACTER>(name));
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
	const sts_t *get(const std::basic_string_view<TCHARACTER> &name) const {return const_cast<sts_t*>(this)->get(name);}

    sts_t *get(signed_t index)
    {
        for (auto it = begin(); it; ++it, --index)
            if (index == 0)
                return it;
        return nullptr;
    }

	sts_t &get_safe(const std::basic_string_view<TCHARACTER> &name)
	{
		if (sts_t *sts = get(name)) return *sts;
		static sts_t defsts;
		return defsts;
	}
	const sts_t &get_safe(const std::basic_string_view<TCHARACTER> &name) const {return const_cast<sts_t*>(this)->get_safe(name);}

	sts_t &set(const std::basic_string_view<TCHARACTER> &name)
	{
		if (sts_t *sts = get(name)) return *sts;
		return add_block( string_type(name) );
	}

	string_type as_string(const string_type &def) const
	{
		if (value_not_specified()) return def;
		return value;
	}

    string_type as_string(const std::basic_string_view<TCHARACTER> &def = std::basic_string_view<TCHARACTER>()) const
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

	string_type get_string(const std::basic_string_view<TCHARACTER> &name, const string_type &def = string_type()) const
	{
		if (const sts_t *sts = get(name))
			return sts->as_string(def);
		return def;
	}

	template <typename CR> void get_comments(const CR& cr) const
	{
		const std::basic_string<TCHARACTER> *c = nullptr;
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

	double get_double(const std::basic_string_view<TCHARACTER> &name, double def = 0.0) const
	{
		if (const sts_t *sts = get(name))
			return sts->as_double(def);
		return def;
	}
	signed_t get_int(const std::basic_string_view<TCHARACTER> &name, signed_t def = 0) const {return (signed_t)get_double(name, (double)def);}
	bool get_bool(const std::basic_string_view<TCHARACTER>& name, bool def = false) const { return (signed_t)get_double(name, def) != 0; }

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

	sts_t&set_value(const std::basic_string_view<TCHARACTER> &val)
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

	sts_t& add_comment(const std::basic_string_view<TCHARACTER>& comment); // return *this
	sts_t& add_block();
    sts_t &add_block(const std::basic_string_view<TCHARACTER> &name);
	sts_t &add_block(const string_type &name);
    sts_t &add_block(const string_type &name, const sts_t &oth); // create copy

	bool read_sts(const TCHARACTER *&s, const TCHARACTER *end);
	const TCHARACTER *load(const TCHARACTER *data, const TCHARACTER *end);
	const TCHARACTER *load(const std::basic_string_view<TCHARACTER> &data) {return load(data.data(), data.data() + data.length()); }
	const TCHARACTER *load(const string_type &str) {return load(std::basic_string_view<TCHARACTER>(str));}
	const string_type store(int=0) const;
};

template <typename TCHARACTER> struct sts_t<TCHARACTER>::element
{
    const string_type *name = nullptr; // if name == &static_name_comment, then comment
    sts_t<TCHARACTER> sts;
    element *next = nullptr;
    element(sts_t<TCHARACTER> *parnt):sts(parnt) {}
    element(sts_t<TCHARACTER> *parnt, const sts_t<TCHARACTER> &oth):sts(parnt, oth) {}
};

template <typename TCHARACTER> class stsreader
{
	const TCHARACTER *data, *end;
	sts_t<TCHARACTER> sts;
public:

	stsreader(const TCHARACTER *data, const TCHARACTER *end) : data(data), end(end) {operator++();}
	stsreader(const TCHARACTER *data, int size)  : data(data), end(data+size) {operator++();}
	explicit operator bool() const {return !sts.empty();}
	const std::basic_string<TCHARACTER> name() const {return sts.begin().name();}
	operator   sts_t<TCHARACTER>*() {return sts.begin();}
	sts_t<TCHARACTER> *operator->() {return sts.begin();}
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
typedef sts_t<wchar_t> wsts;
