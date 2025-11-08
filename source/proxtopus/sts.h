/*
    simple text storage
*/
#pragma once

#include <string>
#include <unordered_map>
#include <variant>

template<typename CH> class sts_t
{
    using string_type = str::xstr<CH>;
    using string_view_type = str::xstr_view<CH>;

#ifndef ANDROID
#define STS_DOUBLE_ENABLE 1
    using value_type = std::variant<bool, str::astr, signed_t, double>;
#else
#define STS_DOUBLE_ENABLE 0
    using value_type = std::variant<bool, str::astr, signed_t>;
#endif


#if defined(ARCH_ARM) && defined(ARCH_32BIT)
#define SZROUND(x) (((x)+7)&(~(7)))
#else
#define SZROUND(x) (x)
#endif

    enum
    {
#ifdef _DEBUG
        SIZEADD = sizeof(void *),
#else
        SIZEADD = 0,
#endif
        MYSIZE = SZROUND(sizeof(tools::shashmap<CH, sts_t<CH>*>)) + SZROUND(sizeof(value_type)) + SZROUND(sizeof(void*) * 3 + SIZEADD),
    };

    struct element
    {
        element();
        element(sts_t<CH>* parnt);
        element(sts_t<CH>* parnt, const sts_t<CH>& oth);

        ~element();

        const sts_t<CH>::string_type* name = nullptr; // if name == &static_name_comment, then comment
        u8 stsd[MYSIZE];
        element* next = nullptr;

        sts_t& sts() { return ref_cast<sts_t>(stsd); };
        const sts_t& sts() const { return ref_cast<sts_t>(stsd); };

    };

    enum
    {
        INOTHING = 0,
        ISTRING = 1,
        IINT = 2,
#if STS_DOUBLE_ENABLE
        IDOUBLE = 3,
#endif
    };

    tools::shashmap<CH, element*> elements;
    value_type value = false;

    element* first_element = nullptr, * last_element = nullptr; // list with original order
    sts_t* parent = nullptr;
    inline static string_type static_name_comment{};

#ifdef _DEBUG
    const CH* source_basis = nullptr;
#endif

    int get_current_line(const CH *s);

    element* get_el(const string_view_type& n) const
    {
        auto it = elements.find(n);
        return it != elements.end() ? it->second : nullptr;
    }

public:
    sts_t() {}
    explicit sts_t(sts_t *parent) : parent(parent) {}
    sts_t(sts_t *parent, const sts_t &oth): value(oth.value), parent(parent)
    {
        for (auto it = oth.begin_with_comments(); it; ++it)
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
        value = std::move(oth.value);

        for (element* e = first_element, *next; e; e = next)
        {
            next = e->next;
            delete e;
        }
        first_element = oth.first_element; oth.first_element = nullptr;
        last_element = oth.last_element; oth.last_element = nullptr;
        elements = std::move(oth.elements);

        return *this;
    }

    sts_t& operator=(const sts_t &oth)
    {
        clear();
        value = oth.value;

        for (auto it = oth.begin_with_comments(); it; ++it)
            add_block(it.name(), *it);

        return *this;
    }

    template<typename RNMR> sts_t& copy(const sts_t &oth, const RNMR& rnmr)
    {
        clear();
        value = oth.value;

        for (auto it = oth.begin_with_comments(); it; ++it)
            add_block(rnmr(it.name()), *it);

        return *this;
    }

    bool value_not_specified() const
    {
        return value.index() == INOTHING;
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
        value = false;
        elements.clear();
    }

    class iterator
    {
        friend class sts_t;
        element *el;
    public:
        const string_type name() const {return el ? *el->name : string_type();}
        bool is_comment() const { return el ? (el->name == &static_name_comment) : false; }
        operator sts_t*() {return el ? &el->sts() : nullptr;}
        sts_t *operator->() {ASSERT(el); return &el->sts();}
        void operator++() {el = el->next;}
        bool operator!=(const iterator &it) const {return el != it.el;}
    };

    class iterator_sc
    {
        friend class sts_t;
        element * el;
        bool is_comment() const { return el ? (el->name == &static_name_comment) : false; }
    public:
        const string_type name() const { return el ? *el->name : string_type(); }
        operator sts_t* () { return el ? &el->sts() : nullptr; }
        sts_t* operator->() { ASSERT(el); return &el->sts(); }
        bool operator!=(const iterator& it) const { return el != it.el; }
        bool operator!=(const iterator_sc& it) const { return el != it.el; }
        void operator++() {
            do
            {
                el = el->next;
            } while (el && is_comment());
        }
        iterator_sc& skip_comments()
        {
            if (is_comment())
                ++(*this);
            return *this;
        }
    };

    class iterator_n
    {
        friend class sts_t;
        element* fel;
        element* el;
        
        iterator_n(element* e) :fel(e), el(e) {}
    public:

        const string_type name() const { return el ? *el->name : string_type(); }
        operator sts_t* () { return el ? &el->sts() : nullptr; }
        sts_t* operator->() { ASSERT(el); return &el->sts(); }
        bool operator!=(const iterator& it) const { return el != it.el; }
        bool operator!=(const iterator_sc& it) const { return el != it.el; }
        bool operator!=(const iterator_n& it) const { return el != it.el; }
        void operator++() {
            el = el->next;
            if (el && (*el->name) != (*fel->name))
                el = nullptr;
        }
    };

    iterator begin_with_comments() const {iterator it; it.el=first_element; return it;}
    iterator end() const {iterator it; it.el = nullptr; return it;}

    iterator_sc begin_skip_comments() const { iterator_sc it; it.el = first_element; return it.skip_comments(); }
    iterator_n begin(const string_view_type &n) const { return iterator_n(get_el(n)); }

    bool present( const sts_t * sts ) const
    {
        for (auto it = begin_skip_comments(); it; ++it)
            if (it == sts) return true;
        return false;
    }

    bool present_r(const sts_t * sts) const
    {
        for (auto it = begin_skip_comments(); it; ++it)
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
            return &it->second->sts();
        return nullptr;
    }
    const sts_t *get(const string_view_type &name) const {return const_cast<sts_t*>(this)->get(name);}

    sts_t *get(signed_t index)
    {
        for (auto it = begin_skip_comments(); it; ++it, --index)
            if (index == 0)
                return it;
        return nullptr;
    }

    sts_t &set(const string_view_type &name)
    {
        if (sts_t *sts = get(name)) return *sts;
        return add_block( string_type(name) );
    }

    const string_type& as_string(const string_type &def) const
    {
        if (value.index() == ISTRING) return std::get<string_type>(value);
        return def;
    }

    string_type as_string(const string_view_type &def = string_view_type()) const
    {
        switch (value.index())
        {
        case ISTRING:
            return std::get<string_type>(value);
        case IINT:
        {
            string_type s;
            return str::append_num(s, std::get<signed_t>(value), 0);
        }
#if STS_DOUBLE_ENABLE
        case IDOUBLE:
        {
            string_type s;
            return str::__assign(s, std::to_string(std::get<double>(value)));
        }
#endif
        default:
            return string_type(def);
        }
    }

#if STS_DOUBLE_ENABLE
    double as_double(double def = 0.0) const
    {
        switch (value.index())
        {
        case ISTRING:
        {
            const string_type& str = std::get<string_type>(value);
            double rv;
            auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), rv);
            return ec == std::errc() ? rv : def;
        }
        case IINT:
            return (double)std::get<signed_t>(value);
        case IDOUBLE:
            return std::get<double>(value);
        default:
            return def;
        }
    }
    double get_double(const string_view_type &name, double def = 0.0) const
    {
        if (const sts_t *sts = get(name))
            return sts->as_double(def);
        return def;
    }
#endif

    template<std::integral INT> INT as_int(INT def = 0) const
    {
        switch (value.index())
        {
        case ISTRING:
        {
            const string_type& str = std::get<string_type>(value);
            return str::parse_int<INT, char>(str::view(str), def);
        }
        case IINT:
            return static_cast<INT>(std::get<signed_t>(value));
#if STS_DOUBLE_ENABLE
        case IDOUBLE:
            return (INT)std::get<double>(value);
#endif
        default:
            return def;
        }
    }

    const string_type& get_string(const string_view_type &name, const string_type &def = string_type()) const
    {
        if (const sts_t *sts = get(name))
            return sts->as_string(def);
        return def;
    }

    template <typename CR> void get_comments(const CR& cr) const
    {
        const str::xstr<CH> *c = nullptr;
        for (element *e = first_element; e; e = e->next)
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

    template<std::integral INT> INT get_int(const string_view_type& name, INT def = 0) const
    {
        if (const sts_t* sts = get(name))
            return sts->as_int(def);
        return def;
    }
    bool get_bool(const string_view_type& name, bool def = false) const { return get_int(name, def) != 0; }

    void get_value( string_type &val, const string_type &name, const string_type &def )
    {
        val = get_string( name, def );
    }
    template <class T> void get_value( T &val, const string_type &name, const T &def = T() )
    {
        if constexpr (std::is_integral_v<T>)
        {
            val = get_int(name, def);
        }
#if STS_DOUBLE_ENABLE
        else if constexpr (std::is_floating_point_v<T>)
        {
            val = get_double(name, def);
        }
#endif
        else if constexpr (std::is_same_v<T, string_type>)
        {
            val = get_string(name, def);
        }
        else
        {
            val = def;
        }
        
    }

    void as_value( string_type &val, const string_type &def )
    {
        val = as_string( def );
    }
    template <class T> void as_value( T &val, const T &def = T() )
    {
        if constexpr (std::is_integral_v<T>)
        {
            val = as_int(def);
        }
#if STS_DOUBLE_ENABLE
        else if constexpr (std::is_floating_point_v<T>)
        {
            val = as_double(def);
        }
#endif
        else if constexpr (std::is_same_v<T, string_type>)
        {
            val = as_string(def);
        }
        else
        {
            val = def;
        }

    }

    sts_t& set_value(const string_view_type& val)
    {
        value = string_type(val);
        return *this;
    }
    sts_t& set_value(const string_type& val)
    {
        value = val;
        return *this;
    }

#if 0
    template<typename T> sts_t& set_value(const T &val)
    {
        value = val;
        return *this;
    }
#endif

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

#if 0
template <typename CHX> class stsreader
{
    const CHX *data, *end;
    sts_t<CHX> sts;
public:

    stsreader(const CHX *data, const CHX *end) : data(data), end(end) {operator++();}
    stsreader(const CHX *data, int size)  : data(data), end(data+size) {operator++();}
    explicit operator bool() const {return !sts.empty();}
    const str::xstr<CHX> name() const {return sts.begin().name();}
    operator   sts_t<CHX>*() {return sts.begin();}
    sts_t<CHX> *operator->() {return sts.begin();}
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
#endif

typedef sts_t<char> asts;
//typedef sts_t<wchar> wsts; // no need
