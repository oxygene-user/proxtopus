#include "pch.h"
#include "sts.h"
#include "str_helpers.h"

template<typename CHX> sts_t<CHX>::element::element()
{
    static_assert(sizeof(stsd) >= sizeof(sts_t<CHX>));
    new (&sts()) sts_t<CHX>();
}

template<typename CHX> sts_t<CHX>::element::element(sts_t<CHX>* parnt)
{
    new (&sts()) sts_t<CHX>(parnt);
}
template<typename CHX> sts_t<CHX>::element::element(sts_t<CHX>* parnt, const sts_t<CHX>& oth)
{
    new (&sts()) sts_t<CHX>(parnt, oth);
}

template<typename CHX> sts_t<CHX>::element::~element()
{
    static_assert(sizeof(stsd) >= sizeof(sts_t<CHX>));
    sts().~sts_t<CHX>();
}

template <typename CH> sts_t<CH>& sts_t<CH>::add_comment(const string_view_type& comment)
{
	element* e = NEW element(this);

	/*auto rslt =*/ elements.insert(std::pair(static_name_comment, e));
	
	e->name = &static_name_comment;
	if (first_element == nullptr) first_element = e; else last_element->next = e;
	last_element = e;
	e->sts().value = string_type(comment);

	return *this;
}

template <typename CH> sts_t<CH>& sts_t<CH>::add_block()
{
	element* e = NEW element(this);
	if (first_element == nullptr) first_element = e; else last_element->next = e;
	last_element = e;
	return e->sts();
}

template <typename CH> sts_t<CH> &sts_t<CH>::add_block(const string_view_type &name)
{
	element* e = NEW element(this);
	if (!name.empty())
	{
		auto rslt = elements.insert(std::pair(name, e));
		e->name = &rslt.first->first;
	}

    if (first_element == nullptr) first_element = e; else last_element->next = e;
    last_element = e;
    return e->sts();
}

template <typename CH> sts_t<CH> &sts_t<CH>::add_block(const string_type &name)
{
	element* e = NEW element(this);
	if (!name.empty())
	{
		auto rslt = elements.insert(std::pair(name, e));
        e->name = &rslt.first->first;
	}

	if (first_element == nullptr) first_element = e; else last_element->next = e;
	last_element = e;
	return e->sts();
}

template <typename CH> sts_t<CH> &sts_t<CH>::add_block(const string_type &name, const sts_t &oth) // create copy
{
	element* e = NEW element(this, oth);

	if (!name.empty())
	{
		auto rslt = elements.insert(std::pair(name, e));
        e->name = &rslt.first->first;
	}

    if (first_element == nullptr) first_element = e; else last_element->next = e;
    last_element = e;
    return e->sts();
}


template <typename CH> int sts_t<CH>::get_current_line([[maybe_unused]] const CH *s)
{
#ifdef _DEBUG
	if (source_basis && s)
	{
		int line = 1;
		for (const CH *t = source_basis; t < s; t++) // calculate number of lines from start of buffer to current position
			if (*t == CH('\r'))
			{
				if (t < s-1 && *(t+1)==CH('\n')) t++; // assume \r\n as one line
				line++;
			}
			else if (*t == CH('\n')) line++;
		return line;
	}
#endif
	return -1;
}


template<typename CH> static const CH *token_start(const CH *t, const CH *end)
{
#define TOKEN_CHECK(c) (c!=' ' && c!=CH('\t') && c!=CH('\r') && c!=CH('\n'))
	for (;t<end-1;t++)
	{
		if (*t==CH('/') && (*(t+1)==CH('*') || *(t+1)==CH('/')))
		{
			if (*(t+1)==CH('*')) // multiline comment
			{
				for (t+=2; t<end-1; t++) // seek for comment end
					if (*t==CH('*') && *(t+1)==CH('/')) break;
				if (t==end-1) {LOG_W("unclosed comment"); break;}
				t++;
			}
			else
			{
				for (t+=2; t<end && *t!=CH('\r') && *t!=CH('\n'); t++);
				//t--;
			}
			continue;
		}
		if (TOKEN_CHECK(*t)) return t;
	}
	if (t<end && TOKEN_CHECK(*t)) return t;
#undef TOKEN_CHECK
	return nullptr;
}

template<typename CH> static const CH *token_end(const CH *&s, const CH *end, CH addc)
{
	const CH *start = s, *t;
	for (; s<end && *s!=CH('\r') && *s!=CH('\n') && *s!=CH('{') && *s!=addc; s++)
		if (*s == '/' && s<end-1 && (*(s+1)==CH('*') || *(s+1)==CH('/'))) break;
	//END_CHECK("looking for end of line")
	for (t = s-1; t>start && (*t == CH(' ') || *t == CH('\t')); t--);

	s = token_start(s, end); // skip comments and empty lines
	return t + 1;
}

template <typename CH> bool sts_t<CH>::read_sts(const CH *&s, const CH *end)
{
#ifdef _DEBUG
	if (!source_basis) source_basis = s;
#endif
#define END_CHECK(msg) if (s >= end) { LOG_W("unexpected eof while " msg "(line: $)", get_current_line(s)); return false; }

	const CH *start = s;
	if ((s = token_start(s, end)) == nullptr) return false;
	if (s > start) // keep comments if needed (only top level block)
	{
		string_view_type comment(start, s-start);
		if (comment.length() >= 2)
		{
			comment = str::trim(comment);
			if (!comment.empty()) add_comment(comment);
		}
	}

	if (*s == CH('}')) {++s; return false;}

	start = s;
	string_type name(start, token_end(s, end, CH('=')) - start);
	sts_t<CH> & sts = add_block(name);
#ifdef _DEBUG
	sts.source_basis = source_basis;
#endif
	if (!s) return false;

	switch (*s)
	{
	case CH('='):
		s++;

		// skip separators
        for (;s < end; ++s)
        {
            if (*s != CH(' ') && *s != CH('\t'))
				break;
        }

		if (*s == CH('`'))
		{
			string_type v;
			start = ++s;
			while (s<end)
			{
				if (*s == CH('`'))
				{
					if (s<end-1 && *(s+1)==CH('`')) // quoted '`'
					{
						v.append(string_view_type(start, s+1-start));
						start = s+=2;
						continue;
					}
					else // line end
					{
						v.append(string_view_type(start, s-start));
						break;
					}
				}
				s++;
			}
			sts.set_value(v);
			END_CHECK("looking for '`'")
			s++;

            // skip separators
            for (; s < end; ++s)
            {
                if (*s != CH(' ') && *s != CH('\t'))
                    break;
            }
		}
		else
		{
			start = s;
			const CH *t;
			sts.set_value(string_view_type(start, (t=token_end(s, end, CH('}'))) - start));
			string_type comment(t, (!s?end:s)-t);
			if (comment.length() >= 2)
			{
				str::trim(comment);
				if (!comment.empty()) add_comment(comment);
			}
			if (!s) return false;
		}
		if (!(s<end && *s==CH('{'))) break;

		[[fallthrough]];

	case CH('{'):
		if ((s = sts.load(s+1, end)) == nullptr) return false;
		break;

	default:
		LOG_W("'=' or '{' expected (line: $)", get_current_line(s));
		return true;
	}
#undef END_CHECK

	return true;
}

template <typename CH> const CH *sts_t<CH>::load(const CH *data, const CH *end)
{
	if (data)
	    while (read_sts(data, end));

	return data;
}


template <typename CH> static void append_value(str::xstr<CH> &s, const str::xstr<CH> &value)
{
    if (value.empty())
		return;
	s.push_back('=');
	s.append(value);
}

template <typename CH> static const str::xstr<CH> store_value(const str::xstr<CH> &value, bool allow_unquoted = true)
{
	if (allow_unquoted && value.find_first_of(XSTR(CH, " \t\r\n`{}"), 0) == str::xstr<CH>::npos) // any of these symbols mean string must be quoted
	{
		signed_t i = 0;
		for (; i < SIGNED % value.length()-1; i++)
			if (value[i] == CH('/') && (value[i+1] == CH('/') || value[i+1] == CH('*'))) break;
		if (i >= SIGNED % value.length()-1) return value;
	}
	str::xstr<CH> r(value);
	str::replace_all(r, XSTR(CH,"`"), XSTR(CH,"``"));
	return str::xstr<CH>(XSTR(CH, "`")).append(r).append(1, '`');
}

template <typename CH> const str::xstr<CH> sts_t<CH>::store(int level) const
{
	// can be block stored as single line?
	bool one_line = true;
	if (elements.size() > 3 || level == 0 || has_comment())
		one_line = false;
	else
	{
		signed_t totalLen = as_string(string_view_type()).length();
		for (element* e = first_element; e; e=e->next)
		{
			if (e->sts().first_element) { one_line = false; break; } // no - there are inner blocks detected
			totalLen += e->name->length() + e->sts().as_string(string_view_type()).length();
			if (totalLen > 40/*ONE_LINE_LIMIT*/) {one_line = false; break;}
		}
	}
	// write
	string_type r, cmnt;
	for (element* e = first_element; e; e=e->next)
	{
		if (e->name == &static_name_comment)
        {
            // this is comment
			r.push_back(' ');
			r.append(e->sts().as_string(string_view_type()));
            continue;
        }

		if (e->sts().value_not_specified() && !e->sts().first_element)
        {
            // correct element skip
            if (e == last_element)
                if ( !one_line && level > 0 )
                    r.append( XSTR( CH, "\r\n" ) ).append( level - 1, '\t' );
            continue;
        }
		if (!one_line && (level > 0 || e!=first_element))
            r.append(XSTR(CH,"\r\n")).append(level, '\t');

		size_t prev_len = r.length();
		bool has_name = false;
		if (e->name)
			r.append( *e->name ), has_name = true;

		if (auto s = e->sts().as_string(string_view_type()); !s.empty())
			append_value(r, store_value(s, !one_line || e == last_element));
		else if (has_name && nullptr == e->sts().first_element)
			r.push_back('=');

		if (e->sts().has_comment(&cmnt) && e->sts().elements.size() == 1)
		{
			r.push_back(' ');
			r.append(cmnt);
		} else if (e->sts().first_element)// inner blocks?
		{
			if (r.length() > prev_len)
                r.push_back(' '); // append space if block has name or/and value
			r.push_back('{');
			r.append(e->sts().store(level + 1)).push_back('}');
		}
		if (e != last_element)
        {
            if (one_line) r.push_back(' ');
        } else
        {
            if (!one_line && level > 0)
                r.append(XSTR(CH,"\r\n")).append(level-1, '\t');
        }
	}
	return r;
}

template class sts_t<char>;
// no need
//template class sts_t<wchar>;

