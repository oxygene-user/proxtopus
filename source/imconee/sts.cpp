#include "pch.h"
#include "sts.h"
#include "str_helpers.h"

template <typename TCHARACTER> sts_t<TCHARACTER>& sts_t<TCHARACTER>::add_comment(const std::basic_string_view<TCHARACTER>& comment)
{
	element* e = new element(this);
	
	auto rslt = elements.try_emplace(static_name_comment, &e->sts);
	e->name = &static_name_comment;
	if (first_element == nullptr) first_element = e; else last_element->next = e;
	last_element = e;
	e->sts.value = comment;

	return *this;
}

template <typename TCHARACTER> sts_t<TCHARACTER>& sts_t<TCHARACTER>::add_block()
{
	element* e = new element(this);
	if (first_element == nullptr) first_element = e; else last_element->next = e;
	last_element = e;
	return e->sts;
}

template <typename TCHARACTER> sts_t<TCHARACTER> &sts_t<TCHARACTER>::add_block(const std::basic_string_view<TCHARACTER> &name)
{
	element* e;
	if (!name.empty())
	{
		auto rslt = elements.try_emplace(std::basic_string<TCHARACTER>(name), nullptr);
		if (!rslt.second)
		{
			return *rslt.first->second; // already exist, return it
		}
		e = new element(this);
		e->name = &rslt.first->first;
		rslt.first->second = &e->sts;
	} else
		e = new element(this);

    if (first_element == nullptr) first_element = e; else last_element->next = e;
    last_element = e;
    return e->sts;
}

template <typename TCHARACTER> sts_t<TCHARACTER> &sts_t<TCHARACTER>::add_block(const string_type &name)
{
	element* e;
	if (!name.empty())
	{
		auto rslt = elements.try_emplace(name, nullptr);
		if (!rslt.second)
		{
			return *rslt.first->second; // already exist, return it
		}
		e = new element(this);
		e->name = &rslt.first->first;
		rslt.first->second = &e->sts;
	}
	else
		e = new element(this);

	if (first_element == nullptr) first_element = e; else last_element->next = e;
	last_element = e;
	return e->sts;
}

template <typename TCHARACTER> sts_t<TCHARACTER> &sts_t<TCHARACTER>::add_block(const string_type &name, const sts_t &oth) // create copy
{
	element* e = new element(this, oth);

	if (!name.empty())
	{
		auto rslt = elements.try_emplace(name, &e->sts);
		e->name = &rslt.first->first;
#ifdef _DEBUG
		if (!rslt.second)
			rslt.first->second = nullptr; // mark as duplicate
#endif
	}


    if (first_element == nullptr) first_element = e; else last_element->next = e;
    last_element = e;
    return e->sts;
}


template <typename TCHARACTER> int sts_t<TCHARACTER>::get_current_line(const TCHARACTER *s)
{
#ifdef _DEBUG
	if (source_basis && s)
	{
		int line = 1;
		for (const TCHARACTER *t = source_basis; t < s; t++) // calculate number of lines from start of buffer to current position
			if (*t == TCHARACTER('\r'))
			{
				if (t < s-1 && *(t+1)==TCHARACTER('\n')) t++; // assume \r\n as one line
				line++;
			}
			else if (*t == TCHARACTER('\n')) line++;
		return line;
	}
#endif
	return -1;
}


template<typename TCHARACTER> static const TCHARACTER *token_start(const TCHARACTER *t, const TCHARACTER *end)
{
#define TOKEN_CHECK(c) (c!=' ' && c!=TCHARACTER('\t') && c!=TCHARACTER('\r') && c!=TCHARACTER('\n'))
	for (;t<end-1;t++)
	{
		if (*t==TCHARACTER('/') && (*(t+1)==TCHARACTER('*') || *(t+1)==TCHARACTER('/')))
		{
			if (*(t+1)==TCHARACTER('*')) // multiline comment
			{
				for (t+=2; t<end-1; t++) // seek for comment end
					if (*t==TCHARACTER('*') && *(t+1)==TCHARACTER('/')) break;
				if (t==end-1) {LOG_W("Unended comment"); break;}
				t++;
			}
			else
			{
				for (t+=2; t<end && *t!=TCHARACTER('\r') && *t!=TCHARACTER('\n'); t++);
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

template<typename TCHARACTER> static const TCHARACTER *token_end(const TCHARACTER *&s, const TCHARACTER *end, TCHARACTER addc)
{
	const TCHARACTER *start = s, *t;
	for (; s<end && *s!=TCHARACTER('\r') && *s!=TCHARACTER('\n') && *s!=TCHARACTER('{') && *s!=addc; s++)
		if (*s == '/' && s<end-1 && (*(s+1)==TCHARACTER('*') || *(s+1)==TCHARACTER('/'))) break;
	//END_CHECK("looking for end of line")
	for (t = s-1; t>start && (*t == TCHARACTER(' ') || *t == TCHARACTER('\t')); t--);

	s = token_start(s, end); // skip comments and empty lines
	return t + 1;
}

template <typename TCHARACTER> bool sts_t<TCHARACTER>::read_sts(const TCHARACTER *&s, const TCHARACTER *end)
{
#ifdef _DEBUG
	if (!source_basis) source_basis = s;
#endif
#define END_CHECK(msg) if (s >= end) { LOG_W("Unexpected eof while " msg "(line: %i)", get_current_line(s)); return false; }
#define SKIP_SEPARATORS(additional_check) \
	while (true)\
	{\
		/*END_CHECK("skipping separators")*/if (s >= end) break;\
		if (*s!=TCHARACTER(' ') && *s!=TCHARACTER('\t') && additional_check) break;\
		s++;\
	}

	const TCHARACTER *start = s;
	if ((s = token_start(s, end)) == nullptr) return false;
	if (s > start) // keep comments if needed (only top level block)
	{
		string_view_type comment(start, (signed_t)(s-start));
		if (comment.length() >= 2)
		{
			comment = str::trim(comment);
			if (!comment.empty()) add_comment(comment);
		}
	}

	if (*s == TCHARACTER('}')) {++s; return false;}

	start = s;
	string_type name(start, (signed_t)(token_end(s, end, TCHARACTER('=')) - start));
	sts_t<TCHARACTER> & sts = add_block(name);
#ifdef _DEBUG
	sts.source_basis = source_basis;
#endif
	//skip separators
	//SKIP_SEPARATORS(*s!=TCHARACTER('\r') && *s!=TCHARACTER('\n'))
	if (!s) return false;

	switch (*s)
	{
	case TCHARACTER('='):
		s++;
		NOWARNING(4127, SKIP_SEPARATORS(true))

		if (*s == TCHARACTER('`'))
		{
			string_type v;
			start = ++s;
			while (s<end)
			{
				if (*s == TCHARACTER('`'))
				{
					if (s<end-1 && *(s+1)==TCHARACTER('`')) // quoted '`'
					{
						v.append(std::basic_string_view<TCHARACTER>(start, (signed_t)(s+1-start)));
						start = s+=2;
						continue;
					}
					else // line end
					{
						v.append(std::basic_string_view<TCHARACTER>(start, (signed_t)(s-start)));
						break;
					}
				}
				s++;
			}
			sts.set_value(v);
			END_CHECK("looking for '`'")
			s++;
			SKIP_SEPARATORS(true)
		}
		else
		{
			start = s;
			const TCHARACTER *t;
			sts.set_value(std::basic_string_view<TCHARACTER>(start, (signed_t)((t=token_end(s, end, TCHARACTER('}'))) - start)));
			string_type comment(t, (signed_t)((!s?end:s)-t));
			if (comment.length() >= 2)
			{
				str::trim(comment);
				if (!comment.empty()) add_comment(comment);
			}
			if (!s) return false;
		}
		if (!(s<end && *s==TCHARACTER('{'))) break;

		[[fallthrough]];

	case TCHARACTER('{'):
		if ((s = sts.load(s+1, end)) == nullptr) return false;
		break;

	default:
		LOG_W("'=' or '{' expected (line: %i)", get_current_line(s));
		return true;
	}
#undef SKIP_SEPARATORS
#undef END_CHECK

	return true;
}

template <typename TCHARACTER> const TCHARACTER *sts_t<TCHARACTER>::load(const TCHARACTER *data, const TCHARACTER *end)
{
	if (data)
	    while (read_sts(data, end));

	return data;
}


template <typename TCHARACTER> static void append_value(std::basic_string<TCHARACTER> &s, const std::basic_string<TCHARACTER> &value)
{
    if (value.empty())
		return;
	s.push_back('=');
	s.append(value);
}

template <typename TCHARACTER> static const std::basic_string<TCHARACTER> store_value(const std::basic_string<TCHARACTER> &value, bool allow_unquoted = true)
{
	if (allow_unquoted && value.find_first_of(CONST_STR_BUILD(TCHARACTER, " \t\r\n`{}"), 0) == std::basic_string<TCHARACTER>::npos) // any of these symbols mean string must be quoted
	{
		signed_t i = 0;
		for (; i<(signed_t)value.length()-1; i++)
			if (value[i] == TCHARACTER('/') && (value[i+1] == TCHARACTER('/') || value[i+1] == TCHARACTER('*'))) break;
		if (i >= (signed_t)value.length()-1) return value;
	}
	std::basic_string<TCHARACTER> r(value);
	str::replace_all(r, CONST_STR_BUILD(TCHARACTER,"`"), CONST_STR_BUILD(TCHARACTER,"``"));
	return std::basic_string<TCHARACTER>( CONST_STR_BUILD(TCHARACTER, "`")).append(r).append(1, '`');
}

template <typename TCHARACTER> const std::basic_string<TCHARACTER> sts_t<TCHARACTER>::store(int level) const
{
	// can be block stored as single line?
	bool one_line = true;
	if (elements.size() > 3 || level == 0 || has_comment())
		one_line = false;
	else
	{
		signed_t totalLen = value.length();
		for (element *e=first_element; e; e=e->next)
		{
			if (e->sts.first_element) {one_line = false; break;} // no - there are inner blocks detected
			totalLen += e->name->length() + e->sts.value.length();
			if (totalLen > 40/*ONE_LINE_LIMIT*/) {one_line = false; break;}
		}
	}
	// write
	string_type r, cmnt;
	for (element *e=first_element; e; e=e->next)
	{
		if (e->name == &static_name_comment)
        {
            // this is comment
			r.push_back(' ');
			r.append(e->sts.value);
            continue;
        } 

		if (e->sts.value_not_specified() && !e->sts.first_element)
        {
            // correct element skip
            if (e == last_element)
                if ( !one_line && level > 0 )
                    r.append( CONST_STR_BUILD( TCHARACTER, "\r\n" ) ).append( level - 1, '\t' );
            continue;
        }
		if (!one_line && (level > 0 || e!=first_element))
            r.append(CONST_STR_BUILD(TCHARACTER,"\r\n")).append(level, '\t');

		size_t prev_len = r.length();
		bool has_name = false;
		if (e->name)
			r.append( *e->name ), has_name = true;

		if (!e->sts.value_not_specified() && !e->sts.value.empty())
			append_value(r, store_value(e->sts.value, !one_line || e == last_element));
		else if (has_name && nullptr == e->sts.first_element)
			r.push_back('=');

		if (e->sts.has_comment(&cmnt) && e->sts.elements.size() == 1)
		{
			r.push_back(' ');
			r.append(cmnt);
		} else if (e->sts.first_element)// inner blocks?
		{
			if (r.length() > prev_len)
                r.push_back(' '); // append space if block has name or/and value
			r.push_back('{');
			r.append(e->sts.store(level + 1)).push_back('}');
		}
		if (e != last_element)
        {
            if (one_line) r.push_back(' ');
        } else
        {
            if (!one_line && level > 0)
                r.append(CONST_STR_BUILD(TCHARACTER,"\r\n")).append(level-1, '\t');
        }
	}
	return r;
}

template <typename TCHARACTER> std::basic_string<TCHARACTER> sts_t<TCHARACTER>::static_name_comment;

template class sts_t<char>;
template class sts_t<wchar_t>;

