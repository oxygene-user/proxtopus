#include "pch.h"

void json_saver::field_name(const str::astr_view& n)
{
    char lc = b.data()[b.size() - 1];
    if (lc == '\"' || lc == '}' || is_digit(lc))
        b += str::span(ASTR(","));

    b += str::span(ASTR("\""));
    b += str::span(n);
    b += str::span(ASTR("\":\""));
}

json_saver& json_saver::num(signed_t n)
{
    char lc = b.data()[b.size() - 1];
    if (lc == '\"' || lc == '}' || is_digit(lc))
        b += str::span(ASTR(","));

    str::append_num(b, n, 0);
    return *this;
}

json_saver& json_saver::string(const str::astr_view& s)
{
    char lc = b.data()[b.size() - 1];
    if (lc == '\"' || lc == '}' || is_digit(lc))
        b += str::span(ASTR(","));

    b += str::span(ASTR("\""));
    if (s.find('\"') != s.npos)
    {
        str::astr ss = str::replace_all_copy(s, ASTR("\""), ASTR("\\\""));
        b += str::span(ss);
    }
    else {
        b += str::span(s);
    }
    b += str::span(ASTR("\""));

    return *this;
}

json_saver& json_saver::field(const str::astr_view& n, const str::astr_view& v)
{
    field_name(n);
    if (v.find('\"') != v.npos)
    {
        str::astr vv = str::replace_all_copy(v, ASTR("\""), ASTR("\\\""));
        b += str::span(vv);
    }
    else
        b += str::span(v);
    b += str::span(ASTR("\""));
    return *this;
}

json_saver& json_saver::field(const str::astr_view& n, signed_t v)
{
    field_name(n);
    b.resize(b.size() - 1);
    str::append_num(b,v,0);

    return *this;
}
