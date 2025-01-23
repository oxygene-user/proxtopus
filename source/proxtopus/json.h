#pragma once

class json_saver
{
    buffer& b;

    void field_name(const str::astr_view& n);

public:
    json_saver(buffer& b) :b(b) {}

    json_saver& obj(const str::astr_view& on)
    {
        field_name(on);
        b.resize(b.size() - 1);
        b += str::span(ASTR("{"));
        return *this;
    }

    json_saver& obj()
    {
        char lc = b.data()[b.size() - 1];
        if (lc == '}')
            b += str::span(ASTR(","));

        b += str::span(ASTR("{"));
        return *this;
    }
    json_saver& objclose()
    {
        b += str::span(ASTR("}"));
        return *this;
    }

    json_saver& arr()
    {
        b += str::span(ASTR("["));
        return *this;
    }
    json_saver& arr(const str::astr_view& on)
    {
        field_name(on);
        b.resize(b.size() - 1);
        b += str::span(ASTR("["));
        return *this;
    }

    json_saver& arrclose()
    {
        b += str::span(ASTR("]"));
        return *this;
    }
    json_saver& field(const str::astr_view& n, const str::astr_view& v);
    json_saver& field(const str::astr_view& n, signed_t v);
    json_saver& string(const str::astr_view& n);
    json_saver& num(signed_t n);
};
