#include "pch.h"

signed_t macro_context::random(signed_t from, signed_t to)
{
    if (!rnd)
        rnd.reset( NEW randomgen() );

    if (to < from)
    {
        tools::swap(from, to);
    }
    size_t delta = to - from;
    if (delta < 2)
        return from;
    size_t rndn;
    rnd->randomize((u8 *) & rndn, sizeof(rndn));

    return from + (rndn % delta);
}

inline str::wstr __from_utf8(const str::astr_view& s) { return str::from_utf8(s); }
inline str::wstr __from_utf8(const str::wstr_view& s) { return str::wstr(s); }
inline void __cvt(str::astr& rslt, const str::wstr_view& s) { rslt = str::to_utf8(s); }
inline void __cvt(str::wstr& rslt, const str::wstr_view& s) { rslt = s; }
inline void __cvt(str::astr& rslt, const str::astr_view& s) { rslt = s; }
inline void __cvt(str::wstr& rslt, const str::astr_view& s) { rslt = __from_utf8(s); }

template <typename SS> size_t __find(SS& s, const str::xstr_view<typename str::chartype<SS>::type> &w, size_t from)
{
    return s.find(w, from);
}

template <typename SS> void __repl(SS& s, size_t from, size_t to, const str::xstr_view<typename str::chartype<SS>::type>& w)
{
    s.replace(s.begin() + from, s.begin() + to, w.data(), w.length());
}

template<typename CC> bool handle_macro(macro_context* ctx, const str::xstr_view<CC>& w, str::xstr<CC>& rslt)
{
    str::token<CC, str::sep_onechar<CC, ':'>> tkn(w);
    if (*tkn == XSTR(CC,"v"))
    {
        tkn();
        signed_t vi = str::parse_int(*tkn, 0);
        if (vi < 0 || vi >= (signed_t)ctx->vars.size())
        {
            rslt.clear();
            return true;
        }
        str::__assign(rslt, ctx->vars[vi]);
        return true;

    } else if (*tkn == XSTR(CC,"rn"))
    {
        tkn();
        str::xstr_view<CC> fn = *tkn;
        tkn();
        str::xstr_view<CC> sn = *tkn;

        signed_t n1 = str::parse_int(fn, -1);
        if (n1 < 0)
            return false;
        signed_t n2 = str::parse_int(sn, -1);
        if (n2 <= n1)
            return false;

        signed_t rnum = ctx->random(n1, n2);
        rslt.clear();
        str::append_num(rslt, rnum, fn.length());
        return true;
    } else if (*tkn == XSTR(CC,"rw"))
    {
        tkn();
        str::xstr_view<CC> rgs = *tkn;
        tkn();
        signed_t numl1 = str::parse_int(*tkn, 0);
        tkn();
        signed_t numl2 = str::parse_int(*tkn, 0);

        if (numl1 == 0 && numl2 == 0)
            return false;

        if (numl1 > 0 && numl2 > 0 && numl2 < numl1)
            tools::swap(numl1, numl2);

        signed_t cnt = rgs.length();
        if (cnt == 0)
            return false;
        if (0 != (cnt & 1))
            return false;

        str::xstr<CC> rrc;

        for (signed_t i = 0; i < cnt; i += 2)
        {
            for (CC c1 = rgs[i], c2 = rgs[i + 1]; c1 <= c2; ++c1)
                rrc.push_back(c1);
        }

        signed_t numl = numl2 == 0 ? numl1 : ctx->random(numl1, numl2+1);
        rslt.clear();
        for (signed_t i = 0; i < numl; ++i)
            rslt.push_back( rrc[ctx->random(0, rrc.length())] );
        return true;
    }

    return false;
}

template<typename CC> bool expand_env(const str::xstr_view<CC>& w, str::xstr<CC>& rslt)
{
#ifdef _WIN32
    wchar b[MAX_PATH_LENGTH];
    u32 pl = GetEnvironmentVariableW(__from_utf8(w).c_str(), b, MAX_PATH_LENGTH);

    if (pl && pl < MAX_PATH_LENGTH)
    {
        __cvt(rslt, str::wstr_view(b, pl));
#endif
#ifdef _NIX
    if (const char* vv = getenv(str::to_utf8(w).c_str()))
    {
        __cvt(rslt, str::astr_view(vv));
#endif
        return true;
    }

    return false;
}

template<typename SS> void macro_expand(macro_context* ctx, SS& s)
{
    using CC = typename str::chartype<SS>::type;

    str::xstr<CC> rslt;
    size_t dprc = 0;
    for (;;)
    {
        size_t ii = __find(s, XSTR(CC, "$("), dprc);
        if (ii == s.npos) break;
        ii += dprc;
        size_t iie = ii + 2;
        for (; iie < s.length();)
        {
            if (s[iie] == ')')
            {
                if ((iie - ii) > 1)
                {
                    size_t ll = iie - ii - 2;
                    str::xstr_view<CC> macro(s.data() + ii + 2, ll);

                    if (handle_macro(ctx, macro, rslt))
                    {
                        __repl( s, ii, iie + 1, rslt );
                        dprc = ii + rslt.length();
                        break;

                    }
                    else if (expand_env(macro, rslt))
                    {
                        __repl(s, ii, iie + 1, rslt);
                        dprc = ii + rslt.length();
                        break;
                    }
                }
                dprc = iie + 1;
                break;
            }
            if (is_letter(s[iie]) || is_digit(s[iie]) || s[iie] == '_' || s[iie] == ':')
            {
                ++iie;
                continue;
            }
            dprc = iie + 1;
            break;
        }
    }

}

template void macro_expand<str::wstr>(macro_context* ctx, str::wstr&);
template void macro_expand<str::astr>(macro_context* ctx, str::astr&);
