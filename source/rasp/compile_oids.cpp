#include "pch.h"
#if defined(_DEBUG) && defined(_WIN32)

namespace
{
    struct rec
    {
        buffer oid;
        str::astr line;
        str::astr soid;
        Botan::Algo_Group ag;
        bool operator<(const rec& r) const
        {
            bool l = oid < r.oid;
            //ASSERT(l == (std::span(oid.data(), oid.size()) < std::span(r.oid.data(), r.oid.size())));
            return l;
        }
        str::astr make_enum_string(signed_t spaces, bool ee = false)
        {
            str::astr s; s.append(spaces, ' ');
            if (ee)
                s += ASTR("static_cast<u8>(oid_index::");
            s.push_back('_');
            s += soid;
            str::replace_all(s, '.', '_');
            if (ee)
                s += ASTR("),\r\n");
            else
                s += ASTR(",\r\n");

            return s;
        }

        static bool sort_ba(const rec& a, const rec& b) {
            u64 x1 = Botan::load_le<u64>((const u8 *) & a.ag, 0);
            u64 x2 = Botan::load_le<u64>((const u8* ) & b.ag, 0);

            return x1 < x2;
        }
        
    };
}

void compile_oids(const FN& cppfile)
{
    buffer f;
    str::astr outf1, outf2, oids;
    signed_t disp = 0;
    if (load_buf(cppfile, f))
    {
        std::vector<rec> recs;
        str::astr ln;
        signed_t spc1 = 0;
        signed_t step = 0;
        for (str::token<char, str::sep_line<char>> t((const char*)f.data(), f.size()); t; t())
        {
            ln = *t;

            if (step == 1)
            {
                if (oids.empty())
                {
                    oids = ln;
                    auto ss = oids.find(ASTR("{"));
                    oids.resize(ss + 1);
                    oids += "\r\n";
                    spc1 = oids.find(str::ltrim(str::view(oids)), 0);
                    oids.append(spc1 + 4, ' ');
                    continue;
                }
            }

            if (step == 0)
            {
                outf1 += ln;
                outf1 += ASTR("\r\n");
            } else if (step == 2) {

                auto x = ln.find(ASTR("{t2id(\""));
                if (x != ln.npos && !str::trim(str::view(ln)).starts_with(ASTR("//")))
                {
                    ln.replace(x+1, 6, ASTR("/*oid*/ /*"));
                    auto y = ln.find(ASTR("\")"), x + 3);
                    if (y == ln.npos)
                        __debugbreak();
                    ln.replace(y, 2, ASTR("*/"));
                }

                bool dontadd4now = false;
                if (auto oid = ln.find(ASTR("/*oid*/")); oid != ln.npos)
                {
                    x = ln.find(ASTR("{"));
                    if (x == ln.npos)
                        __debugbreak();
                    auto z = ln.find(ASTR("*/"), oid + 7);
                    str::astr s = ln.substr(oid + 10, z-oid-10);

                    std::vector<u32> vals;
                    for (str::token<char, str::sep_onechar<char, '.'>> tkn(s); tkn; tkn())
                    {
                        vals.push_back( (u32)str::parse_int(*tkn, 0) );
                    }
                    vals[1] += vals[0] * 40;

                    rec& r = recs.emplace_back();
                    buffer &co = r.oid;
                    
                    Botan::DER_encode(co, vals.data() + 1, vals.size() - 1);

                    for (u8 n: co)
                    {
                        oids += ASTR(" 0x");
                        str::append_hex<str::astr, u8, false>(oids, n);
                        oids += ASTR(",");
                    }

                    oids.append(ASTR(" // "));
                    oids.append(s);
                    oids += ASTR("\r\n");
                    oids.append(spc1 + 4, ' ');

                    str::astr ref(ASTR(" std::span(oids+"));
                    str::append_num(ref, disp, 0);
                    ref.append(ASTR(", "));
                    str::append_num(ref, co.size(), 0);
                    ref.append(ASTR(") "));

                    ln.replace(x+1, oid-x-1, ref);
                    r.line = str::ltrim(str::view(ln));
                    r.line += ASTR("\r\n");
                    r.soid = s;
                    
                    disp += co.size();
                    dontadd4now = true;
                }

                if (!dontadd4now)
                {
                    outf2 += ln;
                    outf2 += ASTR("\r\n");
                }
            }

            if (step == 0 && ln.find(ASTR("/*oids-start*/")) != ln.npos)
            {
                step = 1;
            }
            if (step == 1 && ln.find(ASTR("/*oids-end*/")) != ln.npos)
            {
                step = 2;
                outf2 += ln;
                outf2 += ASTR("\r\n");
            }
        }

        str::rtrim(oids);
        //oids.resize(oids.size()-1);
        oids.append(ASTR("\r\n"));
        oids.append(spc1, ' ');
        oids.append(ASTR("};\r\n"));

        outf1 += oids;
        outf1 += outf2;
        outf1.resize(outf1.size() - 2);

        std::sort(recs.begin(), recs.end());

        auto sb = outf1.find(ASTR("/*sorted_start*/"));
        auto se = outf1.find(ASTR("/*sorted_end*/"));
        signed_t spaces = 0;
        for (; ;++spaces)
        {
            if (outf1[sb - spaces - 1] == '\n')
                break;
        }

        str::astr srecs, enms, sorted1;
        signed_t ri = 1;
        for (rec &r : recs)
        {
            r.ag = Botan::g_oids[ri++].alg;
            srecs.append(spaces, ' ');
            srecs += r.line;
        }

        if (srecs[srecs.size() - 3] == ',')
            srecs.erase(srecs.begin() + srecs.size() - 3);

        auto nl = outf1.find(ASTR("\r\n"), sb);
        outf1.replace(nl+2, se-spaces-nl-2, srecs);


        auto eb = outf1.find(ASTR("/*enum_start*/"));
        auto ee = outf1.find(ASTR("/*enum_end*/"));

        spaces = 0;
        for (; ; ++spaces)
        {
            if (outf1[eb - spaces - 1] == '\n')
                break;
        }

        for (rec r : recs)
        {
            enms += r.make_enum_string(spaces);
        }

        nl = outf1.find(ASTR("\r\n"), eb);
        outf1.replace(nl + 2, ee - spaces - nl - 2, enms);


        auto sbab = outf1.find(ASTR("/*sorted_ba_start*/"));
        auto sbae = outf1.find(ASTR("/*sorted_ba_end*/"));
        spaces = 0;
        for (; ; ++spaces)
        {
            if (outf1[sbab - spaces - 1] == '\n')
                break;
        }

        std::sort(recs.begin(), recs.end(), rec::sort_ba);
        for (rec r : recs)
        {
            sorted1 += r.make_enum_string(spaces, true);
        }

        nl = outf1.find(ASTR("\r\n"), sbab);
        outf1.replace(nl + 2, sbae - spaces - nl - 2, sorted1);


        //save_buf(FN(MAKEFN("t:\\cpp.cpp")), outf1);
        save_buf(cppfile, outf1);
    }
    //__debugbreak();
}

#endif
