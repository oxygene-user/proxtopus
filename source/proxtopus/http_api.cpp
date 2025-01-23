#include "pch.h"

/*virtual*/ bool host_mode_api::load(const asts& b)
{

    return true;
}

struct name2col
{
    str::astr_view name;
    const api_collection& col;
};

mode_result host_mode_api::do_GET(http_server& s)
{
    buffer b;

    name2col n2c[] = {
        { ASTR("/listeners/"),  glb.e->l() },
        { ASTR("/proxy/"),      glb.e->p() } };
 
    for (const name2col& x : n2c)
    {
        if (s.path.starts_with(x.name))
        {
            json_saver j(b);
            if (str::view(s.path).substr(x.name.length()) == ASTR("list"))
            {
                j.arr();
                for (signed_t i = 0, cnt = x.col.count(); i < cnt; ++i)
                {
                    j.obj();
                    x.col.by_index(i)->api(j);
                    j.objclose();
                }
                j.arrclose();
            }
            else if (signed_t id = str::parse_int(str::view(s.path).substr(x.name.length()), 0); id > 0)
            {
                if (const apiobj* o = x.col.by_id(id))
                {
                    j.obj();
                    o->api(j);
                    j.objclose();
                }
                else
                {
                    j.obj()
                        .field(ASTR("message"), ASTR("object not found"))
                        .field(ASTR("path"), s.path)
                        .objclose();
                    s.answer(HC_NOT_FOUND, ASTR("application/json"), b);
                    return MR_OK;
                }
            }
            s.answer(HC_OK, ASTR("application/json"), b);
            return MR_OK;
        }
    }


    json_saver j(b);
    j.obj()
        .field(ASTR("message"), ASTR("path not allowed"))
        .field(ASTR("path"), s.path)
    .objclose();

    s.answer(HC_BAD_REQUEST, ASTR("application/json"), b);
    return MR_OK;
}