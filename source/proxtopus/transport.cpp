#include "pch.h"

transport* transport::new_transport(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st, handler *h)
{
    const str::astr& typ = bb.get_string(ASTR("type"), glb.emptys);
    if (typ.empty())
    {
        ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
        LOG_E("{type} not defined for transport of listener [$]^", str::clean(owner->get_name()));
        return nullptr;
    }

    transport* t = nullptr;
    if (ASTR("tls") == typ)
    {
        t = NEW transport_tls(ldr, owner, bb, st, h);
    }

    if (t != nullptr)
    {
        if (ldr.exit_code != 0)
        {
            delete t;
            return nullptr;
        }
        return t;
    }

    LOG_E("unknown {type} [$] for transport of lisnener [$]^", typ, str::clean(owner->get_name()));
    ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
    return nullptr;
}

