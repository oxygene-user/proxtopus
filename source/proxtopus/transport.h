#pragma once

class transport : public handler // transport is very similar to handler
{
protected:

    std::unique_ptr<handler> hand;

    transport(loader& ldr, listener* owner, const asts& bb, handler* h) :handler(ldr, owner, bb), hand(h)
    {
    }


public:
    static transport* new_transport(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st, handler* h);
};






#include "transport_tls.h"

