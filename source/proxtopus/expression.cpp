#include "pch.h"

std::unique_ptr<expression::enode> expression::parse_node(macro_context& macro_ctx, str::astr_view s)
{
    auto find_close = [](str::astr_view text, signed_t &indexi) -> signed_t
    {
        signed_t index = indexi;
        while (text[index] == ' ')
            ++index;
        if (text[index] != '(')
            return -1;

        signed_t sc = 1;
        indexi = ++index;
        for (signed_t cnt = text.length(); index < cnt; ++index)
        {
            char c = text[index];
            if (c == '(')
            {
                ++sc;
                continue;
            }
            if (c == ')')
            {
                --sc;
                if (sc == 0)
                    break;
            }
        }
        if (sc != 0)
            return -1;

        return index;
    };


    std::vector<std::unique_ptr<enode>> linear;
    for (str::astr_view text = str::trim(s); !text.empty(); )
    {
        if (text[0] == '(')
        {
            signed_t si = 0;
            signed_t cindex = find_close(text, si);
            if (cindex < 0)
                return nullptr;
            auto n = parse_node(macro_ctx, str::substr(text, si, cindex));
            if (n == nullptr)
                return nullptr;
            linear.push_back(std::move(n));
            text = str::trim(str::substr(text, cindex + 1));
            continue;
        }

        if (text[0] == '!')
        {
            linear.push_back(std::move(std::make_unique<enode_not>()));
            text = str::trim(text.substr(1));
            continue;
        }

        if (text[0] == '|')
        {
            // | and || has same effect
            linear.push_back(std::move(std::make_unique<enode_or>()));
            text = str::trim(text.substr(1));
            if (text[0] == '|')
                text = text.substr(1);
            continue;
        }

        if (text.starts_with(ASTR("&&")))
        {
            linear.push_back(std::move(std::make_unique<enode_logic_and>()));
            text = str::trim(text.substr(2));
            continue;
        }

#define EF( fn, par0, nodename ) if (text.starts_with(ASTR(#fn))) \
        { signed_t from = 4; signed_t cls = find_close(text, from); if (cls < 0) return nullptr; \
          auto f = nodename::build(macro_ctx, econtext::par0, str::trim(str::substr(text, from, cls))); \
          if (f == nullptr) return nullptr; \
          linear.push_back(std::move(f)); text = str::trim(str::substr(text, cls+1)); continue; }

EFUNCS
#undef EF
    }

    for (; linear.size() > 1; )
    {
        signed_t mp = 0, fi = -1;
        signed_t cnt = linear.size();
        for (signed_t i = 0; i < cnt; ++i)
        {
            if (linear[i]->prepared() == ps_prepared)
                continue;
            signed_t p = linear[i]->prior();
            if (p > mp)
            {
                fi = i;
                mp = p;
            }
        }
        if (fi >= 0)
        {
            enode *n = linear[fi].get();
            if (n->prepared() == ps_required_01)
            {
                // unary op
                if (fi + 1 >= cnt)
                    return nullptr;
                enode_unary* uop = static_cast<enode_unary*>(linear[fi].get());
                auto op = std::move(linear[fi + 1]);
                if (op->prepared() != ps_prepared)
                    return nullptr;
                uop->set_op(std::move(op));
                linear.erase(linear.begin() + fi + 1);
                continue;
            }
            if (n->prepared() == ps_required_11)
            {
                // infix binary op
                if (fi == 0 || fi + 1 >= cnt)
                    return nullptr;
                enode_binary* uop = static_cast<enode_binary*>(linear[fi].get());
                auto op1 = std::move(linear[fi - 1]);
                auto op2 = std::move(linear[fi + 1]);
                if (op1->prepared() != ps_prepared || op2->prepared() != ps_prepared)
                    return nullptr;
                uop->set_ops(std::move(op1), std::move(op2));
                linear.erase(linear.begin() + fi + 1);
                linear.erase(linear.begin() + fi - 1);
                continue;
            }
        }
        return nullptr;
    }
    if (linear[0]->prepared() != ps_prepared)
        return nullptr;
    return std::move(linear[0]);
}

std::unique_ptr<expression::enode> expression::enode_check_addr_from_file::build(macro_context& mctx, econtext::index idx, str::astr_view par)
{
    str::astr s(par);
    macro_expand(&mctx, s);

    FN fn = tofn(s);
    buffer ib;
    load_buf(fn, ib);
    std::vector<str::astr_view> lines;
    for (str::token<char, str::sep_line<char>> t((const char*)ib.data(), ib.size()); t; t())
    {
        auto ln = str::trim(*t);
        if (ln.length() == 0 || ln[0] == '#')
            continue;
        lines.emplace_back(ln);
    }

    if (lines.size() > 0)
    {
        tools::keep_buffer addrs;
        addrs.resize(sizeof(netkit::ipap) * lines.size(), 0);
        netkit::ipap* subnets = reinterpret_cast<netkit::ipap*>(addrs.data());
        for (const str::astr_view& ln : lines)
        {
            *subnets = netkit::ipap::parse(ln, netkit::ipap::f_prefix | netkit::ipap::f_prefix_default);
            if (!subnets->has_prefix() || subnets->is_empty())
                return nullptr;
            ++subnets;
        }
        return std::unique_ptr<enode>(NEW enode_check_addr_from_file(idx, std::move(addrs)));
    }

    return nullptr;
}
/*virtual*/ signed_t expression::enode_check_addr_from_file::calc(econtext& ctx) const
{
    if (cindex >= econtext::count)
        return 0;

    netkit::endpoint* ep = ctx.eps[cindex];

    ep->resolve_ip(glb.cfg.ipstack | conf::gip_any | conf::gip_log_it);
    if (ep->state() != netkit::EPS_RESLOVED)
        return 0;

    size_t count;
    const netkit::ipap *subnets = addrs.tdata<netkit::ipap>(count);
    for (size_t i = 0; i < count; ++i)
        if (ep->get_ip().match(subnets[i]))
            return 1;

    return 0;

}


std::unique_ptr<expression::enode> expression::enode_check_addr::build(macro_context& /*mctx*/, econtext::index index, str::astr_view par)
{
    netkit::ipap ipa = netkit::ipap::parse(par, netkit::ipap::f_prefix| netkit::ipap::f_prefix_default);
    if (!ipa.has_prefix())
        return nullptr;
    return std::unique_ptr<enode>(NEW enode_check_addr(index, ipa));
}

/*virtual*/ signed_t expression::enode_check_addr::calc(econtext& ctx) const
{
    if (cindex >= econtext::count)
        return 0;

    netkit::endpoint* ep = ctx.eps[cindex];

    ep->resolve_ip(glb.cfg.ipstack | conf::gip_any | conf::gip_log_it);
    if (ep->state() != netkit::EPS_RESLOVED)
        return 0;

    return ep->get_ip().match(addr) ? 1 : 0;

}

/*virtual*/ signed_t expression::enode_prvt::calc(econtext& ctx) const
{
    netkit::endpoint* ep = ctx.eps[econtext::target];

    ep->resolve_ip(glb.cfg.ipstack | conf::gip_any | conf::gip_log_it);
    if (ep->state() != netkit::EPS_RESLOVED)
        return 0;

    return ep->get_ip().is_private() ? 1 : 0;
}


