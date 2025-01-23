#pragma once

struct macro_context
{
    std::unique_ptr<randomgen> rnd;
    const asts* block;
    std::vector<str::astr> vars;

    macro_context(const asts* block):block(block) {}
    macro_context(const str::astr& v0) { vars.push_back(v0); }

    signed_t random(signed_t from, signed_t to);
};

template<typename SS> void macro_expand(macro_context *ctx, SS& s);