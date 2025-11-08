#pragma once

#define EFUNCS \
            EF( srca, source, enode_check_addr ) \
            EF( tgta, target, enode_check_addr ) \
            EF( srcf, source, enode_check_addr_from_file ) \
            EF( tgtf, target, enode_check_addr_from_file ) \
            EF( prvt, none, enode_prvt ) \
            EF( true, none, enode_true ) \


struct econtext
{
    enum index
    {
        source = 0,
        target = 1,

        count,
        none
    };

    netkit::endpoint* eps[count];
    bool has_upstream;

    econtext(netkit::endpoint* ep_source, netkit::endpoint* ep_target, bool has_upstream):has_upstream(has_upstream)
    {
        eps[source] = ep_source;
        eps[target] = ep_target;
    }
};

class expression
{
    enum prepared_state
    {
        ps_prepared,
        ps_required_01,
        ps_required_11,
    };

    struct enode
    {
        virtual ~enode() {}
        virtual signed_t calc(econtext &ctx) const = 0;
        virtual signed_t prior() const = 0;
        virtual prepared_state prepared() const = 0;
    };

    struct enode_check_addr : public enode
    {
        netkit::ipap addr;
        econtext::index cindex = econtext::none;
        enode_check_addr(econtext::index idx, const netkit::ipap& addr) : addr(addr), cindex(idx) {}
        static std::unique_ptr<enode> build(macro_context& mctx, econtext::index, str::astr_view par);
        /*virtual*/ signed_t calc(econtext& ctx) const override;
        /*virtual*/ signed_t prior() const override { return 0; }
        /*virtual*/ prepared_state prepared() const override { return ps_prepared; }
    };

    struct enode_check_addr_from_file : public enode
    {
        tools::keep_buffer addrs;
        econtext::index cindex = econtext::none;
        enode_check_addr_from_file(econtext::index idx, tools::keep_buffer &&addrs) : addrs(std::move(addrs)), cindex(idx) {}
        static std::unique_ptr<enode> build(macro_context &mctx, econtext::index, str::astr_view par);
        /*virtual*/ signed_t calc(econtext& ctx) const override;
        /*virtual*/ signed_t prior() const override { return 0; }
        /*virtual*/ prepared_state prepared() const override { return ps_prepared; }
    };

    struct enode_prvt : public enode
    {
        enode_prvt() {}
        static std::unique_ptr<enode> build(macro_context& /*mctx*/, econtext::index, str::astr_view)
        {
            return std::unique_ptr<enode>(NEW enode_prvt());
        }
        /*virtual*/ signed_t calc(econtext& ctx) const override;
        /*virtual*/ signed_t prior() const override { return 0; }
        /*virtual*/ prepared_state prepared() const override { return ps_prepared; }
    };

    struct enode_true : public enode
    {
        enode_true() {}
        static std::unique_ptr<enode> build(macro_context& /*mctx*/, econtext::index, str::astr_view)
        {
            return std::unique_ptr<enode>(NEW enode_true());
        }
        /*virtual*/ signed_t calc(econtext& /*ctx*/) const override { return 1; }
        /*virtual*/ signed_t prior() const override { return 0; }
        /*virtual*/ prepared_state prepared() const override { return ps_prepared; }
    };

    struct enode_unary : public enode
    {
        std::unique_ptr<enode> op;
        enode_unary() {}
        void set_op(std::unique_ptr<enode>&& op_) { op = std::move(op_); }
        /*virtual*/ signed_t prior() const override { return 1000; }
        /*virtual*/ prepared_state prepared() const override { return op != nullptr ? ps_prepared : ps_required_01; }
    };

    struct enode_binary : public enode
    {
        std::unique_ptr<enode> op_left;
        std::unique_ptr<enode> op_right;
        enode_binary() {}
        void set_ops(std::unique_ptr<enode>&& _left, std::unique_ptr<enode>&& _right) {
            op_left = std::move(_left); op_right = std::move(_right);
        }
        /*virtual*/ signed_t prior() const override { return 500; }
        /*virtual*/ prepared_state prepared() const override { return op_left != nullptr && op_right != nullptr ? ps_prepared : ps_required_11; }
    };

    struct enode_not : public enode_unary
    {
        enode_not() {}
        /*virtual*/ signed_t calc(econtext& ctx) const override {
            return op->calc(ctx) != 0 ? 0 : 1;
        }
    };

    struct enode_or : public enode_binary
    {
        enode_or() {}
        /*virtual*/ signed_t calc(econtext& ctx) const override {
            return op_left->calc(ctx) | op_right->calc(ctx);
        }
    };

    struct enode_logic_and : public enode_binary
    {
        enode_logic_and() {}
        /*virtual*/ signed_t calc(econtext& ctx) const override {
            return ((op_left->calc(ctx) != 0) && (op_right->calc(ctx) != 0)) ? 1 : 0;
        }
    };

    std::unique_ptr<enode> root;

    std::unique_ptr<enode> parse_node(macro_context& macro_ctx, str::astr_view s);

public:
    expression() {}
    ~expression() {}

    bool initialized() const
    {
        return root != nullptr;
    }

    bool parse(macro_context &macro_ctx, const str::astr_view& s)
    {
        root = std::move(parse_node(macro_ctx, s));
        return root != nullptr;
    }

    signed_t calc(econtext& ctx) const
    {
        ASSERT(root);
        return root ? root->calc(ctx) : 0;
    }
};
