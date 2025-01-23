#pragma once

class api_collection
{
public:
    api_collection() {}
    virtual ~api_collection() {}

    virtual const apiobj* by_id(signed_t id) const = 0;
    virtual const apiobj* by_index(signed_t index) const = 0;
    virtual signed_t count() const = 0;
};

template<typename APIOBJ> class api_collection_uptr : public api_collection
{
    std::vector<std::unique_ptr<APIOBJ>> list;
public:

    const apiobj* by_id(signed_t id) const override
    {
        for (const auto& l : list)
            if (l->get_id() == id)
                return l.get();
        return nullptr;
    }
    const apiobj* by_index(signed_t index) const override
    {
        return list[index].get();
    }
    signed_t count() const override
    {
        return list.size();
    }

    decltype(auto) begin() { return list.begin(); }
    decltype(auto) end() { return list.end(); }
    decltype(auto) begin() const { return list.begin(); }
    decltype(auto) end() const { return list.end(); }

    bool empty() const { return list.empty(); }

    template <class... _Valty> decltype(auto) emplace_back(_Valty&&... _Val)
    {
        return list.emplace_back(std::forward<_Valty>(_Val)...);
    }

};

struct host_mode_api : public host_mode
{
    virtual ~host_mode_api() {}
    virtual bool load(const asts& b) override;

    mode_result do_GET(http_server& s);
};
