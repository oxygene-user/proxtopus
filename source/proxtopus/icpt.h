#pragma once


class proxy;
class engine;
class icpt_rule
{
    enum act_e : u8
    {
        act_allow,
        act_deny,
    };
    enum proto_e : u8
    {
        proto_any,
        proto_tcp,
        proto_udp,
    };


    str::astr name, proc;
    const proxy* prx = nullptr;
    proto_e proto = proto_any;
    act_e act = act_allow;
public:
    explicit icpt_rule(engine* eng, const str::astr& name, const str::astr& s);
};

class interceptor
{
    std::vector<icpt_rule> rules;
public:

#ifdef _WIN32

    struct flow_desc
    {
        flow_desc(u32 pid) :processid(pid) {}
        netkit::ipap src;
        volatile u32 processid = 0;
        flow_desc* next = nullptr;
    };
    static_assert(sizeof(flow_desc) == 32);

    struct hand_pair
    {
        flow_desc* get_flow_desc(u32 pid)
        {
            if (sump.size())
            {
                auto &x = sump[sump.size()-1];
                flow_desc* fd = x.release();
                sump.resize(sump.size() - 1);
                fd->processid = pid;
                return fd;
            }
            return NEW flow_desc(pid);
        }

        std::vector<std::unique_ptr<flow_desc>> sump;
        flow_desc *flows = nullptr; // assume number of flows not so big, so linear array will be fast enough

        HANDLE network = nullptr;
        HANDLE flow = nullptr;
        volatile bool stop = false;
        volatile bool stoped1 = false;
        volatile bool stoped2 = false;

        void nthread();
        void fthread();

        ~hand_pair() { close(); }
        bool open();
        void close();
    };


    HANDLE event = nullptr;
    hand_pair udp;
#endif
    
    ~interceptor();

    bool load(engine* e, const asts* s);

};
