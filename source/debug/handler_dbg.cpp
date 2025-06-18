#include "pch.h"

#ifdef _DEBUG

#ifdef _NIX
#include "debug/backward.hpp"
#endif

void execute_cmd(netkit::pipe* pipe, str::astr &cmd)
{
    if (cmd == ASTR("crash"))
    {
        pipe->send((const u8 *)"now crashing...\r\n", 17);
        pipe->close(true);
        //DEBUGBREAK();
        int *foo = (int*)-1; // make a bad pointer
        printf("%d\n", *foo); // causes segfault
    }

    if (cmd == ASTR("info"))
    {
        str::astr ln(ASTR("tcp count: "));
        ln += std::to_string(glb.numtcp);
        ln += "\r\n";
        pipe->send((const u8*)ln.c_str(), ln.size());

        ln = ASTR("udp count: ");
        ln += std::to_string(glb.numudp);
        ln += "\r\n";
        pipe->send((const u8*)ln.c_str(), ln.size());

        return;
    }

#ifdef _NIX
    if (cmd == ASTR("stack"))
    {

        using namespace backward;
        StackTrace st; st.load_here(32);
        TraceResolver tr; tr.load_stacktrace(st);
        for (size_t i = 0; i < st.size(); ++i)
        {
            ResolvedTrace trace = tr.resolve(st[i]);

            str::astr ln(ASTR("#"));
            ln += std::to_string(i);
            ln += " ";
            ln += trace.object_filename;
            ln += " ";
            ln += trace.object_function;
            ln += "\r\n";

            pipe->send((const u8 *)ln.c_str(), ln.size());


            //std::cout << "#" << i << " " << trace.object_filename << " " << trace.object_function << " [" << trace.addr << "]" << std::endl;
        }
        return;
    }
#endif



    cmd.insert(0, ASTR("unknown: ["));
    cmd.append(ASTR("]\r\n"));
    pipe->send((const u8 *)cmd.c_str(), cmd.size());
}


handler_debug::handler_debug(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e /*st*/) :handler(ldr, owner, bb)
{
}

void handler_debug::handle_pipe(netkit::pipe* pipe)
{
    netkit::pipe_ptr p(pipe);

    str::astr bs;

    bs = "proxtopus v" PROXTOPUS_VER " (build " __DATE__ " " __TIME__ ")\r\n";
    pipe->send((const u8*)bs.c_str(), bs.size());
    bs.clear();

    tools::circular_buffer_preallocated<1024> b;
    for (;!glb.is_stop();)
    {
        netkit::wrslt wr = netkit::wait(pipe->get_waitable(), 1000);
        if (wr == netkit::WR_CLOSED)
            break;
        if (wr == netkit::WR_TIMEOUT)
        {
            if (glb.is_stop())
                break;
            continue;
        }

        signed_t r = pipe->recv(b, 0, RECV_BRIDGE_MODE_TIMEOUT DST(, nullptr));
        if (r < 0)
            break;

        // echo
        //pipe->send(b, r);

        b.peek(bs);

        if (bs.size() > 1024)
            break; // too long command line, now disconnect

        signed_t bsc = 0;
        for (signed_t i = bs.size() - 1; i >= 0; --i)
        {
            if (bs[i] == 8)
                ++bsc;
            else if (bsc > 0)
            {
                bs.erase(i, bsc + 1);
                bsc = 0;
            }
        }
        if (bsc)
            bs.clear();

        size_t nl = bs.find('\n');
        if (nl == bs.npos)
            continue;

        str::astr cmd = bs.substr(0, nl);
        bs.erase(0, nl+1);
        str::trim(cmd);
        execute_cmd(pipe, cmd);
    }


}

#endif