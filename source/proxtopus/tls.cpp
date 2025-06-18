#include "pch.h"

tls_pipe::tls_pipe(netkit::pipe_ptr pipe, Botan::Credentials_Manager* cm, Botan::TLS::Session_Manager* sm, const Botan::TLS::Policy *policy, bool alpn_http11) :pipe(pipe), alpn_http11(alpn_http11)
{
    const auto max_version = policy->latest_supported_version(/*is_datagram*/ false);
    if (!max_version.is_pre_tls_13()) {
#if defined(BOTAN_HAS_TLS_13)
        channel.init(this, sm, cm, policy, &rng);
        if (channel->expects_downgrade()) {
            channel->set_io_buffer_size(TLS::Channel::IO_BUF_DEFAULT_SIZE);
        }
#endif
    }
    else {
        channel.init(this, sm, cm, policy, &rng);
    }

}

/*virtual*/ void tls_pipe::tls_emit_data(std::span<const uint8_t> data) {
    encrypted_data.append(data);
    if (SEND_FAIL == send_encrypted())
        pipe = nullptr;
}

/*virtual*/ void tls_pipe::tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> data) {
    
    decrypted_data.append(data);
}

/*virtual*/ void tls_pipe::tls_alert(Botan::TLS::Alert alert) {
    // handle a tls alert received from the tls server
    BOTAN_UNUSED(alert);
}

/*virtual*/ std::string tls_pipe::tls_server_choose_app_protocol(const std::vector<std::string>& clprots)
{
    if (alpn_http11)
    {
        if (signed_t http11 = tools::find(clprots, ASTR("http/1.1")); http11 >= 0)
        {
            return clprots[http11];
        }
    }

    return glb.emptys;
}

/*virtual*/ netkit::pipe::sendrslt tls_pipe::send(const u8* data, signed_t datasize)
{
    if (!pipe)
        return SEND_FAIL;

    incdec ddd(busy, this);
    if (ddd) return SEND_FAIL;

    if (data == nullptr)
        return pipe->send(nullptr, 0); // check allow send

    if (datasize != 0)
        channel->to_peer(std::span<const u8>(data, datasize)); // put data to tls encrypt engine; see callback

    return send_encrypted();
}

netkit::pipe::sendrslt tls_pipe::send_encrypted()
{
    if (!pipe)
        return SEND_FAIL;

    for (;!encrypted_data.is_empty();)
    {
        auto d = encrypted_data.get_1st_chunk();
        sendrslt r = pipe->send(d.data(), d.size());
        if (r == SEND_FAIL)
            return SEND_FAIL;
        encrypted_data.skip(d.size());
        if (r == SEND_BUFFERFULL)
            return SEND_BUFFERFULL;
    }

    return SEND_OK;
}

size_t tls_pipe::from_peer(const std::span<const u8>& data)
{
    auto need_more = channel->from_peer(data);

#if defined(BOTAN_HAS_TLS_13)
    // TODO : implement downgrade to 12
    if (channel->is_downgrading()) {
        auto info = channel->extract_downgrade_info();
        m_impl = std::make_unique<Server_Impl_12>(*info);

        // replay peer data received so far
        need_more = channel->from_peer(info->peer_transcript);
    }
#endif

    return need_more;

}

/*virtual*/ signed_t tls_pipe::recv(tools::circular_buffer_extdata& outdata, signed_t required, signed_t timeout DST(, deep_tracer* tracer))
{
    if (required > 0 && outdata.datasize() >= required)
    {
        DST(if (tracer) tracer->log("tlsrecv alrd"));
        return required;
    }

    if (!pipe)
        return -1;

    incdec ddd(busy, this);
    if (ddd) return -1;

    tools::circular_buffer_preallocated<BRIDGE_BUFFER_SIZE> tempbuf;

    signed_t recvsize = required > 0 ? 1 : 0; // we need at least 1 required byte to recv (it will wait for data)
    bool do_recv = decrypted_data.is_empty();
    if (do_recv)
        netkit::clear_ready(get_waitable(), READY_PIPE);
    else if (required > 0)
    {
        if (decrypted_data.enough(required - outdata.datasize()))
        {
            decrypted_data.peek(outdata);
            ASSERT(outdata.datasize() >= required);
            return required;
        }
        else {
            do_recv = true;
        }
    }

    for (;; do_recv = true)
    {
        signed_t sz = do_recv ? pipe->recv(tempbuf, recvsize, timeout DST(, tracer)) : tempbuf.datasize();
        if (sz < 0)
            return sz;

        if (size_t dsz = tempbuf.datasize(); dsz > 0)
        {
            try
            {
                std::span<const u8> td = tempbuf.data(dsz).p0;
                
                if (channel->from_peer(td) > 0)
                {
                    auto w = pipe->get_waitable();
                    clear_ready(w, READY_PIPE | READY_SYSTEM);
                    netkit::wrslt rslt = wait(w, LOOP_PERIOD);
                    if (rslt == netkit::WR_CLOSED || glb.is_stop())
                        return -1;

                    tempbuf.skip(td.size());
                    continue;
                }
                tempbuf.skip(td.size());
            }
            catch (const std::exception&)
            {
                return -1;
            }
        }

        if (required > 0)
        {
            if (!decrypted_data.enough(required))
            {
                auto w = pipe->get_waitable();
                clear_ready(w, READY_PIPE | READY_SYSTEM);
                netkit::wrslt rslt = wait(w, LOOP_PERIOD);
                if (rslt == netkit::WR_CLOSED || glb.is_stop())
                    return -1;

                continue; // not enough data
            }

            decrypted_data.peek(outdata, required);
            return required;
        }
        break;
    }
    signed_t rv = 0, maxcopysize = outdata.get_free_size();
    if (decrypted_data.enough_for(maxcopysize))
    {
        // just copy whole decrypted data
        rv = decrypted_data.peek(outdata);
    }
    else
    {
        // output buffer is smaller then decrypted
        // copy some

        rv = decrypted_data.peek(outdata, maxcopysize);
        ASSERT(rv = maxcopysize);
    }

    return rv;

}

/*virtual*/ void tls_pipe::unrecv(tools::circular_buffer_extdata& data)
{
    if (size_t dsz = data.datasize(); dsz>0 && pipe)
    {
        tools::memory_pair mp = data.data(dsz);

        if (mp.p1.size())
            decrypted_data.insert(mp.p1);
        decrypted_data.insert(mp.p0);
        data.clear();

        netkit::make_ready(pipe->get_waitable(), READY_PIPE);
    }
}

/*virtual*/ netkit::WAITABLE tls_pipe::get_waitable()
{
    if (!pipe)
        return NULL_WAITABLE;

    incdec ddd(busy, this);
    if (ddd) return NULL_WAITABLE;

    auto r = pipe->get_waitable();
    if (!decrypted_data.is_empty())
        netkit::make_ready(r, READY_PIPE);
    else
        netkit::clear_ready(r, READY_PIPE);
    return r;

}
/*virtual*/ void tls_pipe::close(bool flush_before_close)
{
    spinlock::atomic_add<size_t>(busy, 10001);
    bool io = busy > 10001;
    if (!io && pipe)
    {
        pipe->close(flush_before_close);
        pipe = nullptr;
    }
}
