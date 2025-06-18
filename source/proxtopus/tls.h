#pragma once

// decrypt from-client data and encrypt to-client data

#if defined(BOTAN_HAS_TLS_13)
using tls_channel = Server_Impl_13;
using tls_channel_12 = Botan::TLS::Server_Impl_12;
static_assert(sizeof(tls_channel) >= sizeof(tls_channel_12));
#else
using tls_channel = Botan::TLS::Server_Impl_12;
#endif

class tls_pipe : public netkit::pipe, public Botan::TLS::Callbacks
{
    using outbuffer = tools::chunk_buffer<16384>;
protected:
    struct incdec
    {
        volatile size_t& v;
        tls_pipe* owner;
        incdec(volatile size_t& v, tls_pipe* owner) :v(v), owner(owner) { if (spinlock::atomic_increment(v) > 10000) owner = nullptr; }
        ~incdec() { if (spinlock::atomic_decrement(v) > 10000 && owner) owner->close(true); }
        operator bool() const
        {
            return owner == nullptr;
        }
    };

    volatile size_t busy = 0;
    netkit::pipe_ptr pipe;
    outbuffer encrypted_data; // ready 2 send data
    outbuffer decrypted_data;

    BotanRndGen rng;
    //tools::deferred_init<Botan::TLS::Server> server;
    tools::deferred_init<tls_channel> channel;
    bool alpn_http11 = false;

    sendrslt send_encrypted();

    /*virtual*/ void tls_emit_data(std::span<const uint8_t> data) override;
    /*virtual*/ void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data);
    /*virtual*/ void tls_alert(Botan::TLS::Alert alert) override;
    /*virtual*/ std::string tls_server_choose_app_protocol(const std::vector<std::string>& clprots);

    size_t from_peer(const std::span<const u8> &data);

public:
    tls_pipe(netkit::pipe_ptr pipe, Botan::Credentials_Manager *cm, Botan::TLS::Session_Manager*sm, const Botan::TLS::Policy* policy, bool alpn_http11);
    /*virtual*/ ~tls_pipe()
    {
        close(true);
    }


    /*virtual*/ bool alive() override
    {
        return pipe && pipe->alive();
    }

    /*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;
    /*virtual*/ signed_t recv(tools::circular_buffer_extdata& data, signed_t required, signed_t timeout DST(, deep_tracer*)) override;
    /*virtual*/ void unrecv(tools::circular_buffer_extdata& data) override;
    /*virtual*/ netkit::WAITABLE get_waitable() override;
    /*virtual*/ void close(bool flush_before_close) override;

};
