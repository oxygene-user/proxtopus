#include "pch.h"

#if FEATURE_TLS
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
        set_readypipe(false);
    else if (required > 0)
    {
        if (decrypted_data.enough(required - outdata.datasize()))
        {
            decrypted_data.peek(outdata);
            ASSERT(outdata.datasize() >= required);
            set_readypipe(!decrypted_data.is_empty());
            return required;
        }
        else {
            set_readypipe(false);
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
                    if (0 != (pipe->wait(netkit::SE_READ, LOOP_PERIOD) & netkit::SE_CLOSED) || glb.is_stop())
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
                if (0 != (pipe->wait(netkit::SE_READ, LOOP_PERIOD) & netkit::SE_CLOSED) || glb.is_stop())
                    return -1;
                
                set_readypipe(false);
                continue; // not enough data
            }

            decrypted_data.peek(outdata, required);
            set_readypipe(!decrypted_data.is_empty());
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
    set_readypipe(!decrypted_data.is_empty());
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

        set_readypipe(true);
    }
}

/*virtual*/ netkit::system_socket *tls_pipe::get_socket()
{
    if (!pipe)
        return nullptr;

    incdec ddd(busy, this);
    if (ddd) return nullptr;

    return pipe->get_socket();

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
#endif

size_t generate_random_client_hello(buffer& packet, const str::astr_view& sni_hostname, bool generate_random)
{
    auto add_be = [&](auto value) {
        packet.push_back(static_cast<u8>((value >> 8) & 0xff));
        packet.push_back(static_cast<u8>(value & 0xff));
    };

    // 1. header of TLS record (Record Layer)
    packet.push_back(0x16); // Handshake type
    packet.push_back(0x03); // version TLS 1.0-1.2
    packet.push_back(0x01); // (allowed 0x01-0x03)

    // tls message length  (0 for now, fill later)
    size_t message_len_offset1 = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);

    // 2. Handshake header
    packet.push_back(0x01); // ClientHello type
    // message length (3 bytes, 0 for now, fill later)
    size_t message_len_offset2 = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);

    // 3. TLS version (ClientHello)
    packet.push_back(0x03);
    packet.push_back(0x03); // TLS 1.2

    // 4. Random (32 bytes)
    size_t random_offset = packet.size();
    if (generate_random)
        randomgen::get().randombytes_buf(packet.expand(32), 32);
    else
        packet.expand(32);

    // 5. Session ID (1 byte len + data if present)
    packet.push_back(0);
    //randomgen::get().randombytes_buf(packet.expand(32), 32);

    // 6. list of ciphers (2 bytes len + data)
    uint16_t ciphers[] = {
        0xC02B, 0xC02F, 0xC02C, 0xC030, // ECDHE ciphers
        0x009E, 0x009F, // AES-GCM
        0xCCA8, 0xCCA9, // ChaCha20
        0x0033, 0x0039, 0x002F, 0x0035 // other popular
    };

    add_be( sizeof(ciphers) );
    for (auto cipher : ciphers)
        add_be(cipher);

    // 7. list of compression methods (1 byte len + data)
    packet.push_back(0x01); // len
    packet.push_back(0x00); // Null compression

    // 8. extensions (2 bytes whole len)
    size_t extensions_start = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);

    // 8.1. SNI extension
    add_be(0x0000); // type SNI
    // len of SNI data
    add_be(sni_hostname.length() + 5); // 5 bytes for service data
    // len of name list (hostname + 3 bytes)
    add_be(sni_hostname.length() + 3);
    // name type - hostname (0)
    packet.push_back(0x00);
    // len of hostname
    add_be(sni_hostname.length());
    // hostname itself
    packet += str::span(sni_hostname);

    // 8.2. supported groups (elliptic curves)
    add_be(0x000A); // type
    add_be(0x04);   // len
    add_be(0x02);   // list len
    add_be(0x0017); // secp256r1

    // 8.3. Signature Algorithms
    add_be(0x000D); // type
    add_be(0x08);   // len
    add_be(0x06);   // list len
    add_be(0x0403); // ecdsa_secp256r1_sha256
    add_be(0x0804); // rsa_pss_rsae_sha256
    add_be(0x0401); // rsa_pkcs1_sha256

    // update ext len
    auto extensions_len = packet.size() - extensions_start - 2;
    packet[extensions_start] = static_cast<u8>((extensions_len >> 8) & 0xff);
    packet[extensions_start + 1] = static_cast<u8>(extensions_len & 0xff);

    // update Handshake len (p. 2)
    auto handshake_len = packet.size() - 5 - 4; // minus header
    packet[message_len_offset2] = static_cast<u8>((handshake_len >> 16) & 0xff);
    packet[message_len_offset2+1] = static_cast<u8>((handshake_len >> 8) & 0xff);
    packet[message_len_offset2+2] = static_cast<u8>(handshake_len & 0xff);

    // update TLS record len (p. 1)
    auto record_len = packet.size() - 5; // minus header
    packet[message_len_offset1] = static_cast<u8>((record_len >> 8) & 0xff);
    packet[message_len_offset1+1] = static_cast<u8>(record_len & 0xff);

    return random_offset;
}


const u8 * extract_tls_clienthello_random(const u8* packet, size_t &packet_len)
{
    const size_t min_tls_len = 5 + 4 + 2 + 32;

    if (packet_len < min_tls_len)
        return nullptr;

    if (packet[0] != 0x16)
        return nullptr; // not TLS Handshake

    // check TLS version (must be 0x03 0x01, 0x03 0x02 or 0x03 0x03)
    if (packet[1] != 0x03 || (packet[2] != 0x01 && packet[2] != 0x02 && packet[2] != 0x03))
        return nullptr;

    if (packet[5] != 0x01) {
        return nullptr; // not ClientHello
    }

    u16 handshake_data_len = load_be<2>(packet + 3);
    size_t client_hello_len = load_be<3>(packet + 6);

    if (client_hello_len + 4 > handshake_data_len)
        return nullptr;
    
    packet_len = handshake_data_len + 5;

    return packet + 5 + 4 + 2;

}

std::span<const u8> extract_tls_clienthello_sni(const u8* packet, size_t& packet_len)
{
    const size_t min_tls_len = 5 + 4 + 2 + 32;

    if (packet_len < min_tls_len)
        return {};

    if (packet[0] != 0x16)
        return {}; // not TLS Handshake

    // check TLS version (must be 0x03 0x01, 0x03 0x02 or 0x03 0x03)
    if (packet[1] != 0x03 || (packet[2] != 0x01 && packet[2] != 0x02 && packet[2] != 0x03))
        return {};

    if (packet[5] != 0x01) {
        return {}; // not ClientHello
    }

    u16 handshake_data_len = load_be<2>(packet + 3);
    size_t client_hello_len = load_be<3>(packet + 6);

    if (client_hello_len + 4 > handshake_data_len)
        return {};

    packet_len = handshake_data_len + 5;

    size_t pos = 5 + 4 + 2 + 32; // just after random

    // skip session id
    if (pos + 1 > packet_len) return {};
    u8 session_id_len = packet[pos++];
    pos += session_id_len;

    // skip Cipher Suites
    if (pos + 2 > packet_len) return {};
    u16 cipher_suites_len = load_be<2>(packet + pos);
    pos += 2 + cipher_suites_len;

    // skip Compression Methods
    if (pos + 1 > packet_len) return {};
    u8 compression_methods_len = packet[pos++];
    pos += compression_methods_len;

    if (pos + 2 > packet_len)
        return {}; // no extensions

    u16 extensions_len = load_be<2>(packet + pos);
    pos += 2;

    size_t extensions_end = pos + extensions_len;

    // seek for Extension Server Name (0x00 0x00)
    while (pos + 4 <= extensions_end && pos + 4 <= packet_len) {
        u16 extension_type = load_be<2>(packet + pos);
        u16 extension_len = load_be<2>(packet + pos + 2);
        pos += 4;

        if (extension_type == 0x0000)
        {
            // Server Name Extension
            if (pos + 2 > packet_len) break;

            // read len of Server Name List
            u16 server_name_list_len = load_be<2>(packet + pos);
            pos += 2;

            size_t list_end = pos + server_name_list_len;

            // go through list Server Name
            while (pos + 3 <= list_end && pos + 3 <= packet_len)
            {
                u8 name_type = packet[pos++];
                u16 name_len = load_be<2>(packet + pos);
                pos += 2;

                if (name_type == 0x00)
                {
                    // host_name
                    if (pos + name_len <= packet_len)
                        return std::span(packet + pos, name_len);
                    break;
                }

                pos += name_len;
            }
            break;
        }
        else {
            pos += extension_len;
        }
    }

    return {};
}









