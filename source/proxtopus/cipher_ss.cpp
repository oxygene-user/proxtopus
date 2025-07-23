#include "pch.h"
#include "botan_hash.h"
#include "botan/internal/gcm.h"
#include "botan/internal/aes.h"

std::unique_ptr<Botan::Cipher_Mode> ss::botan_aead::make_aesgcm_128(bool enc)
{
    auto bc = std::make_unique<Botan::AES_128>();

    if (enc) {
        return std::make_unique<Botan::GCM_Encryption>(std::move(bc), SS_AEAD_TAG_SIZE);
    }
    else {
        return std::make_unique<Botan::GCM_Decryption>(std::move(bc), SS_AEAD_TAG_SIZE);
    }
}
std::unique_ptr<Botan::Cipher_Mode> ss::botan_aead::make_aesgcm_192(bool enc)
{
    auto bc = std::make_unique<Botan::AES_192>();

    if (enc) {
        return std::make_unique<Botan::GCM_Encryption>(std::move(bc), SS_AEAD_TAG_SIZE);
    }
    else {
        return std::make_unique<Botan::GCM_Decryption>(std::move(bc), SS_AEAD_TAG_SIZE);
    }

}

std::unique_ptr<Botan::Cipher_Mode> ss::botan_aead::make_aesgcm_256(bool enc)
{
    auto bc = std::make_unique<Botan::AES_256>();

    if (enc) {
        return std::make_unique<Botan::GCM_Encryption>(std::move(bc), SS_AEAD_TAG_SIZE);
    }
    else {
        return std::make_unique<Botan::GCM_Decryption>(std::move(bc), SS_AEAD_TAG_SIZE);
    }

}

void ss::derive_aead_subkey(u8* skey, const u8* master_key, const u8* salt, unsigned keylen)
{
    hkdf< hmac<sha1> >::perform_kdf(std::span(skey, keylen), std::span(master_key, keylen), std::span(salt, keylen), str::span(ASTR("ss-subkey")));
}

void ss::derive_ssp_subkey(u8* skey, const u8* master_key, const u8* salt)
{
    hkdf< hmac<sha256> >::perform_kdf(std::span(skey, 32), std::span(master_key, 32), std::span(salt, 32), str::span(ASTR("ssp-subkey")));
}

signed_t ss::ssp_iv_test(const u8* iv, const u8* ssp_key, signed_t shift) // slow iv check for compliance with the protocol ssp (32 bytes expected)
{
    core::keyspace check_key;
    u8 ive[17];
    tools::memcopy<16>(ive,iv);
    for (signed_t n = 0; n < 256; ++n)
    {
        ive[16] = tools::as_byte(n);
        hkdf< hmac<sha1> >::perform_kdf(check_key.space, std::span(ssp_key, 32), ive, str::span(ASTR("ssp-check")));
        if (memcmp(iv + 16, check_key.space + shift, 16) == 0)
            return n;
    }

    return -1;
}

void ss::ssp_iv_gen(u8* iv, const u8* ssp_key, u8 par)
{
    randomgen::get().random_vec(std::span(iv, 18));
    iv[16] = par;
    signed_t shift;
    for (;;)
    {
        shift = ssp_iv_pretest(iv);
        if (shift >= 0)
            break;

        shift = ((signed_t)iv[17]) % (16-5);
        iv[shift + 5] = 255 ^ iv[shift];
        break;
    }

    core::keyspace check_key;
    hkdf< hmac<sha1> >::perform_kdf(check_key.space, std::span(ssp_key, 32), std::span(iv,17), str::span(ASTR("ssp-check")));
    tools::memcopy<16>(iv + 16, check_key.space + shift);
}

void ss::core::masterkey::gen_ssp_key()
{
    sha256 sha;
    sha.update(key.space);
    sha.fin(ssp_key.space);
    for (signed_t i = 0; i < 32; ++i)
    {
        sha.update(ssp_key.space);
        sha.fin(ssp_key.space);
    }
}

namespace
{
    void md5hash(str::astr& out, const str::astr_view& in)
    {
        md5 md5;
        md5.update(str::span(in));
        out.resize(md5::output_bytes);
        md5.fin(std::span<u8, md5::output_bytes>((u8*)out.data(), md5::output_bytes));
    }

    void evp_bytes_to_key(ss::core::keyspace& master_key, unsigned keyLen, const str::astr_view& password)
    {
        str::astr prevm;
        size_t mkl = 0;
        for (;;) {
            prevm += password;
            md5hash(prevm, prevm);

            auto cpy = math::minv(keyLen-mkl, prevm.size());
            memcpy(master_key.space + mkl, prevm.c_str(), cpy);
            mkl += cpy;
            if (mkl >= keyLen)
                return;
        }
    }
}

std::unique_ptr<ss::core::cryptor> ss::core::crypto_par::build_crypto(crypto_type ct) const
{
    switch (cryptoalg)
    {
    case crypto_chachapoly:
        [[unlikely]] if (NonceSize == 24)
        {
            if (ct == CRYPTO_UDP)
                return std::move(std::make_unique<aead_chacha20poly1305_cryptor<24, CRYPTO_UDP>>());
            if (ct == CRYPTO_TCP)
                return std::move(std::make_unique<aead_chacha20poly1305_cryptor<24, CRYPTO_TCP>>());
            return std::move(std::make_unique<aead_chacha20poly1305_cryptor<24, CRYPTO_TCP_SSP>>());
        }
        if (ct == CRYPTO_UDP)
            return std::move(std::make_unique<aead_chacha20poly1305_cryptor<12, CRYPTO_UDP>>());
        if (ct == CRYPTO_TCP)
            return std::move(std::make_unique<aead_chacha20poly1305_cryptor<12, CRYPTO_TCP>>());
        return std::move(std::make_unique<aead_chacha20poly1305_cryptor<12, CRYPTO_TCP_SSP>>());

    case crypto_aesgcm_256:
        return std::move(std::make_unique<botan_aead_cryptor>(*this, ss::botan_aead::make_aesgcm_256));
    case crypto_aesgcm_192:
        return std::move(std::make_unique<botan_aead_cryptor>(*this, ss::botan_aead::make_aesgcm_192));
    case crypto_aesgcm_128:
        return std::move(std::make_unique<botan_aead_cryptor>(*this, ss::botan_aead::make_aesgcm_128));
    }
    return std::move(std::make_unique<none_cryptor>());

}

void ss::botan_aead::keyed_filter::set_key(std::span<const u8> key, cipher* ciph)
{
    mode->set_key(key);
    memset(iv.data(), 0, sizeof(iv));

    ASSERT(m_next.size() == 1);
    m_next[0] = ciph;
}

/*virtual*/ void ss::botan_aead::keyed_filter::write(const uint8_t input[], size_t input_length)
{
    size_t idealg = mode->ideal_granularity();
    size_t mfz = idealg + mode->minimum_final_size();

    while (input_length >= mfz) {

        buf.assign(input, input + idealg);
        mode->update(buf);
        send(buf.data(), buf.size());

        input += idealg;
        input_length -= idealg;
    }

    if (input_length > 0)
        buf.assign(input, input + input_length);
    else
        buf.clear();

}

/*virtual*/ void ss::botan_aead::keyed_filter::end_msg()
{
    mode->finish(buf);
    send(buf.data(), buf.size());
    incnonce();
}

void ss::botan_aead::cipher_enc::process(std::span<const u8> input, buffer&output)
{
    current_output = &output;
    output.reserve(output.size() + input.size() + SS_AEAD_TAG_SIZE, output.size());
    //size_t offset = output.size();
    recoder.start_msg();
    recoder.write(input.data(), input.size());
    recoder.end_msg();
    //return output.size() == offset + input.size() + SS_AEAD_TAG_SIZE; // no need to check encoding, it always ok
}

bool ss::botan_aead::cipher_dec::process(std::span<const u8> input, tools::memory_pair& output)
{
    handled = 0;
    current_output = &output;
    try
    {
        Botan::Exception::quiet(true);
        recoder.start_msg();
        recoder.write(input.data(), input.size());
        recoder.end_msg();
        Botan::Exception::quiet(false);
    }
    catch (...)
    {
        return false;
    }

    return handled + SS_AEAD_TAG_SIZE == input.size();
}



str::astr ss::core::load(loader& ldr, const str::astr& name, const asts& bb)
{
    const str::astr &url = bb.get_string(ASTR("url"), glb.emptys);

    str::astr method = bb.get_string(ASTR("method"), glb.emptys);
    str::astr password = bb.get_string(ASTR("password"), glb.emptys);
    str::astr addr;

    if (url.starts_with(ASTR("ss://")))
    {
        size_t x = url.find('@');
        if (x != url.npos)
        {
            size_t y = url.find('#', x+1);
            if (y == url.npos) y = url.length();
            addr = url.substr(x + 1, y);
            char *outb = (char*)ALLOCA(x);
            signed_t sz = str::decode_base64(str::astr_view(url.data() + 5, x - 5), outb, x);
            str::astr_view dec(outb, sz);
            size_t z = dec.find(':');
            if (z != dec.npos)
            {
                method = dec.substr(0, z);
                password = dec.substr(z + 1);
            }
        }
    }

    bool allow_empty_password = false;

    if (method.starts_with(ASTR("xchacha20")))
    {
        LOG_W("meaningless cipher method used in shadowsocs core [$]; there are no advantages for using xchacha20 instead of chacha20-ietf; do not use xchacha20 unless a gun is held to your head", str::clean(name));

        cp = { 32, 24, crypto_chachapoly };
    }
    else if (method.starts_with(ASTR("chacha20")))
    {
        cp = { 32, 12, crypto_chachapoly };
    }
    else if (method == ASTR("aes-256-gcm"))
    {
        cp = { 32, 12, crypto_aesgcm_256 };
    }
    else if (method == ASTR("aes-192-gcm"))
    {
        cp = { 24, 12, crypto_aesgcm_192 };
    }
    else if (method == ASTR("aes-128-gcm"))
    {
        cp = { 16, 12, crypto_aesgcm_128 };
    }
    else if (method == ASTR("none"))
    {
        cp = { 0, 0, crypto_none };
        allow_empty_password = true;
    }
    else
    {
        ldr.exit_code = EXIT_FAIL_METHOD_UNDEFINED;
        LOG_FATAL("{method} not defined for shadowsocks core [$]", str::clean(name));
        return str::astr();
    }

    auto mkw = masterkeys.lock_write();

    if (!password.empty())
    {
        auto& mk = mkw().emplace_back();
        mk.name = ASTR("main");
        evp_bytes_to_key(mk.key, cp.KeySize, password);
        mk.gen_ssp_key();
    }

    if (const asts* pwds = bb.get(ASTR("passwords")))
    {
        for (auto it = pwds->begin(); it; ++it)
        {
            if (it.is_comment())
                continue;

            const str::astr_view& p = str::trim(str::view(it->as_string(password)));
            if (p.empty())
                continue;

            auto& mk1 = mkw().emplace_back();
            mk1.name = it.name();
            evp_bytes_to_key(mk1.key, cp.KeySize, p);
            mk1.gen_ssp_key();

            for (signed_t i=0, cnt = mkw().size()-1; i<cnt; ++i)
            {
                if (memcmp(mkw()[i].key.space, mk1.key.space, cp.KeySize) == 0)
                {
                    // do not dup masterkeys
                    mkw().resize(mkw().size()-1);
                    break;
                }
            }
        }
    }

    if (mkw().size() == 0 && !allow_empty_password)
    {
        ldr.exit_code = EXIT_FAIL_NO_PASSWORDS_DEFINED;
        LOG_FATAL("no password defined for shadowsocks core [$]", str::clean(name));
        return str::astr();
    }

    return addr;
}

/*virtual*/ void ss::core::crypto_pipe_base::close(bool flush_before_close)
{
    spinlock::atomic_add<size_t>(busy, 10001);
    bool io = busy > 10001;
    if (!io && pipe)
    {
        pipe->close(flush_before_close);
        pipe = nullptr;
    }
}

/*virtual*/ netkit::WAITABLE ss::core::crypto_pipe_base::get_waitable()
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


/*virtual*/ netkit::pipe::sendrslt ss::core::crypto_pipe_base::send(const u8* data, signed_t datasize)
{
    if (!pipe)
        return SEND_FAIL;

    incdec ddd(busy, this);
    if (ddd) return SEND_FAIL;

    if (data == nullptr)
        return pipe->send(nullptr, 0); // check allow send

    if (datasize != 0)
    {
        if (datasize < 0)
        {
            // don't send data now, collect more bytes for 1st packet
            crypto->encipher(std::span<const u8>(data, -datasize), encrypted_data, nullptr);
            return SEND_OK;
        }
        crypto->encipher(std::span<const u8>(data, datasize), encrypted_data, nullptr);
    }
    sendrslt rslt = pipe->send(encrypted_data.data(), encrypted_data.size());
    encrypted_data.clear(); // IMPORTANT: clear after send, not before (due encrypted_data contains salt before 1st send)

    return rslt;
}

/*virtual*/ signed_t ss::core::crypto_pipe_base::recv(tools::circular_buffer_extdata& outdata, tools::circular_buffer_extdata& tempbuf, signed_t required, signed_t timeout DST(, deep_tracer* tracer))
{
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

        if (tempbuf.datasize() > 0)
        {
            if (!crypto->decipher(decrypted_data, tempbuf, nullptr)) // try decrypt
                return -1;

            ASSERT(tempbuf.datasize() == 0);
        }

        if (required > 0)
        {
            if (!decrypted_data.enough(required - outdata.datasize()))
                continue; // not enough data

            decrypted_data.peek(outdata);
            return required;
        }
        break;
    }
    signed_t maxcopysize = outdata.get_free_size();
    return decrypted_data.peek(outdata, maxcopysize);
}

/*virtual*/ signed_t ss::core::crypto_pipe_base::recv(tools::circular_buffer_extdata& outdata, signed_t required, signed_t timeout DST(, deep_tracer* tracer))
{
    if (required > 0 && outdata.datasize() >= required)
    {
        DST(if (tracer) tracer->log("ssrecv alrd"));
        return required;
    }

    if (!pipe)
        return -1;

    incdec ddd(busy, this);
    if (ddd)
        return -1;

    tools::circular_buffer_preallocated<BRIDGE_BUFFER_SIZE> tempbuf;

    return recv(outdata, tempbuf, required, timeout DST(, tracer));

}

/*virtual*/ void ss::core::crypto_pipe_base::unrecv(tools::circular_buffer_extdata& data)
{
    if (size_t dsz = data.datasize(); dsz > 0 && pipe)
    {
        tools::memory_pair mp = data.data(dsz);

        if (mp.p1.size())
            decrypted_data.insert(mp.p1);
        decrypted_data.insert(mp.p0);
        data.clear();
        
        netkit::make_ready(pipe->get_waitable(), READY_PIPE);
    }
}

ss::core::crypto_pipe* ss::core::crypto_pipe::build(ss::core::masterkey_array& masterkeys, ss::core::crypto_par cp, netkit::pipe_ptr p, tools::circular_buffer_extdata& cipherdata, signed_t sspk)
{
    auto mkr = masterkeys.lock_read();
    if (mkr().size() == 0)
        return nullptr; // inactive

    if (mkr().size() == 1 || sspk >= 0)
    {

        ss::core::keyspace master_key = mkr()[sspk < 0 ? 0 : sspk].key;
        mkr.unlock();

        std::unique_ptr<ss::core::cryptor> crypto = cp.build_crypto(sspk >= 0 ? CRYPTO_TCP_SSP : CRYPTO_TCP);

        const u8* iv = cipherdata.data1st(cp.KeySize); // iv (salt)
        ss::core::keyspace key;
        if (sspk >= 0)
            ss::derive_ssp_subkey(key.space, master_key.space, iv);
        else
            ss::derive_aead_subkey(key.space, master_key.space, iv, cp.KeySize);
        cipherdata.skip(cp.KeySize);

        crypto->init_decryptor(std::span<u8>(key.space, cp.KeySize));

        buffer outsalt;
        outsalt.resize(cp.KeySize, true);
        randomgen::get().random_vec(outsalt);

        if (sspk >= 0)
            ss::derive_ssp_subkey(key.space, master_key.space, outsalt.data());
        else
            ss::derive_aead_subkey(key.space, master_key.space, outsalt.data(), cp.KeySize);
        crypto->init_encryptor(std::span<u8>(key.space, cp.KeySize));

        tools::circular_buffer_extdata ciphertestdata(std::span<u8>(const_cast<u8*>(cipherdata.data1st(2 + SS_AEAD_TAG_SIZE)), 2 + SS_AEAD_TAG_SIZE), true);
        if (!crypto->prebuf(ciphertestdata, 2 + SS_AEAD_TAG_SIZE))
            return nullptr; // no need to support non-aead cryptor
        cipherdata.skip(2 + SS_AEAD_TAG_SIZE);
        p->unrecv(cipherdata);

        outbuffer plaindec;
        return NEW ss::core::crypto_pipe(p, std::move(crypto), std::move(plaindec), std::move(outsalt));
    }

    i64 cur_sec = chrono::now();

    const u8* iv = cipherdata.data1st(cp.KeySize + 2 + SS_AEAD_TAG_SIZE);
    const u8* testdata = iv + cp.KeySize; // 18 bytes

    std::unique_ptr<ss::core::cryptor> crypto = cp.build_crypto(CRYPTO_TCP);
    outbuffer plaindec;

    tools::circular_buffer_extdata ciphertestdata(std::span<u8>(const_cast<u8 *>(testdata), 2+SS_AEAD_TAG_SIZE), true);
    if (!crypto->prebuf(ciphertestdata, 2 + SS_AEAD_TAG_SIZE))
        return nullptr; // no need to support non-aead cryptor

    buffer outsalt;
    outsalt.resize(cp.KeySize, true);

    for (const auto& k : mkr())
    {
        if (k.expired < 0)
            continue;
        if (k.expired > 0 && k.expired < cur_sec)
        {
            const_cast<ss::core::masterkey&>(k).expired = -1; // acceptable hack because it final state of masterkey
            continue;
        }

        ss::core::keyspace temp;
        ss::derive_aead_subkey(temp.space, k.key.space, iv, cp.KeySize);

        crypto->init_decryptor(std::span<u8>(temp.space, cp.KeySize));
        plaindec.clear();
        auto r = crypto->decipher_prebuffered(plaindec);
        if (r == ss::core::cryptor::dr_not_enough_data /* not ok because we try to decode only size of chunk (2 bytes), not whole chunk */)
        {
            // found key!
            ss::core::keyspace master_key = k.key;
            str::astr un = k.name;
            mkr.unlock();

            cipherdata.skip(cp.KeySize + 2 + SS_AEAD_TAG_SIZE);
            p->unrecv(cipherdata);

            // now init encipher with found key
            randomgen::get().random_vec(outsalt);

            ss::derive_aead_subkey(temp.space, master_key.space, outsalt.data(), cp.KeySize);
            crypto->init_encryptor(std::span<const u8>(temp.space, cp.KeySize));

            //LOG_N("ss client ($)", un);

            return NEW ss::core::crypto_pipe_server(p, std::move(crypto), std::move(plaindec), std::move(outsalt), un);

        }
    }

    return nullptr;
}

ss::core::crypto_pipe::crypto_pipe(netkit::pipe_ptr pipe, std::unique_ptr<ss::core::cryptor>&& cry, outbuffer&& dcd, buffer &&ecd):crypto_pipe_base(pipe)
{
    crypto = std::move(cry);
    decrypted_data = std::move(dcd);
    encrypted_data = std::move(ecd);
}

ss::core::crypto_pipe_client::crypto_pipe_client(netkit::pipe_ptr pipe, ss::core::masterkey* key, crypto_par cp) :crypto_pipe(pipe), master_key(key), cp(cp)
{
    encrypted_data.resize(cp.KeySize);
    if (cp.is_ssp())
    {
        ssp_iv_gen(encrypted_data.data(), key->ssp_key.space, SSP_VERSION);
        Botan::secure_scrub_memory(key->ssp_key.space, sizeof(keyspace)); // zeroise
    }
    else
    {
        randomgen::get().random_vec(encrypted_data);
    }

    ss::core::keyspace skey;
    if (cp.is_ssp())
        ss::derive_ssp_subkey(skey.space, key->key.space, encrypted_data.data());
    else 
        ss::derive_aead_subkey(skey.space, key->key.space, encrypted_data.data(), cp.KeySize);

    crypto = cp.build_crypto(cp.is_ssp() ? CRYPTO_TCP_SSP : CRYPTO_TCP);
    crypto->init_encryptor(std::span<u8>(skey.space, cp.KeySize));
}

/*virtual*/ signed_t ss::core::crypto_pipe_client::recv(tools::circular_buffer_extdata& outdata, signed_t required, signed_t timeout DST(, deep_tracer* tracer))
{
    if (required > 0 && outdata.datasize() >= required)
    {
        DST(if (tracer) tracer->log("ssprecv alrd"));
        return required;
    }

    if (!pipe)
        return -1;

    incdec ddd(busy, this);
    if (ddd)
        return -1;

    tools::circular_buffer_preallocated<BRIDGE_BUFFER_SIZE> tempbuf;

    if (master_key)
    {
        signed_t rb = pipe->recv(tempbuf, static_cast<signed_t>(cp.KeySize), RECV_PREPARE_MODE_TIMEOUT DST(, tracer));
        if (rb != cp.KeySize)
            return -1;

        const u8* temp = tempbuf.data1st(cp.KeySize);
        ASSERT(temp != nullptr);
        ss::core::keyspace key;
        if (cp.is_ssp())
            ss::derive_ssp_subkey(key.space, master_key->key.space, temp);
        else
            ss::derive_aead_subkey(key.space, master_key->key.space, temp, cp.KeySize);
        tempbuf.skip(cp.KeySize);

        // clear masterkey (not required anymore)
        Botan::secure_scrub_memory(master_key->key.space, sizeof(keyspace)); // zeroise
        master_key.reset();

        crypto->init_decryptor(std::span<u8>(key.space, cp.KeySize));
    }

    return crypto_pipe::recv(outdata, tempbuf, required, timeout DST(, tracer));

}

ss::core::udp_crypto_pipe::udp_crypto_pipe(const netkit::endpoint& ssproxyep, netkit::udp_pipe* transport, const ss::core::keyspace &master_key, crypto_par cp) :master_key(master_key), transport(transport), cp(cp), ssproxyep(ssproxyep)
{
    crypto = cp.build_crypto(CRYPTO_UDP);
}

/*virtual*/ netkit::io_result ss::core::udp_crypto_pipe::send(const netkit::endpoint& toaddr, const netkit::pgen& pg /* in */)
{
    signed_t presize = proxy_socks5::atyp_size(toaddr);
    buf2s.resize(cp.KeySize);
    randomgen::get().random_vec(buf2s); // make initial salt as starting sequence

    ss::core::keyspace skey;
    std::span<u8> subkey(skey.space, cp.KeySize);
    ss::derive_aead_subkey(skey.space, master_key.space, buf2s.data(), cp.KeySize);

    if (presize <= pg.extra)
    {
        netkit::pgen pgx(const_cast<u8 *>(pg.get_data() - presize), presize + pg.sz);
        proxy_socks5::push_atyp(pgx, toaddr);
        crypto->encipher(pgx.to_span(), buf2s, &subkey);
    }
    else
    {
        u8* b2e = ALLOCA(pg.sz + presize);
        netkit::pgen pgx(b2e, presize + pg.sz);
        proxy_socks5::push_atyp(pgx, toaddr);
        memcpy(b2e + presize, pg.get_data(), pg.sz);
        crypto->encipher(pgx.to_span(), buf2s, &subkey);
    }
    netkit::pgen pgs(buf2s.data(), buf2s.size());
    return transport->send(ssproxyep, pgs);

}

/*virtual*/ netkit::io_result ss::core::udp_crypto_pipe::recv(netkit::ipap& from, netkit::pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/)
{
    u8 rcvbuf[16384];
    netkit::pgen pgr(rcvbuf, sizeof(rcvbuf));
    auto rslt = transport->recv(from, pgr, sizeof(rcvbuf));
    if (rslt != netkit::ior_ok)
        return rslt;

    ss::core::keyspace skey;
    std::span<u8> subkey(skey.space, cp.KeySize);
    ss::derive_aead_subkey(skey.space, master_key.space, rcvbuf, cp.KeySize);
    ss::outbuffer buf2r;
    tools::circular_buffer_extdata cd(std::span<u8>(rcvbuf + cp.KeySize, pgr.sz - cp.KeySize), true);
    if (!crypto->decipher(buf2r, cd, &subkey))
        return netkit::ior_decrypt_fail;
    auto decp = buf2r.get_1st_chunk();
    if (decp.size() == 0)
        return netkit::ior_proxy_fail;
    netkit::pgen repg((u8 *)decp.data(), decp.size());
    netkit::endpoint aaa;
    if (!proxy_socks5::read_atyp(repg, aaa))
        return netkit::ior_proxy_fail;
    from = aaa.resolve_ip(glb.cfg.ipstack | conf::gip_log_it);
    if ((signed_t)(decp.size() - repg.ptr) > max_bufer_size)
        return netkit::ior_proxy_fail;
    memcpy(pg.get_data(), decp.data() + repg.ptr, decp.size() - repg.ptr);
    pg.sz = tools::as_word(decp.size() - repg.ptr);
    return netkit::ior_ok;
}

/*virtual*/ void ss::core::botan_aead_cryptor::init_encryptor(std::span<const u8> key)
{
    encryptor.set_key(key);
}

/*virtual*/ void ss::core::botan_aead_cryptor::init_decryptor(std::span<const u8> key)
{
    decryptor.set_key(key);
    buffered_decryptor::init_decryptor(key); // clear buffer
}

/*virtual*/ void ss::core::botan_aead_cryptor::encipher(std::span<const u8> plain, buffer& cipher, const std::span<u8>* key)
{
    auto encode = [this, &cipher](const u8* d, size_t sz)
    {
        encryptor.process(std::span<const u8>(d, sz), cipher);
    };

    if (key)
    {
        encryptor.set_key(*key);
        encode(plain.data(), plain.size());
        return;
    }

    u16 inLen = (u16)(0xffff & (plain.size() > SS_AEAD_CHUNK_SIZE_MASK ? SS_AEAD_CHUNK_SIZE_MASK : plain.size()));
    u16be size_be = inLen;

    // size block encode
    encode(reinterpret_cast<const u8*>(&size_be), sizeof(size_be));
    // payload block encode
    encode(plain.data(), inLen);

    if (inLen < plain.size()) {
        // Append the remaining part recursively if there is any
        encipher(std::span(plain.data() + inLen, plain.size() - inLen), cipher, key);
    }
}

signed_t ss::core::buffered_decryptor::decrypt_part(size_t& from, outbuffer& plain)
{
    auto decode = [this](signed_t skip, tools::memory_pair &out, size_t capacity) -> signed_t
    {
        if ((unprocessed.size() - skip) < capacity + SS_AEAD_TAG_SIZE)
            return 0;

        if (!decipher_packet(std::span<const u8>(unprocessed.data() + skip, capacity + SS_AEAD_TAG_SIZE), out))
            return -1;
        return capacity + SS_AEAD_TAG_SIZE;
    };

    size_t from_current = from;

    size_t payloadsize = last_block_payload_size;
    if (last_block_payload_size > 0)
    {
        ASSERT(from_current == 0);
        from_current = 2 + 16;
    }
    else
    {
        u16be payloadsize_network_endian;
        tools::memory_pair mp(payloadsize_network_endian);
        signed_t delta = decode(from_current, mp, sizeof(u16));
        if (delta < 0)
            return -1;
        if (delta == 0)
            return 0; // not yet ready data
        from_current += delta;
        payloadsize = payloadsize_network_endian;
        if (payloadsize > SS_AEAD_CHUNK_SIZE_MASK)
            return -1; // looks like chunk size is corrupted or wrong decrypted
        last_block_payload_size = payloadsize; // keep payloadsize in case of incomplete data because we have already increased IV

        if (payloadsize == 0)
            return -1;

    }

    if (payloadsize + SS_AEAD_TAG_SIZE > (unprocessed.size() - from_current))
        return 0; // not yet ready data

    auto mp = plain.alloc(payloadsize);

    signed_t d = decode(from_current, mp, payloadsize);
    if (d < 0)
        return -1;
    from_current += d;
    from = from_current;
    return payloadsize;
}

/*virtual*/ ss::core::cryptor::dec_rslt ss::core::buffered_decryptor::decipher_prebuffered(outbuffer& plain)
{
    size_t from = 0;
    signed_t decr = 0;
    bool not_enough = false;

    for (size_t usz = unprocessed.size(); from < usz;)
    {
        signed_t d = decrypt_part(from, plain);
        if (d < 0)
            return dr_fail;
        if (d == 0)
        {
            not_enough = true;
            break;
        }
        last_block_payload_size = 0;
        decr += d;
    }

    if (decr > 0)
    {
        if (from == unprocessed.size())
        {
            unprocessed.clear();
        }
        else
        {
            if (from == 0 && unprocessed.size() > SS_AEAD_CHUNK_SIZE_MASK)
            {
                // looks like data corrupt: decryptor can't process data
                return dr_fail;
            }
            unprocessed.erase(from);
        }
    }

    return not_enough ? dr_not_enough_data : dr_ok;
}

void ss::core::ssp_cryptor::ssp_encipher(std::span<const u8> plain, buffer& cipher)
{
    u16 inLen = (u16)(0xffff & (plain.size() > SS_AEAD_CHUNK_SIZE_MASK ? SS_AEAD_CHUNK_SIZE_MASK : plain.size()));
    u16be size_be = inLen;

    encryptor.encipher_packet(nonce_enc, std::span(reinterpret_cast<const u8*>(&size_be), sizeof(size_be)), std::span(plain.data(), inLen), [&cipher](size_t sz) -> u8* {

        size_t osz = cipher.size();
        cipher.resize(osz + sz, true);
        return cipher.data() + osz;
    });

    ++nonce_enc;

    if (inLen < plain.size()) {
        // Append the remaining part recursively if there is any
        ssp_encipher(std::span(plain.data() + inLen, plain.size() - inLen), cipher);
    }
}

/*virtual*/ ss::core::cryptor::dec_rslt ss::core::ssp_cryptor::decipher_prebuffered(outbuffer& plain)
{
    size_t from = 0;
    bool not_enough = false;

    for (size_t usz = unprocessed.size(); from < usz;)
    {
        signed_t d = decryptor.decipher_packet_ssp(nonce_dec, std::span(unprocessed.data() + from, unprocessed.size()-from), plain);
        if (d < 0)
            return dr_fail;
        if (d == 0)
        {
            not_enough = true;
            break;
        }
        ++nonce_dec;
        from += d;
    }

    if (from > 0)
    {
        if (from == unprocessed.size())
        {
            unprocessed.clear();
        }
        else
        {
            if ((unprocessed.size() - from) >= SS_AEAD_CHUNK_SIZE_MASK)
                return dr_fail;

            unprocessed.erase(from);
        }
    }

    return not_enough ? dr_not_enough_data : dr_ok;
}

/*virtual*/ bool ss::core::botan_aead_cryptor::decipher(outbuffer& plain, tools::circular_buffer_extdata& cipher, const std::span<u8>* key)
{
    if (key)
    {
        if (cipher.datasize() < SS_AEAD_TAG_SIZE)
            return false;
        decryptor.set_key(*key);
        size_t ciphsz = cipher.datasize();
        auto mp = plain.alloc(ciphsz - SS_AEAD_TAG_SIZE);
        const u8* ciphpacket = cipher.data1st(ciphsz);
        return decryptor.process(std::span(ciphpacket, ciphsz), mp);
    }

    cipher.peek(unprocessed);
    return decipher_prebuffered(plain) != dr_fail;
}
