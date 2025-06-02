#include "pch.h"
#include <botan/data_src.h>
#include <botan/pkcs8.h>

transport_tls::transport_tls(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e /*st*/, handler* h) :transport(ldr, owner, bb, h)
{
    sesionmgr.init(&rng);

    const str::astr &kf = bb.get_string(ASTR("key"), glb.emptys);
    if (kf.empty())
    {
        ldr.exit_code = EXIT_FAIL_KEY_MISSED;
        LOG_FATAL("{key} file not defined for tls transport of listener [$]^", str::clean(owner->get_name()));
        return;
    }

    const str::astr& crtp = bb.get_string(ASTR("crt-path"), glb.emptys);
    const str::astr &crtf = bb.get_string(ASTR("crt"), glb.emptys);
    if (crtf.empty())
    {
        ldr.exit_code = EXIT_FAIL_CRT_MISSED;
        LOG_FATAL("{crt} file not defined for tls transport of listener [$]^", str::clean(owner->get_name()));
        return;
    }

    Botan::DataSource_Memory ds;
    load_buf(tofn(kf), ds.buf());
    try
    {
        m_key.reset(Botan::PKCS8::load_key(ds).release());
    }
    catch (const Botan::Exception &e)
    {
        ldr.exit_code = EXIT_FAIL_KEY_MISSED;
        LOG_FATAL("{key} file [$] not loaded ($) for tls transport of listener [$]^", kf, e, str::clean(owner->get_name()));
        return;
    }

    FN curcrt;
    FN crtpath = tofn(crtp);
    try
    {
        enum_tokens_a(cp, crtf, '|')
        {
            ds.reset_offset();
            if (crtpath.empty())
                curcrt = tofn(*cp);
            else curcrt = path_concat(crtpath, tofn(*cp));
            if (load_buf(curcrt, ds.buf()))
            {
                m_certs.emplace_back(ds);
                auto salg = m_certs.back().signature_algorithm();
                str::astr algs = salg.oid().alg().first().to_string();
                LOG_N("$-certificate loaded for tls transport of listener [$]", algs, str::clean(owner->get_name()));
            }
            else
            {
                throw std::runtime_error("not found");
            }
        }
    }
    catch (std::exception &e)
    {
        ldr.exit_code = EXIT_FAIL_CRT_MISSED;
        LOG_FATAL("{crt} file [$] not loaded ($) for tls transport of listener [$]^", curcrt, e, str::clean(owner->get_name()));
        return;
    }

}

/*virtual*/ std::vector<Botan::X509_Certificate> transport_tls::cert_chain(Botan::Algo_Group cert_key_types,
    const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
    const std::string& type, const std::string& context) {
    BOTAN_UNUSED(cert_key_types, cert_signature_schemes, type, context);
    return m_certs;
}

bool transport_tls::acceptable_ciphersuite(const Botan::TLS::Ciphersuite& suite) const
{
    bool acpt = Botan::TLS::Strict_Policy::acceptable_ciphersuite(suite);
    if (!acpt)
        return false;
    auto a = m_certs[0].signature_algorithm().oid().alg().first().a;
    return a == suite.auth_method().a;
}


/*virtual*/ void transport_tls::handle_pipe(netkit::pipe* pipe)
{
    netkit::pipe_ptr p(pipe); // pipe to client
    tls_pipe *tlspipe = NEW tls_pipe(p, this, &*sesionmgr, this, alpn_http11); // tlspipe will decrypt from-client data and encrypt to-client data
    hand->handle_pipe(tlspipe);
}
