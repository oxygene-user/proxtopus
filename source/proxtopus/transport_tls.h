#pragma once

class transport_tls : public transport, public Botan::Credentials_Manager, public Botan::TLS::Strict_Policy  // tls server
{
    randomgen rng;
    tools::deferred_init<Botan::TLS::Session_Manager_In_Memory> sesionmgr;

    /*virtual*/ std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type, const std::string& context) override {
        BOTAN_UNUSED(type, context);
        // if client authentication is required, this function
        // shall return a list of certificates of CAs we trust
        // for tls client certificates, otherwise return an empty list
        return {};
    }

    /*virtual*/ std::vector<Botan::X509_Certificate> cert_chain(Botan::Algo_Group cert_key_types,
        const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
        const std::string& type, const std::string& context) override;

    /*virtual*/ std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
        const std::string& type,
        const std::string& context) override {
        BOTAN_UNUSED(cert, type, context);
        return m_key;
    }

    virtual bool acceptable_ciphersuite(const Botan::TLS::Ciphersuite& suite) const;

    std::shared_ptr<Botan::Private_Key> m_key;
    std::vector<Botan::X509_Certificate> m_certs;
    bool alpn_http11 = false;
protected:
public:
    transport_tls(loader& ldr, listener* owner, const asts& bb, netkit::socket_type_e st, handler* h);
    virtual ~transport_tls() { stop(); }

    /*virtual*/ str::astr_view desc() const { return ASTR("tls"); }
    /*virtual*/ bool compatible(netkit::socket_type_e st) const
    {
        return st == netkit::ST_TCP;
    }

    /*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
    void set_alpn_http11(bool f) { alpn_http11 = f; }
};
