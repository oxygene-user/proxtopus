#-----------#
# PROXTOPUS #
#-----------#

WORKDIR = `pwd`

CC = gcc
CXX = g++
AR = ar
LD = g++
WINDRES = windres

INC = -I.
CFLAGS = -Wfatal-errors -Wall -m64 -mcx16 -fexceptions -std=c++20 -static-libstdc++
RESINC = 
LIBDIR = 
LIB = 
LDFLAGS = -m64 -static-libstdc++

INC_RELEASE = $(INC)
CFLAGS_RELEASE = $(CFLAGS) -fomit-frame-pointer -fexpensive-optimizations -flto -O3
RESINC_RELEASE = $(RESINC)
RCFLAGS_RELEASE = $(RCFLAGS)
LIBDIR_RELEASE = $(LIBDIR)
LIB_RELEASE = $(LIB)
LDFLAGS_RELEASE = $(LDFLAGS) -flto=auto -s
OBJDIR_RELEASE = obj/Release
DEP_RELEASE = 
OUT_RELEASE = bin/proxtopus

FILES_CPP_PROXTOPUS = botan cipher_ss cmdline connect dnsq engine fsys handler_http handler_ss handlers http_api icpt json known_oids listener loader logger macro main mem
FILES_CPP_PROXTOPUS += netkit os_tools pch proxy proxy_ss rndgen sts tls tools transport transport_tls watchdog aead_chacha20poly1305 sodium_poly1305 chacha20

FILES_CPP_BOTAN = aes aes_ni aes_vaes aes_vperm alg_id alt_name asn1_obj asn1_oid asn1_str asn1_time ber_dec big_code big_ops2 big_ops3 big_rand bigint blake2b blinding buf_comp
FILES_CPP_BOTAN += calendar cbc certstor charset cpuid cpuid_x86 credentials_manager crl_ent ct_utils ctr chacha20poly1305
FILES_CPP_BOTAN += curve448_gf curve448_scalar data_src der_enc dh divide dl_group dl_named dl_scheme donna ec_apoint ec_group ec_inner_data ec_inner_pc ec_key_data
FILES_CPP_BOTAN += ec_named ec_scalar ecc_key ecdh ecdsa ed25519 ed25519_fe ed25519_key eme_pkcs emsa_pkcs1 exceptn filter gcm ge ghash ghash_cpu ghash_vperm hash_id hex hkdf
FILES_CPP_BOTAN += hmac keccak_perm keccak_perm_bmi2 keypair make_prm md5 mem_ops mem_utils mgf1 mod_inv monty monty_exp mp_comba mp_karat mp_monty mp_monty_n
FILES_CPP_BOTAN += msg_cert_req msg_cert_status msg_cert_verify msg_certificate_12 msg_client_hello msg_client_kex msg_finished msg_hello_verify msg_server_hello msg_server_kex
FILES_CPP_BOTAN += msg_session_ticket name_constraint numthry ocsp ocsp_types os_utils pcurves pcurves_generic pcurves_secp224r1 pcurves_secp256r1 pcurves_secp384r1
FILES_CPP_BOTAN += pcurves_secp521r1 pem pk_algs pk_keys pk_ops pkcs8 prf_tls primality primes pss_params pssr pubkey reducer rmd160 rng rsa salsa20 sc_muladd sc_reduce
FILES_CPP_BOTAN += sha1 sha1_simd sha1_x86 sha2_32 sha2_32_avx2 sha2_32_simd sha2_32_x86 sha2_64 sha2_64_x86 sha2_64_avx2 sha3 sm3 tls_alert tls_algos
FILES_CPP_BOTAN += tls_callbacks tls_cbc tls_channel_impl_12 tls_ciphersuite tls_extensions tls_extensions_cert_status_req tls_handshake_hash tls_handshake_io tls_handshake_state
FILES_CPP_BOTAN += tls_handshake_transitions tls_policy tls_record tls_server_impl_12 tls_session tls_session_key tls_session_manager tls_session_manager_memory
FILES_CPP_BOTAN += tls_signature_scheme tls_suite_info tls_version x448 x448_internal x509_crl x509_dn x509_ext x509_key x509_obj x509cert x509path x25519 xmd

FILES_CPP = $(addprefix botan/, $(FILES_CPP_BOTAN))
FILES_CPP += $(addprefix proxtopus/, $(FILES_CPP_PROXTOPUS))
FILES_TXT = res/help res/help_nix

CPP_RELEASE = $(addprefix $(OBJDIR_RELEASE)/, $(addsuffix .o, $(FILES_CPP)))
TXT_RELEASE = $(addprefix $(OBJDIR_RELEASE)/, $(addsuffix .o, $(FILES_TXT)))

OBJ_RELEASE = $(CPP_RELEASE)
OBJ_RELEASE += $(TXT_RELEASE)


all: release

clean: clean_release

before_release: 
	test -d bin || mkdir -p bin
	test -d $(OBJDIR_RELEASE)/botan || mkdir -p $(OBJDIR_RELEASE)/botan
	test -d $(OBJDIR_RELEASE)/proxtopus || mkdir -p $(OBJDIR_RELEASE)/proxtopus
	test -d $(OBJDIR_RELEASE)/res || mkdir -p $(OBJDIR_RELEASE)/res

after_release: 

release: before_release out_release after_release

out_release: before_release $(OBJ_RELEASE) $(DEP_RELEASE)
	$(LD) $(LIBDIR_RELEASE) -o $(OUT_RELEASE) $(OBJ_RELEASE) $(LDFLAGS_RELEASE) $(LIB_RELEASE)

$(CPP_RELEASE) : $(OBJDIR_RELEASE)/%.o: %.cpp
	$(CXX) $(CFLAGS_RELEASE) $(INC_RELEASE) -c $< -o $@

$(TXT_RELEASE) : $(OBJDIR_RELEASE)/%.o: %.txt
	objcopy --input binary --output elf64-x86-64 --binary-architecture i386:x86-64 $< $@

clean_release: 
	rm -f $(OBJ_RELEASE) $(OUT_RELEASE)
	rm -rf bin
	rm -rf $(OBJDIR_RELEASE)/botan
	rm -rf $(OBJDIR_RELEASE)/proxtopus
	rm -rf $(OBJDIR_RELEASE)/res

.PHONY: before_release after_release clean_release

