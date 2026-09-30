#include "connection_common.h"

#include <stddef.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

NORETURN(static void quic_server_raise_unacceptable(void));

/* The first datagram cannot start a connection. code stays nil: this is
   _accept's own verdict, not an ngtcp2 error passed through. */
static void
quic_server_raise_unacceptable(void)
{
  rb_raise(rb_eQUICErrorProto, "not an acceptable Initial packet");
}

/* Pick the first of the server's ALPN protocols, in the server's order of
   preference, that the client offered. Runs inside read_pkt with the GVL
   held and never touches Ruby objects. */
static int
quic_server_on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                               ptls_on_client_hello_parameters_t *params)
{
  quic_conn_t *c = (quic_conn_t *)((char *)self - offsetof(quic_conn_t, on_client_hello));
  for (size_t i = 0; i < c->alpn_count; i++) {
    for (size_t j = 0; j < params->negotiated_protocols.count; j++) {
      ptls_iovec_t offered = params->negotiated_protocols.list[j];
      if (offered.len == c->alpn[i].len &&
          memcmp(offered.base, c->alpn[i].base, offered.len) == 0) {
        return ptls_set_negotiated_protocol(tls, (const char *)offered.base, offered.len) == 0
          ? 0 : PTLS_ERROR_NO_MEMORY;
      }
    }
  }
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

/* Never supply a passphrase. Without a callback, PEM_read_bio_PrivateKey
   falls back to PEM_def_callback, which prompts on the controlling terminal;
   this way an encrypted key fails to load like any other unreadable one. */
static int
quic_server_no_passphrase_cb(char *buf, int size, int rwflag, void *userdata)
{
  (void)buf;
  (void)size;
  (void)rwflag;
  (void)userdata;
  return -1;
}

/* Load the certificate chain and private key into c->tls_ctx and install
   the signer. The certificate file is PEM, the leaf first and then any
   intermediates; there is no limit on their number. A misconfiguration
   raises ArgumentError naming the step that failed. Everything allocated
   here is released before raising, and libcrypto's error queue, which is
   shared with Ruby's openssl extension, is left empty on every return. */
static void
quic_server_load_certificate_and_key(quic_conn_t *c, VALUE certificate_path,
                                     VALUE private_key_path)
{
  VALUE failure_class = rb_eArgError;
  const char *failure = NULL;
  VALUE failed_path = Qnil;
  BIO *cert_bio = NULL;
  BIO *key_bio = NULL;
  X509 *leaf = NULL;
  X509 *x;
  STACK_OF(X509) *chain = NULL;
  EVP_PKEY *pkey = NULL;
  unsigned long err;

  ERR_clear_error();

  cert_bio = BIO_new_file(RSTRING_PTR(certificate_path), "r");
  if (cert_bio == NULL || (leaf = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) == NULL) {
    failure = "failed to load certificate";
    failed_path = certificate_path;
    goto done;
  }

  if ((chain = sk_X509_new_null()) == NULL) {
    failure_class = rb_eRuntimeError;
    failure = "sk_X509_new_null failed";
    goto done;
  }
  while ((x = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
    if (!sk_X509_push(chain, x)) {
      X509_free(x);
      failure_class = rb_eRuntimeError;
      failure = "sk_X509_push failed";
      goto done;
    }
  }
  /* The loop ends with PEM_R_NO_START_LINE once no PEM block is left. Any
     other error means a broken block, as in SSL_CTX_use_certificate_chain_file. */
  err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) != ERR_LIB_PEM || ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
    failure = "failed to load certificate";
    failed_path = certificate_path;
    goto done;
  }

  key_bio = BIO_new_file(RSTRING_PTR(private_key_path), "r");
  if (key_bio == NULL ||
      (pkey = PEM_read_bio_PrivateKey(key_bio, NULL, quic_server_no_passphrase_cb, NULL)) == NULL) {
    failure = "failed to load private key";
    failed_path = private_key_path;
    goto done;
  }

  /* picotls has no counterpart of SSL_CTX_check_private_key. */
  if (X509_check_private_key(leaf, pkey) != 1) {
    failure = "private key does not match certificate";
    failed_path = private_key_path;
    goto done;
  }

  /* Takes its own reference on pkey. */
  if (ptls_openssl_init_sign_certificate(&c->sign_cert, pkey) != 0) {
    failure = "unsupported private key type";
    failed_path = private_key_path;
    goto done;
  }
  c->sign_cert_initialized = true;
  c->tls_ctx.sign_certificate = &c->sign_cert.super;

  /* Copies the DER of each certificate into a list quic_conn_free releases.
     It fails only on allocation, and frees what it allocated then. */
  if (ptls_openssl_load_certificates(&c->tls_ctx, leaf, chain) != 0) {
    failure_class = rb_eRuntimeError;
    failure = "ptls_openssl_load_certificates failed";
    goto done;
  }

done:
  sk_X509_pop_free(chain, X509_free);
  X509_free(leaf);
  EVP_PKEY_free(pkey);
  BIO_free(cert_bio);
  BIO_free(key_bio);
  ERR_clear_error();

  if (failure == NULL) return;
  if (NIL_P(failed_path)) rb_raise(failure_class, "%s", failure);
  rb_raise(failure_class, "%s: %"PRIsVALUE, failure, failed_path);
}

/* Build a server connection from the first datagram a client sent. Only the
   ngtcp2_conn and the TLS session are set up here; QUIC::Connection::Server
   .accept feeds that datagram to #read_pkt afterwards. */
static VALUE
quic_server_accept(int argc, VALUE *argv, VALUE klass)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) {
    rb_raise(rb_eArgError,
             "missing keywords: initial_packet, local_sockaddr, remote_sockaddr, "
             "certificate_path, private_key_path, transport_params, settings");
  }

  VALUE initial_packet   = rb_hash_aref(opts, ID2SYM(rb_intern("initial_packet")));
  VALUE local_sockaddr   = rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr  = rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));
  VALUE certificate_path = rb_hash_aref(opts, ID2SYM(rb_intern("certificate_path")));
  VALUE private_key_path = rb_hash_aref(opts, ID2SYM(rb_intern("private_key_path")));
  VALUE transport_params = rb_hash_aref(opts, ID2SYM(rb_intern("transport_params")));
  VALUE settings_v       = rb_hash_aref(opts, ID2SYM(rb_intern("settings")));

  if (NIL_P(initial_packet) || NIL_P(local_sockaddr) || NIL_P(remote_sockaddr) ||
      NIL_P(certificate_path) || NIL_P(private_key_path) ||
      NIL_P(transport_params) || NIL_P(settings_v)) {
    rb_raise(rb_eArgError,
             "all keywords required: initial_packet, local_sockaddr, remote_sockaddr, "
             "certificate_path, private_key_path, transport_params, settings");
  }

  quic_require_binary(initial_packet,  "initial_packet");
  quic_require_binary(local_sockaddr,  "local_sockaddr");
  quic_require_binary(remote_sockaddr, "remote_sockaddr");
  certificate_path = quic_path_value(certificate_path, "certificate_path");
  private_key_path = quic_path_value(private_key_path, "private_key_path");

  const uint8_t *data = (const uint8_t *)RSTRING_PTR(initial_packet);
  size_t datalen = (size_t)RSTRING_LEN(initial_packet);

  /* ngtcp2_pkt_decode_version_cid asserts datalen > 0, and ngtcp2 is built
     with assertions enabled, so an empty datagram would abort the process. */
  if (datalen == 0) quic_server_raise_unacceptable();

  ngtcp2_version_cid vc;
  int rv = ngtcp2_pkt_decode_version_cid(&vc, data, datalen, QUIC_SCID_LEN);
  if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
    rb_raise(rb_eQUICErrorProto,
             "unsupported QUIC version 0x%08x (Version Negotiation is not implemented)",
             (unsigned int)vc.version);
  }
  if (rv != 0) quic_server_raise_unacceptable();

  /* Unlike vc, hd holds the CIDs by value, so it outlives the packet buffer.
     A token (address validation) is accepted without checking it: no Retry
     is ever sent, so a well-behaved client does not send one. */
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, data, datalen) != 0) quic_server_raise_unacceptable();

  VALUE self = quic_conn_alloc(klass);
  quic_conn_t *c = quic_conn_get(self);
  c->owner = self;
  c->is_server = true;

  /* Without an ALPN to pick, every handshake would end in
     no_application_protocol. */
  quic_conn_copy_alpn(c, settings_v);
  if (c->alpn_count == 0) {
    rb_raise(rb_eArgError, "alpn must not be empty for a server");
  }

  c->dcid = hd.scid;
  c->scid.datalen = QUIC_SCID_LEN;
  if (RAND_bytes(c->scid.data, QUIC_SCID_LEN) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(scid) failed");
  }

  ngtcp2_transport_params params;
  quic_fill_transport_params(&params, transport_params);
  /* Without Retry, the original DCID is the one in this first packet. The
     handshake fails if it is missing. */
  params.original_dcid = hd.dcid;
  params.original_dcid_present = 1;

  /* quic_conn_alloc already zeroed the struct, but calling ctx_init keeps
     the ngtcp2-side initialization explicit, as in _open. */
  ngtcp2_crypto_picotls_ctx_init(&c->cptls);
  c->tls_ctx = (ptls_context_t){
    .random_bytes = ptls_openssl_random_bytes,
    .get_time = &ptls_get_time,
    .key_exchanges = quic_key_exchanges,
    .cipher_suites = quic_cipher_suites,
    /* No session resumption: encrypt_ticket stays NULL, so no ticket is
       ever issued. Keep this so that PSK-only resumption is refused once
       resumption is added. */
    .require_dhe_on_psk = 1,
    .server_cipher_preference = 1,
  };
  if (ngtcp2_crypto_picotls_configure_server_context(&c->tls_ctx) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_picotls_configure_server_context failed");
  }
  /* verify_certificate stays NULL: no client certificate is requested, and
     settings.verify_mode / ca_file / ca_path are not read. */
  quic_server_load_certificate_and_key(c, certificate_path, private_key_path);
  c->on_client_hello.cb = quic_server_on_client_hello_cb;
  c->tls_ctx.on_client_hello = &c->on_client_hello;

  ngtcp2_callbacks callbacks;
  quic_conn_fill_common_callbacks(&callbacks);
  callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

  ngtcp2_settings settings;
  quic_fill_settings(&settings, settings_v);

  c->conn_ref.get_conn = quic_conn_get_conn;
  c->conn_ref.user_data = c;

  ngtcp2_path path = {
    {(struct sockaddr *)RSTRING_PTR(local_sockaddr),  (ngtcp2_socklen)RSTRING_LEN(local_sockaddr)},
    {(struct sockaddr *)RSTRING_PTR(remote_sockaddr), (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr)},
    NULL,
  };

  rv = ngtcp2_conn_server_new(&c->conn, &c->dcid, &c->scid, &path, hd.version,
                              &callbacks, &settings, &params, NULL, c);
  if (rv != 0) {
    quic_raise_ngtcp2_error(rv);
  }

  c->cptls.ptls = ptls_server_new(&c->tls_ctx);
  if (c->cptls.ptls == NULL) {
    rb_raise(rb_eRuntimeError, "ptls_server_new failed");
  }
  /* Let ngtcp2's crypto callbacks resolve the ngtcp2_conn from the ptls_t. */
  *ptls_get_data_ptr(c->cptls.ptls) = &c->conn_ref;
  /* [0] carries the QUIC transport parameters, filled in by ngtcp2; [1]
     terminates the list. */
  c->tls_exts[0].type = UINT16_MAX;
  c->tls_exts[1].type = UINT16_MAX;
  c->cptls.handshake_properties.additional_extensions = c->tls_exts;
  if (ngtcp2_crypto_picotls_configure_server_session(&c->cptls) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_picotls_configure_server_session failed");
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, &c->cptls);

  /* Stream registry and accept queue, as in _open. The accept queue holds
     client-initiated streams here. */
  rb_ivar_set(self, rb_intern("@streams"), rb_hash_new());
  rb_ivar_set(self, rb_intern("@accept_queue"), rb_ary_new());

  return self;
}

void
Init_quic_connection_server(VALUE rb_mQUICConnectionArg)
{
  rb_cQUICConnectionServer = rb_define_class_under(rb_mQUICConnectionArg, "Server", rb_cObject);
  rb_define_alloc_func(rb_cQUICConnectionServer, quic_conn_alloc);
  rb_define_singleton_method(rb_cQUICConnectionServer, "_accept", quic_server_accept, -1);
  quic_conn_define_shared_methods(rb_cQUICConnectionServer);
}
