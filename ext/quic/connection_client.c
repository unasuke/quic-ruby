#include "connection_common.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>

/* The system default store is loaded once per process: reading the CA bundle
   takes several milliseconds. X509_STORE is reference counted and safe to
   share across verifications; creation runs under the GVL. Never freed. */
static X509_STORE *quic_default_store;

static X509_STORE *
quic_get_default_store(void)
{
  if (quic_default_store == NULL) {
    X509_STORE *store = X509_STORE_new();
    if (store == NULL || X509_STORE_set_default_paths(store) != 1) {
      X509_STORE_free(store);
      rb_raise(rb_eRuntimeError, "failed to load the default certificate store");
    }
    quic_default_store = store;
  }
  return quic_default_store;
}

/* Record the X509 verification result so read_pkt can raise a descriptive
   error. The verdict itself is left to picotls: ret is returned unchanged.
   Runs synchronously inside read_pkt with the GVL held; it only writes to the
   struct and never touches Ruby objects. */
static int
quic_override_verify_cb(ptls_openssl_override_verify_certificate_t *self,
                        ptls_t *tls, int ret, int ossl_ret, X509 *cert,
                        STACK_OF(X509) *chain)
{
  (void)self;
  (void)cert;
  (void)chain;
  ngtcp2_crypto_conn_ref *ref = *ptls_get_data_ptr(tls);
  quic_conn_t *c = (quic_conn_t *)ref->user_data;
  if (ret != 0) {
    c->verify_failed = true;
    c->verify_result = ossl_ret;
  }
  return ret;
}

static ptls_openssl_override_verify_certificate_t quic_override_verify = {
  quic_override_verify_cb,
};

/* Install picotls's certificate verifier on c->tls_ctx according to the
   verify_mode / ca_file / ca_path settings. Leaves verify_certificate NULL
   for verify_mode :none, which skips verification altogether. */
static void
quic_client_setup_verify(quic_conn_t *c, VALUE settings_v, VALUE server_name)
{
  VALUE mode = rb_funcall(settings_v, rb_intern("verify_mode"), 0);
  /* ca_file and ca_path are not even type-checked under :none. */
  if (mode == ID2SYM(rb_intern("none"))) return;
  if (mode != ID2SYM(rb_intern("peer"))) {
    rb_raise(rb_eArgError, "verify_mode must be :peer or :none (got %+"PRIsVALUE")", mode);
  }

  VALUE ca_file = quic_path_value(rb_funcall(settings_v, rb_intern("ca_file"), 0), "ca_file");
  VALUE ca_path = quic_path_value(rb_funcall(settings_v, rb_intern("ca_path"), 0), "ca_path");

  /* An empty name makes OpenSSL clear its host list and skip the name check,
     and both SNI and the check would silently stop at an embedded NUL. */
  if (RSTRING_LEN(server_name) == 0 ||
      memchr(RSTRING_PTR(server_name), '\0', (size_t)RSTRING_LEN(server_name)) != NULL) {
    rb_raise(rb_eArgError,
             "server_name must be a non-empty string without NUL bytes when verify_mode is :peer");
  }
  /* X509_LOOKUP_hash_dir does not check that the directory exists. */
  if (!NIL_P(ca_path) && !RTEST(rb_funcall(rb_cFile, rb_intern("directory?"), 1, ca_path))) {
    rb_raise(rb_eArgError, "ca_path is not a directory: %"PRIsVALUE, ca_path);
  }

  X509_STORE *store;
  bool own_store = !NIL_P(ca_file) || !NIL_P(ca_path);
  if (own_store) {
    /* Trust only what was given; the system store is not consulted. */
    store = X509_STORE_new();
    if (store == NULL) {
      rb_raise(rb_eRuntimeError, "X509_STORE_new failed");
    }
    if (X509_STORE_load_locations(store,
                                  NIL_P(ca_file) ? NULL : RSTRING_PTR(ca_file),
                                  NIL_P(ca_path) ? NULL : RSTRING_PTR(ca_path)) != 1) {
      X509_STORE_free(store);
      /* libcrypto is shared with Ruby's openssl extension; do not leave our
         failure on its error queue. */
      ERR_clear_error();
      if (NIL_P(ca_file)) {
        rb_raise(rb_eArgError, "failed to load ca_path: %"PRIsVALUE, ca_path);
      }
      rb_raise(rb_eArgError, "failed to load ca_file: %"PRIsVALUE, ca_file);
    }
  } else {
    store = quic_get_default_store();
  }

  /* init takes its own reference on the store, so ours can go right away. */
  int rv = ptls_openssl_init_verify_certificate(&c->verify_cert, store);
  if (own_store) X509_STORE_free(store);
  if (rv != 0) {
    rb_raise(rb_eRuntimeError, "ptls_openssl_init_verify_certificate failed");
  }
  c->verify_cert_initialized = true;
  c->verify_cert.override_callback = &quic_override_verify;
  c->tls_ctx.verify_certificate = &c->verify_cert.super;
}

static VALUE
quic_client_open(int argc, VALUE *argv, VALUE klass)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) {
    rb_raise(rb_eArgError,
             "missing keywords: local_sockaddr, remote_sockaddr, server_name, transport_params, settings");
  }

  VALUE local_sockaddr   = rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr  = rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));
  VALUE server_name      = rb_hash_aref(opts, ID2SYM(rb_intern("server_name")));
  VALUE transport_params = rb_hash_aref(opts, ID2SYM(rb_intern("transport_params")));
  VALUE settings_v       = rb_hash_aref(opts, ID2SYM(rb_intern("settings")));

  if (NIL_P(local_sockaddr) || NIL_P(remote_sockaddr) || NIL_P(server_name) ||
      NIL_P(transport_params) || NIL_P(settings_v)) {
    rb_raise(rb_eArgError,
             "all keywords required: local_sockaddr, remote_sockaddr, server_name, transport_params, settings");
  }

  quic_require_binary(local_sockaddr,  "local_sockaddr");
  quic_require_binary(remote_sockaddr, "remote_sockaddr");
  Check_Type(server_name, T_STRING);

  VALUE self = quic_conn_alloc(klass);
  rb_ivar_set(self, rb_intern("@server_name"), server_name);

  quic_conn_t *c = quic_conn_get(self);
  c->owner = self;
  c->is_server = false;

  /* An empty list means no ALPN extension, matching the old
     skip-SSL_set_alpn_protos path. */
  quic_conn_copy_alpn(c, settings_v);

  /* quic_conn_alloc already zeroed the struct, but calling ctx_init keeps
     the ngtcp2-side initialization explicit and the TLS setup in one place. */
  ngtcp2_crypto_picotls_ctx_init(&c->cptls);
  c->tls_ctx = (ptls_context_t){
    .random_bytes = ptls_openssl_random_bytes,
    .get_time = &ptls_get_time,
    .key_exchanges = quic_key_exchanges,
    .cipher_suites = quic_cipher_suites,
    /* No session resumption yet, so this has no effect today. Keep it so that
       when resumption is added, PSK-only (non-forward-secret) resumption is
       refused rather than silently accepted. */
    .require_dhe_on_psk = 1,
  };
  if (ngtcp2_crypto_picotls_configure_client_context(&c->tls_ctx) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_picotls_configure_client_context failed");
  }

  /* ptls_client_new keeps a pointer to tls_ctx, so the verifier has to be in
     place before it runs. */
  quic_client_setup_verify(c, settings_v, server_name);

  c->conn_ref.get_conn = quic_conn_get_conn;
  c->conn_ref.user_data = c;

  c->scid.datalen = QUIC_SCID_LEN;
  if (RAND_bytes(c->scid.data, QUIC_SCID_LEN) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(scid) failed");
  }
  c->dcid.datalen = 8;
  if (RAND_bytes(c->dcid.data, 8) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(dcid) failed");
  }

  ngtcp2_callbacks callbacks;
  quic_conn_fill_common_callbacks(&callbacks);
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

  ngtcp2_settings settings;
  quic_fill_settings(&settings, settings_v);

  ngtcp2_transport_params params;
  quic_fill_transport_params(&params, transport_params);

  ngtcp2_path path = {
    {(struct sockaddr *)RSTRING_PTR(local_sockaddr),  (ngtcp2_socklen)RSTRING_LEN(local_sockaddr)},
    {(struct sockaddr *)RSTRING_PTR(remote_sockaddr), (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr)},
    NULL,
  };

  int rv = ngtcp2_conn_client_new(&c->conn, &c->dcid, &c->scid, &path,
                                  NGTCP2_PROTO_VER_V1, &callbacks,
                                  &settings, &params, NULL, c);
  if (rv != 0) {
    quic_raise_ngtcp2_error(rv);
  }

  /* The TLS session is built last: configure_client_session derives the QUIC
     transport parameters from the conn, so it needs the conn to exist. */
  c->cptls.ptls = ptls_client_new(&c->tls_ctx);
  if (c->cptls.ptls == NULL) {
    rb_raise(rb_eRuntimeError, "ptls_client_new failed");
  }
  /* Let ngtcp2's crypto callbacks (add_handshake_data,
     set_encryption_secrets, ...) resolve the ngtcp2_conn from the ptls_t. */
  *ptls_get_data_ptr(c->cptls.ptls) = &c->conn_ref;
  /* [0] is filled in by configure_client_session with the QUIC transport
     parameters; [1] terminates the list. */
  c->tls_exts[0].type = UINT16_MAX;
  c->tls_exts[1].type = UINT16_MAX;
  c->cptls.handshake_properties.additional_extensions = c->tls_exts;
  if (ngtcp2_crypto_picotls_configure_client_session(&c->cptls, c->conn) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_picotls_configure_client_session failed");
  }
  c->cptls.handshake_properties.client.negotiated_protocols.list = c->alpn;
  c->cptls.handshake_properties.client.negotiated_protocols.count = c->alpn_count;
  /* ptls_set_server_name copies the name. */
  if (ptls_set_server_name(c->cptls.ptls, RSTRING_PTR(server_name),
                           (size_t)RSTRING_LEN(server_name)) != 0) {
    rb_raise(rb_eRuntimeError, "ptls_set_server_name failed");
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, &c->cptls);

  /* Stream registry: stream_id (Integer) -> QUIC::Stream.
     Populated by #open_bidi_stream / #open_uni_stream and the stream_open
     callback. Entries are removed in the stream_close callback. */
  rb_ivar_set(self, rb_intern("@streams"), rb_hash_new());

  /* FIFO of peer-initiated streams awaiting #accept_stream. The
     recv_stream_data callback pushes each new peer stream here once. */
  rb_ivar_set(self, rb_intern("@accept_queue"), rb_ary_new());

  return self;
}

void
Init_quic_connection_client(VALUE rb_mQUICConnectionArg)
{
  rb_cQUICConnectionClient = rb_define_class_under(rb_mQUICConnectionArg, "Client", rb_cObject);
  rb_define_alloc_func(rb_cQUICConnectionClient, quic_conn_alloc);
  rb_define_singleton_method(rb_cQUICConnectionClient, "_open", quic_client_open, -1);
  quic_conn_define_shared_methods(rb_cQUICConnectionClient);
}
