#include "quic.h"
#include "stream.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/rand.h>

/* Buffer size for #write_pkt. NGTCP2_MAX_UDP_PAYLOAD_SIZE (1200) is the
   minimum destlen ngtcp2 accepts. Revisit when PMTUD is enabled (Phase 4+). */
#define QUIC_WRITE_PKT_BUFLEN NGTCP2_MAX_UDP_PAYLOAD_SIZE

/* picotls sends a key share only for the first entry; the others are offered
   in supported_groups and reached via HelloRetryRequest. X25519 is first so
   the common case stays 1-RTT. */
static ptls_key_exchange_algorithm_t *quic_key_exchanges[] = {
  &ptls_openssl_x25519,
  &ptls_openssl_secp256r1,
#if PTLS_OPENSSL_HAVE_SECP384R1
  &ptls_openssl_secp384r1,
#endif
  NULL,
};

static ptls_cipher_suite_t *quic_cipher_suites[] = {
  &ptls_openssl_aes128gcmsha256,
  &ptls_openssl_aes256gcmsha384,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
  &ptls_openssl_chacha20poly1305sha256,
#endif
  NULL,
};

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

typedef struct {
  ngtcp2_conn *conn;
  /* Referenced by cptls.ptls, which only keeps the pointer, so this has to
     outlive the ptls_t. */
  ptls_context_t tls_ctx;
  /* Referenced by tls_ctx.verify_certificate when verify_mode is :peer. Holds
     a reference to an X509_STORE, released in quic_client_free. */
  ptls_openssl_verify_certificate_t verify_cert;
  bool verify_cert_initialized;
  /* Filled by quic_override_verify_cb during the handshake so that a failed
     read_pkt can raise CertificateVerifyFailed with the X509 error. */
  bool verify_failed;
  int verify_result;  /* X509_V_ERR_*, 0 when the server sent no certificate */
  /* The TLS native handle handed to ngtcp2 (&cptls, not cptls.ptls). */
  ngtcp2_crypto_picotls_ctx cptls;
  /* [0]: QUIC transport params, filled in by ngtcp2; [1]: terminator. */
  ptls_raw_extension_t tls_exts[2];
  /* ALPN list handed to picotls, which keeps the pointers for the whole
     handshake (unlike SSL_set_alpn_protos, which copies). The entries point
     into alpn_buf, and both are owned by this struct. */
  ptls_iovec_t *alpn;
  size_t alpn_count;
  uint8_t *alpn_buf;
  ngtcp2_cid scid;
  ngtcp2_cid dcid;
  /* ngtcp2 1.x requires applications to associate an ngtcp2_conn with the
     TLS object so that crypto callbacks (e.g. add_handshake_data) can recover
     the conn. picotls carries it in the ptls_t's data pointer, set via
     ptls_get_data_ptr. The ref must outlive the ptls_t. */
  ngtcp2_crypto_conn_ref conn_ref;
  /* Back-reference to the QUIC::Connection::Client Ruby object that owns
     this struct. ngtcp2 stream callbacks receive a void* user_data equal
     to this struct, and they look up @streams via owner. We are stored
     INSIDE owner via TypedData_Wrap_Struct, so owner is guaranteed alive
     while we exist (no dmark needed). GC.compact may relocate owner, so
     quic_client_compact updates this field via rb_gc_location. */
  VALUE owner;
} quic_client_t;

static void
quic_client_free(void *ptr)
{
  quic_client_t *c = (quic_client_t *)ptr;
  if (c->conn) ngtcp2_conn_del(c->conn);
  if (c->cptls.ptls) {
    /* Safe even when configure_client_session never ran or failed midway. */
    ngtcp2_crypto_picotls_deconfigure_session(&c->cptls);
    ptls_free(c->cptls.ptls);
  }
  /* After ptls_free: the ptls_t references verify_cert through tls_ctx. */
  if (c->verify_cert_initialized) ptls_openssl_dispose_verify_certificate(&c->verify_cert);
  xfree(c->alpn);
  xfree(c->alpn_buf);
  xfree(c);
}

static size_t
quic_client_size(const void *ptr)
{
  (void)ptr;
  return sizeof(quic_client_t);
}

/* GC.compact may relocate the owner Client object. Follow it so the
   void* user_data ngtcp2 callbacks receive (which equals this struct,
   stored inside owner) keeps resolving @streams / @accept_queue. The
   raw ngtcp2/picotls pointers are outside Ruby's heap and are left alone. */
static void
quic_client_compact(void *ptr)
{
  quic_client_t *c = (quic_client_t *)ptr;
  c->owner = rb_gc_location(c->owner);
}

static const rb_data_type_t quic_client_data_type = {
  "QUIC::Connection::Client",
  {NULL, quic_client_free, quic_client_size, quic_client_compact,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE
quic_client_alloc(VALUE klass)
{
  quic_client_t *c = ALLOC(quic_client_t);
  memset(c, 0, sizeof(*c));
  return TypedData_Wrap_Struct(klass, &quic_client_data_type, c);
}

ngtcp2_conn *
quic_client_conn(VALUE client_v)
{
  quic_client_t *c;
  TypedData_Get_Struct(client_v, quic_client_t, &quic_client_data_type, c);
  return c->conn;
}

static ngtcp2_tstamp
quic_now(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static void
quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  (void)rand_ctx;
  RAND_bytes(dest, (int)destlen);
}

static int
quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                              uint8_t *token, size_t cidlen, void *user_data)
{
  (void)conn;
  (void)user_data;
  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static ngtcp2_conn *
quic_client_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  return ((quic_client_t *)conn_ref->user_data)->conn;
}

static void
quic_require_binary(VALUE str, const char *name)
{
  Check_Type(str, T_STRING);
  if (rb_enc_get_index(str) != rb_ascii8bit_encindex()) {
    rb_raise(rb_eArgError, "%s must be ASCII-8BIT (binary) encoding", name);
  }
}

static uint64_t
quic_get_uint64_field(VALUE obj, const char *name)
{
  VALUE v = rb_funcall(obj, rb_intern(name), 0);
  return (uint64_t)NUM2ULL(v);
}

static ngtcp2_cc_algo
quic_cc_algo_from_sym(VALUE sym)
{
  Check_Type(sym, T_SYMBOL);
  ID id = SYM2ID(sym);
  if (id == rb_intern("reno"))  return NGTCP2_CC_ALGO_RENO;
  if (id == rb_intern("cubic")) return NGTCP2_CC_ALGO_CUBIC;
  if (id == rb_intern("bbr"))   return NGTCP2_CC_ALGO_BBR;
  rb_raise(rb_eArgError, "unknown cc_algo: %"PRIsVALUE" (expected :reno, :cubic, or :bbr)", sym);
}

static void
quic_fill_transport_params(ngtcp2_transport_params *params, VALUE tp)
{
  ngtcp2_transport_params_default(params);
  params->initial_max_stream_data_bidi_local =
    quic_get_uint64_field(tp, "initial_max_stream_data_bidi_local");
  params->initial_max_stream_data_bidi_remote =
    quic_get_uint64_field(tp, "initial_max_stream_data_bidi_remote");
  params->initial_max_stream_data_uni =
    quic_get_uint64_field(tp, "initial_max_stream_data_uni");
  params->initial_max_data =
    quic_get_uint64_field(tp, "initial_max_data");
  params->initial_max_streams_bidi =
    quic_get_uint64_field(tp, "initial_max_streams_bidi");
  params->initial_max_streams_uni =
    quic_get_uint64_field(tp, "initial_max_streams_uni");
  params->max_idle_timeout =
    (ngtcp2_duration)quic_get_uint64_field(tp, "max_idle_timeout");
  params->active_connection_id_limit =
    quic_get_uint64_field(tp, "active_connection_id_limit");
}

static void
quic_fill_settings(ngtcp2_settings *settings, VALUE st)
{
  ngtcp2_settings_default(settings);
  settings->initial_ts = quic_now();
  settings->cc_algo = quic_cc_algo_from_sym(rb_funcall(st, rb_intern("cc_algo"), 0));
  settings->initial_rtt =
    (ngtcp2_duration)quic_get_uint64_field(st, "initial_rtt");
  settings->max_window =
    quic_get_uint64_field(st, "max_window");
  settings->max_stream_window =
    quic_get_uint64_field(st, "max_stream_window");
  settings->handshake_timeout =
    (ngtcp2_duration)quic_get_uint64_field(st, "handshake_timeout");
  VALUE no_pmtud = rb_funcall(st, rb_intern("no_pmtud"), 0);
  settings->no_pmtud = RTEST(no_pmtud) ? 1 : 0;
}

/* Shared helper: look up the QUIC::Stream registered for stream_id in the
   owner Client's @streams Hash. Returns Qnil if not found (which can happen
   if the stream was already removed by a previous stream_close callback). */
static VALUE
quic_client_lookup_stream(quic_client_t *c, int64_t stream_id)
{
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  return rb_hash_aref(streams, LL2NUM(stream_id));
}

/* ngtcp2 stream callbacks. Each returns 0 on success or
   NGTCP2_ERR_CALLBACK_FAILURE on Ruby-side errors. We assume rb_str_buf_cat /
   rb_ary_* won't raise in normal operation (allocation failures aside, which
   would abort the process anyway), so we don't wrap in rb_protect for now. */

static int
quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  (void)conn;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  if (!NIL_P(rb_hash_aref(streams, LL2NUM(stream_id)))) {
    return 0;  /* already known (client-initiated) */
  }
  VALUE stream = quic_stream_new(stream_id, c->owner);
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return 0;
}

static int
quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data)
{
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE stream = quic_client_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);

  /* Surface peer-initiated (server) streams to #accept_stream. For a client
     connection the low stream-id bit marks the initiator: 1 == server. Push
     once, on first data arrival, then mark so later data does not re-enqueue. */
  if (!s->accept_queued && (stream_id & 0x01)) {
    VALUE accept_queue = rb_ivar_get(c->owner, rb_intern("@accept_queue"));
    rb_ary_push(accept_queue, stream);
    s->accept_queued = true;
  }

  if (datalen > 0) {
    VALUE recv_buffer = rb_ivar_get(stream, rb_intern("@recv_buffer"));
    rb_str_buf_cat(recv_buffer, (const char *)data, (long)datalen);
  }
  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    s->fin_received = true;
  }
  return 0;
}

static int
quic_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t offset, uint64_t datalen,
                                 void *user_data, void *stream_user_data)
{
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE stream = quic_client_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->acked_offset += datalen;

  /* Shift any head Chunks of @pending_chunks whose end-offset is fully
     covered by acked_offset. Each Chunk's start-offset in the stream is
     pending_shifted (after previous shifts); its end-offset is
     pending_shifted + RSTRING_LEN(head). */
  VALUE pending = rb_ivar_get(stream, rb_intern("@pending_chunks"));
  while (RARRAY_LEN(pending) > 0) {
    VALUE head = RARRAY_AREF(pending, 0);
    uint64_t head_end = s->pending_shifted + (uint64_t)RSTRING_LEN(head);
    if (head_end <= s->acked_offset) {
      rb_ary_shift(pending);
      s->pending_shifted = head_end;
    } else {
      break;
    }
  }
  return 0;
}

static int
quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t app_error_code, void *user_data,
                     void *stream_user_data)
{
  (void)conn;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  VALUE stream = rb_hash_aref(streams, LL2NUM(stream_id));
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->closed = true;
  if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
    s->close_has_app_error_code = true;
    s->close_app_error_code = app_error_code;
  }
  rb_hash_delete(streams, LL2NUM(stream_id));
  return 0;
}

static int
quic_stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                     uint64_t app_error_code, void *user_data,
                     void *stream_user_data)
{
  (void)conn;
  (void)final_size;
  (void)stream_user_data;
  quic_client_t *c = (quic_client_t *)user_data;
  VALUE stream = quic_client_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->reset = true;
  s->close_app_error_code = app_error_code;
  s->close_has_app_error_code = true;
  return 0;
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
  quic_client_t *c = (quic_client_t *)ref->user_data;
  if (ret != 0) {
    c->verify_failed = true;
    c->verify_result = ossl_ret;
  }
  return ret;
}

static ptls_openssl_override_verify_certificate_t quic_override_verify = {
  quic_override_verify_cb,
};

/* Validate a ca_file / ca_path setting and return it as a String, or Qnil.
   Accepts a String or anything responding to #to_path. Every misconfiguration
   of the verification settings raises ArgumentError, including a wrong type. */
static VALUE
quic_verify_path_value(VALUE value, const char *name)
{
  if (NIL_P(value)) return Qnil;

  VALUE path = value;
  if (!RB_TYPE_P(path, T_STRING)) {
    if (rb_respond_to(path, rb_intern("to_path"))) {
      path = rb_funcall(path, rb_intern("to_path"), 0);
    }
    if (!RB_TYPE_P(path, T_STRING)) {
      rb_raise(rb_eArgError, "%s must be a String or Pathname (got %"PRIsVALUE")",
               name, rb_obj_class(value));
    }
  }
  /* Raises ArgumentError when the path contains a NUL byte. */
  StringValueCStr(path);
  return path;
}

/* Install picotls's certificate verifier on c->tls_ctx according to the
   verify_mode / ca_file / ca_path settings. Leaves verify_certificate NULL
   for verify_mode :none, which skips verification altogether. */
static void
quic_client_setup_verify(quic_client_t *c, VALUE settings_v, VALUE server_name)
{
  VALUE mode = rb_funcall(settings_v, rb_intern("verify_mode"), 0);
  /* ca_file and ca_path are not even type-checked under :none. */
  if (mode == ID2SYM(rb_intern("none"))) return;
  if (mode != ID2SYM(rb_intern("peer"))) {
    rb_raise(rb_eArgError, "verify_mode must be :peer or :none (got %+"PRIsVALUE")", mode);
  }

  VALUE ca_file = quic_verify_path_value(rb_funcall(settings_v, rb_intern("ca_file"), 0), "ca_file");
  VALUE ca_path = quic_verify_path_value(rb_funcall(settings_v, rb_intern("ca_path"), 0), "ca_path");

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

  VALUE self = quic_client_alloc(klass);
  rb_ivar_set(self, rb_intern("@server_name"), server_name);

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  c->owner = self;

  /* Copy the ALPN list into memory owned by c: picotls keeps the pointers
     for the whole handshake, so ALLOCA_N would not survive. An empty list
     means no ALPN extension, matching the old skip-SSL_set_alpn_protos path. */
  VALUE alpn_ary = rb_funcall(settings_v, rb_intern("alpn"), 0);
  Check_Type(alpn_ary, T_ARRAY);
  long n_alpn = RARRAY_LEN(alpn_ary);
  if (n_alpn > 0) {
    size_t total = 0;
    for (long i = 0; i < n_alpn; i++) {
      VALUE entry = RARRAY_AREF(alpn_ary, i);
      Check_Type(entry, T_STRING);
      long len = RSTRING_LEN(entry);
      if (len < 1 || len > 255) {
        rb_raise(rb_eArgError, "alpn entry must be 1-255 bytes (got %ld)", len);
      }
      total += (size_t)len;
    }
    c->alpn_buf = ALLOC_N(uint8_t, total);
    c->alpn = ALLOC_N(ptls_iovec_t, n_alpn);
    uint8_t *p = c->alpn_buf;
    for (long i = 0; i < n_alpn; i++) {
      VALUE entry = RARRAY_AREF(alpn_ary, i);
      size_t len = (size_t)RSTRING_LEN(entry);
      memcpy(p, RSTRING_PTR(entry), len);
      c->alpn[i] = ptls_iovec_init(p, len);
      p += len;
    }
    c->alpn_count = (size_t)n_alpn;
  }

  /* quic_client_alloc already zeroed the struct, but calling ctx_init keeps
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

  c->conn_ref.get_conn = quic_client_get_conn;
  c->conn_ref.user_data = c;

  c->scid.datalen = 8;
  if (RAND_bytes(c->scid.data, 8) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(scid) failed");
  }
  c->dcid.datalen = 8;
  if (RAND_bytes(c->dcid.data, 8) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(dcid) failed");
  }

  ngtcp2_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.rand = quic_rand_cb;
  callbacks.get_new_connection_id = quic_get_new_connection_id_cb;
  callbacks.stream_open = quic_stream_open_cb;
  callbacks.recv_stream_data = quic_recv_stream_data_cb;
  callbacks.acked_stream_data_offset = quic_acked_stream_data_offset_cb;
  callbacks.stream_close = quic_stream_close_cb;
  callbacks.stream_reset = quic_stream_reset_cb;

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

  /* FIFO of peer-initiated (server) streams awaiting #accept_stream. The
     recv_stream_data callback pushes each new server stream here once. */
  rb_ivar_set(self, rb_intern("@accept_queue"), rb_ary_new());

  return self;
}

/* Find the first stream in @streams that has either pending bytes or a
   pending FIN to flush. Phase 4 minimum: linear scan, take the first match
   (no round-robin). Sets *out_datav to the byte slice to send, *out_datavcnt
   to 0 or 1, *out_flags to NGTCP2_WRITE_STREAM_FLAG_FIN when applicable.
   Returns the stream's Ruby VALUE (or Qnil if no candidate). */
static VALUE
quic_client_pick_send_stream(VALUE self, ngtcp2_vec *out_datav,
                             size_t *out_datavcnt, uint32_t *out_flags,
                             int64_t *out_stream_id)
{
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  VALUE stream_values = rb_funcall(streams, rb_intern("values"), 0);

  for (long i = 0; i < RARRAY_LEN(stream_values); i++) {
    VALUE st = RARRAY_AREF(stream_values, i);
    quic_stream_t *s;
    TypedData_Get_Struct(st, quic_stream_t, &quic_stream_data_type, s);
    if (s->fin_flushed) continue;

    VALUE pending = rb_ivar_get(st, rb_intern("@pending_chunks"));
    uint64_t position = s->sent_offset - s->pending_shifted;
    long chunks_count = RARRAY_LEN(pending);

    /* Walk pending Chunks to find the one containing the next unsent byte. */
    long chunk_idx = -1;
    long offset_in_chunk = 0;
    for (long j = 0; j < chunks_count; j++) {
      VALUE chunk = RARRAY_AREF(pending, j);
      long clen = RSTRING_LEN(chunk);
      if (position < (uint64_t)clen) {
        chunk_idx = j;
        offset_in_chunk = (long)position;
        break;
      }
      position -= (uint64_t)clen;
    }

    if (chunk_idx >= 0) {
      VALUE chunk = RARRAY_AREF(pending, chunk_idx);
      out_datav->base = (uint8_t *)RSTRING_PTR(chunk) + offset_in_chunk;
      out_datav->len = (size_t)(RSTRING_LEN(chunk) - offset_in_chunk);
      *out_datavcnt = 1;
      *out_stream_id = s->stream_id;
      /* Attach FIN if this is the LAST chunk and we're going to send all
         remaining bytes of it (ngtcp2 may encode less, in which case FIN
         won't actually be flushed and we'll retry next call). */
      *out_flags = (s->fin_sent && chunk_idx == chunks_count - 1)
                     ? NGTCP2_WRITE_STREAM_FLAG_FIN
                     : 0;
      return st;
    }

    if (s->fin_sent && !s->fin_flushed) {
      /* No data to send but a pending FIN-only frame. */
      out_datav->base = NULL;
      out_datav->len = 0;
      *out_datavcnt = 0;
      *out_stream_id = s->stream_id;
      *out_flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
      return st;
    }
  }

  return Qnil;
}

static VALUE
quic_client_write_pkt(int argc, VALUE *argv, VALUE self)
{
  VALUE buffer = Qnil;
  rb_scan_args(argc, argv, "01", &buffer);

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  if (NIL_P(buffer)) {
    /* rb_str_buf_new returns an ASCII-8BIT (binary) String per CRuby spec,
       so no explicit rb_enc_associate is required. */
    buffer = rb_str_buf_new(QUIC_WRITE_PKT_BUFLEN);
  } else {
    Check_Type(buffer, T_STRING);
    if (rb_enc_get_index(buffer) != rb_ascii8bit_encindex()) {
      rb_raise(rb_eArgError, "buffer must be ASCII-8BIT (binary) encoding");
    }
    if (RSTRING_LEN(buffer) < (long)QUIC_WRITE_PKT_BUFLEN) {
      rb_str_modify_expand(buffer, (long)QUIC_WRITE_PKT_BUFLEN - RSTRING_LEN(buffer));
    }
  }

  ngtcp2_path_storage path_storage;
  ngtcp2_path_storage_zero(&path_storage);

  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  uint8_t *dest = (uint8_t *)RSTRING_PTR(buffer);
  size_t destlen = (size_t)QUIC_WRITE_PKT_BUFLEN;

  /* Stream-aware path: if any stream has pending bytes or a pending FIN,
     route the packet through ngtcp2_conn_writev_stream so the stream data
     gets framed alongside connection-level frames. Falls back to conn-only
     when no stream is queued. */
  ngtcp2_vec datav;
  size_t datavcnt = 0;
  uint32_t writev_flags = 0;
  int64_t send_stream_id = -1;
  VALUE selected_stream = quic_client_pick_send_stream(
    self, &datav, &datavcnt, &writev_flags, &send_stream_id);

  ngtcp2_ssize pdatalen = -1;
  ngtcp2_ssize n = ngtcp2_conn_writev_stream(
    c->conn, &path_storage.path, &pi, dest, destlen, &pdatalen,
    writev_flags, send_stream_id, &datav, datavcnt, quic_now());

  if (n < 0) {
    /* ngtcp2 does not partially write on failure, but truncate explicitly so
       that a rescued caller cannot accidentally transmit stale bytes. */
    rb_str_set_len(buffer, 0);
    quic_raise_ngtcp2_error((int)n);
  }

  /* Update the selected stream's accounting only when we actually sent
     bytes. pdatalen >= 0 means ngtcp2 framed that many data bytes into the
     packet; if 0, no data was framed (but the packet may still contain ACK
     or other frames). */
  if (!NIL_P(selected_stream) && pdatalen > 0) {
    quic_stream_t *s;
    TypedData_Get_Struct(selected_stream, quic_stream_t,
                         &quic_stream_data_type, s);
    s->sent_offset += (uint64_t)pdatalen;
    /* FIN is only actually written when all requested data fits in the
       frame (see ngtcp2 docs on NGTCP2_WRITE_STREAM_FLAG_FIN). */
    if ((writev_flags & NGTCP2_WRITE_STREAM_FLAG_FIN) &&
        (size_t)pdatalen == datav.len) {
      s->fin_flushed = true;
    }
  } else if (!NIL_P(selected_stream) && datavcnt == 0 && n > 0 &&
             (writev_flags & NGTCP2_WRITE_STREAM_FLAG_FIN)) {
    /* FIN-only packet (no data) was successfully written. */
    quic_stream_t *s;
    TypedData_Get_Struct(selected_stream, quic_stream_t,
                         &quic_stream_data_type, s);
    s->fin_flushed = true;
  }

  if (n == 0) {
    rb_str_set_len(buffer, 0);
    return Qnil;
  }
  rb_str_set_len(buffer, n);
  return buffer;
}

NORETURN(static void quic_client_raise_error(quic_client_t *c, int rv));

/* Like quic_raise_ngtcp2_error, but for errors from read_pkt, where the TLS
   handshake runs: NGTCP2_ERR_CRYPTO carries the TLS alert this client sent,
   and becomes CertificateVerifyFailed when the verifier rejected the peer. */
static void
quic_client_raise_error(quic_client_t *c, int rv)
{
  if (rv != NGTCP2_ERR_CRYPTO) quic_raise_ngtcp2_error(rv);

  /* 0 means "not set" to ngtcp2; close_notify (0) is never sent for a
     verification failure, so report it as nil. */
  uint8_t alert = ngtcp2_conn_get_tls_alert2(c->conn);
  VALUE exc;
  if (c->verify_failed) {
    VALUE msg = c->verify_result
      ? rb_sprintf("certificate verify failed (%s)",
                   X509_verify_cert_error_string(c->verify_result))
      : rb_str_new_cstr("certificate verify failed (server sent no certificate)");
    exc = rb_exc_new_str(rb_eQUICErrorCertificateVerifyFailed, msg);
    rb_ivar_set(exc, rb_intern("@verify_result"),
                c->verify_result ? INT2NUM(c->verify_result) : Qnil);
  } else {
    exc = rb_exc_new_cstr(rb_eQUICErrorCryptoError, ngtcp2_strerror(rv));
  }
  rb_ivar_set(exc, rb_intern("@code"), INT2NUM(rv));
  rb_ivar_set(exc, rb_intern("@tls_alert"), alert ? INT2NUM(alert) : Qnil);
  rb_exc_raise(exc);
}

struct quic_read_pkt_args {
  quic_client_t *c;
  VALUE packet;
  ngtcp2_path path;
  ngtcp2_pkt_info pi;
};

static VALUE
quic_read_pkt_body(VALUE arg)
{
  struct quic_read_pkt_args *a = (struct quic_read_pkt_args *)arg;
  int rv = ngtcp2_conn_read_pkt(a->c->conn, &a->path, &a->pi,
                                (const uint8_t *)RSTRING_PTR(a->packet),
                                (size_t)RSTRING_LEN(a->packet),
                                quic_now());
  if (rv != 0) {
    /* NORETURN: longjmp passes through rb_ensure so unlock still fires. */
    quic_client_raise_error(a->c, rv);
  }
  return Qnil;
}

static VALUE
quic_read_pkt_unlock(VALUE arg)
{
  rb_str_unlocktmp(((struct quic_read_pkt_args *)arg)->packet);
  return Qnil;
}

static VALUE
quic_client_read_pkt(int argc, VALUE *argv, VALUE self)
{
  VALUE packet = Qnil;
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "1:", &packet, &opts);

  if (NIL_P(opts)) {
    rb_raise(rb_eArgError, "missing keywords: local_sockaddr, remote_sockaddr");
  }

  VALUE local_sockaddr  = rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr = rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));

  if (NIL_P(local_sockaddr) || NIL_P(remote_sockaddr)) {
    rb_raise(rb_eArgError, "missing keywords: local_sockaddr, remote_sockaddr");
  }

  quic_require_binary(packet,          "packet");
  quic_require_binary(local_sockaddr,  "local_sockaddr");
  quic_require_binary(remote_sockaddr, "remote_sockaddr");

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  struct quic_read_pkt_args args;
  args.c = c;
  args.packet = packet;
  args.path.local.addr     = (struct sockaddr *)RSTRING_PTR(local_sockaddr);
  args.path.local.addrlen  = (ngtcp2_socklen)RSTRING_LEN(local_sockaddr);
  args.path.remote.addr    = (struct sockaddr *)RSTRING_PTR(remote_sockaddr);
  args.path.remote.addrlen = (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr);
  args.path.user_data      = NULL;
  memset(&args.pi, 0, sizeof(args.pi));

  rb_str_locktmp(packet);
  return rb_ensure(quic_read_pkt_body, (VALUE)&args,
                   quic_read_pkt_unlock, (VALUE)&args);
}

static VALUE
quic_client_handshake_completed_p(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  return ngtcp2_conn_get_handshake_completed2(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_client_in_closing_period_p(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  return ngtcp2_conn_in_closing_period2(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_client_in_draining_period_p(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  return ngtcp2_conn_in_draining_period2(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_client_expiry(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  ngtcp2_tstamp t = ngtcp2_conn_get_expiry2(c->conn);
  if (t == UINT64_MAX) return Qnil;
  return ULL2NUM((unsigned long long)t);
}

/* Caller is responsible for ordering with #read_pkt / #write_pkt:
   read_pkt or handle_expiry to advance ngtcp2 state, then write_pkt to flush. */
static VALUE
quic_client_handle_expiry(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);
  int rv = ngtcp2_conn_handle_expiry(c->conn, quic_now());
  if (rv != 0) quic_raise_ngtcp2_error(rv);
  return Qnil;
}

static VALUE
quic_client_open_bidi_stream(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
  if (rv != 0) quic_raise_ngtcp2_error(rv);

  VALUE stream = quic_stream_new(stream_id, self);
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return stream;
}

static VALUE
quic_client_open_uni_stream(VALUE self)
{
  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_uni_stream(c->conn, &stream_id, NULL);
  if (rv != 0) quic_raise_ngtcp2_error(rv);

  VALUE stream = quic_stream_new(stream_id, self);
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return stream;
}

/* Send an application CONNECTION_CLOSE (frame type 0x1d) to the peer and
   transition the underlying ngtcp2_conn to the closing period. One UDP
   datagram is written to the bound socket; ngtcp2 handles closing-period
   retransmits via the caller's pump loop. Calling #close on a connection
   that is already in the closing or draining period is a no-op (= returns
   nil without doing any I/O). */
static VALUE
quic_client_close_m(int argc, VALUE *argv, VALUE self)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);

  uint64_t error_code = 0;
  const uint8_t *reason_ptr = (const uint8_t *)"";
  size_t reason_len = 0;

  if (!NIL_P(opts)) {
    VALUE error_code_v = rb_hash_aref(opts, ID2SYM(rb_intern("error_code")));
    VALUE reason_v = rb_hash_aref(opts, ID2SYM(rb_intern("reason")));
    if (!NIL_P(error_code_v)) {
      error_code = NUM2ULL(error_code_v);
    }
    if (!NIL_P(reason_v)) {
      Check_Type(reason_v, T_STRING);
      reason_ptr = (const uint8_t *)RSTRING_PTR(reason_v);
      reason_len = (size_t)RSTRING_LEN(reason_v);
    }
  }

  quic_client_t *c;
  TypedData_Get_Struct(self, quic_client_t, &quic_client_data_type, c);

  /* Idempotent: a subsequent #close after the conn already entered the
     closing/draining period does not emit another CONNECTION_CLOSE. */
  if (ngtcp2_conn_in_closing_period2(c->conn) ||
      ngtcp2_conn_in_draining_period2(c->conn)) {
    return Qnil;
  }

  VALUE sock = rb_ivar_get(self, rb_intern("@sock"));
  if (NIL_P(sock)) {
    rb_raise(rb_eQUICErrorNotBound,
             "QUIC::Connection::Client#bind(sock) has not been called");
  }

  ngtcp2_ccerr ccerr;
  ngtcp2_ccerr_set_application_error(&ccerr, error_code,
                                     reason_len > 0 ? reason_ptr : NULL,
                                     reason_len);

  ngtcp2_path_storage path_storage;
  ngtcp2_path_storage_zero(&path_storage);
  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  VALUE buffer = rb_str_buf_new(QUIC_WRITE_PKT_BUFLEN);
  uint8_t *dest = (uint8_t *)RSTRING_PTR(buffer);

  ngtcp2_ssize n = ngtcp2_conn_write_connection_close(
      c->conn, &path_storage.path, &pi, dest,
      (size_t)QUIC_WRITE_PKT_BUFLEN, &ccerr, quic_now());

  /* Pre-handshake or otherwise not in a state where CONNECTION_CLOSE can be
     emitted (ngtcp2 returns NGTCP2_ERR_INVALID_STATE). Spec treats this as
     best-effort: silently no-op rather than surface an error. The Ruby
     Client is effectively dead from here. */
  if (n == NGTCP2_ERR_INVALID_STATE) {
    return Qnil;
  }

  if (n < 0) {
    rb_str_set_len(buffer, 0);
    quic_raise_ngtcp2_error((int)n);
  }

  if (n == 0) {
    return Qnil;
  }

  rb_str_set_len(buffer, n);
  rb_funcall(sock, rb_intern("send"), 2, buffer, INT2NUM(0));
  return Qnil;
}

void
Init_quic_connection_client(VALUE rb_mQUICConnectionArg)
{
  rb_cQUICConnectionClient = rb_define_class_under(rb_mQUICConnectionArg, "Client", rb_cObject);
  rb_define_alloc_func(rb_cQUICConnectionClient, quic_client_alloc);
  rb_define_singleton_method(rb_cQUICConnectionClient, "_open", quic_client_open, -1);
  rb_define_method(rb_cQUICConnectionClient, "write_pkt", quic_client_write_pkt, -1);
  rb_define_method(rb_cQUICConnectionClient, "read_pkt",  quic_client_read_pkt,  -1);
  rb_define_method(rb_cQUICConnectionClient, "expiry", quic_client_expiry, 0);
  rb_define_method(rb_cQUICConnectionClient, "handle_expiry", quic_client_handle_expiry, 0);
  rb_define_method(rb_cQUICConnectionClient, "handshake_completed?", quic_client_handshake_completed_p, 0);
  rb_define_method(rb_cQUICConnectionClient, "in_closing_period?", quic_client_in_closing_period_p, 0);
  rb_define_method(rb_cQUICConnectionClient, "in_draining_period?", quic_client_in_draining_period_p, 0);
  rb_define_method(rb_cQUICConnectionClient, "open_bidi_stream", quic_client_open_bidi_stream, 0);
  rb_define_method(rb_cQUICConnectionClient, "open_uni_stream", quic_client_open_uni_stream, 0);
  rb_define_method(rb_cQUICConnectionClient, "close", quic_client_close_m, -1);
}
