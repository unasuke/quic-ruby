#include "connection_common.h"
#include "endpoint.h"
#include "stream.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/rand.h>

/* picotls sends a key share only for the first entry; the others are offered
   in supported_groups and reached via HelloRetryRequest. X25519 is first so
   the common case stays 1-RTT. */
ptls_key_exchange_algorithm_t *quic_key_exchanges[] = {
    &ptls_openssl_x25519,
    &ptls_openssl_secp256r1,
#if PTLS_OPENSSL_HAVE_SECP384R1
    &ptls_openssl_secp384r1,
#endif
    NULL,
};

ptls_cipher_suite_t *quic_cipher_suites[] = {
    &ptls_openssl_aes128gcmsha256,
    &ptls_openssl_aes256gcmsha384,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    &ptls_openssl_chacha20poly1305sha256,
#endif
    NULL,
};

static void quic_conn_free(void *ptr) {
  quic_conn_t *c = (quic_conn_t *)ptr;
  /* The Endpoint may be swept in the same GC cycle and freed first; nothing
     from here on may reach its CID table. */
  c->endpoint = NULL;
  if (c->conn)
    ngtcp2_conn_del(c->conn);
  if (c->cptls.ptls) {
    /* Safe even when configure_client_session never ran or failed midway. */
    ngtcp2_crypto_picotls_deconfigure_session(&c->cptls);
    ptls_free(c->cptls.ptls);
  }
  /* After ptls_free: the ptls_t references verify_cert through tls_ctx, or
     the shared context on a server. */
  if (c->verify_cert_initialized)
    ptls_openssl_dispose_verify_certificate(&c->verify_cert);
  if (c->tls != NULL)
    quic_tls_ctx_unref(c->tls);
  /* Still open only if no ngtcp2_conn was made to finish it; the
     constructors close it before raising, so this is a safety net. */
  quic_conn_close_qlog(c);
  xfree(c->alpn);
  xfree(c->alpn_buf);
  xfree(c);
}

static size_t quic_conn_size(const void *ptr) {
  (void)ptr;
  return sizeof(quic_conn_t);
}

/* owner is the object wrapping this struct, so it needs no mark. */
static void quic_conn_mark(void *ptr) {
  quic_conn_t *c = (quic_conn_t *)ptr;
  rb_gc_mark_movable(c->pending_exc);
  rb_gc_mark_movable(c->handler_owner);
  rb_gc_mark_movable(c->endpoint_owner);
  rb_gc_mark_movable(c->error);
  rb_gc_mark_movable(c->closebuf);
}

/* GC.compact may relocate the owner connection object. Follow it so the
   void* user_data ngtcp2 callbacks receive (which equals this struct,
   stored inside owner) keeps resolving @streams / @accept_queue. The
   raw ngtcp2/picotls pointers are outside Ruby's heap and are left alone. */
static void quic_conn_compact(void *ptr) {
  quic_conn_t *c = (quic_conn_t *)ptr;
  c->owner = rb_gc_location(c->owner);
  c->pending_exc = rb_gc_location(c->pending_exc);
  c->handler_owner = rb_gc_location(c->handler_owner);
  c->endpoint_owner = rb_gc_location(c->endpoint_owner);
  c->error = rb_gc_location(c->error);
  c->closebuf = rb_gc_location(c->closebuf);
}

const rb_data_type_t quic_conn_data_type = {
    "QUIC::Connection",
    {
        quic_conn_mark,
        quic_conn_free,
        quic_conn_size,
        quic_conn_compact,
    },
    NULL,
    NULL,
    RUBY_TYPED_FREE_IMMEDIATELY,
};

VALUE
quic_conn_alloc(VALUE klass) {
  quic_conn_t *c = ALLOC(quic_conn_t);
  memset(c, 0, sizeof(*c));
  c->pending_exc = Qnil;
  c->handler_owner = Qnil;
  c->endpoint_owner = Qnil;
  c->error = Qnil;
  c->closebuf = Qnil;
  return TypedData_Wrap_Struct(klass, &quic_conn_data_type, c);
}

/* Re-raise the exception a callback left in c->pending_exc, if any. Called
   right after ngtcp2 returns, before its return value is looked at: the
   NGTCP2_ERR_CALLBACK_FAILURE it reports is the result of that exception. */
static void quic_conn_raise_pending(quic_conn_t *c) {
  if (NIL_P(c->pending_exc))
    return;
  VALUE exc = c->pending_exc;
  c->pending_exc = Qnil;
  rb_exc_raise(exc);
}

int quic_conn_protect(quic_conn_t *c, VALUE (*body)(VALUE), void *arg) {
  int state = 0;
  rb_protect(body, (VALUE)arg, &state);
  if (state == 0)
    return 0;
  if (NIL_P(c->pending_exc))
    c->pending_exc = rb_errinfo();
  rb_set_errinfo(Qnil);
  return NGTCP2_ERR_CALLBACK_FAILURE;
}

quic_conn_t *quic_conn_get(VALUE self) {
  quic_conn_t *c;
  TypedData_Get_Struct(self, quic_conn_t, &quic_conn_data_type, c);
  return c;
}

ngtcp2_conn *quic_conn_ptr(VALUE owner) { return quic_conn_get(owner)->conn; }

ngtcp2_tstamp quic_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static void quic_rand_cb(uint8_t *dest, size_t destlen,
                         const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  RAND_bytes(dest, (int)destlen);
}

/* A connection an Endpoint holds derives the token from the Endpoint's
   secret and enters the new CID in its table. Any other connection never
   sends a Stateless Reset, so a random token does. */
static int quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                         ngtcp2_stateless_reset_token *token,
                                         size_t cidlen, void *user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (c->endpoint == NULL) {
    return RAND_bytes(token->data, NGTCP2_STATELESS_RESET_TOKENLEN) == 1
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (quic_endpoint_generate_reset_token(c->endpoint, token->data, cid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  quic_endpoint_associate_cid(c->endpoint, cid, c->owner);
  return 0;
}

static int quic_remove_connection_id_cb(ngtcp2_conn *conn,
                                        const ngtcp2_cid *cid,
                                        void *user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->endpoint != NULL)
    quic_endpoint_dissociate_cid(c->endpoint, cid, c->owner);
  return 0;
}

ngtcp2_conn *quic_conn_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  return ((quic_conn_t *)conn_ref->user_data)->conn;
}

void quic_require_binary(VALUE str, const char *name) {
  Check_Type(str, T_STRING);
  if (rb_enc_get_index(str) != rb_ascii8bit_encindex()) {
    rb_raise(rb_eArgError, "%s must be ASCII-8BIT (binary) encoding", name);
  }
}

void quic_require_sockaddr(VALUE str, const char *name) {
  quic_require_binary(str, name);

  long len = RSTRING_LEN(str);
  sa_family_t family = AF_UNSPEC;
  if (len >= (long)(offsetof(struct sockaddr, sa_family) + sizeof(family))) {
    memcpy(&family, RSTRING_PTR(str) + offsetof(struct sockaddr, sa_family),
           sizeof(family));
  }
  if ((family == AF_INET && len == (long)sizeof(struct sockaddr_in)) ||
      (family == AF_INET6 && len == (long)sizeof(struct sockaddr_in6))) {
    return;
  }
  rb_raise(rb_eArgError,
           "%s must be an AF_INET or AF_INET6 sockaddr (Addrinfo#to_sockaddr)",
           name);
}

static uint64_t quic_get_uint64_field(VALUE obj, const char *name) {
  VALUE v = rb_funcall(obj, rb_intern(name), 0);
  return (uint64_t)NUM2ULL(v);
}

static ngtcp2_cc_algo quic_cc_algo_from_sym(VALUE sym) {
  Check_Type(sym, T_SYMBOL);
  ID id = SYM2ID(sym);
  if (id == rb_intern("reno"))
    return NGTCP2_CC_ALGO_RENO;
  if (id == rb_intern("cubic"))
    return NGTCP2_CC_ALGO_CUBIC;
  if (id == rb_intern("bbr"))
    return NGTCP2_CC_ALGO_BBR;
  rb_raise(rb_eArgError,
           "unknown cc_algo: %" PRIsVALUE " (expected :reno, :cubic, or :bbr)",
           sym);
}

void quic_fill_transport_params(ngtcp2_transport_params *params, VALUE tp) {
  ngtcp2_transport_params_default(params);
  params->initial_max_stream_data_bidi_local =
      quic_get_uint64_field(tp, "initial_max_stream_data_bidi_local");
  params->initial_max_stream_data_bidi_remote =
      quic_get_uint64_field(tp, "initial_max_stream_data_bidi_remote");
  params->initial_max_stream_data_uni =
      quic_get_uint64_field(tp, "initial_max_stream_data_uni");
  params->initial_max_data = quic_get_uint64_field(tp, "initial_max_data");
  params->initial_max_streams_bidi =
      quic_get_uint64_field(tp, "initial_max_streams_bidi");
  params->initial_max_streams_uni =
      quic_get_uint64_field(tp, "initial_max_streams_uni");
  params->max_idle_timeout =
      (ngtcp2_duration)quic_get_uint64_field(tp, "max_idle_timeout");
  params->active_connection_id_limit =
      quic_get_uint64_field(tp, "active_connection_id_limit");
}

void quic_fill_settings(ngtcp2_settings *settings, VALUE st) {
  ngtcp2_settings_default(settings);
  settings->initial_ts = quic_now();
  settings->cc_algo =
      quic_cc_algo_from_sym(rb_funcall(st, rb_intern("cc_algo"), 0));
  settings->initial_rtt =
      (ngtcp2_duration)quic_get_uint64_field(st, "initial_rtt");
  settings->max_window = quic_get_uint64_field(st, "max_window");
  settings->max_stream_window = quic_get_uint64_field(st, "max_stream_window");
  settings->handshake_timeout =
      (ngtcp2_duration)quic_get_uint64_field(st, "handshake_timeout");
  VALUE no_pmtud = rb_funcall(st, rb_intern("no_pmtud"), 0);
  settings->no_pmtud = RTEST(no_pmtud) ? 1 : 0;
}

/* ngtcp2_settings.qlog_write. Touches no Ruby object, so it needs no
   rb_protect. A write error only costs qlog. */
static void quic_qlog_write_cb(void *user_data, uint32_t flags,
                               const void *data, size_t datalen) {
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->qlog == NULL)
    return;
  fwrite(data, 1, datalen, c->qlog);
  if (flags & NGTCP2_QLOG_WRITE_FLAG_FIN)
    quic_conn_close_qlog(c);
}

void quic_conn_close_qlog(quic_conn_t *c) {
  if (c->qlog == NULL)
    return;
  fclose(c->qlog);
  c->qlog = NULL;
}

void quic_conn_open_qlog(quic_conn_t *c, VALUE settings_v,
                         ngtcp2_settings *settings) {
  VALUE dir = quic_path_value(rb_funcall(settings_v, rb_intern("qlog_dir"), 0),
                              "qlog_dir");
  if (NIL_P(dir))
    return;

  char hex[NGTCP2_MAX_CIDLEN * 2 + 1];
  for (size_t i = 0; i < c->scid.datalen; i++) {
    snprintf(hex + i * 2, 3, "%02x", c->scid.data[i]);
  }
  hex[c->scid.datalen * 2] = '\0';
  VALUE path = rb_sprintf("%" PRIsVALUE "/%s.sqlog", dir, hex);
  c->qlog = fopen(StringValueCStr(path), "w");
  if (c->qlog != NULL)
    settings->qlog_write = quic_qlog_write_cb;
}

/* Validate a path setting (ca_file, ca_path, ...) and return it as a String,
   or Qnil. Accepts a String or anything responding to #to_path. Every
   misconfiguration raises ArgumentError, including a wrong type. */
VALUE
quic_path_value(VALUE value, const char *name) {
  if (NIL_P(value))
    return Qnil;

  VALUE path = value;
  if (!RB_TYPE_P(path, T_STRING)) {
    if (rb_respond_to(path, rb_intern("to_path"))) {
      path = rb_funcall(path, rb_intern("to_path"), 0);
    }
    if (!RB_TYPE_P(path, T_STRING)) {
      rb_raise(rb_eArgError,
               "%s must be a String or Pathname (got %" PRIsVALUE ")", name,
               rb_obj_class(value));
    }
  }
  /* Raises ArgumentError when the path contains a NUL byte. */
  StringValueCStr(path);
  return path;
}

/* picotls keeps the pointers of an ALPN list for the whole handshake, so
   ALLOCA_N would not survive. */
void quic_copy_alpn(VALUE alpn_ary, ptls_iovec_t **list, size_t *count,
                    uint8_t **buf) {
  Check_Type(alpn_ary, T_ARRAY);
  long n_alpn = RARRAY_LEN(alpn_ary);
  *count = 0;
  if (n_alpn <= 0)
    return;

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
  *buf = ALLOC_N(uint8_t, total);
  *list = ALLOC_N(ptls_iovec_t, n_alpn);
  uint8_t *p = *buf;
  for (long i = 0; i < n_alpn; i++) {
    VALUE entry = RARRAY_AREF(alpn_ary, i);
    size_t len = (size_t)RSTRING_LEN(entry);
    memcpy(p, RSTRING_PTR(entry), len);
    (*list)[i] = ptls_iovec_init(p, len);
    p += len;
  }
  *count = (size_t)n_alpn;
}

/* An empty list leaves c->alpn NULL, which a client sends as no ALPN
   extension at all. */
void quic_conn_copy_alpn(quic_conn_t *c, VALUE settings_v) {
  quic_copy_alpn(rb_funcall(settings_v, rb_intern("alpn"), 0), &c->alpn,
                 &c->alpn_count, &c->alpn_buf);
}

void quic_conn_give_back_peer_stream(ngtcp2_conn *conn, int64_t stream_id) {
  if (!ngtcp2_conn_is_local_stream2(conn, stream_id) &&
      ngtcp2_is_bidi_stream(stream_id)) {
    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
  }
}

/* The ngtcp2 stream callbacks hand each stream to the stream handler (the
   quic_handler_* functions below) or, without one, to its QUIC::Stream
   (quic_stream_on_* in stream.c). */

static int quic_handler_recv_stream_data(quic_conn_t *c, ngtcp2_conn *conn,
                                         uint32_t flags, int64_t stream_id,
                                         const uint8_t *data, size_t datalen) {
  size_t consumed = 0;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
  if (c->handler->recv_stream_data(c->handler_ud, stream_id, data, datalen, fin,
                                   c->now, &consumed) < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  /* What the handler consumed outright (for HTTP/3, everything but the
     request body) goes straight back to the peer as credit. */
  if (consumed > 0) {
    if (ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed) != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ngtcp2_conn_extend_max_offset(conn, consumed);
  }
  return 0;
}

static int quic_handler_acked_stream_data(quic_conn_t *c, int64_t stream_id,
                                          uint64_t datalen) {
  return c->handler->acked_stream_data(c->handler_ud, stream_id, datalen) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

static int quic_handler_stream_close(quic_conn_t *c, ngtcp2_conn *conn,
                                     uint32_t flags, int64_t stream_id,
                                     uint64_t app_error_code) {
  /* The handler keeps no stream waiting for the application, so the peer
     gets its stream back at once. */
  quic_conn_give_back_peer_stream(conn, stream_id);
  int has_code = (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0;
  return c->handler->stream_close(c->handler_ud, stream_id, has_code,
                                  app_error_code) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

static int quic_handler_stream_reset(quic_conn_t *c, int64_t stream_id,
                                     uint64_t final_size,
                                     uint64_t app_error_code) {
  return c->handler->stream_reset(c->handler_ud, stream_id, final_size,
                                  app_error_code) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

/* A handler built against ABI 1.0 lacks recv_stop_sending, and learns of
   STOP_SENDING only when #write_pkt finds the send side shut
   (stream_shut_write) or the stream closes. */
static int quic_handler_recv_stop_sending(quic_conn_t *c, int64_t stream_id,
                                          uint64_t app_error_code) {
  if (!QUIC_EXT_HANDLER_HAS(c->handler, recv_stop_sending))
    return 0;
  return c->handler->recv_stop_sending(c->handler_ud, stream_id,
                                       app_error_code) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

/* Called only for a stream the peer opened. */
static int quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id,
                               void *user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler)
    return 0; /* the handler keeps its own stream state */
  return quic_stream_on_open(c, stream_id);
}

static int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                    int64_t stream_id, uint64_t offset,
                                    const uint8_t *data, size_t datalen,
                                    void *user_data, void *stream_user_data) {
  (void)offset;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler)
    return quic_handler_recv_stream_data(c, conn, flags, stream_id, data,
                                         datalen);
  return quic_stream_on_recv_data(c, stream_user_data, flags, data, datalen);
}

static int quic_acked_stream_data_offset_cb(ngtcp2_conn *conn,
                                            int64_t stream_id, uint64_t offset,
                                            uint64_t datalen, void *user_data,
                                            void *stream_user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler)
    return quic_handler_acked_stream_data(c, stream_id, datalen);
  quic_stream_on_acked(stream_user_data, offset, datalen);
  return 0;
}

static int quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t app_error_code,
                                void *user_data, void *stream_user_data) {
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler)
    return quic_handler_stream_close(c, conn, flags, stream_id, app_error_code);
  return quic_stream_on_close(c, stream_user_data, stream_id, flags,
                              app_error_code);
}

static int quic_stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                uint64_t final_size, uint64_t app_error_code,
                                void *user_data, void *stream_user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler)
    return quic_handler_stream_reset(c, stream_id, final_size, app_error_code);
  quic_stream_on_reset(stream_user_data, app_error_code);
  return 0;
}

/* The peer sent STOP_SENDING. ngtcp2 shuts the send side and sends
   RESET_STREAM itself once this returns. */
static int quic_recv_stop_sending_cb(ngtcp2_conn *conn, int64_t stream_id,
                                     uint64_t app_error_code, void *user_data,
                                     void *stream_user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler)
    return quic_handler_recv_stop_sending(c, stream_id, app_error_code);
  quic_stream_on_recv_stop_sending(c, stream_user_data, app_error_code);
  return 0;
}

/* The callbacks below matter only to a stream handler. Without one, the
   QUIC::Stream mode needs none of them. */

/* This endpoint stopped reading the stream, and STOP_SENDING is going out.
   Not to be confused with recv_stop_sending above. */
static int quic_stream_stop_sending_cb(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t app_error_code, void *user_data,
                                       void *stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler)
    return 0;
  return c->handler->stream_stop_sending(c->handler_ud, stream_id,
                                         app_error_code) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

static int quic_extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
                                          uint64_t max_data, void *user_data,
                                          void *stream_user_data) {
  (void)conn;
  (void)max_data;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler)
    return 0;
  return c->handler->extend_max_stream_data(c->handler_ud, stream_id) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

static int quic_extend_max_remote_streams_bidi_cb(ngtcp2_conn *conn,
                                                  uint64_t max_streams,
                                                  void *user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler)
    return 0;
  return c->handler->extend_max_remote_streams_bidi(c->handler_ud,
                                                    max_streams) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler)
    return 0;
  return c->handler->handshake_completed(c->handler_ud) < 0
             ? NGTCP2_ERR_CALLBACK_FAILURE
             : 0;
}

void quic_conn_fill_common_callbacks(ngtcp2_callbacks *callbacks) {
  memset(callbacks, 0, sizeof(*callbacks));
  callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks->update_key = ngtcp2_crypto_update_key_cb;
  callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks->delete_crypto_cipher_ctx =
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks->get_path_challenge_data2 =
      ngtcp2_crypto_get_path_challenge_data2_cb;
  callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks->rand = quic_rand_cb;
  callbacks->get_new_connection_id2 = quic_get_new_connection_id_cb;
  callbacks->remove_connection_id = quic_remove_connection_id_cb;
  callbacks->stream_open = quic_stream_open_cb;
  callbacks->recv_stream_data = quic_recv_stream_data_cb;
  callbacks->acked_stream_data_offset = quic_acked_stream_data_offset_cb;
  callbacks->stream_close = quic_stream_close_cb;
  callbacks->stream_reset = quic_stream_reset_cb;
  callbacks->recv_stop_sending = quic_recv_stop_sending_cb;
  callbacks->stream_stop_sending = quic_stream_stop_sending_cb;
  callbacks->extend_max_stream_data = quic_extend_max_stream_data_cb;
  callbacks->extend_max_remote_streams_bidi =
      quic_extend_max_remote_streams_bidi_cb;
  callbacks->handshake_completed = quic_handshake_completed_cb;
}

/* The number of vectors #write_pkt asks a stream handler for per packet. */
#define QUIC_HANDLER_VECCNT 16

_Static_assert(sizeof(quic_ext_vec) == sizeof(ngtcp2_vec),
               "quic_ext_vec must have the layout of ngtcp2_vec");
_Static_assert(offsetof(quic_ext_vec, base) == offsetof(ngtcp2_vec, base),
               "quic_ext_vec.base must line up with ngtcp2_vec.base");
_Static_assert(offsetof(quic_ext_vec, len) == offsetof(ngtcp2_vec, len),
               "quic_ext_vec.len must line up with ngtcp2_vec.len");

/* #write_pkt with a stream handler: pull the next stream data from the
   handler for every packet, as ngtcp2's examples/server.cc does with
   nghttp3. NGTCP2_WRITE_STREAM_FLAG_MORE is not used, so a packet carries
   data of one stream at most. A handler failure is reported as
   NGTCP2_ERR_CALLBACK_FAILURE. */
static ngtcp2_ssize quic_conn_write_pkt_handler(quic_conn_t *c,
                                                ngtcp2_path *path,
                                                ngtcp2_pkt_info *pi,
                                                uint8_t *dest, size_t destlen) {
  const quic_ext_stream_handler *h = c->handler;
  for (;;) {
    int64_t sid = -1;
    int fin = 0;
    quic_ext_vec vec[QUIC_HANDLER_VECCNT];
    size_t nvec = 0;
    if (ngtcp2_conn_get_max_data_left2(c->conn) &&
        h->next_stream_data(c->handler_ud, &sid, &fin, vec, QUIC_HANDLER_VECCNT,
                            &nvec) < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    ngtcp2_ssize ndatalen = -1;
    ngtcp2_ssize n =
        ngtcp2_conn_writev_stream(c->conn, path, pi, dest, destlen, &ndatalen,
                                  fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0, sid,
                                  (const ngtcp2_vec *)vec, nvec, c->now);
    if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      if (h->stream_blocked(c->handler_ud, sid) < 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
      continue;
    }
    if (n == NGTCP2_ERR_STREAM_SHUT_WR) {
      if (h->stream_shut_write(c->handler_ud, sid) < 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
      continue;
    }
    if (n < 0)
      return n;
    if (ndatalen >= 0 &&
        h->stream_data_written(c->handler_ud, sid, (size_t)ndatalen) < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return n; /* 0: nothing to send */
  }
}

ngtcp2_ssize quic_conn_write_pkt_raw(VALUE self, quic_conn_t *c,
                                     ngtcp2_path *path, uint8_t *dest) {
  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  c->now = quic_now();
  return c->handler ? quic_conn_write_pkt_handler(c, path, &pi, dest,
                                                  QUIC_WRITE_PKT_BUFLEN)
                    : quic_streams_write_pkt(self, c, path, &pi, dest,
                                             QUIC_WRITE_PKT_BUFLEN);
}

static VALUE quic_conn_write_pkt(int argc, VALUE *argv, VALUE self) {
  VALUE buffer = Qnil;
  rb_scan_args(argc, argv, "01", &buffer);

  quic_conn_t *c = quic_conn_get(self);

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
      rb_str_modify_expand(buffer,
                           (long)QUIC_WRITE_PKT_BUFLEN - RSTRING_LEN(buffer));
    }
  }

  ngtcp2_path_storage path_storage;
  ngtcp2_path_storage_zero(&path_storage);

  ngtcp2_ssize n = quic_conn_write_pkt_raw(self, c, &path_storage.path,
                                           (uint8_t *)RSTRING_PTR(buffer));

  if (!NIL_P(c->pending_exc)) {
    rb_str_set_len(buffer, 0);
    quic_conn_raise_pending(c);
  }

  if (n < 0) {
    /* ngtcp2 does not partially write on failure, but truncate explicitly so
       that a rescued caller cannot accidentally transmit stale bytes. */
    rb_str_set_len(buffer, 0);
    quic_raise_ngtcp2_error((int)n);
  }

  if (n == 0) {
    rb_str_set_len(buffer, 0);
    return Qnil;
  }
  rb_str_set_len(buffer, n);
  return buffer;
}

/* Like quic_ngtcp2_error_new, but for errors from read_pkt, where the TLS
   handshake runs: NGTCP2_ERR_CRYPTO carries the TLS alert this endpoint
   sent, and becomes CertificateVerifyFailed when the verifier rejected the
   peer. */
VALUE
quic_conn_error_new(quic_conn_t *c, int rv) {
  if (rv != NGTCP2_ERR_CRYPTO)
    return quic_ngtcp2_error_new(rv);

  /* 0 means "not set" to ngtcp2; close_notify (0) is never sent for a
     verification failure, so report it as nil. */
  uint8_t alert = ngtcp2_conn_get_tls_alert2(c->conn);
  VALUE exc;
  if (c->verify_failed) {
    VALUE msg =
        c->verify_result
            ? rb_sprintf("certificate verify failed (%s)",
                         X509_verify_cert_error_string(c->verify_result))
            : rb_str_new_cstr(
                  "certificate verify failed (server sent no certificate)");
    exc = rb_exc_new_str(rb_eQUICErrorCertificateVerifyFailed, msg);
    rb_ivar_set(exc, rb_intern("@verify_result"),
                c->verify_result ? INT2NUM(c->verify_result) : Qnil);
  } else {
    exc = rb_exc_new_cstr(rb_eQUICErrorCryptoError, ngtcp2_strerror(rv));
  }
  rb_ivar_set(exc, rb_intern("@code"), INT2NUM(rv));
  rb_ivar_set(exc, rb_intern("@tls_alert"), alert ? INT2NUM(alert) : Qnil);
  return exc;
}

int quic_conn_read_pkt_raw(quic_conn_t *c, const ngtcp2_path *path,
                           const uint8_t *data, size_t datalen) {
  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  c->now = quic_now();
  return ngtcp2_conn_read_pkt(c->conn, path, &pi, data, datalen, c->now);
}

struct quic_read_pkt_args {
  quic_conn_t *c;
  VALUE packet;
  ngtcp2_path path;
};

static VALUE quic_read_pkt_body(VALUE arg) {
  struct quic_read_pkt_args *a = (struct quic_read_pkt_args *)arg;
  int rv = quic_conn_read_pkt_raw(a->c, &a->path,
                                  (const uint8_t *)RSTRING_PTR(a->packet),
                                  (size_t)RSTRING_LEN(a->packet));
  /* The peer closed or reset the connection; ngtcp2 logs nothing more. */
  if (ngtcp2_conn_in_draining_period2(a->c->conn))
    quic_conn_close_qlog(a->c);
  quic_conn_raise_pending(a->c);
  if (rv != 0) {
    /* longjmp passes through rb_ensure so unlock still fires. */
    rb_exc_raise(quic_conn_error_new(a->c, rv));
  }
  return Qnil;
}

static VALUE quic_read_pkt_unlock(VALUE arg) {
  rb_str_unlocktmp(((struct quic_read_pkt_args *)arg)->packet);
  return Qnil;
}

static VALUE quic_conn_read_pkt(int argc, VALUE *argv, VALUE self) {
  VALUE packet = Qnil;
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "1:", &packet, &opts);

  if (NIL_P(opts)) {
    rb_raise(rb_eArgError, "missing keywords: local_sockaddr, remote_sockaddr");
  }

  VALUE local_sockaddr =
      rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr =
      rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));

  if (NIL_P(local_sockaddr) || NIL_P(remote_sockaddr)) {
    rb_raise(rb_eArgError, "missing keywords: local_sockaddr, remote_sockaddr");
  }

  quic_require_binary(packet, "packet");
  quic_require_sockaddr(local_sockaddr, "local_sockaddr");
  quic_require_sockaddr(remote_sockaddr, "remote_sockaddr");

  quic_conn_t *c = quic_conn_get(self);

  struct quic_read_pkt_args args;
  args.c = c;
  args.packet = packet;
  args.path.local.addr = (struct sockaddr *)RSTRING_PTR(local_sockaddr);
  args.path.local.addrlen = (ngtcp2_socklen)RSTRING_LEN(local_sockaddr);
  args.path.remote.addr = (struct sockaddr *)RSTRING_PTR(remote_sockaddr);
  args.path.remote.addrlen = (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr);
  args.path.user_data = NULL;

  rb_str_locktmp(packet);
  return rb_ensure(quic_read_pkt_body, (VALUE)&args, quic_read_pkt_unlock,
                   (VALUE)&args);
}

static VALUE quic_conn_handshake_completed_p(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  return ngtcp2_conn_get_handshake_completed2(c->conn) ? Qtrue : Qfalse;
}

static VALUE quic_conn_in_closing_period_p(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  return ngtcp2_conn_in_closing_period2(c->conn) ? Qtrue : Qfalse;
}

static VALUE quic_conn_in_draining_period_p(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  return ngtcp2_conn_in_draining_period2(c->conn) ? Qtrue : Qfalse;
}

static VALUE quic_conn_expiry(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  ngtcp2_tstamp t = ngtcp2_conn_get_expiry2(c->conn);
  if (t == UINT64_MAX)
    return Qnil;
  return ULL2NUM((unsigned long long)t);
}

/* Caller is responsible for ordering with #read_pkt / #write_pkt:
   read_pkt or handle_expiry to advance ngtcp2 state, then write_pkt to flush.
 */
static VALUE quic_conn_handle_expiry(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  c->now = quic_now();
  int rv = ngtcp2_conn_handle_expiry(c->conn, c->now);
  /* Timed out idle: the connection ends without a CONNECTION_CLOSE. */
  if (rv == NGTCP2_ERR_IDLE_CLOSE)
    quic_conn_close_qlog(c);
  quic_conn_raise_pending(c);
  if (rv != 0)
    quic_raise_ngtcp2_error(rv);
  return Qnil;
}

/* QUIC::Stream objects exist only without a stream handler. */
static void quic_conn_require_stream_mode(quic_conn_t *c) {
  if (c->handler) {
    rb_raise(rb_eQUICErrorInvalidState,
             "the connection's streams belong to a C stream handler");
  }
}

static VALUE quic_conn_open_bidi_stream(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  quic_conn_require_stream_mode(c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
  if (rv != 0)
    quic_raise_ngtcp2_error(rv);
  return quic_stream_open_local(self, c, stream_id);
}

static VALUE quic_conn_open_uni_stream(VALUE self) {
  quic_conn_t *c = quic_conn_get(self);
  quic_conn_require_stream_mode(c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_uni_stream(c->conn, &stream_id, NULL);
  if (rv != 0)
    quic_raise_ngtcp2_error(rv);
  return quic_stream_open_local(self, c, stream_id);
}

/* Send an application CONNECTION_CLOSE (frame type 0x1d) to the peer and
   transition the underlying ngtcp2_conn to the closing period. One UDP
   datagram is written to the bound socket, once: nothing sends it again
   for packets the peer keeps sending (an Endpoint does, for its own
   connections), and #write_pkt raises QUIC::Error::Closed from here on.
   Calling #close on a connection that is already in the closing or
   draining period is a no-op (= returns nil without doing any I/O). */
static VALUE quic_conn_close_m(int argc, VALUE *argv, VALUE self) {
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

  quic_conn_t *c = quic_conn_get(self);

  /* Idempotent: a subsequent #close after the conn already entered the
     closing/draining period does not emit another CONNECTION_CLOSE. */
  if (ngtcp2_conn_in_closing_period2(c->conn) ||
      ngtcp2_conn_in_draining_period2(c->conn)) {
    return Qnil;
  }

  /* A connection an Endpoint made has no socket: the CONNECTION_CLOSE goes
     out through Endpoint#write_pkt. Once it has left the Endpoint's table
     it is finished, and #close does nothing. */
  if (c->from_endpoint) {
    if (c->endpoint == NULL)
      return Qnil;
    ngtcp2_ccerr ccerr;
    ngtcp2_ccerr_set_application_error(
        &ccerr, error_code, reason_len > 0 ? reason_ptr : NULL, reason_len);
    quic_endpoint_close_conn(c->endpoint, c, &ccerr);
    return Qnil;
  }

  VALUE sock = rb_ivar_get(self, rb_intern("@sock"));
  if (NIL_P(sock)) {
    rb_raise(rb_eQUICErrorNotBound,
             "%" PRIsVALUE "#bind(sock) has not been called",
             rb_obj_class(self));
  }

  ngtcp2_ccerr ccerr;
  ngtcp2_ccerr_set_application_error(
      &ccerr, error_code, reason_len > 0 ? reason_ptr : NULL, reason_len);

  ngtcp2_path_storage path_storage;
  ngtcp2_path_storage_zero(&path_storage);
  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  VALUE buffer = rb_str_buf_new(QUIC_WRITE_PKT_BUFLEN);
  uint8_t *dest = (uint8_t *)RSTRING_PTR(buffer);

  ngtcp2_ssize n = ngtcp2_conn_write_connection_close(
      c->conn, &path_storage.path, &pi, dest, (size_t)QUIC_WRITE_PKT_BUFLEN,
      &ccerr, quic_now());
  /* The connection ends here whatever ngtcp2 returned, and the
     CONNECTION_CLOSE, if one was built, is in the qlog already. */
  quic_conn_close_qlog(c);

  /* Pre-handshake or otherwise not in a state where CONNECTION_CLOSE can be
     emitted (ngtcp2 returns NGTCP2_ERR_INVALID_STATE). Spec treats this as
     best-effort: silently no-op rather than surface an error. The Ruby
     connection object is effectively dead from here. */
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

/* Why an Endpoint closed this connection; see quic_conn_t.error. Always nil
   for a connection no Endpoint made. */
static VALUE quic_conn_error_m(VALUE self) {
  return quic_conn_get(self)->error;
}

void quic_conn_define_shared_methods(VALUE klass) {
  rb_define_method(klass, "write_pkt", quic_conn_write_pkt, -1);
  rb_define_method(klass, "read_pkt", quic_conn_read_pkt, -1);
  rb_define_method(klass, "expiry", quic_conn_expiry, 0);
  rb_define_method(klass, "handle_expiry", quic_conn_handle_expiry, 0);
  rb_define_method(klass, "handshake_completed?",
                   quic_conn_handshake_completed_p, 0);
  rb_define_method(klass, "in_closing_period?", quic_conn_in_closing_period_p,
                   0);
  rb_define_method(klass, "in_draining_period?", quic_conn_in_draining_period_p,
                   0);
  rb_define_method(klass, "open_bidi_stream", quic_conn_open_bidi_stream, 0);
  rb_define_method(klass, "open_uni_stream", quic_conn_open_uni_stream, 0);
  rb_define_method(klass, "close", quic_conn_close_m, -1);
  rb_define_method(klass, "error", quic_conn_error_m, 0);
}
