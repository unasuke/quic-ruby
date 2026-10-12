#include "connection_common.h"
#include "stream.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/rand.h>

/* Buffer size for #write_pkt. NGTCP2_MAX_UDP_PAYLOAD_SIZE (1200) is the
   minimum destlen ngtcp2 accepts. Revisit when PMTUD is enabled (Phase 4+). */
#define QUIC_WRITE_PKT_BUFLEN NGTCP2_MAX_UDP_PAYLOAD_SIZE

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

static void
quic_conn_free(void *ptr)
{
  quic_conn_t *c = (quic_conn_t *)ptr;
  if (c->conn) ngtcp2_conn_del(c->conn);
  if (c->cptls.ptls) {
    /* Safe even when configure_client_session never ran or failed midway. */
    ngtcp2_crypto_picotls_deconfigure_session(&c->cptls);
    ptls_free(c->cptls.ptls);
  }
  /* After ptls_free: the ptls_t references verify_cert through tls_ctx, or
     the shared context on a server. */
  if (c->verify_cert_initialized) ptls_openssl_dispose_verify_certificate(&c->verify_cert);
  if (c->tls != NULL) quic_tls_ctx_unref(c->tls);
  xfree(c->alpn);
  xfree(c->alpn_buf);
  xfree(c);
}

static size_t
quic_conn_size(const void *ptr)
{
  (void)ptr;
  return sizeof(quic_conn_t);
}

/* owner is the object wrapping this struct, so it needs no mark. */
static void
quic_conn_mark(void *ptr)
{
  quic_conn_t *c = (quic_conn_t *)ptr;
  rb_gc_mark_movable(c->pending_exc);
  rb_gc_mark_movable(c->handler_owner);
}

/* GC.compact may relocate the owner connection object. Follow it so the
   void* user_data ngtcp2 callbacks receive (which equals this struct,
   stored inside owner) keeps resolving @streams / @accept_queue. The
   raw ngtcp2/picotls pointers are outside Ruby's heap and are left alone. */
static void
quic_conn_compact(void *ptr)
{
  quic_conn_t *c = (quic_conn_t *)ptr;
  c->owner = rb_gc_location(c->owner);
  c->pending_exc = rb_gc_location(c->pending_exc);
  c->handler_owner = rb_gc_location(c->handler_owner);
}

const rb_data_type_t quic_conn_data_type = {
  "QUIC::Connection",
  {quic_conn_mark, quic_conn_free, quic_conn_size, quic_conn_compact,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

VALUE
quic_conn_alloc(VALUE klass)
{
  quic_conn_t *c = ALLOC(quic_conn_t);
  memset(c, 0, sizeof(*c));
  c->pending_exc = Qnil;
  c->handler_owner = Qnil;
  return TypedData_Wrap_Struct(klass, &quic_conn_data_type, c);
}

/* Re-raise the exception a callback left in c->pending_exc, if any. Called
   right after ngtcp2 returns, before its return value is looked at: the
   NGTCP2_ERR_CALLBACK_FAILURE it reports is the result of that exception. */
static void
quic_conn_raise_pending(quic_conn_t *c)
{
  if (NIL_P(c->pending_exc)) return;
  VALUE exc = c->pending_exc;
  c->pending_exc = Qnil;
  rb_exc_raise(exc);
}

/* Run body(arg) under rb_protect. An exception is kept in c->pending_exc
   (the first one wins; ngtcp2 stops at the first failing callback anyway)
   and turned into NGTCP2_ERR_CALLBACK_FAILURE, so that it never unwinds
   through ngtcp2. */
static int
quic_conn_protect(quic_conn_t *c, VALUE (*body)(VALUE), void *arg)
{
  int state = 0;
  rb_protect(body, (VALUE)arg, &state);
  if (state == 0) return 0;
  if (NIL_P(c->pending_exc)) c->pending_exc = rb_errinfo();
  rb_set_errinfo(Qnil);
  return NGTCP2_ERR_CALLBACK_FAILURE;
}

quic_conn_t *
quic_conn_get(VALUE self)
{
  quic_conn_t *c;
  TypedData_Get_Struct(self, quic_conn_t, &quic_conn_data_type, c);
  return c;
}

ngtcp2_conn *
quic_conn_ptr(VALUE owner)
{
  return quic_conn_get(owner)->conn;
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
                              ngtcp2_stateless_reset_token *token, size_t cidlen,
                              void *user_data)
{
  (void)conn;
  (void)user_data;
  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (RAND_bytes(token->data, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

ngtcp2_conn *
quic_conn_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  return ((quic_conn_t *)conn_ref->user_data)->conn;
}

void
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

void
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

void
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

/* Validate a path setting (ca_file, ca_path, ...) and return it as a String,
   or Qnil. Accepts a String or anything responding to #to_path. Every
   misconfiguration raises ArgumentError, including a wrong type. */
VALUE
quic_path_value(VALUE value, const char *name)
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

/* picotls keeps the pointers of an ALPN list for the whole handshake, so
   ALLOCA_N would not survive. */
void
quic_copy_alpn(VALUE alpn_ary, ptls_iovec_t **list, size_t *count, uint8_t **buf)
{
  Check_Type(alpn_ary, T_ARRAY);
  long n_alpn = RARRAY_LEN(alpn_ary);
  *count = 0;
  if (n_alpn <= 0) return;

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
void
quic_conn_copy_alpn(quic_conn_t *c, VALUE settings_v)
{
  quic_copy_alpn(rb_funcall(settings_v, rb_intern("alpn"), 0), &c->alpn, &c->alpn_count,
                 &c->alpn_buf);
}

/* Shared helper: look up the QUIC::Stream registered for stream_id in the
   owner connection's @streams Hash. Returns Qnil if not found (which can
   happen if the stream was already removed by a previous stream_close
   callback). */
static VALUE
quic_conn_lookup_stream(quic_conn_t *c, int64_t stream_id)
{
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  return rb_hash_aref(streams, LL2NUM(stream_id));
}

/* ngtcp2 stream callbacks. The Ruby-touching part of each is a *_body
   function run under rb_protect by quic_conn_protect, so that an exception
   (a frozen @streams, an allocation failure, ...) never unwinds through
   ngtcp2. The callback then returns NGTCP2_ERR_CALLBACK_FAILURE and the
   exception is re-raised once ngtcp2 has returned. */

/* The arguments of a stream callback, handed to its body through
   rb_protect's single VALUE. Each body reads only the fields it needs. */
struct quic_stream_cb_args {
  quic_conn_t *c;
  int64_t stream_id;
  uint32_t flags;
  const uint8_t *data;
  size_t datalen;
  uint64_t acked;
  uint64_t app_error_code;
};

static VALUE
quic_stream_open_body(VALUE arg)
{
  struct quic_stream_cb_args *a = (struct quic_stream_cb_args *)arg;
  VALUE streams = rb_ivar_get(a->c->owner, rb_intern("@streams"));
  if (!NIL_P(rb_hash_aref(streams, LL2NUM(a->stream_id)))) {
    return Qnil;  /* already known (opened by this endpoint) */
  }
  VALUE stream = quic_stream_new(a->stream_id, a->c->owner);
  rb_hash_aset(streams, LL2NUM(a->stream_id), stream);
  return Qnil;
}

void
quic_conn_give_back_peer_stream(ngtcp2_conn *conn, int64_t stream_id)
{
  if (!ngtcp2_conn_is_local_stream2(conn, stream_id) && ngtcp2_is_bidi_stream(stream_id)) {
    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
  }
}

static int
quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler) return 0;  /* the handler keeps its own stream state */
  struct quic_stream_cb_args a = {.c = c, .stream_id = stream_id};
  return quic_conn_protect(c, quic_stream_open_body, &a);
}

static VALUE
quic_recv_stream_data_body(VALUE arg)
{
  struct quic_stream_cb_args *a = (struct quic_stream_cb_args *)arg;
  quic_conn_t *c = a->c;
  VALUE stream = quic_conn_lookup_stream(c, a->stream_id);
  if (NIL_P(stream)) return Qnil;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);

  /* Surface peer-initiated streams to #accept_stream. The low stream-id bit
     marks the initiator (0 == client, 1 == server), so a client queues the
     odd ids and a server the even ones. Push once, on first data arrival,
     then mark so later data does not re-enqueue. */
  bool peer_initiated = c->is_server ? !(a->stream_id & 0x01) : (a->stream_id & 0x01);
  if (!s->accept_queued && peer_initiated) {
    VALUE accept_queue = rb_ivar_get(c->owner, rb_intern("@accept_queue"));
    rb_ary_push(accept_queue, stream);
    s->accept_queued = true;
  }

  if (a->datalen > 0) {
    VALUE recv_buffer = rb_ivar_get(stream, rb_intern("@recv_buffer"));
    rb_str_buf_cat(recv_buffer, (const char *)a->data, (long)a->datalen);
  }
  if (a->flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    s->fin_received = true;
  }
  return Qnil;
}

static int
quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data)
{
  (void)offset;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler) {
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
  struct quic_stream_cb_args a = {
    .c = c, .stream_id = stream_id, .flags = flags, .data = data, .datalen = datalen,
  };
  return quic_conn_protect(c, quic_recv_stream_data_body, &a);
}

static VALUE
quic_acked_stream_data_offset_body(VALUE arg)
{
  struct quic_stream_cb_args *a = (struct quic_stream_cb_args *)arg;
  VALUE stream = quic_conn_lookup_stream(a->c, a->stream_id);
  if (NIL_P(stream)) return Qnil;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->acked_offset += a->acked;

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
  return Qnil;
}

static int
quic_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                 uint64_t offset, uint64_t datalen,
                                 void *user_data, void *stream_user_data)
{
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler) {
    return c->handler->acked_stream_data(c->handler_ud, stream_id, datalen) < 0
      ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
  }
  struct quic_stream_cb_args a = {.c = c, .stream_id = stream_id, .acked = datalen};
  return quic_conn_protect(c, quic_acked_stream_data_offset_body, &a);
}

static VALUE
quic_stream_close_body(VALUE arg)
{
  struct quic_stream_cb_args *a = (struct quic_stream_cb_args *)arg;
  VALUE streams = rb_ivar_get(a->c->owner, rb_intern("@streams"));
  VALUE stream = rb_hash_aref(streams, LL2NUM(a->stream_id));
  if (NIL_P(stream)) {
    quic_conn_give_back_peer_stream(a->c->conn, a->stream_id);
    return Qnil;
  }

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->closed = true;
  if (a->flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
    s->close_has_app_error_code = true;
    s->close_app_error_code = a->app_error_code;
  }
  /* A stream still waiting in @accept_queue holds on to what it received.
     Were the peer given its stream back now, it could open and close
     streams until the queue had used up our memory, so it gets the stream
     back only once the application has accepted this one
     (QUIC::Stream#_accepted). */
  if (s->accept_queued && !s->accepted) {
    s->peer_stream_held = true;
  } else {
    quic_conn_give_back_peer_stream(a->c->conn, a->stream_id);
  }
  rb_hash_delete(streams, LL2NUM(a->stream_id));
  return Qnil;
}

static int
quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t app_error_code, void *user_data,
                     void *stream_user_data)
{
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler) {
    /* The handler keeps no stream waiting for the application, so the peer
       gets its stream back at once. */
    quic_conn_give_back_peer_stream(conn, stream_id);
    int has_code = (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0;
    return c->handler->stream_close(c->handler_ud, stream_id, has_code, app_error_code) < 0
      ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
  }
  struct quic_stream_cb_args a = {
    .c = c, .stream_id = stream_id, .flags = flags, .app_error_code = app_error_code,
  };
  return quic_conn_protect(c, quic_stream_close_body, &a);
}

static VALUE
quic_stream_reset_body(VALUE arg)
{
  struct quic_stream_cb_args *a = (struct quic_stream_cb_args *)arg;
  VALUE stream = quic_conn_lookup_stream(a->c, a->stream_id);
  if (NIL_P(stream)) return Qnil;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->reset = true;
  s->close_app_error_code = a->app_error_code;
  s->close_has_app_error_code = true;
  return Qnil;
}

static int
quic_stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                     uint64_t app_error_code, void *user_data,
                     void *stream_user_data)
{
  (void)conn;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (c->handler) {
    return c->handler->stream_reset(c->handler_ud, stream_id, final_size, app_error_code) < 0
      ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
  }
  struct quic_stream_cb_args a = {.c = c, .stream_id = stream_id, .app_error_code = app_error_code};
  return quic_conn_protect(c, quic_stream_reset_body, &a);
}

/* The callbacks below matter only to a stream handler. Without one, the
   QUIC::Stream mode needs none of them. */

static int
quic_stream_stop_sending_cb(ngtcp2_conn *conn, int64_t stream_id,
                            uint64_t app_error_code, void *user_data,
                            void *stream_user_data)
{
  (void)conn;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler) return 0;
  return c->handler->stream_stop_sending(c->handler_ud, stream_id, app_error_code) < 0
    ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int
quic_extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t max_data, void *user_data,
                               void *stream_user_data)
{
  (void)conn;
  (void)max_data;
  (void)stream_user_data;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler) return 0;
  return c->handler->extend_max_stream_data(c->handler_ud, stream_id) < 0
    ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int
quic_extend_max_remote_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams,
                                       void *user_data)
{
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler) return 0;
  return c->handler->extend_max_remote_streams_bidi(c->handler_ud, max_streams) < 0
    ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int
quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  if (!c->handler) return 0;
  return c->handler->handshake_completed(c->handler_ud) < 0
    ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

void
quic_conn_fill_common_callbacks(ngtcp2_callbacks *callbacks)
{
  memset(callbacks, 0, sizeof(*callbacks));
  callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks->update_key = ngtcp2_crypto_update_key_cb;
  callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks->get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks->rand = quic_rand_cb;
  callbacks->get_new_connection_id2 = quic_get_new_connection_id_cb;
  callbacks->stream_open = quic_stream_open_cb;
  callbacks->recv_stream_data = quic_recv_stream_data_cb;
  callbacks->acked_stream_data_offset = quic_acked_stream_data_offset_cb;
  callbacks->stream_close = quic_stream_close_cb;
  callbacks->stream_reset = quic_stream_reset_cb;
  callbacks->stream_stop_sending = quic_stream_stop_sending_cb;
  callbacks->extend_max_stream_data = quic_extend_max_stream_data_cb;
  callbacks->extend_max_remote_streams_bidi = quic_extend_max_remote_streams_bidi_cb;
  callbacks->handshake_completed = quic_handshake_completed_cb;
}

/* Find the first stream in @streams that has either pending bytes or a
   pending FIN to flush. Phase 4 minimum: linear scan, take the first match
   (no round-robin). Sets *out_datav to the byte slice to send, *out_datavcnt
   to 0 or 1, *out_flags to NGTCP2_WRITE_STREAM_FLAG_FIN when applicable.
   Returns the stream's Ruby VALUE (or Qnil if no candidate). */
static VALUE
quic_conn_pick_send_stream(VALUE self, ngtcp2_vec *out_datav,
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

/* #write_pkt for the QUIC::Stream mode. If any stream has pending bytes or
   a pending FIN, route the packet through ngtcp2_conn_writev_stream so the
   stream data gets framed alongside connection-level frames. Falls back to
   conn-only when no stream is queued. Returns what ngtcp2 returned. */
static ngtcp2_ssize
quic_conn_write_pkt_streams(VALUE self, quic_conn_t *c, ngtcp2_path *path,
                            ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen)
{
  ngtcp2_vec datav;
  size_t datavcnt = 0;
  uint32_t writev_flags = 0;
  int64_t send_stream_id = -1;
  VALUE selected_stream = quic_conn_pick_send_stream(
    self, &datav, &datavcnt, &writev_flags, &send_stream_id);

  ngtcp2_ssize pdatalen = -1;
  ngtcp2_ssize n = ngtcp2_conn_writev_stream(
    c->conn, path, pi, dest, destlen, &pdatalen,
    writev_flags, send_stream_id, &datav, datavcnt, c->now);

  if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED && NIL_P(c->pending_exc)) {
    /* The stream's queued data is beyond what the peer's flow control lets
       through right now. Keep it queued and build the packet without it, so
       that ACKs and other frames still go out; the data follows once the
       peer extends its window (MAX_STREAM_DATA / MAX_DATA). */
    selected_stream = Qnil;
    datavcnt = 0;
    writev_flags = 0;
    pdatalen = -1;
    n = ngtcp2_conn_writev_stream(c->conn, path, pi, dest, destlen, &pdatalen,
                                  0, -1, NULL, 0, c->now);
  }

  if (n < 0 || !NIL_P(c->pending_exc)) return n;

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
  return n;
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
static ngtcp2_ssize
quic_conn_write_pkt_handler(quic_conn_t *c, ngtcp2_path *path, ngtcp2_pkt_info *pi,
                            uint8_t *dest, size_t destlen)
{
  const quic_ext_stream_handler *h = c->handler;
  for (;;) {
    int64_t sid = -1;
    int fin = 0;
    quic_ext_vec vec[QUIC_HANDLER_VECCNT];
    size_t nvec = 0;
    if (ngtcp2_conn_get_max_data_left2(c->conn) &&
        h->next_stream_data(c->handler_ud, &sid, &fin, vec, QUIC_HANDLER_VECCNT, &nvec) < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    ngtcp2_ssize ndatalen = -1;
    ngtcp2_ssize n = ngtcp2_conn_writev_stream(
      c->conn, path, pi, dest, destlen, &ndatalen,
      fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0, sid,
      (const ngtcp2_vec *)vec, nvec, c->now);
    if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      if (h->stream_blocked(c->handler_ud, sid) < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
      continue;
    }
    if (n == NGTCP2_ERR_STREAM_SHUT_WR) {
      if (h->stream_shut_write(c->handler_ud, sid) < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
      continue;
    }
    if (n < 0) return n;
    if (ndatalen >= 0 && h->stream_data_written(c->handler_ud, sid, (size_t)ndatalen) < 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return n;  /* 0: nothing to send */
  }
}

static VALUE
quic_conn_write_pkt(int argc, VALUE *argv, VALUE self)
{
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
      rb_str_modify_expand(buffer, (long)QUIC_WRITE_PKT_BUFLEN - RSTRING_LEN(buffer));
    }
  }

  ngtcp2_path_storage path_storage;
  ngtcp2_path_storage_zero(&path_storage);

  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  uint8_t *dest = (uint8_t *)RSTRING_PTR(buffer);
  size_t destlen = (size_t)QUIC_WRITE_PKT_BUFLEN;

  c->now = quic_now();
  ngtcp2_ssize n = c->handler
    ? quic_conn_write_pkt_handler(c, &path_storage.path, &pi, dest, destlen)
    : quic_conn_write_pkt_streams(self, c, &path_storage.path, &pi, dest, destlen);

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

NORETURN(static void quic_conn_raise_error(quic_conn_t *c, int rv));

/* Like quic_raise_ngtcp2_error, but for errors from read_pkt, where the TLS
   handshake runs: NGTCP2_ERR_CRYPTO carries the TLS alert this endpoint
   sent, and becomes CertificateVerifyFailed when the verifier rejected the
   peer. */
static void
quic_conn_raise_error(quic_conn_t *c, int rv)
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
  quic_conn_t *c;
  VALUE packet;
  ngtcp2_path path;
  ngtcp2_pkt_info pi;
};

static VALUE
quic_read_pkt_body(VALUE arg)
{
  struct quic_read_pkt_args *a = (struct quic_read_pkt_args *)arg;
  a->c->now = quic_now();
  int rv = ngtcp2_conn_read_pkt(a->c->conn, &a->path, &a->pi,
                                (const uint8_t *)RSTRING_PTR(a->packet),
                                (size_t)RSTRING_LEN(a->packet),
                                a->c->now);
  quic_conn_raise_pending(a->c);
  if (rv != 0) {
    /* NORETURN: longjmp passes through rb_ensure so unlock still fires. */
    quic_conn_raise_error(a->c, rv);
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
quic_conn_read_pkt(int argc, VALUE *argv, VALUE self)
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

  quic_conn_t *c = quic_conn_get(self);

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
quic_conn_handshake_completed_p(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  return ngtcp2_conn_get_handshake_completed2(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_conn_in_closing_period_p(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  return ngtcp2_conn_in_closing_period2(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_conn_in_draining_period_p(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  return ngtcp2_conn_in_draining_period2(c->conn) ? Qtrue : Qfalse;
}

static VALUE
quic_conn_expiry(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  ngtcp2_tstamp t = ngtcp2_conn_get_expiry2(c->conn);
  if (t == UINT64_MAX) return Qnil;
  return ULL2NUM((unsigned long long)t);
}

/* Caller is responsible for ordering with #read_pkt / #write_pkt:
   read_pkt or handle_expiry to advance ngtcp2 state, then write_pkt to flush. */
static VALUE
quic_conn_handle_expiry(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  c->now = quic_now();
  int rv = ngtcp2_conn_handle_expiry(c->conn, c->now);
  quic_conn_raise_pending(c);
  if (rv != 0) quic_raise_ngtcp2_error(rv);
  return Qnil;
}

/* QUIC::Stream objects exist only without a stream handler. */
static void
quic_conn_require_stream_mode(quic_conn_t *c)
{
  if (c->handler) {
    rb_raise(rb_eQUICErrorInvalidState, "the connection's streams belong to a C stream handler");
  }
}

static VALUE
quic_conn_open_bidi_stream(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  quic_conn_require_stream_mode(c);

  int64_t stream_id;
  int rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
  if (rv != 0) quic_raise_ngtcp2_error(rv);

  VALUE stream = quic_stream_new(stream_id, self);
  VALUE streams = rb_ivar_get(self, rb_intern("@streams"));
  rb_hash_aset(streams, LL2NUM(stream_id), stream);
  return stream;
}

static VALUE
quic_conn_open_uni_stream(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);
  quic_conn_require_stream_mode(c);

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
quic_conn_close_m(int argc, VALUE *argv, VALUE self)
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

  quic_conn_t *c = quic_conn_get(self);

  /* Idempotent: a subsequent #close after the conn already entered the
     closing/draining period does not emit another CONNECTION_CLOSE. */
  if (ngtcp2_conn_in_closing_period2(c->conn) ||
      ngtcp2_conn_in_draining_period2(c->conn)) {
    return Qnil;
  }

  VALUE sock = rb_ivar_get(self, rb_intern("@sock"));
  if (NIL_P(sock)) {
    rb_raise(rb_eQUICErrorNotBound, "%"PRIsVALUE"#bind(sock) has not been called",
             rb_obj_class(self));
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

void
quic_conn_define_shared_methods(VALUE klass)
{
  rb_define_method(klass, "write_pkt", quic_conn_write_pkt, -1);
  rb_define_method(klass, "read_pkt",  quic_conn_read_pkt,  -1);
  rb_define_method(klass, "expiry", quic_conn_expiry, 0);
  rb_define_method(klass, "handle_expiry", quic_conn_handle_expiry, 0);
  rb_define_method(klass, "handshake_completed?", quic_conn_handshake_completed_p, 0);
  rb_define_method(klass, "in_closing_period?", quic_conn_in_closing_period_p, 0);
  rb_define_method(klass, "in_draining_period?", quic_conn_in_draining_period_p, 0);
  rb_define_method(klass, "open_bidi_stream", quic_conn_open_bidi_stream, 0);
  rb_define_method(klass, "open_uni_stream", quic_conn_open_uni_stream, 0);
  rb_define_method(klass, "close", quic_conn_close_m, -1);
}
