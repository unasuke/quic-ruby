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
  /* After ptls_free: the ptls_t references verify_cert, sign_cert and the
     certificate list through tls_ctx. */
  if (c->verify_cert_initialized) ptls_openssl_dispose_verify_certificate(&c->verify_cert);
  if (c->sign_cert_initialized) ptls_openssl_dispose_sign_certificate(&c->sign_cert);
  /* picotls malloc()ed the list and each entry, so free(), not xfree(). */
  if (c->tls_ctx.certificates.list != NULL) {
    for (size_t i = 0; i < c->tls_ctx.certificates.count; i++) free(c->tls_ctx.certificates.list[i].base);
    free(c->tls_ctx.certificates.list);
  }
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

/* GC.compact may relocate the owner connection object. Follow it so the
   void* user_data ngtcp2 callbacks receive (which equals this struct,
   stored inside owner) keeps resolving @streams / @accept_queue. The
   raw ngtcp2/picotls pointers are outside Ruby's heap and are left alone. */
static void
quic_conn_compact(void *ptr)
{
  quic_conn_t *c = (quic_conn_t *)ptr;
  c->owner = rb_gc_location(c->owner);
}

const rb_data_type_t quic_conn_data_type = {
  "QUIC::Connection",
  {NULL, quic_conn_free, quic_conn_size, quic_conn_compact,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

VALUE
quic_conn_alloc(VALUE klass)
{
  quic_conn_t *c = ALLOC(quic_conn_t);
  memset(c, 0, sizeof(*c));
  return TypedData_Wrap_Struct(klass, &quic_conn_data_type, c);
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

/* Copy the ALPN list into memory owned by c: picotls keeps the pointers for
   the whole handshake, so ALLOCA_N would not survive. An empty list leaves
   c->alpn NULL, which a client sends as no ALPN extension at all. */
void
quic_conn_copy_alpn(quic_conn_t *c, VALUE settings_v)
{
  VALUE alpn_ary = rb_funcall(settings_v, rb_intern("alpn"), 0);
  Check_Type(alpn_ary, T_ARRAY);
  long n_alpn = RARRAY_LEN(alpn_ary);
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

/* ngtcp2 stream callbacks. Each returns 0 on success or
   NGTCP2_ERR_CALLBACK_FAILURE on Ruby-side errors. We assume rb_str_buf_cat /
   rb_ary_* won't raise in normal operation (allocation failures aside, which
   would abort the process anyway), so we don't wrap in rb_protect for now. */

static int
quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  (void)conn;
  quic_conn_t *c = (quic_conn_t *)user_data;
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  if (!NIL_P(rb_hash_aref(streams, LL2NUM(stream_id)))) {
    return 0;  /* already known (opened by this endpoint) */
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
  quic_conn_t *c = (quic_conn_t *)user_data;
  VALUE stream = quic_conn_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);

  /* Surface peer-initiated streams to #accept_stream. The low stream-id bit
     marks the initiator (0 == client, 1 == server), so a client queues the
     odd ids and a server the even ones. Push once, on first data arrival,
     then mark so later data does not re-enqueue. */
  bool peer_initiated = c->is_server ? !(stream_id & 0x01) : (stream_id & 0x01);
  if (!s->accept_queued && peer_initiated) {
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
  quic_conn_t *c = (quic_conn_t *)user_data;
  VALUE stream = quic_conn_lookup_stream(c, stream_id);
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
  quic_conn_t *c = (quic_conn_t *)user_data;
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
  quic_conn_t *c = (quic_conn_t *)user_data;
  VALUE stream = quic_conn_lookup_stream(c, stream_id);
  if (NIL_P(stream)) return 0;

  quic_stream_t *s;
  TypedData_Get_Struct(stream, quic_stream_t, &quic_stream_data_type, s);
  s->reset = true;
  s->close_app_error_code = app_error_code;
  s->close_has_app_error_code = true;
  return 0;
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

  /* Stream-aware path: if any stream has pending bytes or a pending FIN,
     route the packet through ngtcp2_conn_writev_stream so the stream data
     gets framed alongside connection-level frames. Falls back to conn-only
     when no stream is queued. */
  ngtcp2_vec datav;
  size_t datavcnt = 0;
  uint32_t writev_flags = 0;
  int64_t send_stream_id = -1;
  VALUE selected_stream = quic_conn_pick_send_stream(
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
  int rv = ngtcp2_conn_read_pkt(a->c->conn, &a->path, &a->pi,
                                (const uint8_t *)RSTRING_PTR(a->packet),
                                (size_t)RSTRING_LEN(a->packet),
                                quic_now());
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
  int rv = ngtcp2_conn_handle_expiry(c->conn, quic_now());
  if (rv != 0) quic_raise_ngtcp2_error(rv);
  return Qnil;
}

static VALUE
quic_conn_open_bidi_stream(VALUE self)
{
  quic_conn_t *c = quic_conn_get(self);

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
