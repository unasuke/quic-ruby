/* A test-only stream handler for quic.so's C function table (quic/ext.h):
   it sends every bidirectional stream back to the peer. It stands in for
   the http3 gem, which drives the same table with nghttp3.

   Received data is copied into chunks that stay put until the peer
   acknowledges them, since ngtcp2 needs sent stream data intact until then.
   Handler functions use malloc, not xmalloc, so that they never raise. */

#include <ruby.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "quic/ext.h"

#ifdef HAVE_RB_EXT_RESOLVE_SYMBOL

static const quic_ext_api *api;
static quic_ext_get_api_fn get_api;

typedef struct {
  uint8_t *base;
  size_t len;
} echo_chunk;

typedef struct echo_stream {
  int64_t id;
  echo_chunk *chunks;  /* received data, oldest first, until acknowledged */
  size_t nchunks;
  size_t cap;
  uint64_t shifted;    /* stream offset where chunks[0] starts */
  uint64_t received;   /* stream offset of the end of what was received */
  uint64_t sent;       /* bytes ngtcp2 has written */
  uint64_t acked;
  bool fin_received;
  bool fin_requested;  /* next_stream_data asked for FIN with the data up to received */
  bool fin_sent;
  bool blocked;
  bool shut;
  struct echo_stream *next;
} echo_stream;

typedef struct {
  VALUE conn;
  quic_ext_conn *qc;
  echo_stream *streams;
  long handshakes;
  long closed_streams;
  uint64_t max_remote_streams_bidi;
} echo_handler;

static void
echo_stream_free(echo_stream *s)
{
  for (size_t i = 0; i < s->nchunks; i++) free(s->chunks[i].base);
  free(s->chunks);
  free(s);
}

static echo_stream *
echo_find_stream(echo_handler *h, int64_t id, bool create)
{
  for (echo_stream *s = h->streams; s != NULL; s = s->next) {
    if (s->id == id) return s;
  }
  if (!create) return NULL;
  echo_stream *s = calloc(1, sizeof(*s));
  if (s == NULL) return NULL;
  s->id = id;
  s->next = h->streams;
  h->streams = s;
  return s;
}

static int
echo_recv_stream_data(void *ud, int64_t id, const uint8_t *data, size_t len, int fin,
                      uint64_t ts, size_t *consumed)
{
  (void)ts;
  echo_handler *h = ud;
  echo_stream *s = echo_find_stream(h, id, true);
  if (s == NULL) return -1;
  if (len > 0) {
    if (s->nchunks == s->cap) {
      size_t cap = s->cap ? s->cap * 2 : 8;
      echo_chunk *chunks = realloc(s->chunks, cap * sizeof(*chunks));
      if (chunks == NULL) return -1;
      s->chunks = chunks;
      s->cap = cap;
    }
    uint8_t *copy = malloc(len);
    if (copy == NULL) return -1;
    memcpy(copy, data, len);
    s->chunks[s->nchunks++] = (echo_chunk){copy, len};
    s->received += len;
  }
  if (fin) s->fin_received = true;
  *consumed = len;
  return 0;
}

static int
echo_next_stream_data(void *ud, int64_t *id, int *fin, quic_ext_vec *vecs, size_t cap,
                      size_t *nvecs)
{
  echo_handler *h = ud;
  *id = -1;
  *fin = 0;
  *nvecs = 0;
  for (echo_stream *s = h->streams; s != NULL; s = s->next) {
    if (s->blocked || s->shut || s->fin_sent) continue;
    if (s->sent == s->received && !s->fin_received) continue;

    uint64_t start = s->shifted;
    uint64_t covered = s->sent;
    size_t n = 0;
    for (size_t i = 0; i < s->nchunks && n < cap; i++) {
      uint64_t end = start + s->chunks[i].len;
      if (end > covered) {
        size_t skip = (size_t)(covered - start);
        vecs[n++] = (quic_ext_vec){s->chunks[i].base + skip, s->chunks[i].len - skip};
        covered = end;
      }
      start = end;
    }
    *id = s->id;
    *nvecs = n;
    s->fin_requested = s->fin_received && covered == s->received;
    *fin = s->fin_requested;
    return 0;
  }
  return 0;
}

static int
echo_stream_data_written(void *ud, int64_t id, size_t n)
{
  echo_stream *s = echo_find_stream(ud, id, false);
  if (s == NULL) return 0;
  s->sent += n;
  if (s->fin_requested && s->sent == s->received) s->fin_sent = true;
  s->fin_requested = false;
  return 0;
}

static int
echo_stream_blocked(void *ud, int64_t id)
{
  echo_stream *s = echo_find_stream(ud, id, false);
  if (s != NULL) s->blocked = true;
  return 0;
}

static int
echo_stream_shut_write(void *ud, int64_t id)
{
  echo_stream *s = echo_find_stream(ud, id, false);
  if (s != NULL) s->shut = true;
  return 0;
}

static int
echo_acked_stream_data(void *ud, int64_t id, uint64_t n)
{
  echo_stream *s = echo_find_stream(ud, id, false);
  if (s == NULL) return 0;
  s->acked += n;
  size_t drop = 0;
  while (drop < s->nchunks && s->shifted + s->chunks[drop].len <= s->acked) {
    s->shifted += s->chunks[drop].len;
    free(s->chunks[drop].base);
    drop++;
  }
  memmove(s->chunks, s->chunks + drop, (s->nchunks - drop) * sizeof(*s->chunks));
  s->nchunks -= drop;
  return 0;
}

static int
echo_extend_max_stream_data(void *ud, int64_t id)
{
  echo_stream *s = echo_find_stream(ud, id, false);
  if (s != NULL) s->blocked = false;
  return 0;
}

static int
echo_extend_max_remote_streams_bidi(void *ud, uint64_t max)
{
  echo_handler *h = ud;
  h->max_remote_streams_bidi = max;
  return 0;
}

static int
echo_stream_stop_sending(void *ud, int64_t id, uint64_t app_error_code)
{
  (void)app_error_code;
  echo_stream *s = echo_find_stream(ud, id, false);
  if (s != NULL) s->shut = true;
  return 0;
}

static int
echo_stream_reset(void *ud, int64_t id, uint64_t final_size, uint64_t app_error_code)
{
  (void)ud;
  (void)id;
  (void)final_size;
  (void)app_error_code;
  return 0;
}

static int
echo_stream_close(void *ud, int64_t id, int has_code, uint64_t app_error_code)
{
  (void)has_code;
  (void)app_error_code;
  echo_handler *h = ud;
  for (echo_stream **p = &h->streams; *p != NULL; p = &(*p)->next) {
    if ((*p)->id == id) {
      echo_stream *s = *p;
      *p = s->next;
      echo_stream_free(s);
      break;
    }
  }
  h->closed_streams++;
  return 0;
}

static int
echo_handshake_completed(void *ud)
{
  echo_handler *h = ud;
  h->handshakes++;
  return 0;
}

static const quic_ext_stream_handler echo_stream_handler = {
  .size = sizeof(quic_ext_stream_handler),
  .recv_stream_data = echo_recv_stream_data,
  .next_stream_data = echo_next_stream_data,
  .stream_data_written = echo_stream_data_written,
  .stream_blocked = echo_stream_blocked,
  .stream_shut_write = echo_stream_shut_write,
  .acked_stream_data = echo_acked_stream_data,
  .extend_max_stream_data = echo_extend_max_stream_data,
  .extend_max_remote_streams_bidi = echo_extend_max_remote_streams_bidi,
  .stream_stop_sending = echo_stream_stop_sending,
  .stream_reset = echo_stream_reset,
  .stream_close = echo_stream_close,
  .handshake_completed = echo_handshake_completed,
};

/* QUICExtEcho::Handler. The connection marks this object as the handler's
   owner, and this object marks the connection back. The dfree never
   touches the connection: the two may be collected in either order. */

static void
echo_handler_mark(void *ptr)
{
  echo_handler *h = ptr;
  rb_gc_mark_movable(h->conn);
}

static void
echo_handler_free(void *ptr)
{
  echo_handler *h = ptr;
  while (h->streams != NULL) {
    echo_stream *s = h->streams;
    h->streams = s->next;
    echo_stream_free(s);
  }
  xfree(h);
}

static void
echo_handler_compact(void *ptr)
{
  echo_handler *h = ptr;
  h->conn = rb_gc_location(h->conn);
}

static const rb_data_type_t echo_handler_type = {
  "QUICExtEcho::Handler",
  {echo_handler_mark, echo_handler_free, NULL, echo_handler_compact,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

static echo_handler *
echo_handler_get(VALUE self)
{
  echo_handler *h;
  TypedData_Get_Struct(self, echo_handler, &echo_handler_type, h);
  return h;
}

/* Handler.attach(conn): register an echo handler on conn. Raises
   RuntimeError carrying the QUIC_EXT_ERR_* code when quic.so refuses. */
static VALUE
echo_handler_s_attach(VALUE klass, VALUE conn)
{
  quic_ext_conn *qc = api->conn_get(conn);
  echo_handler *h;
  VALUE self = TypedData_Make_Struct(klass, echo_handler, &echo_handler_type, h);
  h->conn = conn;
  h->qc = qc;
  int rv = api->set_stream_handler(qc, &echo_stream_handler, h, self);
  if (rv != 0) rb_raise(rb_eRuntimeError, "set_stream_handler failed: %d", rv);
  return self;
}

static VALUE
echo_handler_handshakes(VALUE self)
{
  return LONG2NUM(echo_handler_get(self)->handshakes);
}

static VALUE
echo_handler_closed_streams(VALUE self)
{
  return LONG2NUM(echo_handler_get(self)->closed_streams);
}

static VALUE
echo_handler_max_remote_streams_bidi(VALUE self)
{
  return ULL2NUM(echo_handler_get(self)->max_remote_streams_bidi);
}

static VALUE
echo_handler_local_max_streams_bidi(VALUE self)
{
  return ULL2NUM(api->local_max_streams_bidi(echo_handler_get(self)->qc));
}

/* QUICExtEcho.load_api(major): whether quic_ext_get_api hands out a table
   for that major version. */
static VALUE
echo_s_load_api(VALUE mod, VALUE major)
{
  (void)mod;
  return get_api(NUM2UINT(major)) != NULL ? Qtrue : Qfalse;
}

#endif /* HAVE_RB_EXT_RESOLVE_SYMBOL */

RUBY_FUNC_EXPORTED void
Init_quic_ext_echo(void)
{
  VALUE mod = rb_define_module("QUICExtEcho");
#ifdef HAVE_RB_EXT_RESOLVE_SYMBOL
  rb_require("quic");
  get_api = (quic_ext_get_api_fn)rb_ext_resolve_symbol("quic/quic", "quic_ext_get_api");
  if (get_api == NULL) rb_raise(rb_eLoadError, "quic_ext_get_api not found in quic/quic");
  api = get_api(QUIC_EXT_ABI_MAJOR);
  if (api == NULL) rb_raise(rb_eLoadError, "quic.so offers no ABI %d table", QUIC_EXT_ABI_MAJOR);

  rb_define_const(mod, "AVAILABLE", Qtrue);
  rb_define_singleton_method(mod, "load_api", echo_s_load_api, 1);
  VALUE handler = rb_define_class_under(mod, "Handler", rb_cObject);
  rb_undef_alloc_func(handler);
  rb_define_singleton_method(handler, "attach", echo_handler_s_attach, 1);
  rb_define_method(handler, "handshakes", echo_handler_handshakes, 0);
  rb_define_method(handler, "closed_streams", echo_handler_closed_streams, 0);
  rb_define_method(handler, "max_remote_streams_bidi", echo_handler_max_remote_streams_bidi, 0);
  rb_define_method(handler, "local_max_streams_bidi", echo_handler_local_max_streams_bidi, 0);
#else
  rb_define_const(mod, "AVAILABLE", Qfalse);
#endif
}
