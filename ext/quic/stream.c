#include "stream.h"
#include "connection_common.h"

#include <string.h>

VALUE rb_cQUICStream;

static void
quic_stream_free(void *ptr)
{
  xfree(ptr);
}

static size_t
quic_stream_size(const void *ptr)
{
  (void)ptr;
  return sizeof(quic_stream_t);
}

const rb_data_type_t quic_stream_data_type = {
  "QUIC::Stream",
  {NULL, quic_stream_free, quic_stream_size,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE
quic_stream_alloc(VALUE klass)
{
  quic_stream_t *s = ALLOC(quic_stream_t);
  memset(s, 0, sizeof(*s));
  return TypedData_Wrap_Struct(klass, &quic_stream_data_type, s);
}

VALUE
quic_stream_new(int64_t stream_id, VALUE owner)
{
  VALUE self = quic_stream_alloc(rb_cQUICStream);
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  s->stream_id = stream_id;

  rb_ivar_set(self, rb_intern("@id"), LL2NUM(stream_id));
  rb_ivar_set(self, rb_intern("@client"), owner);
  rb_ivar_set(self, rb_intern("@pending_chunks"), rb_ary_new());
  /* recv_buffer is a binary String; rb_str_buf_new returns ASCII-8BIT. */
  rb_ivar_set(self, rb_intern("@recv_buffer"), rb_str_buf_new(0));
  return self;
}

/* Append a binary copy of |data| to @pending_chunks and optionally set the
   fin_sent flag. Flow control is the caller's concern (#write blocks in
   quic_stream_write_m and #write_nonblock returns a partial byte count in
   quic_stream_write_nonblock_m). This helper is reached only after the
   caller has confirmed the bytes fit in the current send window, so it
   never raises QUIC::Error::WaitWritable on its own. */
static VALUE
quic_stream_enqueue(VALUE self, VALUE data, bool fin)
{
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  if (s->reset || s->closed) {
    rb_raise(rb_eQUICErrorStreamClosed, "stream is closed");
  }
  if (s->fin_sent) {
    rb_raise(rb_eQUICErrorStreamClosed, "stream FIN already sent");
  }

  Check_Type(data, T_STRING);
  long len = RSTRING_LEN(data);

  if (len > 0) {
    VALUE chunk = rb_str_new(RSTRING_PTR(data), len);
    /* rb_str_new returns ASCII-8BIT, so no encoding adjustment is needed.
       Force it explicitly to be defensive against future CRuby changes. */
    rb_enc_associate_index(chunk, rb_ascii8bit_encindex());
    VALUE pending = rb_ivar_get(self, rb_intern("@pending_chunks"));
    rb_ary_push(pending, chunk);
  }

  if (fin) {
    s->fin_sent = true;
  }

  return LONG2NUM(len);
}

static bool
quic_stream_fin_kwarg(int argc, VALUE *argv, VALUE *data)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "1:", data, &opts);
  if (NIL_P(opts)) return false;
  VALUE fin = rb_hash_lookup(opts, ID2SYM(rb_intern("fin")));
  return RTEST(fin);
}

/* Return the effective send window for this stream, capped by both the
   per-stream and the per-connection flow control limits ngtcp2 tracks. */
static uint64_t
quic_stream_window_left(VALUE client_v, quic_stream_t *s)
{
  ngtcp2_conn *conn = quic_conn_ptr(client_v);
  uint64_t stream_left = ngtcp2_conn_get_max_stream_data_left2(conn, s->stream_id);
  uint64_t conn_left = ngtcp2_conn_get_max_data_left2(conn);
  return stream_left < conn_left ? stream_left : conn_left;
}

/* Blocking write: block by repeatedly invoking #pump_once on the owning
   connection (@client) until the peer's flow control window has enough room
   for the full payload, then enqueue. IO#write-compatible: always queues all
   of `data`. Bare Streams (built via QUIC::Stream.allocate for unit tests,
   with @client = nil) skip the window check entirely. */
static VALUE
quic_stream_write_m(int argc, VALUE *argv, VALUE self)
{
  VALUE data;
  bool fin = quic_stream_fin_kwarg(argc, argv, &data);

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (NIL_P(client_v)) {
    return quic_stream_enqueue(self, data, fin);  /* bare-Stream test escape */
  }

  /* These will be re-validated by quic_stream_enqueue, but we need the
     length up-front to drive the window loop. */
  Check_Type(data, T_STRING);
  long needed = RSTRING_LEN(data);

  if (needed > 0) {
    quic_stream_t *s;
    TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
    /* Loop until the full payload would fit in the current window. pump_once
       raises QUIC::Error::NotBound if the connection has not been #bind'ed;
       that error surfaces verbatim. */
    while ((uint64_t)needed > quic_stream_window_left(client_v, s)) {
      rb_funcall(client_v, rb_intern("pump_once"), 0);
    }
  }

  return quic_stream_enqueue(self, data, fin);
}

/* Non-blocking write: enqueue at most `window_left` bytes from `data` and
   return the count actually queued. Raises QUIC::Error::WaitWritable if the
   window is zero and we have a non-empty payload to send. If only a partial
   prefix fits, FIN is NOT set on this call (caller re-issues with
   `fin: true` once the remainder is accepted) so we don't half-commit FIN.
   Bare Streams with @client = nil skip the window check entirely. */
static VALUE
quic_stream_write_nonblock_m(int argc, VALUE *argv, VALUE self)
{
  VALUE data;
  bool fin = quic_stream_fin_kwarg(argc, argv, &data);

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (NIL_P(client_v)) {
    return quic_stream_enqueue(self, data, fin);  /* bare-Stream test escape */
  }

  Check_Type(data, T_STRING);
  long needed = RSTRING_LEN(data);

  if (needed == 0) {
    /* fin-only call (or zero-byte write); no window concern. */
    return quic_stream_enqueue(self, data, fin);
  }

  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  uint64_t avail = quic_stream_window_left(client_v, s);

  if (avail == 0) {
    rb_raise(rb_eQUICErrorWaitWritable, "stream send window is full");
  }

  long take = ((uint64_t)needed <= avail) ? needed : (long)avail;
  bool effective_fin = (take == needed) ? fin : false;
  VALUE slice = (take == needed) ? data : rb_str_new(RSTRING_PTR(data), take);
  return quic_stream_enqueue(self, slice, effective_fin);
}

static VALUE
quic_stream_close_write_m(VALUE self)
{
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  if (s->fin_sent) return Qnil;  /* idempotent */
  VALUE empty = rb_str_new("", 0);
  rb_enc_associate_index(empty, rb_ascii8bit_encindex());
  quic_stream_enqueue(self, empty, true);
  return Qnil;
}

/* Pull up to |length| bytes from the head of @recv_buffer and return them
   as a new binary String. The buffer is mutated in place (left-shifted)
   to drop the returned prefix.

   - buffer empty + fin_received: raise EOFError (IO#read_nonblock semantics)
   - buffer empty + !fin_received: raise QUIC::Error::WaitReadable
   - buffer non-empty: return min(length, buffer.bytesize) bytes
*/
static VALUE
quic_stream_read_nonblock_m(VALUE self, VALUE length_v)
{
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  long length = NUM2LONG(length_v);
  if (length < 0) {
    rb_raise(rb_eArgError, "negative length %ld given", length);
  }

  VALUE buffer = rb_ivar_get(self, rb_intern("@recv_buffer"));
  long have = RSTRING_LEN(buffer);
  if (have == 0) {
    if (s->fin_received) {
      rb_raise(rb_eEOFError, "end of file reached");
    }
    rb_raise(rb_eQUICErrorWaitReadable, "no data available");
  }

  long take = (length < have) ? length : have;
  VALUE out = rb_str_new(RSTRING_PTR(buffer), take);
  rb_enc_associate_index(out, rb_ascii8bit_encindex());

  /* Drop the first |take| bytes from buffer by memmove + truncate. */
  if (take < have) {
    memmove(RSTRING_PTR(buffer), RSTRING_PTR(buffer) + take, (size_t)(have - take));
  }
  rb_str_set_len(buffer, have - take);

  return out;
}

static VALUE
quic_stream_eof_p(VALUE self)
{
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  VALUE buffer = rb_ivar_get(self, rb_intern("@recv_buffer"));
  return (RSTRING_LEN(buffer) == 0 && s->fin_received) ? Qtrue : Qfalse;
}

static VALUE
quic_stream_close_read_m(VALUE self)
{
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  ngtcp2_conn *conn = quic_conn_ptr(client_v);

  /* ngtcp2_conn_shutdown_stream_read sends STOP_SENDING. app_error_code 0
     since no QUIC-level error API is exposed yet. */
  int rv = ngtcp2_conn_shutdown_stream_read(conn, 0, s->stream_id, 0);
  if (rv != 0) quic_raise_ngtcp2_error(rv);
  return Qnil;
}

static VALUE
quic_stream_close_m(VALUE self)
{
  /* Send FIN (if not yet) then STOP_SENDING. Idempotent on each leg. */
  quic_stream_close_write_m(self);
  quic_stream_close_read_m(self);
  return Qnil;
}

/* Abort the send side of the stream with RESET_STREAM
   (ngtcp2_conn_shutdown_stream_write), carrying the given application error
   code (default 0). After #reset, #write / #write_nonblock raise
   QUIC::Error::StreamClosed because quic_stream_enqueue rejects a stream
   with s->reset set. The read side is untouched (use #close_read /
   #close for STOP_SENDING). Idempotent: a second #reset is a no-op.

   A bare Stream (@client == nil, used by unit-test fixtures) skips the
   ngtcp2 call and only flips s->reset, mirroring the #write / #close_write
   bare-Stream escapes. */
static VALUE
quic_stream_reset_m(int argc, VALUE *argv, VALUE self)
{
  VALUE error_code_v = Qnil;
  rb_scan_args(argc, argv, "01", &error_code_v);
  uint64_t error_code = NIL_P(error_code_v) ? 0 : NUM2ULL(error_code_v);

  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  if (s->reset) return Qnil;  /* idempotent */

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (NIL_P(client_v)) {
    s->reset = true;  /* bare Stream escape */
    return Qnil;
  }

  ngtcp2_conn *conn = quic_conn_ptr(client_v);
  int rv = ngtcp2_conn_shutdown_stream_write(conn, 0, s->stream_id, error_code);
  if (rv != 0) quic_raise_ngtcp2_error(rv);
  s->reset = true;
  return Qnil;
}

void
Init_quic_stream(VALUE rb_mQUICArg)
{
  rb_cQUICStream = rb_define_class_under(rb_mQUICArg, "Stream", rb_cObject);
  rb_define_alloc_func(rb_cQUICStream, quic_stream_alloc);
  rb_define_method(rb_cQUICStream, "write", quic_stream_write_m, -1);
  rb_define_method(rb_cQUICStream, "write_nonblock", quic_stream_write_nonblock_m, -1);
  rb_define_method(rb_cQUICStream, "close_write", quic_stream_close_write_m, 0);
  rb_define_method(rb_cQUICStream, "read_nonblock", quic_stream_read_nonblock_m, 1);
  rb_define_method(rb_cQUICStream, "eof?", quic_stream_eof_p, 0);
  rb_define_method(rb_cQUICStream, "close_read", quic_stream_close_read_m, 0);
  rb_define_method(rb_cQUICStream, "close", quic_stream_close_m, 0);
  rb_define_method(rb_cQUICStream, "reset", quic_stream_reset_m, -1);
  /* #read (blocking) and #initiator are defined in lib/quic/stream.rb. */
}
