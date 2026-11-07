#include "stream.h"
#include "connection_common.h"

#include <string.h>

VALUE rb_cQUICStream;

void quic_stream_free_send_buffer(quic_stream_t *s) {
  quic_send_chunk *chunk = s->send_head;
  while (chunk != NULL) {
    quic_send_chunk *next = chunk->next;
    xfree(chunk);
    chunk = next;
  }
  s->send_head = NULL;
  s->send_tail = NULL;
  s->send_next = NULL;
  s->send_next_off = 0;
  s->buffered = 0;
}

/* Touches neither the connection nor any Ruby object: the connection may
   have been freed first, in the same GC. */
static void quic_stream_free(void *ptr) {
  quic_stream_free_send_buffer((quic_stream_t *)ptr);
  xfree(ptr);
}

static size_t quic_stream_size(const void *ptr) {
  return sizeof(quic_stream_t) + ((const quic_stream_t *)ptr)->buffered;
}

static void quic_stream_compact(void *ptr) {
  quic_stream_t *s = (quic_stream_t *)ptr;
  s->self = rb_gc_location(s->self);
}

const rb_data_type_t quic_stream_data_type = {
    "QUIC::Stream",
    {
        NULL,
        quic_stream_free,
        quic_stream_size,
        quic_stream_compact,
    },
    NULL,
    NULL,
    RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE quic_stream_alloc(VALUE klass) {
  quic_stream_t *s = ALLOC(quic_stream_t);
  memset(s, 0, sizeof(*s));
  VALUE self = TypedData_Wrap_Struct(klass, &quic_stream_data_type, s);
  s->self = self;
  return self;
}

VALUE
quic_stream_new(int64_t stream_id, VALUE owner) {
  VALUE self = quic_stream_alloc(rb_cQUICStream);
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  s->stream_id = stream_id;

  rb_ivar_set(self, rb_intern("@id"), LL2NUM(stream_id));
  rb_ivar_set(self, rb_intern("@client"), owner);
  /* recv_buffer is a binary String; rb_str_buf_new returns ASCII-8BIT. */
  rb_ivar_set(self, rb_intern("@recv_buffer"), rb_str_buf_new(0));
  return self;
}

/* Raise QUIC::Error::StreamClosed if nothing more can be written to the
   stream: it was reset or has closed, or the peer sent STOP_SENDING. */
static void quic_stream_check_writable(quic_stream_t *s) {
  if (s->reset || s->closed) {
    rb_raise(rb_eQUICErrorStreamClosed, "stream is closed");
  }
  if (s->stopped) {
    rb_raise(rb_eQUICErrorStreamClosed,
             "the peer asked to stop sending (error code %llu)",
             (unsigned long long)s->stop_app_error_code);
  }
}

/* Append a copy of |data| to the send buffer as one chunk, and optionally
   set the fin_sent flag. Flow control is the caller's concern (#write
   blocks in quic_stream_write_m and #write_nonblock returns a partial byte
   count in quic_stream_write_nonblock_m). This helper is reached only after
   the caller has confirmed the bytes fit in the current send window, so it
   never raises QUIC::Error::WaitWritable on its own. */
static VALUE quic_stream_enqueue(VALUE self, VALUE data, bool fin) {
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  quic_stream_check_writable(s);
  if (s->fin_sent) {
    rb_raise(rb_eQUICErrorStreamClosed, "stream FIN already sent");
  }

  Check_Type(data, T_STRING);
  long len = RSTRING_LEN(data);

  if (len > 0) {
    /* len is a long, so the header cannot overflow size_t. */
    size_t size = offsetof(quic_send_chunk, data) + (size_t)len;
    quic_send_chunk *chunk = (quic_send_chunk *)xmalloc(size);
    chunk->next = NULL;
    chunk->len = (size_t)len;
    memcpy(chunk->data, RSTRING_PTR(data), (size_t)len);
    if (s->send_tail != NULL) {
      s->send_tail->next = chunk;
    } else {
      s->send_head = chunk;
      s->head_offset = s->queued_offset;
    }
    s->send_tail = chunk;
    if (s->send_next == NULL) {
      s->send_next = chunk;
      s->send_next_off = 0;
    }
    s->queued_offset += (uint64_t)len;
    s->buffered += size;
  }

  if (fin) {
    s->fin_sent = true;
  }

  return LONG2NUM(len);
}

static bool quic_stream_fin_kwarg(int argc, VALUE *argv, VALUE *data) {
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "1:", data, &opts);
  if (NIL_P(opts))
    return false;
  VALUE fin = rb_hash_lookup(opts, ID2SYM(rb_intern("fin")));
  return RTEST(fin);
}

/* Return the effective send window for this stream: the smaller of the
   per-stream and the per-connection flow control limits ngtcp2 tracks, less
   the bytes already queued but not yet handed to ngtcp2. ngtcp2 only counts
   what it has sent, so without the subtraction a run of writes could queue
   far more than the peer allows. Callers check the stream is writable
   first. */
static uint64_t quic_stream_window_left(VALUE client_v, quic_stream_t *s) {
  ngtcp2_conn *conn = quic_conn_ptr(client_v);
  uint64_t stream_left =
      ngtcp2_conn_get_max_stream_data_left2(conn, s->stream_id);
  uint64_t conn_left = ngtcp2_conn_get_max_data_left2(conn);
  uint64_t left = stream_left < conn_left ? stream_left : conn_left;

  uint64_t unsent = s->queued_offset - s->sent_offset;
  return left > unsent ? left - unsent : 0;
}

bool quic_stream_next_send(const quic_stream_t *s, ngtcp2_vec *datav,
                           size_t *datavcnt, uint32_t *flags) {
  if (s->stopped || s->fin_flushed)
    return false;

  if (s->send_next != NULL) {
    datav->base = s->send_next->data + s->send_next_off;
    datav->len = s->send_next->len - s->send_next_off;
    *datavcnt = 1;
    /* FIN goes with the last chunk only if ngtcp2 frames all of it; when
       it encodes less, FIN is not flushed and the next call retries. */
    *flags = (s->fin_sent && s->send_next == s->send_tail)
                 ? NGTCP2_WRITE_STREAM_FLAG_FIN
                 : 0;
    return true;
  }

  if (s->fin_sent) {
    /* No data to send but a pending FIN-only frame. */
    datav->base = NULL;
    datav->len = 0;
    *datavcnt = 0;
    *flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
    return true;
  }
  return false;
}

void quic_stream_sent(quic_stream_t *s, size_t datalen, uint32_t flags,
                      ngtcp2_ssize pdatalen, ngtcp2_ssize n) {
  if (pdatalen > 0) {
    s->sent_offset += (uint64_t)pdatalen;
    s->send_next_off += (size_t)pdatalen;
    /* Leave send_next on no fully handed over chunk: an acknowledgement
       of all that was sent would free it under us. */
    if (s->send_next_off == s->send_next->len) {
      s->send_next = s->send_next->next;
      s->send_next_off = 0;
    }
    /* FIN is only actually written when all requested data fits in the
       frame (see ngtcp2 docs on NGTCP2_WRITE_STREAM_FLAG_FIN). */
    if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) && (size_t)pdatalen == datalen)
      s->fin_flushed = true;
  } else if (datalen == 0 && n > 0 && (flags & NGTCP2_WRITE_STREAM_FLAG_FIN)) {
    /* FIN-only packet (no data) was successfully written. */
    s->fin_flushed = true;
  }
}

void quic_stream_release_acked(quic_stream_t *s, uint64_t offset,
                               uint64_t datalen) {
  /* ngtcp2 reports the acknowledged ranges of a stream in order and
     without overlap; datalen is 0 only for a FIN alone. */
  s->acked_offset = offset + datalen;
  while (s->send_head != NULL &&
         s->head_offset + s->send_head->len <= s->acked_offset) {
    quic_send_chunk *chunk = s->send_head;
    s->head_offset += chunk->len;
    s->send_head = chunk->next;
    if (s->send_head == NULL)
      s->send_tail = NULL;
    s->buffered -= offsetof(quic_send_chunk, data) + chunk->len;
    xfree(chunk);
  }
}

/* Blocking write: block by repeatedly invoking #pump_once on the owning
   connection (@client) until the peer's flow control window has enough room
   for the full payload, then enqueue. IO#write-compatible: always queues all
   of `data`. A window that can no longer open, because the peer sent
   STOP_SENDING or the stream ended meanwhile, raises
   QUIC::Error::StreamClosed. Bare Streams (built via QUIC::Stream.allocate
   for unit tests, with @client = nil) skip the window check entirely. */
static VALUE quic_stream_write_m(int argc, VALUE *argv, VALUE self) {
  VALUE data;
  bool fin = quic_stream_fin_kwarg(argc, argv, &data);

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (NIL_P(client_v)) {
    return quic_stream_enqueue(self, data, fin); /* bare-Stream test escape */
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
    quic_stream_check_writable(s);
    while ((uint64_t)needed > quic_stream_window_left(client_v, s)) {
      rb_funcall(client_v, rb_intern("pump_once"), 0);
      quic_stream_check_writable(s);
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
static VALUE quic_stream_write_nonblock_m(int argc, VALUE *argv, VALUE self) {
  VALUE data;
  bool fin = quic_stream_fin_kwarg(argc, argv, &data);

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (NIL_P(client_v)) {
    return quic_stream_enqueue(self, data, fin); /* bare-Stream test escape */
  }

  Check_Type(data, T_STRING);
  long needed = RSTRING_LEN(data);

  if (needed == 0) {
    /* fin-only call (or zero-byte write); no window concern. */
    return quic_stream_enqueue(self, data, fin);
  }

  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  /* Before the window: a stream that cannot be written to never gets one. */
  quic_stream_check_writable(s);
  uint64_t avail = quic_stream_window_left(client_v, s);

  if (avail == 0) {
    rb_raise(rb_eQUICErrorWaitWritable, "stream send window is full");
  }

  long take = ((uint64_t)needed <= avail) ? needed : (long)avail;
  bool effective_fin = (take == needed) ? fin : false;
  VALUE slice = (take == needed) ? data : rb_str_new(RSTRING_PTR(data), take);
  return quic_stream_enqueue(self, slice, effective_fin);
}

static VALUE quic_stream_close_write_m(VALUE self) {
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  if (s->fin_sent)
    return Qnil; /* idempotent */
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
static VALUE quic_stream_read_nonblock_m(VALUE self, VALUE length_v) {
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
    memmove(RSTRING_PTR(buffer), RSTRING_PTR(buffer) + take,
            (size_t)(have - take));
  }
  rb_str_set_len(buffer, have - take);

  /* The application has consumed |take| bytes, so give the peer that much
     more stream and connection credit. Without this the peer stops sending
     once initial_max_data / initial_max_stream_data are used up. A stream
     ngtcp2 has already forgotten is ignored (the call returns 0), but the
     connection window still grows. Bare Streams have no connection. */
  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (!NIL_P(client_v)) {
    ngtcp2_conn *conn = quic_conn_ptr(client_v);
    int rv = ngtcp2_conn_extend_max_stream_offset(conn, s->stream_id,
                                                  (uint64_t)take);
    if (rv != 0)
      quic_raise_ngtcp2_error(rv);
    ngtcp2_conn_extend_max_offset(conn, (uint64_t)take);
  }

  return out;
}

static VALUE quic_stream_eof_p(VALUE self) {
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  VALUE buffer = rb_ivar_get(self, rb_intern("@recv_buffer"));
  return (RSTRING_LEN(buffer) == 0 && s->fin_received) ? Qtrue : Qfalse;
}

/* True once the stream is fully closed: both directions have finished (FIN
   or reset) and everything sent has been acknowledged. Stays false if the
   connection closes first, since ngtcp2 does not report stream closure then.
   Keeps returning true after the stream has left the connection's @streams.
   A bare Stream is never closed. */
static VALUE quic_stream_closed_p(VALUE self) {
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  return s->closed ? Qtrue : Qfalse;
}

static VALUE quic_stream_close_read_m(VALUE self) {
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  ngtcp2_conn *conn = quic_conn_ptr(client_v);

  /* ngtcp2_conn_shutdown_stream_read sends STOP_SENDING. app_error_code 0
     since no QUIC-level error API is exposed yet. */
  int rv = ngtcp2_conn_shutdown_stream_read(conn, 0, s->stream_id, 0);
  if (rv != 0)
    quic_raise_ngtcp2_error(rv);
  return Qnil;
}

static VALUE quic_stream_close_m(VALUE self) {
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
static VALUE quic_stream_reset_m(int argc, VALUE *argv, VALUE self) {
  VALUE error_code_v = Qnil;
  rb_scan_args(argc, argv, "01", &error_code_v);
  uint64_t error_code = NIL_P(error_code_v) ? 0 : NUM2ULL(error_code_v);

  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);

  if (s->reset)
    return Qnil; /* idempotent */

  VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
  if (NIL_P(client_v)) {
    s->reset = true; /* bare Stream escape */
    return Qnil;
  }

  ngtcp2_conn *conn = quic_conn_ptr(client_v);
  int rv = ngtcp2_conn_shutdown_stream_write(conn, 0, s->stream_id, error_code);
  if (rv != 0)
    quic_raise_ngtcp2_error(rv);
  s->reset = true;
  return Qnil;
}

/* Called by #accept_stream / #accept_stream_nonblock for the stream they
   take off @accept_queue. A stream that closed while it waited there gives
   the peer back the stream it used up now (see quic_stream_close_body). */
static VALUE quic_stream_accepted_m(VALUE self) {
  quic_stream_t *s;
  TypedData_Get_Struct(self, quic_stream_t, &quic_stream_data_type, s);
  s->accepted = true;
  if (s->peer_stream_held) {
    s->peer_stream_held = false;
    VALUE client_v = rb_ivar_get(self, rb_intern("@client"));
    if (!NIL_P(client_v)) {
      quic_conn_give_back_peer_stream(quic_conn_ptr(client_v), s->stream_id);
    }
  }
  return Qnil;
}

void Init_quic_stream(VALUE rb_mQUICArg) {
  rb_cQUICStream = rb_define_class_under(rb_mQUICArg, "Stream", rb_cObject);
  rb_define_alloc_func(rb_cQUICStream, quic_stream_alloc);
  rb_define_method(rb_cQUICStream, "write", quic_stream_write_m, -1);
  rb_define_method(rb_cQUICStream, "write_nonblock",
                   quic_stream_write_nonblock_m, -1);
  rb_define_method(rb_cQUICStream, "close_write", quic_stream_close_write_m, 0);
  rb_define_method(rb_cQUICStream, "read_nonblock", quic_stream_read_nonblock_m,
                   1);
  rb_define_method(rb_cQUICStream, "eof?", quic_stream_eof_p, 0);
  rb_define_method(rb_cQUICStream, "closed?", quic_stream_closed_p, 0);
  rb_define_method(rb_cQUICStream, "close_read", quic_stream_close_read_m, 0);
  rb_define_method(rb_cQUICStream, "close", quic_stream_close_m, 0);
  rb_define_method(rb_cQUICStream, "reset", quic_stream_reset_m, -1);
  rb_define_private_method(rb_cQUICStream, "_accepted", quic_stream_accepted_m,
                           0);
  /* #read (blocking) and #initiator are defined in lib/quic/stream.rb. */
}
