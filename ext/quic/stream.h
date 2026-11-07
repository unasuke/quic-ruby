#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H 1

#include "connection_common.h"
#include "quic.h"

extern VALUE rb_cQUICStream;

void Init_quic_stream(VALUE rb_mQUICArg);

/* Internal helpers used by connection_common.c stream callbacks and
   write_pkt's stream-aware path. */

/* One write's bytes, kept until the peer acknowledges them. Outside the
   Ruby heap: ngtcp2 keeps pointers into data to retransmit from, and
   GC.compact moves an embedded String. */
typedef struct quic_send_chunk {
  struct quic_send_chunk *next;
  size_t len;
  uint8_t data[];
} quic_send_chunk;

typedef struct {
  /* The QUIC::Stream wrapping this struct, for the stream callbacks, which
     get the struct from ngtcp2's stream_user_data. It needs no mark, as it
     holds the struct; quic_stream_compact follows it when GC.compact moves
     it. */
  VALUE self;
  int64_t stream_id;
  /* The send buffer: what #write queued and the peer has not acknowledged,
     as chunks in stream order. Every offset below is a position in the
     stream. The buffer is freed only where ngtcp2 can no longer read it:
     as the peer acknowledges it, when the stream closes, and in dfree. */
  quic_send_chunk *send_head;
  quic_send_chunk *send_tail;
  /* The chunk holding the next byte to hand to ngtcp2 (sent_offset), and
     where in it; NULL once everything queued has been handed over. That
     chunk ends after sent_offset, which acked_offset never passes, so an
     acknowledgement never frees it. */
  quic_send_chunk *send_next;
  size_t send_next_off;
  uint64_t head_offset;   /* where send_head->data[0] sits */
  uint64_t queued_offset; /* just past the last byte queued */
  uint64_t sent_offset;   /* just past the last byte handed to ngtcp2 */
  uint64_t acked_offset;  /* just past the last byte acknowledged */
  /* What the chunks take from xmalloc, headers included; part of dsize. */
  size_t buffered;
  bool fin_received; /* recv_stream_data delivered FIN */
  bool fin_sent;     /* #write(fin: true) queued FIN */
  bool fin_flushed;  /* write_pkt actually wrote the FIN frame */
  bool reset;        /* stream_reset callback fired */
  bool closed;       /* stream_close callback fired */
  uint64_t close_app_error_code;
  bool close_has_app_error_code;
  /* The send side is shut (quic_stream_stop): the peer's STOP_SENDING
     arrived, #reset was called, ngtcp2 reported the send side shut while
     writing, or the stream closed. Nothing queued goes out any more,
     #write_pkt skips the stream, and what it had not sent no longer counts
     in quic_conn_t.stream_unsent. The send buffer stays until the stream
     closes: ngtcp2 may still hold pointers into it at this point
     (recv_stop_sending runs before it drops the stream's queued frames). */
  bool stopped;
  uint64_t stop_app_error_code; /* the STOP_SENDING's, 0 if none arrived */
  /* Set once a peer-initiated stream has been pushed onto the owning
     connection's @accept_queue, so recv_stream_data does not enqueue it
     again on subsequent data arrivals. */
  bool accept_queued;
  /* Set once #accept_stream has handed the stream to the application. */
  bool accepted;
  /* The stream closed while it waited in @accept_queue: the peer gets the
     stream it used up back when the stream is accepted. */
  bool peer_stream_held;
} quic_stream_t;

extern const rb_data_type_t quic_stream_data_type;

/* Allocate a new QUIC::Stream Ruby object for stream_id with a
   zero-initialized quic_stream_t, and set its ivars (@id / @client /
   @recv_buffer). @client is owner, the Client or Server the stream belongs
   to; the ivar keeps its name for both. */
VALUE quic_stream_new(int64_t stream_id, VALUE owner);

/* What s has to send next: the unsent part of the chunk at send_next in
   *datav (*datavcnt = 1), or nothing but a FIN (*datavcnt = 0). *flags gets
   NGTCP2_WRITE_STREAM_FLAG_FIN when the FIN goes with it, that is when the
   chunk is the last one queued. Returns false when s has nothing to send,
   which includes a stopped stream. */
bool quic_stream_next_send(const quic_stream_t *s, ngtcp2_vec *datav,
                           size_t *datavcnt, uint32_t *flags);

/* Account for a packet ngtcp2_conn_writev_stream built for c from what
   quic_stream_next_send offered: datalen bytes (0 for a FIN alone) with
   flags, of which ngtcp2 framed pdatalen, in a packet of n bytes. */
void quic_stream_sent(quic_conn_t *c, quic_stream_t *s, size_t datalen,
                      uint32_t flags, ngtcp2_ssize pdatalen, ngtcp2_ssize n);

/* Shut the send side of s, a stream of c (NULL for a bare Stream): nothing
   it has queued goes out any more. Does nothing the second time. */
void quic_stream_stop(quic_conn_t *c, quic_stream_t *s);

/* The peer acknowledged [offset, offset + datalen): free the chunks that
   end at or before offset + datalen. */
void quic_stream_release_acked(quic_stream_t *s, uint64_t offset,
                               uint64_t datalen);

/* Free the whole send buffer. Safe to call more than once. */
void quic_stream_free_send_buffer(quic_stream_t *s);

#endif /* QUIC_STREAM_H */
