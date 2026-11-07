#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H 1

#include "connection_common.h"
#include "quic.h"

extern VALUE rb_cQUICStream;

void Init_quic_stream(VALUE rb_mQUICArg);

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

/* What a connection without a stream handler does with its streams, as
   QUIC::Streams. connection_common.c hands its ngtcp2 stream callbacks and
   #write_pkt here, and keeps only the choice between this and the
   handler. */

/* Make a QUIC::Stream for stream_id, a stream #open_bidi_stream or
   #open_uni_stream has just opened on the connection self (wrapping c),
   and register it. Returns the Stream. */
VALUE quic_stream_open_local(VALUE self, quic_conn_t *c, int64_t stream_id);

/* The ngtcp2 stream callbacks. s is the stream's stream_user_data: NULL for
   a stream whose QUIC::Stream could not be made, which they ignore. Those
   returning int return 0, or NGTCP2_ERR_CALLBACK_FAILURE when Ruby code
   raised; the exception waits in c->pending_exc. */
int quic_stream_on_open(quic_conn_t *c, int64_t stream_id);
int quic_stream_on_recv_data(quic_conn_t *c, quic_stream_t *s, uint32_t flags,
                             const uint8_t *data, size_t datalen);
void quic_stream_on_acked(quic_stream_t *s, uint64_t offset, uint64_t datalen);
int quic_stream_on_close(quic_conn_t *c, quic_stream_t *s, int64_t stream_id,
                         uint32_t flags, uint64_t app_error_code);
void quic_stream_on_reset(quic_stream_t *s, uint64_t app_error_code);
void quic_stream_on_recv_stop_sending(quic_conn_t *c, quic_stream_t *s,
                                      uint64_t app_error_code);

/* #write_pkt for the connection self (wrapping c): build the next packet
   into dest, with data from the first stream in @streams that has any.
   Returns what ngtcp2_conn_writev_stream returned. Raises nothing. */
ngtcp2_ssize quic_streams_write_pkt(VALUE self, quic_conn_t *c,
                                    ngtcp2_path *path, ngtcp2_pkt_info *pi,
                                    uint8_t *dest, size_t destlen);

#endif /* QUIC_STREAM_H */
