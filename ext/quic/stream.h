#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H 1

#include "quic.h"

extern VALUE rb_cQUICStream;

void Init_quic_stream(VALUE rb_mQUICArg);

/* Internal helpers used by connection_common.c stream callbacks and
   write_pkt's stream-aware path. */

typedef struct {
  int64_t stream_id;
  /* Cumulative bytes handed to ngtcp2 via writev_stream so far. Increases
     monotonically; used to derive the next send position within
     @pending_chunks. */
  uint64_t sent_offset;
  /* Cumulative bytes acked by the peer (per acked_stream_data_offset).
     Increases monotonically. */
  uint64_t acked_offset;
  /* Cumulative bytes shifted out of @pending_chunks. Always
     <= acked_offset (we only shift a Chunk after its end is acked). */
  uint64_t pending_shifted;
  bool fin_received; /* recv_stream_data delivered FIN */
  bool fin_sent;     /* #write(fin: true) queued FIN */
  bool fin_flushed;  /* write_pkt actually wrote the FIN frame */
  bool reset;        /* stream_reset callback fired */
  bool closed;       /* stream_close callback fired */
  uint64_t close_app_error_code;
  bool close_has_app_error_code;
  /* The send side is shut: the peer's STOP_SENDING arrived, or ngtcp2
     reported the send side shut while writing. @pending_chunks has been
     emptied, so the offsets above no longer describe it, and #write_pkt
     skips the stream. */
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
   @pending_chunks / @recv_buffer). @client is owner, the Client or Server
   the stream belongs to; the ivar keeps its name for both. */
VALUE quic_stream_new(int64_t stream_id, VALUE owner);

#endif /* QUIC_STREAM_H */
