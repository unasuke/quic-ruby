#include "connection_common.h"

/* The quic_ext_api table of quic/ext.h. A quic_ext_conn * is a quic_conn_t *
   behind the opaque type. None of these functions raises a Ruby exception
   except quic_ext_conn_get; they return 0 or a QUIC_EXT_ERR_* code. */

static quic_conn_t *quic_ext_conn_struct(quic_ext_conn *ec) {
  return (quic_conn_t *)ec;
}

/* Raises TypeError unless conn is a QUIC::Connection::Client or Server. */
static quic_ext_conn *quic_ext_conn_get(VALUE conn) {
  return (quic_ext_conn *)rb_check_typeddata(conn, &quic_conn_data_type);
}

/* Hand every stream of the connection to h. Allowed once, and only before
   the connection has a QUIC::Stream: the two modes cannot share streams.
   Every member of the ABI 1.0 handler is called, so h must be at least that
   large. @stream_handler marks the connection for the Ruby side, which then
   refuses #accept_stream. */
static int quic_ext_set_stream_handler(quic_ext_conn *ec,
                                       const quic_ext_stream_handler *h,
                                       void *ud, VALUE owner) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  if (h == NULL || h->size < sizeof(quic_ext_stream_handler))
    return QUIC_EXT_ERR_OTHER;
  if (c->handler != NULL)
    return QUIC_EXT_ERR_INVALID_STATE;
  VALUE streams = rb_ivar_get(c->owner, rb_intern("@streams"));
  if (RB_TYPE_P(streams, T_HASH) && RHASH_SIZE(streams) > 0)
    return QUIC_EXT_ERR_INVALID_STATE;

  c->handler = h;
  c->handler_ud = ud;
  c->handler_owner = owner;
  rb_ivar_set(c->owner, rb_intern("@stream_handler"), Qtrue);
  return 0;
}

static int quic_ext_open_uni_stream(quic_ext_conn *ec, int64_t *id) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  int rv = ngtcp2_conn_open_uni_stream(c->conn, id, NULL);
  if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED)
    return QUIC_EXT_ERR_STREAM_ID_BLOCKED;
  return rv == 0 ? 0 : QUIC_EXT_ERR_OTHER;
}

/* Give the peer n more bytes of credit on the stream and the connection,
   for data the handler has now consumed (for HTTP/3, request body handed
   to the application). */
static int quic_ext_consume(quic_ext_conn *ec, int64_t id, uint64_t n) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  if (ngtcp2_conn_extend_max_stream_offset(c->conn, id, n) != 0)
    return QUIC_EXT_ERR_OTHER;
  ngtcp2_conn_extend_max_offset(c->conn, n);
  return 0;
}

/* Both return 0 for a stream ngtcp2 no longer knows. */
static int quic_ext_shutdown_stream_read(quic_ext_conn *ec, int64_t id,
                                         uint64_t app_error_code) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  return ngtcp2_conn_shutdown_stream_read(c->conn, 0, id, app_error_code) == 0
             ? 0
             : QUIC_EXT_ERR_OTHER;
}

static int quic_ext_shutdown_stream_write(quic_ext_conn *ec, int64_t id,
                                          uint64_t app_error_code) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  return ngtcp2_conn_shutdown_stream_write(c->conn, 0, id, app_error_code) == 0
             ? 0
             : QUIC_EXT_ERR_OTHER;
}

/* This endpoint's initial_max_streams_bidi. nghttp3 needs it at setup;
   later raises arrive through the extend_max_remote_streams_bidi handler. */
static uint64_t quic_ext_local_max_streams_bidi(quic_ext_conn *ec) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  return ngtcp2_conn_get_local_transport_params2(c->conn)
      ->initial_max_streams_bidi;
}

/* Remember the application error to close the connection with after the
   handler reports a failure (for HTTP/3, the H3_* code nghttp3 gave). */
static int quic_ext_set_application_error(quic_ext_conn *ec,
                                          uint64_t app_error_code) {
  quic_conn_t *c = quic_ext_conn_struct(ec);
  ngtcp2_ccerr_set_application_error(&c->close_error, app_error_code, NULL, 0);
  c->close_error_set = true;
  return 0;
}

const quic_ext_api quic_ext_api_table = {
    .abi_major = QUIC_EXT_ABI_MAJOR,
    .abi_minor = 0,
    .size = sizeof(quic_ext_api),
    .conn_get = quic_ext_conn_get,
    .set_stream_handler = quic_ext_set_stream_handler,
    .open_uni_stream = quic_ext_open_uni_stream,
    .consume = quic_ext_consume,
    .shutdown_stream_read = quic_ext_shutdown_stream_read,
    .shutdown_stream_write = quic_ext_shutdown_stream_write,
    .local_max_streams_bidi = quic_ext_local_max_streams_bidi,
    .set_application_error = quic_ext_set_application_error,
};
