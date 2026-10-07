#ifndef QUIC_CONNECTION_COMMON_H
#define QUIC_CONNECTION_COMMON_H 1

#include <stdio.h>

#include "quic.h"
#include "quic/ext.h"
#include "tls_context.h"

/* Length of the source connection ID this endpoint picks for itself. */
#define QUIC_SCID_LEN 8

/* Buffer size for #write_pkt. NGTCP2_MAX_UDP_PAYLOAD_SIZE (1200) is the
   minimum destlen ngtcp2 accepts. Revisit when PMTUD is enabled (Phase 4+). */
#define QUIC_WRITE_PKT_BUFLEN NGTCP2_MAX_UDP_PAYLOAD_SIZE

/* A QUIC::Endpoint (endpoint.c). */
typedef struct quic_endpoint quic_endpoint_t;

/* The C side of a QUIC::Connection::Client or QUIC::Connection::Server. Both
   classes wrap it with quic_conn_data_type, so stream.c can reach the
   ngtcp2_conn of either through quic_conn_ptr. Only the constructors
   (_open / _accept) are class specific. */
typedef struct {
  ngtcp2_conn *conn;
  /* Client only. Referenced by cptls.ptls, which only keeps the pointer, so
     this has to outlive the ptls_t. */
  ptls_context_t tls_ctx;
  /* Server only. The shared context cptls.ptls was made from, holding the
     certificate chain, the signer and the ALPN list. This connection holds
     a reference, released in quic_conn_free after the ptls_t. */
  quic_tls_ctx_t *tls;
  /* Client only. Referenced by tls_ctx.verify_certificate when verify_mode
     is :peer. Holds a reference to an X509_STORE, released in
     quic_conn_free. */
  ptls_openssl_verify_certificate_t verify_cert;
  bool verify_cert_initialized;
  /* Filled by quic_override_verify_cb during the handshake so that a failed
     read_pkt can raise CertificateVerifyFailed with the X509 error. */
  bool verify_failed;
  int verify_result;  /* X509_V_ERR_*, 0 when the server sent no certificate */
  /* The TLS native handle handed to ngtcp2 (&cptls, not cptls.ptls). */
  ngtcp2_crypto_picotls_ctx cptls;
  /* [0]: QUIC transport params, filled in by ngtcp2; [1]: terminator. */
  ptls_raw_extension_t tls_exts[2];
  /* Client only. ALPN list handed to picotls, which keeps the pointers for
     the whole handshake (unlike SSL_set_alpn_protos, which copies). The
     entries point into alpn_buf, and both are owned by this struct. */
  ptls_iovec_t *alpn;
  size_t alpn_count;
  uint8_t *alpn_buf;
  ngtcp2_cid scid;
  ngtcp2_cid dcid;
  /* ngtcp2 1.x requires applications to associate an ngtcp2_conn with the
     TLS object so that crypto callbacks (e.g. add_handshake_data) can recover
     the conn. picotls carries it in the ptls_t's data pointer, set via
     ptls_get_data_ptr. The ref must outlive the ptls_t. */
  ngtcp2_crypto_conn_ref conn_ref;
  /* Back-reference to the Client or Server Ruby object that owns this
     struct. ngtcp2 stream callbacks receive a void* user_data equal to this
     struct, and they look up @streams via owner. We are stored INSIDE owner
     via TypedData_Wrap_Struct, so owner is guaranteed alive while we exist
     (no dmark needed). GC.compact may relocate owner, so quic_conn_compact
     updates this field via rb_gc_location. */
  VALUE owner;
  /* An exception raised by Ruby code inside an ngtcp2 callback, caught with
     rb_protect so that it does not unwind through ngtcp2's frames. #read_pkt,
     #write_pkt and #handle_expiry re-raise it once ngtcp2 has returned.
     Qnil when there is none. Marked by quic_conn_data_type's dmark. */
  VALUE pending_exc;
  /* The C stream handler registered through the quic_ext_api table
     (set_stream_handler), or NULL. With a handler the connection makes no
     QUIC::Stream objects: every stream callback goes to the handler, and
     #write_pkt pulls stream data from it. handler_owner is marked while the
     connection lives. */
  const quic_ext_stream_handler *handler;
  void *handler_ud;
  VALUE handler_owner;
  /* The time #read_pkt, #write_pkt or #handle_expiry read on entry. Handed
     to the handler as `ts`, since ngtcp2 callbacks receive no time. */
  ngtcp2_tstamp now;
  /* The application error the handler left with set_application_error, to
     close the connection with after it reports a failure. */
  ngtcp2_ccerr close_error;
  bool close_error_set;
  /* Set by the constructor. Decides which peer-initiated streams
     recv_stream_data queues for #accept_stream. */
  bool is_server;
  /* <qlog_dir>/<SCID>.sqlog while ngtcp2 writes qlog to it, else NULL.
     Closed on NGTCP2_QLOG_WRITE_FLAG_FIN, which ngtcp2_conn_del sends at
     the latest. */
  FILE *qlog;
  /* The rest is for a connection a QUIC::Endpoint made, and stays zero (nil)
     otherwise. endpoint is the Endpoint whose table holds this connection,
     NULL once it has left the table; endpoint_owner is that Endpoint's
     object, marked so that it outlives the connections it holds. */
  bool from_endpoint;
  quic_endpoint_t *endpoint;
  VALUE endpoint_owner;
  /* Why the Endpoint closed the connection (Connection#error): nil for a
     close by the peer, by idle timeout or by #close. */
  VALUE error;
  /* When the closing or draining period ends; 0 while the connection is
     open. */
  ngtcp2_tstamp close_deadline;
  /* The CONNECTION_CLOSE packet built on entering the closing period, sent
     again for packets the peer keeps sending, at most three times what they
     add up to and with exponential backoff (examples/server.cc). */
  VALUE closebuf;
  uint64_t close_bytes_recv;
  uint64_t close_bytes_sent;
  uint64_t close_pkts_recv;
  uint64_t close_next_pkts_recv;
} quic_conn_t;

extern const rb_data_type_t quic_conn_data_type;

extern ptls_key_exchange_algorithm_t *quic_key_exchanges[];
extern ptls_cipher_suite_t *quic_cipher_suites[];

/* Allocator for both connection classes. The struct starts zeroed, except
   its VALUE fields, which start as Qnil. */
VALUE quic_conn_alloc(VALUE klass);

/* CLOCK_MONOTONIC in ngtcp2's units (nanoseconds). */
ngtcp2_tstamp quic_now(void);

/* Build the next packet of the connection self (wrapping c) into dest of
   QUIC_WRITE_PKT_BUFLEN bytes, as #write_pkt does, and store its path in
   *path. Returns the packet's length, 0 when there is nothing to send, or a
   negative ngtcp2 error. Never raises for the connection's own failures: an
   exception from a Ruby callback is left in c->pending_exc. */
ngtcp2_ssize quic_conn_write_pkt_raw(VALUE self, quic_conn_t *c, ngtcp2_path *path,
                                     uint8_t *dest);

/* Feed one datagram to the connection, as #read_pkt does, and return what
   ngtcp2_conn_read_pkt returned. Like quic_conn_write_pkt_raw, it leaves an
   exception from a Ruby callback in c->pending_exc. */
int quic_conn_read_pkt_raw(quic_conn_t *c, const ngtcp2_path *path, const uint8_t *data,
                           size_t datalen);

/* The exception #read_pkt raises for rv, an error ngtcp2_conn_read_pkt
   returned: a CryptoError (or CertificateVerifyFailed) with the TLS alert
   for NGTCP2_ERR_CRYPTO, quic_ngtcp2_error_new(rv) otherwise. */
VALUE quic_conn_error_new(quic_conn_t *c, int rv);

/* Build a QUIC::Connection::Server of class klass for the client whose
   first Initial is hd, received on path, with the TLS context tls_context
   (a QUIC::TLSContext). ep is the Endpoint that will hold it (its object
   ep_owner), or NULL for Server.accept. Raises if ngtcp2 or picotls cannot
   set the connection up. */
VALUE quic_server_conn_new(VALUE klass, const ngtcp2_pkt_hd *hd, const ngtcp2_path *path,
                           VALUE tls_context, VALUE transport_params, VALUE settings_v,
                           quic_endpoint_t *ep, VALUE ep_owner);

quic_conn_t *quic_conn_get(VALUE self);

/* The raw ngtcp2_conn of a Client or Server, for stream.c to issue ngtcp2
   calls (e.g. ngtcp2_conn_shutdown_stream_read) on streams whose @client is
   that connection. The caller must keep the connection object alive for the
   duration of the call. */
ngtcp2_conn *quic_conn_ptr(VALUE owner);

/* ngtcp2_crypto_conn_ref.get_conn for quic_conn_t. */
ngtcp2_conn *quic_conn_get_conn(ngtcp2_crypto_conn_ref *conn_ref);

void quic_require_binary(VALUE str, const char *name);

/* str must be a binary String holding an AF_INET or AF_INET6 sockaddr of
   exactly that family's size, as Addrinfo#to_sockaddr makes. ngtcp2 copies
   an address by its length into storage only as large as sockaddr_in6, so
   anything longer would overrun it. Raises ArgumentError otherwise. */
void quic_require_sockaddr(VALUE str, const char *name);

/* Validate a path argument and return it as a String, or Qnil for nil.
   Accepts a String or anything responding to #to_path, and raises
   ArgumentError for any other type or a path containing NUL. */
VALUE quic_path_value(VALUE value, const char *name);

/* Copy alpn_ary, an Array of 1-255 byte Strings, into a list and a buffer
   the list's entries point into. Both are stored in *list and *buf as soon
   as they are allocated, for the caller to release with xfree even when
   this raises. An empty Array allocates nothing and sets *count to 0. */
void quic_copy_alpn(VALUE alpn_ary, ptls_iovec_t **list, size_t *count, uint8_t **buf);

/* Copy settings.alpn into memory owned by c (c->alpn / c->alpn_buf). An
   empty list leaves c->alpn_count at 0. */
void quic_conn_copy_alpn(quic_conn_t *c, VALUE settings_v);

/* Give the peer back the stream stream_id used up, if it is a
   bidirectional stream the peer opened, as ngtcp2's examples/server.cc
   does when such a stream closes. Without this the peer can open only
   initial_max_streams_bidi streams over the whole connection. */
void quic_conn_give_back_peer_stream(ngtcp2_conn *conn, int64_t stream_id);

void quic_fill_transport_params(ngtcp2_transport_params *params, VALUE tp);
void quic_fill_settings(ngtcp2_settings *settings, VALUE st);

/* When settings_v.qlog_dir is set, open <qlog_dir>/<c->scid in hex>.sqlog
   (as ngtcp2's examples name it) and have ngtcp2 write the connection's
   qlog there. c->scid must be set. A file that cannot be opened only goes
   without qlog. */
void quic_conn_open_qlog(quic_conn_t *c, VALUE settings_v, ngtcp2_settings *settings);

/* Zero *callbacks and fill in everything both endpoints share. The caller
   adds the endpoint specific ones (client_initial / recv_retry, or
   recv_client_initial). */
void quic_conn_fill_common_callbacks(ngtcp2_callbacks *callbacks);

/* Define the packet I/O, timer, state and stream methods on klass. */
void quic_conn_define_shared_methods(VALUE klass);

/* The quic_ext_api table (ext_api.c) that quic_ext_get_api hands out. */
extern const quic_ext_api quic_ext_api_table;

#endif /* QUIC_CONNECTION_COMMON_H */
