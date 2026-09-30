#ifndef QUIC_CONNECTION_COMMON_H
#define QUIC_CONNECTION_COMMON_H 1

#include "quic.h"

/* Length of the source connection ID this endpoint picks for itself. */
#define QUIC_SCID_LEN 8

/* The C side of a QUIC::Connection::Client or QUIC::Connection::Server. Both
   classes wrap it with quic_conn_data_type, so stream.c can reach the
   ngtcp2_conn of either through quic_conn_ptr. Only the constructors
   (_open / _accept) are class specific. */
typedef struct {
  ngtcp2_conn *conn;
  /* Referenced by cptls.ptls, which only keeps the pointer, so this has to
     outlive the ptls_t. */
  ptls_context_t tls_ctx;
  /* Client only. Referenced by tls_ctx.verify_certificate when verify_mode
     is :peer. Holds a reference to an X509_STORE, released in
     quic_conn_free. */
  ptls_openssl_verify_certificate_t verify_cert;
  bool verify_cert_initialized;
  /* Filled by quic_override_verify_cb during the handshake so that a failed
     read_pkt can raise CertificateVerifyFailed with the X509 error. */
  bool verify_failed;
  int verify_result;  /* X509_V_ERR_*, 0 when the server sent no certificate */
  /* Server only. Referenced by tls_ctx.sign_certificate; holds a reference
     to the private key, released in quic_conn_free. The certificate chain
     itself lives in tls_ctx.certificates, also freed there. */
  ptls_openssl_sign_certificate_t sign_cert;
  bool sign_cert_initialized;
  /* Server only. tls_ctx.on_client_hello points here; the callback recovers
     this struct from its self argument with offsetof. */
  ptls_on_client_hello_t on_client_hello;
  /* The TLS native handle handed to ngtcp2 (&cptls, not cptls.ptls). */
  ngtcp2_crypto_picotls_ctx cptls;
  /* [0]: QUIC transport params, filled in by ngtcp2; [1]: terminator. */
  ptls_raw_extension_t tls_exts[2];
  /* ALPN list handed to picotls, which keeps the pointers for the whole
     handshake (unlike SSL_set_alpn_protos, which copies). The entries point
     into alpn_buf, and both are owned by this struct. */
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
  /* Set by the constructor. Decides which peer-initiated streams
     recv_stream_data queues for #accept_stream. */
  bool is_server;
} quic_conn_t;

extern const rb_data_type_t quic_conn_data_type;

extern ptls_key_exchange_algorithm_t *quic_key_exchanges[];
extern ptls_cipher_suite_t *quic_cipher_suites[];

/* Allocator for both connection classes. The struct starts zeroed. */
VALUE quic_conn_alloc(VALUE klass);

quic_conn_t *quic_conn_get(VALUE self);

/* The raw ngtcp2_conn of a Client or Server, for stream.c to issue ngtcp2
   calls (e.g. ngtcp2_conn_shutdown_stream_read) on streams whose @client is
   that connection. The caller must keep the connection object alive for the
   duration of the call. */
ngtcp2_conn *quic_conn_ptr(VALUE owner);

/* ngtcp2_crypto_conn_ref.get_conn for quic_conn_t. */
ngtcp2_conn *quic_conn_get_conn(ngtcp2_crypto_conn_ref *conn_ref);

void quic_require_binary(VALUE str, const char *name);

/* Validate a path argument and return it as a String, or Qnil for nil.
   Accepts a String or anything responding to #to_path, and raises
   ArgumentError for any other type or a path containing NUL. */
VALUE quic_path_value(VALUE value, const char *name);

/* Copy settings.alpn into memory owned by c (c->alpn / c->alpn_buf). An
   empty list leaves c->alpn_count at 0. */
void quic_conn_copy_alpn(quic_conn_t *c, VALUE settings_v);

void quic_fill_transport_params(ngtcp2_transport_params *params, VALUE tp);
void quic_fill_settings(ngtcp2_settings *settings, VALUE st);

/* Zero *callbacks and fill in everything both endpoints share. The caller
   adds the endpoint specific ones (client_initial / recv_retry, or
   recv_client_initial). */
void quic_conn_fill_common_callbacks(ngtcp2_callbacks *callbacks);

/* Define the packet I/O, timer, state and stream methods on klass. */
void quic_conn_define_shared_methods(VALUE klass);

#endif /* QUIC_CONNECTION_COMMON_H */
