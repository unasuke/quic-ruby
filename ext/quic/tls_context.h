#ifndef QUIC_TLS_CONTEXT_H
#define QUIC_TLS_CONTEXT_H 1

#include "quic.h"

/* A server's TLS context: the certificate chain, the signer and the ALPN
   list, read once and shared by every connection made from it. Reference
   counted: the QUIC::TLSContext object holds one reference and each server
   connection another, so a context replaced on an Endpoint lives on until
   the last connection that uses it is freed. */
typedef struct {
  /* Handed to ptls_server_new. certificates.list is malloc()ed by picotls
     and freed with the context. */
  ptls_context_t ctx;
  /* Referenced by ctx.sign_certificate; holds a reference to the key. */
  ptls_openssl_sign_certificate_t sign_cert;
  bool sign_cert_initialized;
  /* ctx.on_client_hello points here; the callback recovers this struct
     from its self argument with offsetof, so it needs no connection. */
  ptls_on_client_hello_t on_client_hello;
  /* The ALPN protocols the server accepts, in its order of preference. The
     entries point into alpn_buf. */
  ptls_iovec_t *alpn;
  size_t alpn_count;
  uint8_t *alpn_buf;
  long refcnt;
} quic_tls_ctx_t;

extern VALUE rb_cQUICTLSContext;

void Init_quic_tls_context(VALUE rb_mQUICArg);

/* QUIC::TLSContext.server, callable from C: a new QUIC::TLSContext object
   holding the one reference to a new context. alpn_ary must be a non-empty
   Array of 1-255 byte Strings. Raises ArgumentError naming what could not
   be loaded or used. */
VALUE quic_tls_context_server_new(VALUE certificate_path, VALUE private_key_path, VALUE alpn_ary);

/* The context behind a QUIC::TLSContext object. Raises TypeError for any
   other object. */
quic_tls_ctx_t *quic_tls_context_get(VALUE tls_context);

void quic_tls_ctx_ref(quic_tls_ctx_t *t);
void quic_tls_ctx_unref(quic_tls_ctx_t *t);

#endif /* QUIC_TLS_CONTEXT_H */
