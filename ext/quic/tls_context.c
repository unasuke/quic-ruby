#include "tls_context.h"
#include "connection_common.h"

#include <stddef.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

VALUE rb_cQUICTLSContext;

void
quic_tls_ctx_ref(quic_tls_ctx_t *t)
{
  t->refcnt++;
}

void
quic_tls_ctx_unref(quic_tls_ctx_t *t)
{
  if (--t->refcnt > 0) return;
  if (t->sign_cert_initialized) ptls_openssl_dispose_sign_certificate(&t->sign_cert);
  /* picotls malloc()ed the list and each entry, so free(), not xfree(). */
  if (t->ctx.certificates.list != NULL) {
    for (size_t i = 0; i < t->ctx.certificates.count; i++) free(t->ctx.certificates.list[i].base);
    free(t->ctx.certificates.list);
  }
  xfree(t->alpn);
  xfree(t->alpn_buf);
  xfree(t);
}

/* The QUIC::TLSContext object holds one reference. A context it never
   finished building (an exception mid-way) is released the same way. */
static void
quic_tls_context_free(void *ptr)
{
  if (ptr != NULL) quic_tls_ctx_unref((quic_tls_ctx_t *)ptr);
}

static size_t
quic_tls_context_size(const void *ptr)
{
  (void)ptr;
  return sizeof(quic_tls_ctx_t);
}

static const rb_data_type_t quic_tls_context_type = {
  "QUIC::TLSContext",
  {NULL, quic_tls_context_free, quic_tls_context_size,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

quic_tls_ctx_t *
quic_tls_context_get(VALUE tls_context)
{
  return (quic_tls_ctx_t *)rb_check_typeddata(tls_context, &quic_tls_context_type);
}

/* Pick the first of the server's ALPN protocols, in the server's order of
   preference, that the client offered. Runs inside read_pkt with the GVL
   held and never touches Ruby objects. */
static int
quic_tls_on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                            ptls_on_client_hello_parameters_t *params)
{
  quic_tls_ctx_t *t = (quic_tls_ctx_t *)((char *)self - offsetof(quic_tls_ctx_t, on_client_hello));
  for (size_t i = 0; i < t->alpn_count; i++) {
    for (size_t j = 0; j < params->negotiated_protocols.count; j++) {
      ptls_iovec_t offered = params->negotiated_protocols.list[j];
      if (offered.len == t->alpn[i].len &&
          memcmp(offered.base, t->alpn[i].base, offered.len) == 0) {
        return ptls_set_negotiated_protocol(tls, (const char *)offered.base, offered.len) == 0
          ? 0 : PTLS_ERROR_NO_MEMORY;
      }
    }
  }
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

/* Never supply a passphrase. Without a callback, PEM_read_bio_PrivateKey
   falls back to PEM_def_callback, which prompts on the controlling terminal;
   this way an encrypted key fails to load like any other unreadable one. */
static int
quic_tls_no_passphrase_cb(char *buf, int size, int rwflag, void *userdata)
{
  (void)buf;
  (void)size;
  (void)rwflag;
  (void)userdata;
  return -1;
}

/* Load the certificate chain and private key into t->ctx and install the
   signer. The certificate file is PEM, the leaf first and then any
   intermediates; there is no limit on their number. A misconfiguration
   raises ArgumentError naming the step that failed. Everything allocated
   here is released before raising, and libcrypto's error queue, which is
   shared with Ruby's openssl extension, is left empty on every return. */
static void
quic_tls_ctx_load_certificate_and_key(quic_tls_ctx_t *t, VALUE certificate_path,
                                      VALUE private_key_path)
{
  VALUE failure_class = rb_eArgError;
  const char *failure = NULL;
  VALUE failed_path = Qnil;
  BIO *cert_bio = NULL;
  BIO *key_bio = NULL;
  X509 *leaf = NULL;
  X509 *x;
  STACK_OF(X509) *chain = NULL;
  EVP_PKEY *pkey = NULL;
  unsigned long err;

  ERR_clear_error();

  cert_bio = BIO_new_file(RSTRING_PTR(certificate_path), "r");
  if (cert_bio == NULL || (leaf = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) == NULL) {
    failure = "failed to load certificate";
    failed_path = certificate_path;
    goto done;
  }

  if ((chain = sk_X509_new_null()) == NULL) {
    failure_class = rb_eRuntimeError;
    failure = "sk_X509_new_null failed";
    goto done;
  }
  while ((x = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
    if (!sk_X509_push(chain, x)) {
      X509_free(x);
      failure_class = rb_eRuntimeError;
      failure = "sk_X509_push failed";
      goto done;
    }
  }
  /* The loop ends with PEM_R_NO_START_LINE once no PEM block is left. Any
     other error means a broken block, as in SSL_CTX_use_certificate_chain_file. */
  err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) != ERR_LIB_PEM || ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
    failure = "failed to load certificate";
    failed_path = certificate_path;
    goto done;
  }

  key_bio = BIO_new_file(RSTRING_PTR(private_key_path), "r");
  if (key_bio == NULL ||
      (pkey = PEM_read_bio_PrivateKey(key_bio, NULL, quic_tls_no_passphrase_cb, NULL)) == NULL) {
    failure = "failed to load private key";
    failed_path = private_key_path;
    goto done;
  }

  /* picotls has no counterpart of SSL_CTX_check_private_key. */
  if (X509_check_private_key(leaf, pkey) != 1) {
    failure = "private key does not match certificate";
    failed_path = private_key_path;
    goto done;
  }

  /* Takes its own reference on pkey. */
  if (ptls_openssl_init_sign_certificate(&t->sign_cert, pkey) != 0) {
    failure = "unsupported private key type";
    failed_path = private_key_path;
    goto done;
  }
  t->sign_cert_initialized = true;
  t->ctx.sign_certificate = &t->sign_cert.super;

  /* Copies the DER of each certificate into a list quic_tls_ctx_unref
     releases. It fails only on allocation, and frees what it allocated then. */
  if (ptls_openssl_load_certificates(&t->ctx, leaf, chain) != 0) {
    failure_class = rb_eRuntimeError;
    failure = "ptls_openssl_load_certificates failed";
    goto done;
  }

done:
  sk_X509_pop_free(chain, X509_free);
  X509_free(leaf);
  EVP_PKEY_free(pkey);
  BIO_free(cert_bio);
  BIO_free(key_bio);
  ERR_clear_error();

  if (failure == NULL) return;
  if (NIL_P(failed_path)) rb_raise(failure_class, "%s", failure);
  rb_raise(failure_class, "%s: %"PRIsVALUE, failure, failed_path);
}

VALUE
quic_tls_context_server_new(VALUE certificate_path, VALUE private_key_path, VALUE alpn_ary)
{
  certificate_path = quic_path_value(certificate_path, "certificate_path");
  private_key_path = quic_path_value(private_key_path, "private_key_path");
  if (NIL_P(certificate_path)) rb_raise(rb_eArgError, "certificate_path must not be nil");
  if (NIL_P(private_key_path)) rb_raise(rb_eArgError, "private_key_path must not be nil");

  /* The object owns the context from the start, so that an exception below
     releases whatever was built so far. */
  VALUE self = TypedData_Wrap_Struct(rb_cQUICTLSContext, &quic_tls_context_type, NULL);
  quic_tls_ctx_t *t = ZALLOC(quic_tls_ctx_t);
  t->refcnt = 1;
  DATA_PTR(self) = t;

  /* Without an ALPN to pick, every handshake would end in
     no_application_protocol. */
  quic_copy_alpn(alpn_ary, &t->alpn, &t->alpn_count, &t->alpn_buf);
  if (t->alpn_count == 0) rb_raise(rb_eArgError, "alpn must not be empty for a server");

  t->ctx = (ptls_context_t){
    .random_bytes = ptls_openssl_random_bytes,
    .get_time = &ptls_get_time,
    .key_exchanges = quic_key_exchanges,
    .cipher_suites = quic_cipher_suites,
    /* No session resumption: encrypt_ticket stays NULL, so no ticket is
       ever issued. Keep this so that PSK-only resumption is refused once
       resumption is added. */
    .require_dhe_on_psk = 1,
    .server_cipher_preference = 1,
  };
  if (ngtcp2_crypto_picotls_configure_server_context(&t->ctx) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_picotls_configure_server_context failed");
  }
  /* verify_certificate stays NULL: no client certificate is requested. */
  quic_tls_ctx_load_certificate_and_key(t, certificate_path, private_key_path);
  t->on_client_hello.cb = quic_tls_on_client_hello_cb;
  t->ctx.on_client_hello = &t->on_client_hello;
  return self;
}

/* QUIC::TLSContext.server(certificate_path:, private_key_path:, alpn:). A
   missing or unknown keyword raises ArgumentError as a Ruby method would. */
static VALUE
quic_tls_context_s_server(int argc, VALUE *argv, VALUE klass)
{
  (void)klass;
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) opts = rb_hash_new();

  ID keywords[3];
  VALUE values[3];
  keywords[0] = rb_intern("certificate_path");
  keywords[1] = rb_intern("private_key_path");
  keywords[2] = rb_intern("alpn");
  rb_get_kwargs(opts, keywords, 3, 0, values);
  return quic_tls_context_server_new(values[0], values[1], values[2]);
}

void
Init_quic_tls_context(VALUE rb_mQUICArg)
{
  rb_cQUICTLSContext = rb_define_class_under(rb_mQUICArg, "TLSContext", rb_cObject);
  rb_undef_alloc_func(rb_cQUICTLSContext);
  rb_define_singleton_method(rb_cQUICTLSContext, "server", quic_tls_context_s_server, -1);
}
