#ifndef QUIC_H
#define QUIC_H 1

#include "ruby.h"
#include "ruby/encoding.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <openssl/crypto.h>

/* picotls disables ptls_openssl_x25519 unless it is built with the patch in
   ext/quic/patches/picotls/. extconf.rb checks the same condition at configure
   time; this catches a prebuilt ports/ tree whose patch was swapped out. */
#if !PTLS_OPENSSL_HAVE_X25519
#error "picotls was built without X25519; is ext/quic/patches/picotls/*.patch applied?"
#endif

extern VALUE rb_mQUIC;
extern VALUE rb_mQUICConnection;
extern VALUE rb_cQUICConnectionClient;
extern VALUE rb_cQUICConnectionServer;

extern VALUE rb_eQUICError;
extern VALUE rb_eQUICErrorProto;
extern VALUE rb_eQUICErrorDropConn;
extern VALUE rb_eQUICErrorRetry;
extern VALUE rb_eQUICErrorClosed;
extern VALUE rb_eQUICErrorCryptoError;
extern VALUE rb_eQUICErrorCertificateVerifyFailed;
extern VALUE rb_eQUICErrorHandshakeTimeout;
extern VALUE rb_eQUICErrorFlowControl;
extern VALUE rb_eQUICErrorUnknown;
extern VALUE rb_eQUICErrorWaitReadable;
extern VALUE rb_eQUICErrorWaitWritable;
extern VALUE rb_eQUICErrorStreamClosed;
extern VALUE rb_eQUICErrorStreamReset;
extern VALUE rb_eQUICErrorNotBound;

void Init_quic_connection_client(VALUE rb_mQUICConnection);
void Init_quic_connection_server(VALUE rb_mQUICConnection);

/* Raise a QUIC::Error subclass mapped from an ngtcp2 negative error code.
   Never returns. */
NORETURN(void quic_raise_ngtcp2_error(int rv));

#endif /* QUIC_H */
