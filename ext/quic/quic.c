#include "quic.h"
#include "stream.h"

VALUE rb_mQUIC;
VALUE rb_mQUICConnection;
VALUE rb_cQUICConnectionClient;
VALUE rb_cQUICConnectionServer;

VALUE rb_eQUICError;
VALUE rb_eQUICErrorProto;
VALUE rb_eQUICErrorDropConn;
VALUE rb_eQUICErrorRetry;
VALUE rb_eQUICErrorClosed;
VALUE rb_eQUICErrorCryptoError;
VALUE rb_eQUICErrorCertificateVerifyFailed;
VALUE rb_eQUICErrorHandshakeTimeout;
VALUE rb_eQUICErrorFlowControl;
VALUE rb_eQUICErrorUnknown;
VALUE rb_eQUICErrorWaitReadable;
VALUE rb_eQUICErrorWaitWritable;
VALUE rb_eQUICErrorStreamClosed;
VALUE rb_eQUICErrorStreamReset;
VALUE rb_eQUICErrorNotBound;

static VALUE
quic_library_versions(VALUE self)
{
  (void)self;
  VALUE h = rb_hash_new();
  rb_hash_aset(h, ID2SYM(rb_intern("ngtcp2")),
               rb_str_new_cstr(ngtcp2_version(0)->version_str));
  rb_hash_aset(h, ID2SYM(rb_intern("openssl")),
               rb_str_new_cstr(OpenSSL_version(OPENSSL_VERSION)));
  /* picotls has neither a version macro nor releases, so report the commit
     extconf.rb built against (passed in as -DQUIC_PICOTLS_COMMIT). */
  rb_hash_aset(h, ID2SYM(rb_intern("picotls")),
               rb_str_new_cstr(QUIC_PICOTLS_COMMIT));
  return h;
}

void
quic_raise_ngtcp2_error(int rv)
{
  VALUE cls;
  switch (rv) {
    case NGTCP2_ERR_PROTO:
      cls = rb_eQUICErrorProto;
      break;
    case NGTCP2_ERR_DROP_CONN:
      cls = rb_eQUICErrorDropConn;
      break;
    case NGTCP2_ERR_RETRY:
      cls = rb_eQUICErrorRetry;
      break;
    case NGTCP2_ERR_CLOSING:
    case NGTCP2_ERR_DRAINING:
      cls = rb_eQUICErrorClosed;
      break;
    case NGTCP2_ERR_IDLE_CLOSE:
      cls = rb_eQUICErrorClosed;
      break;
    case NGTCP2_ERR_CRYPTO:
      cls = rb_eQUICErrorCryptoError;
      break;
    case NGTCP2_ERR_HANDSHAKE_TIMEOUT:
      cls = rb_eQUICErrorHandshakeTimeout;
      break;
    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      cls = rb_eQUICErrorFlowControl;
      break;
    case NGTCP2_ERR_STREAM_SHUT_WR:
      cls = rb_eQUICErrorStreamClosed;
      break;
    default:
      cls = rb_eQUICErrorUnknown;
      break;
  }

  VALUE exc = rb_exc_new_cstr(cls, ngtcp2_strerror(rv));
  rb_ivar_set(exc, rb_intern("@code"), INT2NUM(rv));
  rb_exc_raise(exc);
}

RUBY_FUNC_EXPORTED void
Init_quic(void)
{
  rb_mQUIC = rb_define_module("QUIC");
  rb_mQUICConnection = rb_define_module_under(rb_mQUIC, "Connection");
  rb_define_singleton_method(rb_mQUIC, "library_versions", quic_library_versions, 0);

  /* QUIC::Error is defined in Ruby (lib/quic.rb) before this Init_quic runs,
     so rb_const_get retrieves the already-defined base class. Subclasses live
     under QUIC::Error::<Name>. */
  rb_eQUICError = rb_const_get(rb_mQUIC, rb_intern("Error"));
  rb_eQUICErrorProto = rb_define_class_under(rb_eQUICError, "Proto", rb_eQUICError);
  rb_eQUICErrorDropConn = rb_define_class_under(rb_eQUICError, "DropConn", rb_eQUICError);
  rb_eQUICErrorRetry = rb_define_class_under(rb_eQUICError, "Retry", rb_eQUICError);
  rb_eQUICErrorClosed = rb_define_class_under(rb_eQUICError, "Closed", rb_eQUICError);
  rb_eQUICErrorCryptoError = rb_define_class_under(rb_eQUICError, "CryptoError", rb_eQUICError);
  /* The TLS alert this endpoint sent, when read_pkt fails in the handshake.
     Alerts received from the peer are not recorded by ngtcp2. */
  rb_define_attr(rb_eQUICErrorCryptoError, "tls_alert", 1, 0);
  rb_eQUICErrorCertificateVerifyFailed =
    rb_define_class_under(rb_eQUICError, "CertificateVerifyFailed", rb_eQUICErrorCryptoError);
  /* X509_V_ERR_* from the chain / name check, or nil when no certificate came. */
  rb_define_attr(rb_eQUICErrorCertificateVerifyFailed, "verify_result", 1, 0);
  rb_eQUICErrorHandshakeTimeout = rb_define_class_under(rb_eQUICError, "HandshakeTimeout", rb_eQUICError);
  rb_eQUICErrorFlowControl = rb_define_class_under(rb_eQUICError, "FlowControl", rb_eQUICError);
  rb_eQUICErrorUnknown = rb_define_class_under(rb_eQUICError, "Unknown", rb_eQUICError);

  /* IO-style non-blocking errors. Mix in the standard IO::Wait{Readable,Writable}
     modules so callers can `rescue IO::WaitReadable` (or the QUIC subclass)
     interchangeably with stdlib IO objects. */
  VALUE io_wait_readable = rb_const_get(rb_cIO, rb_intern("WaitReadable"));
  VALUE io_wait_writable = rb_const_get(rb_cIO, rb_intern("WaitWritable"));
  rb_eQUICErrorWaitReadable = rb_define_class_under(rb_eQUICError, "WaitReadable", rb_eQUICError);
  rb_include_module(rb_eQUICErrorWaitReadable, io_wait_readable);
  rb_eQUICErrorWaitWritable = rb_define_class_under(rb_eQUICError, "WaitWritable", rb_eQUICError);
  rb_include_module(rb_eQUICErrorWaitWritable, io_wait_writable);

  rb_eQUICErrorStreamClosed = rb_define_class_under(rb_eQUICError, "StreamClosed", rb_eQUICError);
  rb_eQUICErrorStreamReset = rb_define_class_under(rb_eQUICError, "StreamReset", rb_eQUICError);
  rb_eQUICErrorNotBound = rb_define_class_under(rb_eQUICError, "NotBound", rb_eQUICError);

  Init_quic_connection_client(rb_mQUICConnection);
  Init_quic_connection_server(rb_mQUICConnection);
  Init_quic_stream(rb_mQUIC);
}
