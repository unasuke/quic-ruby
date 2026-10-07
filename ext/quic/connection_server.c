#include "connection_common.h"

#include <openssl/rand.h>

NORETURN(static void quic_server_raise_unacceptable(void));

/* The first datagram cannot start a connection. code stays nil: this is
   _accept's own verdict, not an ngtcp2 error passed through. */
static void
quic_server_raise_unacceptable(void)
{
  rb_raise(rb_eQUICErrorProto, "not an acceptable Initial packet");
}

VALUE
quic_server_conn_new(VALUE klass, const ngtcp2_pkt_hd *hd, const ngtcp2_path *path,
                     VALUE tls_context, VALUE transport_params, VALUE settings_v)
{
  VALUE self = quic_conn_alloc(klass);
  quic_conn_t *c = quic_conn_get(self);
  c->owner = self;
  c->is_server = true;

  /* The reference taken here keeps the context alive until quic_conn_free,
     whatever happens to the QUIC::TLSContext object. */
  c->tls = quic_tls_context_get(tls_context);
  quic_tls_ctx_ref(c->tls);

  c->dcid = hd->scid;
  c->scid.datalen = QUIC_SCID_LEN;
  if (RAND_bytes(c->scid.data, QUIC_SCID_LEN) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(scid) failed");
  }

  ngtcp2_transport_params params;
  quic_fill_transport_params(&params, transport_params);
  /* Without Retry, the original DCID is the one in this first packet. The
     handshake fails if it is missing. */
  params.original_dcid = hd->dcid;
  params.original_dcid_present = 1;

  /* quic_conn_alloc already zeroed the struct, but calling ctx_init keeps
     the ngtcp2-side initialization explicit, as in _open. */
  ngtcp2_crypto_picotls_ctx_init(&c->cptls);

  ngtcp2_callbacks callbacks;
  quic_conn_fill_common_callbacks(&callbacks);
  callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

  ngtcp2_settings settings;
  quic_fill_settings(&settings, settings_v);

  c->conn_ref.get_conn = quic_conn_get_conn;
  c->conn_ref.user_data = c;

  int rv = ngtcp2_conn_server_new(&c->conn, &c->dcid, &c->scid, path, hd->version,
                                  &callbacks, &settings, &params, NULL, c);
  if (rv != 0) {
    quic_raise_ngtcp2_error(rv);
  }

  c->cptls.ptls = ptls_server_new(&c->tls->ctx);
  if (c->cptls.ptls == NULL) {
    rb_raise(rb_eRuntimeError, "ptls_server_new failed");
  }
  /* Let ngtcp2's crypto callbacks resolve the ngtcp2_conn from the ptls_t. */
  *ptls_get_data_ptr(c->cptls.ptls) = &c->conn_ref;
  /* [0] carries the QUIC transport parameters, filled in by ngtcp2; [1]
     terminates the list. */
  c->tls_exts[0].type = UINT16_MAX;
  c->tls_exts[1].type = UINT16_MAX;
  c->cptls.handshake_properties.additional_extensions = c->tls_exts;
  if (ngtcp2_crypto_picotls_configure_server_session(&c->cptls) != 0) {
    rb_raise(rb_eRuntimeError, "ngtcp2_crypto_picotls_configure_server_session failed");
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, &c->cptls);

  /* Stream registry and accept queue, as in _open. The accept queue holds
     client-initiated streams here. */
  rb_ivar_set(self, rb_intern("@streams"), rb_hash_new());
  rb_ivar_set(self, rb_intern("@accept_queue"), rb_ary_new());

  return self;
}

/* Build a server connection from the first datagram a client sent. Only the
   ngtcp2_conn and the TLS session are set up here; QUIC::Connection::Server
   .accept feeds that datagram to #read_pkt afterwards. */
static VALUE
quic_server_accept(int argc, VALUE *argv, VALUE klass)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) {
    rb_raise(rb_eArgError,
             "missing keywords: initial_packet, local_sockaddr, remote_sockaddr, "
             "certificate_path, private_key_path, transport_params, settings");
  }

  VALUE initial_packet   = rb_hash_aref(opts, ID2SYM(rb_intern("initial_packet")));
  VALUE local_sockaddr   = rb_hash_aref(opts, ID2SYM(rb_intern("local_sockaddr")));
  VALUE remote_sockaddr  = rb_hash_aref(opts, ID2SYM(rb_intern("remote_sockaddr")));
  VALUE certificate_path = rb_hash_aref(opts, ID2SYM(rb_intern("certificate_path")));
  VALUE private_key_path = rb_hash_aref(opts, ID2SYM(rb_intern("private_key_path")));
  VALUE transport_params = rb_hash_aref(opts, ID2SYM(rb_intern("transport_params")));
  VALUE settings_v       = rb_hash_aref(opts, ID2SYM(rb_intern("settings")));

  if (NIL_P(initial_packet) || NIL_P(local_sockaddr) || NIL_P(remote_sockaddr) ||
      NIL_P(certificate_path) || NIL_P(private_key_path) ||
      NIL_P(transport_params) || NIL_P(settings_v)) {
    rb_raise(rb_eArgError,
             "all keywords required: initial_packet, local_sockaddr, remote_sockaddr, "
             "certificate_path, private_key_path, transport_params, settings");
  }

  quic_require_binary(initial_packet,  "initial_packet");
  quic_require_sockaddr(local_sockaddr,  "local_sockaddr");
  quic_require_sockaddr(remote_sockaddr, "remote_sockaddr");
  certificate_path = quic_path_value(certificate_path, "certificate_path");
  private_key_path = quic_path_value(private_key_path, "private_key_path");

  const uint8_t *data = (const uint8_t *)RSTRING_PTR(initial_packet);
  size_t datalen = (size_t)RSTRING_LEN(initial_packet);

  /* ngtcp2_pkt_decode_version_cid asserts datalen > 0, and ngtcp2 is built
     with assertions enabled, so an empty datagram would abort the process. */
  if (datalen == 0) quic_server_raise_unacceptable();

  ngtcp2_version_cid vc;
  int rv = ngtcp2_pkt_decode_version_cid(&vc, data, datalen, QUIC_SCID_LEN);
  if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
    rb_raise(rb_eQUICErrorProto,
             "unsupported QUIC version 0x%08x (Version Negotiation is not implemented)",
             (unsigned int)vc.version);
  }
  if (rv != 0) quic_server_raise_unacceptable();

  /* Unlike vc, hd holds the CIDs by value, so it outlives the packet buffer.
     A token (address validation) is accepted without checking it: no Retry
     is ever sent, so a well-behaved client does not send one. */
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, data, datalen) != 0) quic_server_raise_unacceptable();

  /* A context of this connection's own, as one made by
     QUIC::TLSContext.server. verify_mode, ca_file and ca_path are not read,
     since no client certificate is requested. */
  VALUE tls_context = quic_tls_context_server_new(
    certificate_path, private_key_path, rb_funcall(settings_v, rb_intern("alpn"), 0));

  ngtcp2_path path = {
    {(struct sockaddr *)RSTRING_PTR(local_sockaddr),  (ngtcp2_socklen)RSTRING_LEN(local_sockaddr)},
    {(struct sockaddr *)RSTRING_PTR(remote_sockaddr), (ngtcp2_socklen)RSTRING_LEN(remote_sockaddr)},
    NULL,
  };

  return quic_server_conn_new(klass, &hd, &path, tls_context, transport_params, settings_v);
}

void
Init_quic_connection_server(VALUE rb_mQUICConnectionArg)
{
  rb_cQUICConnectionServer = rb_define_class_under(rb_mQUICConnectionArg, "Server", rb_cObject);
  rb_define_alloc_func(rb_cQUICConnectionServer, quic_conn_alloc);
  rb_define_singleton_method(rb_cQUICConnectionServer, "_accept", quic_server_accept, -1);
  quic_conn_define_shared_methods(rb_cQUICConnectionServer);
}
