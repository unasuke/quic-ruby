#include "endpoint.h"

#include <string.h>

#include <openssl/rand.h>

/* How many Stateless Resets an Endpoint sends in a burst; the allowance comes
   back at one a second. As examples/server.cc's
   NGTCP2_STATELESS_RESET_BURST. */
#define QUIC_STATELESS_RESET_BURST 100

/* Length of the secret Stateless Reset tokens are derived from. */
#define QUIC_STATELESS_RESET_SECRETLEN 32

/* How many of the Endpoint's own answers may wait for #write_pkt. Any
   datagram can prompt one, so without a limit a flood read faster than it
   is answered would take memory without bound. Every one of them may be
   lost on the wire anyway, so those beyond are dropped. */
#define QUIC_ENDPOINT_MAX_RESPONSES 1024

VALUE rb_cQUICEndpoint;

/* Many server connections on one UDP socket. The Endpoint routes each
   datagram by its DCID and answers what no connection can (Version
   Negotiation, Stateless Reset, CONNECTION_REFUSED); the I/O loop stays
   with the caller. Dispatch follows Server::read_pkt in ngtcp2's
   examples/server.cc. */
struct quic_endpoint {
  /* CID -> the Connection::Server it routes to. A connection is entered
     under the client's first DCID and every SCID it issues. Keys are
     xmalloc()ed ngtcp2_cid copies; values are marked by dmark and followed
     by dcompact. */
  st_table *cids;
  /* The connections in the table, in the order they joined. */
  VALUE conns;
  /* The index into conns #write_pkt continues from. */
  long write_cursor;
  /* [packet, sockaddr] pairs the Endpoint itself answered with, sent before
     any connection's packets. */
  VALUE responses;
  /* Connections that left the table since the last #take_closed. */
  VALUE closed;
  /* The local address of every path (no IP_PKTINFO in v1). */
  VALUE local_sockaddr;
  /* What new connections are made with. */
  VALUE tls_context;
  VALUE transport_params;
  VALUE settings;
  long max_connections;
  bool accepting;
  uint8_t reset_secret[QUIC_STATELESS_RESET_SECRETLEN];
  /* Stateless Resets left to send, and when the allowance last grew. */
  size_t reset_bucket;
  ngtcp2_tstamp reset_refill_ts;
};

/* Seeds the CID hash, so that a client cannot pick initial DCIDs that
   collide. */
static st_index_t quic_cid_hash_seed;

static int
quic_cid_cmp(st_data_t a, st_data_t b)
{
  return !ngtcp2_cid_eq((const ngtcp2_cid *)a, (const ngtcp2_cid *)b);
}

static st_index_t
quic_cid_hash(st_data_t a)
{
  const ngtcp2_cid *cid = (const ngtcp2_cid *)a;
  return st_hash(cid->data, cid->datalen, quic_cid_hash_seed);
}

static const struct st_hash_type quic_cid_hash_type = {quic_cid_cmp, quic_cid_hash};

static int
quic_endpoint_mark_i(st_data_t key, st_data_t value, st_data_t arg)
{
  (void)key;
  (void)arg;
  rb_gc_mark_movable((VALUE)value);
  return ST_CONTINUE;
}

static void
quic_endpoint_mark(void *ptr)
{
  quic_endpoint_t *ep = (quic_endpoint_t *)ptr;
  if (ep->cids != NULL) st_foreach(ep->cids, quic_endpoint_mark_i, 0);
  rb_gc_mark_movable(ep->conns);
  rb_gc_mark_movable(ep->responses);
  rb_gc_mark_movable(ep->closed);
  rb_gc_mark_movable(ep->local_sockaddr);
  rb_gc_mark_movable(ep->tls_context);
  rb_gc_mark_movable(ep->transport_params);
  rb_gc_mark_movable(ep->settings);
}

static int
quic_endpoint_compact_check_i(st_data_t key, st_data_t value, st_data_t arg, int error)
{
  (void)key;
  (void)value;
  (void)arg;
  (void)error;
  return ST_REPLACE;
}

static int
quic_endpoint_compact_replace_i(st_data_t *key, st_data_t *value, st_data_t arg, int existing)
{
  (void)key;
  (void)arg;
  (void)existing;
  *value = (st_data_t)rb_gc_location((VALUE)*value);
  return ST_CONTINUE;
}

static void
quic_endpoint_compact(void *ptr)
{
  quic_endpoint_t *ep = (quic_endpoint_t *)ptr;
  if (ep->cids != NULL) {
    st_foreach_with_replace(ep->cids, quic_endpoint_compact_check_i,
                            quic_endpoint_compact_replace_i, 0);
  }
  ep->conns = rb_gc_location(ep->conns);
  ep->responses = rb_gc_location(ep->responses);
  ep->closed = rb_gc_location(ep->closed);
  ep->local_sockaddr = rb_gc_location(ep->local_sockaddr);
  ep->tls_context = rb_gc_location(ep->tls_context);
  ep->transport_params = rb_gc_location(ep->transport_params);
  ep->settings = rb_gc_location(ep->settings);
}

static int
quic_endpoint_free_key_i(st_data_t key, st_data_t value, st_data_t arg)
{
  (void)value;
  (void)arg;
  xfree((void *)key);
  return ST_CONTINUE;
}

/* Connections still in the table are unreachable too (each marks the
   Endpoint), and quic_conn_free never reaches back here. */
static void
quic_endpoint_free(void *ptr)
{
  quic_endpoint_t *ep = (quic_endpoint_t *)ptr;
  if (ep->cids != NULL) {
    st_foreach(ep->cids, quic_endpoint_free_key_i, 0);
    st_free_table(ep->cids);
  }
  OPENSSL_cleanse(ep->reset_secret, sizeof(ep->reset_secret));
  xfree(ep);
}

static size_t
quic_endpoint_size(const void *ptr)
{
  const quic_endpoint_t *ep = (const quic_endpoint_t *)ptr;
  return sizeof(*ep) + (ep->cids != NULL ? st_memsize(ep->cids) : 0);
}

static const rb_data_type_t quic_endpoint_data_type = {
  "QUIC::Endpoint",
  {quic_endpoint_mark, quic_endpoint_free, quic_endpoint_size, quic_endpoint_compact,},
  NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY,
};

static quic_endpoint_t *
quic_endpoint_get(VALUE self)
{
  quic_endpoint_t *ep;
  TypedData_Get_Struct(self, quic_endpoint_t, &quic_endpoint_data_type, ep);
  return ep;
}

void
quic_endpoint_associate_cid(quic_endpoint_t *ep, const ngtcp2_cid *cid, VALUE conn)
{
  /* For a key already there, st_insert replaces the value and keeps the
     key it has, so a copy is made only for a new key. */
  if (st_lookup(ep->cids, (st_data_t)cid, NULL)) {
    st_insert(ep->cids, (st_data_t)cid, (st_data_t)conn);
    return;
  }
  ngtcp2_cid *key = ALLOC(ngtcp2_cid);
  *key = *cid;
  st_insert(ep->cids, (st_data_t)key, (st_data_t)conn);
}

void
quic_endpoint_dissociate_cid(quic_endpoint_t *ep, const ngtcp2_cid *cid, VALUE conn)
{
  st_data_t key = (st_data_t)cid;
  st_data_t value;
  if (!st_lookup(ep->cids, key, &value) || (VALUE)value != conn) return;
  /* st_delete hands back the stored key. */
  if (st_delete(ep->cids, &key, &value)) xfree((void *)key);
}

int
quic_endpoint_generate_reset_token(const quic_endpoint_t *ep, uint8_t *token,
                                   const ngtcp2_cid *cid)
{
  return ngtcp2_crypto_generate_stateless_reset_token(token, ep->reset_secret,
                                                      sizeof(ep->reset_secret), cid) == 0
    ? 0 : -1;
}

static VALUE
quic_addr_str(const ngtcp2_addr *addr)
{
  return rb_str_new((const char *)addr->addr, (long)addr->addrlen);
}

/* Queue an answer for #write_pkt. Returns false when the queue is full and
   the answer was dropped. */
static bool
quic_endpoint_push_response(quic_endpoint_t *ep, VALUE pkt, VALUE to)
{
  if (RARRAY_LEN(ep->responses) >= QUIC_ENDPOINT_MAX_RESPONSES) return false;
  rb_ary_push(ep->responses, rb_assoc_new(pkt, to));
  return true;
}

static void
quic_conn_set_error(quic_conn_t *c, VALUE exc)
{
  /* The first failure is the reason; what follows is its consequence. */
  if (NIL_P(c->error)) c->error = exc;
}

/* Take the Stateless Resets that came back since the last call, one per
   whole second. Computed on read_pkt rather than with a timer. */
static void
quic_endpoint_refill_reset_bucket(quic_endpoint_t *ep, ngtcp2_tstamp now)
{
  if (ep->reset_bucket >= QUIC_STATELESS_RESET_BURST) {
    ep->reset_refill_ts = now;
    return;
  }
  uint64_t n = (now - ep->reset_refill_ts) / NGTCP2_SECONDS;
  if (n == 0) return;
  ep->reset_bucket = n >= QUIC_STATELESS_RESET_BURST - ep->reset_bucket
    ? QUIC_STATELESS_RESET_BURST : ep->reset_bucket + (size_t)n;
  ep->reset_refill_ts += n * NGTCP2_SECONDS;
}

static void
quic_endpoint_send_version_negotiation(quic_endpoint_t *ep, const ngtcp2_version_cid *vc,
                                       VALUE remote)
{
  uint8_t unused_bits;
  uint32_t grease;
  if (RAND_bytes(&unused_bits, 1) != 1 ||
      RAND_bytes((uint8_t *)&grease, sizeof(grease)) != 1) {
    return;
  }
  /* A reserved version (0x?a?a?a?a) ahead of the one supported, so that
     clients keep handling versions they do not know (RFC 9000 section
     6.3). */
  uint32_t versions[] = {(grease & 0xf0f0f0f0U) | 0x0a0a0a0aU, NGTCP2_PROTO_VER_V1};

  VALUE pkt = rb_str_buf_new(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
  ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(
    (uint8_t *)RSTRING_PTR(pkt), NGTCP2_MAX_UDP_PAYLOAD_SIZE, unused_bits, vc->scid, vc->scidlen,
    vc->dcid, vc->dcidlen, versions, sizeof(versions) / sizeof(versions[0]));
  if (n <= 0) return;
  rb_str_set_len(pkt, n);
  quic_endpoint_push_response(ep, pkt, rb_str_dup(remote));
}

/* Tell the peer that this Endpoint has no state for dcid, as
   examples/server.cc's send_stateless_reset does. */
static void
quic_endpoint_send_stateless_reset(quic_endpoint_t *ep, const ngtcp2_cid *dcid, size_t pktlen,
                                   VALUE remote)
{
  if (ep->reset_bucket == 0) return;
  ep->reset_bucket--;

  ngtcp2_stateless_reset_token token;
  if (quic_endpoint_generate_reset_token(ep, token.data, dcid) != 0) return;

  /* Shorter than the packet that prompted it, so that two endpoints cannot
     keep answering each other's resets (RFC 9000 section 10.3.3): one byte
     shorter up to 43 bytes, 42 bytes beyond. */
  enum { MAX_RANDLEN = NGTCP2_MAX_CIDLEN + 22 - NGTCP2_STATELESS_RESET_TOKENLEN };
  uint8_t rand_bytes[MAX_RANDLEN];
  size_t randlen = pktlen <= 43 ? pktlen - NGTCP2_STATELESS_RESET_TOKENLEN - 1 : MAX_RANDLEN;
  if (RAND_bytes(rand_bytes, (int)randlen) != 1) return;

  VALUE pkt = rb_str_buf_new(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
  ngtcp2_ssize n = ngtcp2_pkt_write_stateless_reset2(
    (uint8_t *)RSTRING_PTR(pkt), NGTCP2_MAX_UDP_PAYLOAD_SIZE, &token, rand_bytes, randlen);
  if (n <= 0) return;
  rb_str_set_len(pkt, n);
  quic_endpoint_push_response(ep, pkt, rb_str_dup(remote));
}

/* Turn a new connection away with CONNECTION_REFUSED in an Initial packet,
   without making any state for it. */
static void
quic_endpoint_refuse(quic_endpoint_t *ep, const ngtcp2_pkt_hd *hd, VALUE remote)
{
  VALUE pkt = rb_str_buf_new(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
  /* Despite its documentation, this returns the packet's length. */
  ngtcp2_ssize n = ngtcp2_crypto_write_connection_close(
    (uint8_t *)RSTRING_PTR(pkt), NGTCP2_MAX_UDP_PAYLOAD_SIZE, hd->version, &hd->scid, &hd->dcid,
    NGTCP2_CONNECTION_REFUSED, NULL, 0);
  if (n <= 0) return;
  rb_str_set_len(pkt, n);
  quic_endpoint_push_response(ep, pkt, rb_str_dup(remote));
}

/* The closing and draining periods last three PTOs (RFC 9000 section
   10.2). */
static ngtcp2_tstamp
quic_close_deadline(const quic_conn_t *c, ngtcp2_tstamp now)
{
  return now + 3 * ngtcp2_conn_get_pto2(c->conn);
}

/* Enter the closing period with a CONNECTION_CLOSE carrying ccerr, and
   queue that packet. Returns false when ngtcp2 cannot build it; the
   connection then has to leave the table at once. */
static bool
quic_endpoint_start_closing(quic_endpoint_t *ep, quic_conn_t *c, const ngtcp2_ccerr *ccerr)
{
  ngtcp2_tstamp now = quic_now();
  if (ngtcp2_conn_in_closing_period2(c->conn) || ngtcp2_conn_in_draining_period2(c->conn)) {
    if (c->close_deadline == 0) c->close_deadline = quic_close_deadline(c, now);
    return true;
  }

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;
  VALUE pkt = rb_str_buf_new(QUIC_WRITE_PKT_BUFLEN);
  ngtcp2_ssize n = ngtcp2_conn_write_connection_close(
    c->conn, &ps.path, &pi, (uint8_t *)RSTRING_PTR(pkt), QUIC_WRITE_PKT_BUFLEN, ccerr, now);
  if (n < 0) return false;

  c->close_deadline = quic_close_deadline(c, now);
  c->close_next_pkts_recv = 1;
  if (n == 0) return true;
  rb_str_set_len(pkt, n);
  c->closebuf = pkt;
  quic_endpoint_push_response(ep, rb_str_dup(pkt), quic_addr_str(&ps.path.remote));
  return true;
}

/* A packet came for a connection in its closing period: send the
   CONNECTION_CLOSE again, but no more than three times what the peer sent
   and to every 1st, 2nd, 4th, 8th, ... packet only (examples/server.cc's
   Handler::send_conn_close). */
static void
quic_endpoint_resend_close(quic_endpoint_t *ep, quic_conn_t *c, size_t pktlen, VALUE remote)
{
  if (NIL_P(c->closebuf)) return;

  c->close_bytes_recv += pktlen;
  c->close_pkts_recv++;
  uint64_t len = (uint64_t)RSTRING_LEN(c->closebuf);
  if (c->close_pkts_recv < c->close_next_pkts_recv ||
      c->close_bytes_recv * 3 < c->close_bytes_sent + len) {
    return;
  }
  if (!quic_endpoint_push_response(ep, rb_str_dup(c->closebuf), rb_str_dup(remote))) return;
  c->close_bytes_sent += len;
  c->close_next_pkts_recv *= 2;
}

/* Deal with a failure of connection c: rv from ngtcp2, or an exception a
   Ruby callback left in c->pending_exc (rv is ignored then). Never raises
   for it; the reason goes to c->error. Returns true when the connection has
   to leave the table now, false when it stays for its closing or draining
   period. */
static bool
quic_endpoint_handle_error(quic_endpoint_t *ep, quic_conn_t *c, int rv)
{
  VALUE exc = c->pending_exc;
  c->pending_exc = Qnil;
  if (!NIL_P(exc)) rv = NGTCP2_ERR_CALLBACK_FAILURE;

  ngtcp2_ccerr ccerr;
  switch (rv) {
  case NGTCP2_ERR_DRAINING:
    /* The peer closed the connection. */
    c->close_deadline = quic_close_deadline(c, quic_now());
    return false;
  case NGTCP2_ERR_IDLE_CLOSE:
    /* Gone without a word, as RFC 9000 section 10.1 has it. */
    return true;
  case NGTCP2_ERR_DROP_CONN:
  case NGTCP2_ERR_RETRY:
    quic_conn_set_error(c, quic_ngtcp2_error_new(rv));
    return true;
  case NGTCP2_ERR_CALLBACK_FAILURE:
    quic_conn_set_error(c, NIL_P(exc) ? quic_ngtcp2_error_new(rv) : exc);
    if (c->close_error_set) {
      ccerr = c->close_error;
    } else {
      ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_INTERNAL_ERROR, NULL, 0);
    }
    break;
  case NGTCP2_ERR_CRYPTO:
    /* Send the TLS alert itself, as examples/server.cc does; set_liberr
       would only know that the handshake failed. */
    quic_conn_set_error(c, quic_conn_error_new(c, rv));
    ngtcp2_ccerr_set_tls_alert(&ccerr, ngtcp2_conn_get_tls_alert2(c->conn), NULL, 0);
    break;
  default:
    quic_conn_set_error(c, quic_conn_error_new(c, rv));
    ngtcp2_ccerr_set_liberr(&ccerr, rv, NULL, 0);
    break;
  }
  return !quic_endpoint_start_closing(ep, c, &ccerr);
}

/* Drop every table entry of conn and cut it loose from the Endpoint. */
static void
quic_endpoint_detach(quic_endpoint_t *ep, VALUE conn, quic_conn_t *c)
{
  quic_endpoint_dissociate_cid(ep, ngtcp2_conn_get_client_initial_dcid2(c->conn), conn);

  size_t n = ngtcp2_conn_get_scid2(c->conn, NULL);
  VALUE tmp;
  ngtcp2_cid *scids = ALLOCV_N(ngtcp2_cid, tmp, n);
  ngtcp2_conn_get_scid2(c->conn, scids);
  for (size_t i = 0; i < n; i++) quic_endpoint_dissociate_cid(ep, &scids[i], conn);
  ALLOCV_END(tmp);

  c->endpoint = NULL;
  c->endpoint_owner = Qnil;
}

/* Take conn out of the table and hand it to #take_closed. */
static void
quic_endpoint_remove(quic_endpoint_t *ep, VALUE conn, quic_conn_t *c)
{
  quic_endpoint_detach(ep, conn, c);
  long len = RARRAY_LEN(ep->conns);
  for (long i = 0; i < len; i++) {
    if (RARRAY_AREF(ep->conns, i) != conn) continue;
    rb_ary_delete_at(ep->conns, i);
    if (i < ep->write_cursor) ep->write_cursor--;
    break;
  }
  rb_ary_push(ep->closed, conn);
}

void
quic_endpoint_close_conn(quic_endpoint_t *ep, quic_conn_t *c, const ngtcp2_ccerr *ccerr)
{
  if (!quic_endpoint_start_closing(ep, c, ccerr)) quic_endpoint_remove(ep, c->owner, c);
}

/* QUIC::Endpoint._new(local_sockaddr:, tls_context:, transport_params:,
   settings:, max_connections:), every keyword required. Endpoint.new
   (lib/quic/endpoint.rb) fills in the defaults. */
static VALUE
quic_endpoint_s_new(int argc, VALUE *argv, VALUE klass)
{
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "0:", &opts);
  if (NIL_P(opts)) opts = rb_hash_new();

  ID keywords[5];
  VALUE values[5];
  keywords[0] = rb_intern("local_sockaddr");
  keywords[1] = rb_intern("tls_context");
  keywords[2] = rb_intern("transport_params");
  keywords[3] = rb_intern("settings");
  keywords[4] = rb_intern("max_connections");
  rb_get_kwargs(opts, keywords, 5, 0, values);

  quic_require_sockaddr(values[0], "local_sockaddr");
  quic_tls_context_get(values[1]);
  /* Read both once here, so that a bad value raises now rather than on
     every new connection. */
  ngtcp2_transport_params params;
  quic_fill_transport_params(&params, values[2]);
  ngtcp2_settings settings;
  quic_fill_settings(&settings, values[3]);
  long max_connections = NUM2LONG(values[4]);
  if (max_connections <= 0) {
    rb_raise(rb_eArgError, "max_connections must be positive (got %ld)", max_connections);
  }

  quic_endpoint_t *ep;
  VALUE self = TypedData_Make_Struct(klass, quic_endpoint_t, &quic_endpoint_data_type, ep);
  ep->conns = Qnil;
  ep->responses = Qnil;
  ep->closed = Qnil;
  ep->local_sockaddr = rb_str_new_frozen(values[0]);
  ep->tls_context = values[1];
  ep->transport_params = values[2];
  ep->settings = values[3];
  ep->max_connections = max_connections;
  ep->accepting = true;
  ep->reset_bucket = QUIC_STATELESS_RESET_BURST;
  ep->reset_refill_ts = quic_now();
  if (RAND_bytes(ep->reset_secret, sizeof(ep->reset_secret)) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(stateless reset secret) failed");
  }
  ep->conns = rb_ary_new();
  ep->responses = rb_ary_new();
  ep->closed = rb_ary_new();
  ep->cids = st_init_table(&quic_cid_hash_type);
  return self;
}

struct quic_endpoint_read_args {
  VALUE self;
  quic_endpoint_t *ep;
  VALUE packet;
  VALUE remote;
  ngtcp2_path path;
};

/* A packet for a connection in the table. */
static VALUE
quic_endpoint_dispatch(struct quic_endpoint_read_args *a, VALUE conn)
{
  quic_conn_t *c = quic_conn_get(conn);
  const uint8_t *data = (const uint8_t *)RSTRING_PTR(a->packet);
  size_t datalen = (size_t)RSTRING_LEN(a->packet);

  if (ngtcp2_conn_in_closing_period2(c->conn)) {
    quic_endpoint_resend_close(a->ep, c, datalen, a->remote);
    return Qnil;
  }
  if (c->close_deadline != 0) return Qnil;

  int rv = quic_conn_read_pkt_raw(c, &a->path, data, datalen);
  if ((rv != 0 || !NIL_P(c->pending_exc)) && quic_endpoint_handle_error(a->ep, c, rv)) {
    quic_endpoint_remove(a->ep, conn, c);
    return Qnil;
  }
  return conn;
}

/* A packet for no connection in the table: a new connection, or one this
   Endpoint has forgotten. */
static VALUE
quic_endpoint_accept(struct quic_endpoint_read_args *a, const ngtcp2_cid *dcid)
{
  quic_endpoint_t *ep = a->ep;
  const uint8_t *data = (const uint8_t *)RSTRING_PTR(a->packet);
  size_t datalen = (size_t)RSTRING_LEN(a->packet);

  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, data, datalen) != 0) {
    /* A short header packet long enough that a reset shorter than it can
       still pass for one (examples/server.cc). */
    if (!(data[0] & 0x80) && datalen >= QUIC_SCID_LEN + 21) {
      quic_endpoint_send_stateless_reset(ep, dcid, datalen, a->remote);
    }
    return Qnil;
  }

  if (!ep->accepting || RARRAY_LEN(ep->conns) >= ep->max_connections) {
    quic_endpoint_refuse(ep, &hd, a->remote);
    return Qnil;
  }

  /* As in Server._accept, a token is accepted without checking it. */
  VALUE conn = quic_server_conn_new(rb_cQUICConnectionServer, &hd, &a->path, ep->tls_context,
                                    ep->transport_params, ep->settings, ep, a->self);
  quic_conn_t *c = quic_conn_get(conn);
  int rv = quic_conn_read_pkt_raw(c, &a->path, data, datalen);
  if (rv != 0 || !NIL_P(c->pending_exc)) {
    /* As examples/server.cc: send the CONNECTION_CLOSE, if there is one,
       and forget the connection. It never joins the table. */
    quic_endpoint_handle_error(ep, c, rv);
    quic_endpoint_detach(ep, conn, c);
    return Qnil;
  }

  quic_endpoint_associate_cid(ep, ngtcp2_conn_get_client_initial_dcid2(c->conn), conn);
  size_t n = ngtcp2_conn_get_scid2(c->conn, NULL);
  VALUE tmp;
  ngtcp2_cid *scids = ALLOCV_N(ngtcp2_cid, tmp, n);
  ngtcp2_conn_get_scid2(c->conn, scids);
  for (size_t i = 0; i < n; i++) quic_endpoint_associate_cid(ep, &scids[i], conn);
  ALLOCV_END(tmp);
  rb_ary_push(ep->conns, conn);
  return conn;
}

static VALUE
quic_endpoint_read_pkt_body(VALUE arg)
{
  struct quic_endpoint_read_args *a = (struct quic_endpoint_read_args *)arg;
  const uint8_t *data = (const uint8_t *)RSTRING_PTR(a->packet);
  size_t datalen = (size_t)RSTRING_LEN(a->packet);

  quic_endpoint_refill_reset_bucket(a->ep, quic_now());

  /* ngtcp2_pkt_decode_version_cid asserts datalen > 0. */
  if (datalen == 0) return Qnil;

  ngtcp2_version_cid vc;
  int rv = ngtcp2_pkt_decode_version_cid(&vc, data, datalen, QUIC_SCID_LEN);
  if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
    quic_endpoint_send_version_negotiation(a->ep, &vc, a->remote);
    return Qnil;
  }
  /* A supported version never carries a DCID longer than this. */
  if (rv != 0 || vc.dcidlen > NGTCP2_MAX_CIDLEN) return Qnil;

  ngtcp2_cid dcid;
  ngtcp2_cid_init(&dcid, vc.dcid, vc.dcidlen);
  st_data_t conn;
  if (st_lookup(a->ep->cids, (st_data_t)&dcid, &conn)) {
    return quic_endpoint_dispatch(a, (VALUE)conn);
  }
  return quic_endpoint_accept(a, &dcid);
}

static VALUE
quic_endpoint_read_pkt_unlock(VALUE arg)
{
  rb_str_unlocktmp(((struct quic_endpoint_read_args *)arg)->packet);
  return Qnil;
}

/* #read_pkt(packet, remote:, local: nil): route one datagram. Returns the
   Connection::Server it went to, which may be a new one, or nil when the
   Endpoint answered or dropped it. A connection's own failure is never
   raised; it closes that connection (see quic_endpoint_handle_error). */
static VALUE
quic_endpoint_read_pkt(int argc, VALUE *argv, VALUE self)
{
  VALUE packet = Qnil;
  VALUE opts = Qnil;
  rb_scan_args(argc, argv, "1:", &packet, &opts);
  if (NIL_P(opts)) opts = rb_hash_new();

  ID keywords[2];
  VALUE values[2];
  keywords[0] = rb_intern("remote");
  keywords[1] = rb_intern("local");
  rb_get_kwargs(opts, keywords, 1, 1, values);

  quic_endpoint_t *ep = quic_endpoint_get(self);
  VALUE remote = values[0];
  VALUE local = values[1] == Qundef || NIL_P(values[1]) ? ep->local_sockaddr : values[1];
  quic_require_binary(packet, "packet");
  quic_require_sockaddr(remote, "remote");
  quic_require_sockaddr(local, "local");

  struct quic_endpoint_read_args args;
  args.self = self;
  args.ep = ep;
  args.packet = packet;
  args.remote = remote;
  args.path.local.addr = (struct sockaddr *)RSTRING_PTR(local);
  args.path.local.addrlen = (ngtcp2_socklen)RSTRING_LEN(local);
  args.path.remote.addr = (struct sockaddr *)RSTRING_PTR(remote);
  args.path.remote.addrlen = (ngtcp2_socklen)RSTRING_LEN(remote);
  args.path.user_data = NULL;

  /* Callbacks run Ruby code, which must not change the packet under ngtcp2. */
  rb_str_locktmp(packet);
  VALUE conn = rb_ensure(quic_endpoint_read_pkt_body, (VALUE)&args,
                         quic_endpoint_read_pkt_unlock, (VALUE)&args);
  RB_GC_GUARD(local);
  RB_GC_GUARD(remote);
  return conn;
}

/* #write_pkt: the next packet to send as [packet, destination sockaddr], or
   nil when there is none left. The Endpoint's own answers go first, then
   each connection's packets until it has none, resuming where the last
   call stopped. After nil, the next call starts over. */
static VALUE
quic_endpoint_write_pkt(VALUE self)
{
  quic_endpoint_t *ep = quic_endpoint_get(self);
  for (;;) {
    if (RARRAY_LEN(ep->responses) > 0) return rb_ary_shift(ep->responses);
    if (ep->write_cursor >= RARRAY_LEN(ep->conns)) {
      ep->write_cursor = 0;
      return Qnil;
    }

    VALUE conn = RARRAY_AREF(ep->conns, ep->write_cursor);
    quic_conn_t *c = quic_conn_get(conn);
    /* A closing connection's CONNECTION_CLOSE goes through responses. */
    if (c->close_deadline != 0) {
      ep->write_cursor++;
      continue;
    }

    VALUE pkt = rb_str_buf_new(QUIC_WRITE_PKT_BUFLEN);
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_ssize n = quic_conn_write_pkt_raw(conn, c, &ps.path, (uint8_t *)RSTRING_PTR(pkt));
    if (n < 0 || !NIL_P(c->pending_exc)) {
      if (quic_endpoint_handle_error(ep, c, n < 0 ? (int)n : 0)) {
        quic_endpoint_remove(ep, conn, c);
      }
      continue;
    }
    if (n == 0) {
      ep->write_cursor++;
      continue;
    }
    rb_str_set_len(pkt, n);
    return rb_assoc_new(pkt, quic_addr_str(&ps.path.remote));
  }
}

/* #expiry: the earliest time (CLOCK_MONOTONIC ns) any connection in the
   table needs #handle_expiry, the end of a closing or draining period
   included. nil when no connection waits for one. */
static VALUE
quic_endpoint_expiry(VALUE self)
{
  quic_endpoint_t *ep = quic_endpoint_get(self);
  ngtcp2_tstamp earliest = UINT64_MAX;
  for (long i = 0; i < RARRAY_LEN(ep->conns); i++) {
    quic_conn_t *c = quic_conn_get(RARRAY_AREF(ep->conns, i));
    ngtcp2_tstamp t = c->close_deadline != 0 ? c->close_deadline : ngtcp2_conn_get_expiry2(c->conn);
    if (t < earliest) earliest = t;
  }
  return earliest == UINT64_MAX ? Qnil : ULL2NUM((unsigned long long)earliest);
}

/* #handle_expiry: run the timers of every connection due, and take out of
   the table those whose closing or draining period is over or that timed
   out. */
static VALUE
quic_endpoint_handle_expiry(VALUE self)
{
  quic_endpoint_t *ep = quic_endpoint_get(self);
  ngtcp2_tstamp now = quic_now();
  /* A copy, since connections leave ep->conns along the way. */
  VALUE conns = rb_ary_dup(ep->conns);
  for (long i = 0; i < RARRAY_LEN(conns); i++) {
    VALUE conn = RARRAY_AREF(conns, i);
    quic_conn_t *c = quic_conn_get(conn);
    if (c->endpoint == NULL) continue;
    if (c->close_deadline != 0) {
      if (c->close_deadline <= now) quic_endpoint_remove(ep, conn, c);
      continue;
    }
    if (ngtcp2_conn_get_expiry2(c->conn) > now) continue;

    c->now = now;
    int rv = ngtcp2_conn_handle_expiry(c->conn, now);
    if ((rv != 0 || !NIL_P(c->pending_exc)) && quic_endpoint_handle_error(ep, c, rv)) {
      quic_endpoint_remove(ep, conn, c);
    }
  }
  RB_GC_GUARD(conns);
  return Qnil;
}

/* #take_closed: the connections that left the table since the last call,
   in the order they left. */
static VALUE
quic_endpoint_take_closed(VALUE self)
{
  quic_endpoint_t *ep = quic_endpoint_get(self);
  VALUE closed = ep->closed;
  ep->closed = rb_ary_new();
  return closed;
}

/* #connections: the connections in the table, closing and draining ones
   included. */
static VALUE
quic_endpoint_connections(VALUE self)
{
  return rb_ary_dup(quic_endpoint_get(self)->conns);
}

/* #stop_accepting: refuse every new connection from now on with
   CONNECTION_REFUSED. There is no way back. */
static VALUE
quic_endpoint_stop_accepting(VALUE self)
{
  quic_endpoint_get(self)->accepting = false;
  return Qnil;
}

/* #tls_context=: the context new connections are made with. Connections
   already made keep theirs. */
static VALUE
quic_endpoint_set_tls_context(VALUE self, VALUE tls_context)
{
  quic_endpoint_t *ep = quic_endpoint_get(self);
  quic_tls_context_get(tls_context);
  ep->tls_context = tls_context;
  return tls_context;
}

void
Init_quic_endpoint(VALUE rb_mQUICArg)
{
  if (RAND_bytes((uint8_t *)&quic_cid_hash_seed, sizeof(quic_cid_hash_seed)) != 1) {
    rb_raise(rb_eRuntimeError, "RAND_bytes(CID hash seed) failed");
  }

  rb_cQUICEndpoint = rb_define_class_under(rb_mQUICArg, "Endpoint", rb_cObject);
  rb_undef_alloc_func(rb_cQUICEndpoint);
  rb_define_singleton_method(rb_cQUICEndpoint, "_new", quic_endpoint_s_new, -1);
  rb_define_method(rb_cQUICEndpoint, "read_pkt", quic_endpoint_read_pkt, -1);
  rb_define_method(rb_cQUICEndpoint, "write_pkt", quic_endpoint_write_pkt, 0);
  rb_define_method(rb_cQUICEndpoint, "expiry", quic_endpoint_expiry, 0);
  rb_define_method(rb_cQUICEndpoint, "handle_expiry", quic_endpoint_handle_expiry, 0);
  rb_define_method(rb_cQUICEndpoint, "take_closed", quic_endpoint_take_closed, 0);
  rb_define_method(rb_cQUICEndpoint, "connections", quic_endpoint_connections, 0);
  rb_define_method(rb_cQUICEndpoint, "stop_accepting", quic_endpoint_stop_accepting, 0);
  rb_define_method(rb_cQUICEndpoint, "tls_context=", quic_endpoint_set_tls_context, 1);
}
