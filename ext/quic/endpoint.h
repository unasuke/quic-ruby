#ifndef QUIC_ENDPOINT_H
#define QUIC_ENDPOINT_H 1

#include "connection_common.h"

extern VALUE rb_cQUICEndpoint;

/* The CID table, for the get_new_connection_id2 and remove_connection_id
   callbacks of a connection the Endpoint holds. conn is that connection's
   object. Neither touches Ruby objects, so the callbacks need no
   rb_protect. dissociate leaves an entry that maps to another connection
   alone. */
void quic_endpoint_associate_cid(quic_endpoint_t *ep, const ngtcp2_cid *cid, VALUE conn);
void quic_endpoint_dissociate_cid(quic_endpoint_t *ep, const ngtcp2_cid *cid, VALUE conn);

/* The Stateless Reset token for cid, derived from the Endpoint's secret so
   that it can be made again for a CID no longer in the table. token is
   NGTCP2_STATELESS_RESET_TOKENLEN bytes. Returns 0, or -1 on failure. */
int quic_endpoint_generate_reset_token(const quic_endpoint_t *ep, uint8_t *token,
                                       const ngtcp2_cid *cid);

/* Connection#close of a connection the Endpoint holds: build the
   CONNECTION_CLOSE carrying ccerr, queue it for Endpoint#write_pkt and
   start the closing period. When ngtcp2 cannot build the packet, the
   connection leaves the table at once. */
void quic_endpoint_close_conn(quic_endpoint_t *ep, quic_conn_t *c, const ngtcp2_ccerr *ccerr);

#endif /* QUIC_ENDPOINT_H */
