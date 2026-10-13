/* quic/ext.h — the C function table quic.so offers to other extensions.
 *
 * Another extension (the http3 gem) registers a stream handler on a
 * connection and drives it through this table instead of QUIC::Stream.
 * Obtain the table after rb_require("quic") with
 *
 *   quic_ext_get_api_fn get = (quic_ext_get_api_fn)rb_ext_resolve_symbol(
 *       "quic/quic", "quic_ext_get_api");
 *   const quic_ext_api *api = get ? get(QUIC_EXT_ABI_MAJOR) : NULL;
 *
 * Rules:
 *
 * - Version: quic_ext_get_api(major) returns NULL when major differs from
 *   the table's. The structs below grow only by appending, which bumps
 *   abi_minor; reordering, removing or retyping a member bumps abi_major.
 *   Check `size` before calling a member added after the version you were
 *   built against. The handler struct follows the same rules.
 * - Exceptions: no function in the table and no handler function raises a
 *   Ruby exception; they return 0 or a negative error code. The one
 *   exception is conn_get, which raises TypeError for a wrong object and is
 *   meant for initialization called from a Ruby method. A handler function
 *   returning a negative value makes the ngtcp2 callback fail with
 *   NGTCP2_ERR_CALLBACK_FAILURE.
 * - Lifetime: `owner` passed to set_stream_handler is marked by the
 *   connection while it lives. `ud` must not move (allocate it with
 *   xmalloc, not as a Ruby object), and `h` must outlive the connection
 *   (a static const struct). quic.so never calls a handler from its dfree,
 *   and the owner's dfree must not touch the quic_ext_conn.
 * - Where: table functions may be called from inside handler functions.
 *   Everything runs with the GVL held.
 */
#ifndef QUIC_EXT_H
#define QUIC_EXT_H 1

#include <ruby.h>
#include <stddef.h>
#include <stdint.h>

#define QUIC_EXT_ABI_MAJOR 1

#define QUIC_EXT_ERR_INVALID_STATE (-1)
#define QUIC_EXT_ERR_STREAM_ID_BLOCKED (-2)
#define QUIC_EXT_ERR_STREAM_NOT_FOUND (-3)
#define QUIC_EXT_ERR_OTHER (-99)

typedef struct {
  const uint8_t *base;
  size_t len;
} quic_ext_vec;                             /* same layout as ngtcp2_vec */
typedef struct quic_ext_conn quic_ext_conn; /* opaque */

typedef struct {
  size_t size; /* sizeof(quic_ext_stream_handler); tells which members exist */
  int (*recv_stream_data)(void *ud, int64_t id, const uint8_t *data, size_t len,
                          int fin, uint64_t ts, size_t *consumed);
  int (*next_stream_data)(void *ud, int64_t *id, int *fin, quic_ext_vec *vecs,
                          size_t cap, size_t *nvecs);
  int (*stream_data_written)(void *ud, int64_t id, size_t n);
  int (*stream_blocked)(void *ud, int64_t id);
  int (*stream_shut_write)(void *ud, int64_t id);
  int (*acked_stream_data)(void *ud, int64_t id, uint64_t n);
  int (*extend_max_stream_data)(void *ud, int64_t id);
  int (*extend_max_remote_streams_bidi)(void *ud, uint64_t max);
  int (*stream_stop_sending)(void *ud, int64_t id, uint64_t app_error_code);
  int (*stream_reset)(void *ud, int64_t id, uint64_t final_size,
                      uint64_t app_error_code);
  int (*stream_close)(void *ud, int64_t id, int has_code,
                      uint64_t app_error_code);
  int (*handshake_completed)(void *ud);
} quic_ext_stream_handler;

typedef struct {
  uint32_t abi_major; /* bumped only to break compatibility */
  uint32_t abi_minor; /* bumped whenever a member is appended */
  size_t size;        /* sizeof(quic_ext_api) */
  quic_ext_conn *(*conn_get)(VALUE conn); /* TypeError for a wrong object */
  int (*set_stream_handler)(quic_ext_conn *c, const quic_ext_stream_handler *h,
                            void *ud, VALUE owner);
  int (*open_uni_stream)(quic_ext_conn *c, int64_t *id);
  int (*consume)(quic_ext_conn *c, int64_t id, uint64_t n);
  int (*shutdown_stream_read)(quic_ext_conn *c, int64_t id,
                              uint64_t app_error_code);
  int (*shutdown_stream_write)(quic_ext_conn *c, int64_t id,
                               uint64_t app_error_code);
  uint64_t (*local_max_streams_bidi)(quic_ext_conn *c);
  int (*set_application_error)(quic_ext_conn *c, uint64_t app_error_code);
} quic_ext_api;

typedef const quic_ext_api *(*quic_ext_get_api_fn)(uint32_t abi_major);

#endif /* QUIC_EXT_H */
