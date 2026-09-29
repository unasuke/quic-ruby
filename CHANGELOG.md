## [Unreleased]

### Changed
- The extension no longer uses the ngtcp2 functions and callbacks deprecated in 1.22.0 and 1.23.0, and calls their `*2` replacements instead. Behavior is unchanged. ([#8](https://github.com/unasuke/quic-ruby/pull/8))

## [0.0.2] - 2026-09-27

### Added
- Server certificates are now verified, by default against the system's trusted CAs. `QUIC::Settings` gains `verify_mode` (`:peer`, the default, or `:none`), `ca_file` and `ca_path`; setting either of the latter trusts only the certificates found there. The system store is loaded once per process, so `SSL_CERT_FILE` / `SSL_CERT_DIR` are honoured but later changes to them are not picked up. A rejected certificate raises `QUIC::Error::CertificateVerifyFailed`, which carries the X509 error as `#verify_result`. ([#3](https://github.com/unasuke/quic-ruby/pull/3))
- `QUIC::Error::CryptoError#tls_alert` holds the TLS alert this client sent when a handshake failed in `#read_pkt`. Alerts received from the peer are not recorded. ([#3](https://github.com/unasuke/quic-ruby/pull/3))
- `QUIC::Connection::Client#close(error_code: 0, reason: "")` sends an application CONNECTION_CLOSE (frame type 0x1d) over the bound socket and transitions ngtcp2 to the closing period. Pre-handshake calls are a best-effort no-op; a second `#close` after the closing/draining period is also a no-op.
- `QUIC::Connection::Client.new(address_family:)` accepts `:inet` / `:inet6` / `nil` to pin the resolved peer address family, and `QUIC::Connection::Client#remote_address` exposes the resolved `Addrinfo` so callers can line their connected socket's path up with ngtcp2's.
- `QUIC::Connection::Client#accept_stream(timeout: nil)` / `#accept_stream_nonblock` return peer-initiated (server) streams. `#accept_stream` blocks (driving the I/O loop) until a stream arrives, with `timeout: 0` returning immediately and a `Numeric` timeout returning `nil` after the deadline; `#accept_stream_nonblock` raises `QUIC::Error::WaitReadable` when none is queued.
- `QUIC::Stream#reset(error_code = 0)` aborts the send side with RESET_STREAM. Subsequent `#write` / `#write_nonblock` raise `QUIC::Error::StreamClosed`.
- `QUIC.library_versions` now includes a `:picotls` key holding the commit hash picotls was built from, since picotls has neither a version macro nor releases.

### Changed
- The top-level namespace is now `QUIC` instead of `Quic`, and every constant moves with it: `QUIC::Connection::Client`, `QUIC::Stream`, `QUIC::Settings`, `QUIC::TransportParams`, and `QUIC::Error` together with its subclasses. No `Quic` alias is left behind. The gem name and `require "quic"` are unchanged.
- The TLS 1.3 handshake is now performed by [picotls](https://github.com/h2o/picotls) instead of LibreSSL's libssl.
- LibreSSL is no longer vendored. ngtcp2 and picotls are downloaded and built at install time and linked statically, but the cryptographic primitives and X.509 handling now come from the host's OpenSSL (or LibreSSL), linked dynamically and located through `pkg-config` (`--with-openssl-dir=` overrides it). OpenSSL 1.1.1 or later is required, and installing now needs the OpenSSL development package. This shares one libcrypto with Ruby's `openssl` extension: two copies in one process interposed on each other's global symbols, which reported the wrong library version and could segfault depending on `require` order. `QUIC.library_versions[:openssl]` therefore reports the host library.
- ngtcp2 is now built from 1.25.0 (was 1.22.1), and picotls from `f07f1c8`, the revision ngtcp2 1.25.0 is tested against. ngtcp2 now requires a C11 compiler to build. ([#4](https://github.com/unasuke/quic-ruby/pull/4))
- quic.so exports only `Init_quic`. The symbols of the statically linked ngtcp2 and picotls are no longer visible to the rest of the process. ([#2](https://github.com/unasuke/quic-ruby/pull/2), by [@hanazuki](https://github.com/hanazuki))
- `QUIC::Connection::Client` is now GC.compact safe: the C-side struct's back-reference to the owning Ruby object is updated via a `dcompact` slot.
- The entries in this section were rewritten to state the difference from 0.0.1, rather than the succession of steps that got there. ([#5](https://github.com/unasuke/quic-ruby/pull/5))

### Fixed
- `QUIC::Stream#read` hung until the idle timeout instead of returning. Both branches of the blocking read waited on a predicate that could never become true once the peer had sent anything, so the read spun in the I/O loop until ngtcp2 gave up. A read that can be satisfied from the receive buffer now performs no I/O at all.

## [0.0.1] - 2026-05-28

- Initial release
