## [Unreleased]

### Added
- `Quic::Connection::Client#close(error_code: 0, reason: "")` sends an application CONNECTION_CLOSE (frame type 0x1d) over the bound socket and transitions ngtcp2 to the closing period. Pre-handshake calls are a best-effort no-op; a second `#close` after the closing/draining period is also a no-op.
- `Quic::Connection::Client.new(address_family:)` accepts `:inet` / `:inet6` / `nil` to pin the resolved peer address family, and `Quic::Connection::Client#remote_address` exposes the resolved `Addrinfo` so callers can line their connected socket's path up with ngtcp2's.
- `Quic::Connection::Client#accept_stream(timeout: nil)` / `#accept_stream_nonblock` return peer-initiated (server) streams. `#accept_stream` blocks (driving the I/O loop) until a stream arrives, with `timeout: 0` returning immediately and a `Numeric` timeout returning `nil` after the deadline; `#accept_stream_nonblock` raises `Quic::Error::WaitReadable` when none is queued.
- `Quic::Stream#reset(error_code = 0)` aborts the send side with RESET_STREAM. Subsequent `#write` / `#write_nonblock` raise `Quic::Error::StreamClosed`.

### Changed
- `Quic::Connection::Client` is now GC.compact safe: the C-side struct's back-reference to the owning Ruby object is updated via a `dcompact` slot.
- The TLS 1.3 handshake is now performed by [picotls](https://github.com/h2o/picotls) instead of LibreSSL's libssl. LibreSSL is still vendored and supplies libcrypto (cryptographic primitives and X.509). Server certificates were not verified before and are still not verified, but the omission now goes one step further: OpenSSL checks the CertificateVerify signature against the leaf public key even with verification disabled, while picotls skips that too.
- `Quic.library_versions` now includes a `:picotls` key holding the commit hash picotls was built from. picotls has neither a version macro nor releases. The existing `:ngtcp2` and `:openssl` keys are unchanged; `:openssl` still reports the vendored LibreSSL.
- The top-level namespace is now `QUIC` instead of `Quic`, and every constant moves with it: `QUIC::Connection::Client`, `QUIC::Stream`, `QUIC::Settings`, `QUIC::TransportParams`, and `QUIC::Error` together with its subclasses. No `Quic` alias is left behind. The gem name and `require "quic"` are unchanged. The entries above were written before the rename and keep the old spelling.
- LibreSSL is no longer vendored. ngtcp2 and picotls are still downloaded and built at install time and linked statically, but the cryptographic primitives and X.509 handling now come from the host's OpenSSL (or LibreSSL), linked dynamically and located through `pkg-config` (`--with-openssl-dir=` overrides it). OpenSSL 1.1.1 or later is required, and installing now needs the OpenSSL development package. This shares one libcrypto with Ruby's `openssl` extension: two copies in one process interposed on each other's global symbols, which reported the wrong library version and could segfault depending on `require` order.
- The precompiled `x86_64-linux-gnu` gem is gone; the gem is distributed as a source gem only. It was never released. Without a LibreSSL build, installing from source is much cheaper than it was.
- ngtcp2 is now built from 1.25.0 (was 1.22.1), and picotls from `f07f1c8` (was `b84869f`), the revision ngtcp2 1.25.0 is tested against. ngtcp2 now requires a C11 compiler to build.

## [0.0.1] - 2026-05-28

- Initial release
