# QUIC

`quic` is a thin Ruby binding around [ngtcp2](https://github.com/ngtcp2/ngtcp2) for the QUIC transport protocol. TLS 1.3 is handled by [picotls](https://github.com/h2o/picotls). ngtcp2 and picotls are vendored at install time via [`mini_portile2`](https://github.com/flavorjones/mini_portile) and linked statically; the cryptographic primitives and X.509 handling come from the host's OpenSSL (or LibreSSL), linked dynamically.

The gem is intentionally optimized for **synchronous I/O and `String`-based buffers**. It exposes ngtcp2 primitives (`#read_pkt` / `#write_pkt` / `#expiry` / `#handle_expiry`) and lets the caller own the I/O loop. If you need Fiber Scheduler / `IO::Buffer` / `async` ecosystem integration, see [`socketry/protocol-quic`](https://github.com/socketry/protocol-quic) instead.

This project is in early development; the public API is not yet stable.

## Installation

```ruby
gem "quic"
```

The gem is built from source at install time, so the host needs:

- OpenSSL 1.1.1 or later, **with its development package** (`libssl-dev`, `openssl-devel`, …). LibreSSL works too — see below.
- `autoconf`, `automake`, `libtool`, `pkg-config` and a C11 compiler, to build ngtcp2.
- either `patch` or `git`, to apply the picotls patch in `ext/quic/patches/` (`mini_portile2` uses `git apply` when `git` is available and falls back to `patch -p1`).

OpenSSL is located through `pkg-config`. If it lives somewhere `pkg-config` does not look, point at the prefix:

```console
$ gem install quic -- --with-openssl-dir=$(brew --prefix openssl@3)
```

Linking the host's libcrypto rather than bundling one is deliberate: the process then shares a single libcrypto with Ruby's own `openssl` extension. Two copies in one process interpose on each other's global symbols, which silently misroutes calls and can crash the VM.

**LibreSSL** is supported and exercised: `ext/quic/patches/picotls/` carries a patch that restores picotls's X25519 key exchange there, which upstream disables because LibreSSL lacks `EVP_PKEY_{get1,set1}_tls_encodedpoint()`. The patch is a no-op on OpenSSL, where X25519 is available anyway.

## Usage

```ruby
require "quic"
require "socket"

client = QUIC::Connection::Client.new(
  host: "cloudflare-quic.com", port: 443, address_family: :inet,
  settings: QUIC::Settings.default.with(alpn: ["h3"])
)
sock = UDPSocket.new(Socket::AF_INET)
sock.connect(client.remote_address.ip_address, client.remote_address.ip_port)
client.bind(sock).run # completes the handshake, verifying the certificate
client.handshake_completed? # => true
```

Pinning the address family and connecting the socket to `client.remote_address` keeps the socket and ngtcp2's connection path on the same peer address; resolving the host name twice could otherwise pick different DNS records.

More complete programs live in [`examples/`](examples/):

- [`handshake_demo.rb`](examples/handshake_demo.rb): prints the library versions and times a handshake.
- [`echo_demo.rb`](examples/echo_demo.rb): exchanges data on a stream with a local echo server.
- [`echo_server_demo.rb`](examples/echo_server_demo.rb): the echo server for `echo_demo.rb`, generating its own certificate.
- [`doq_demo.rb`](examples/doq_demo.rb): sends a DNS over QUIC query.
- [`io_loop_demo.rb`](examples/io_loop_demo.rb): sends the same query from an I/O loop the script owns, calling `#write_pkt` / `#read_pkt` / `#handle_expiry` itself.
- [`verify_demo.rb`](examples/verify_demo.rb): tries the certificate verification settings described below against a public server.

### Server

```ruby
require "quic"
require "socket"

sock = UDPSocket.new(Socket::AF_INET)
sock.bind("127.0.0.1", 4433)
server = QUIC::Connection::Server.accept(
  sock: sock, certificate_path: "server.pem", private_key_path: "server.key",
  settings: QUIC::Settings.default.with(alpn: ["perf"])
)
server.run # completes the handshake
stream = server.accept_stream
stream.write(stream.read, fin: true) # echo everything up to the client's FIN
begin
  server.pump_until { stream.closed? }
rescue QUIC::Error::Closed
  # the client closed the connection before the stream finished
end
```

`accept` connects the socket to the first client that sends to it and serves that one connection only. [`echo_server_demo.rb`](examples/echo_server_demo.rb) generates its own certificate, so it runs as is against `echo_demo.rb`.

### Certificate verification

The server certificate is verified by default, against the system's trusted CAs.

Setting `ca_file` (a PEM bundle) or `ca_path` (a hashed certificate directory) trusts only the certificates found there:

```ruby
settings = QUIC::Settings.default.with(alpn: ["h3"], ca_file: "/path/to/ca.pem")
```

`verify_mode: :none` turns verification off, for example against a local test server with a self-signed certificate:

```ruby
settings = QUIC::Settings.default.with(alpn: ["perf"], verify_mode: :none)
```

## Limitations

- **No certificate revocation checking.** CRLs and OCSP are not consulted.
- **No session resumption or 0-RTT.**
- **The server handles one connection per socket.** `QUIC::Connection::Server.accept` serves the first client that sends to the socket; there is no Retry, address validation, Version Negotiation, or client certificate authentication.
- **Key exchanges and cipher suites are fixed.** X25519, secp256r1 and secp384r1 with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. They cannot be selected from Ruby.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then run `bundle exec rake` to compile the C extension and run the tests + linter. You can also run `bin/console` for an interactive prompt.

To install this gem onto your local machine, run `bundle exec rake install`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/unasuke/quic-ruby. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/unasuke/quic-ruby/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

The gem ships no third-party binaries: [ngtcp2](https://github.com/ngtcp2/ngtcp2) (MIT, with an embedded PCG random number generator under Apache-2.0 OR MIT) and [picotls](https://github.com/h2o/picotls) (MIT) are downloaded and built on the installing machine, and libcrypto is the host's. Their license texts are in [LICENSE-DEPENDENCIES.txt](LICENSE-DEPENDENCIES.txt) for reference.

## Code of Conduct

Everyone interacting in the quic-ruby project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/unasuke/quic-ruby/blob/main/CODE_OF_CONDUCT.md).
