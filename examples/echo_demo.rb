# frozen_string_literal: true

# Stream API demo: open a bidirectional stream, write a small payload with
# FIN, then block on Stream#read until the peer echoes the bytes back and
# closes its side. Requires a local QUIC echo server (default: 127.0.0.1:4433
# with ALPN "perf"); ngtcp2 ships an examples/server binary that does this
# when built with --enable-examples.
#
# Override the target via env vars:
#   QUIC_ECHO_HOST  (default 127.0.0.1)
#   QUIC_ECHO_PORT  (default 4433)
#   QUIC_ECHO_ALPN  (default perf)
#   QUIC_ECHO_CA_FILE (default unset: the server certificate is not verified)
#
# The echo server usually runs with a self-signed certificate, so
# verification is off unless QUIC_ECHO_CA_FILE names a CA to trust. When it
# is set, the certificate must match QUIC_ECHO_HOST, which means an IP SAN
# of 127.0.0.1 with the default host.
#
# Run with: bundle exec ruby examples/echo_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "socket"

TARGET_HOST = ENV.fetch("QUIC_ECHO_HOST", "127.0.0.1")
TARGET_PORT = Integer(ENV.fetch("QUIC_ECHO_PORT", "4433"))
TARGET_ALPN = ENV.fetch("QUIC_ECHO_ALPN", "perf")
TARGET_CA_FILE = ENV["QUIC_ECHO_CA_FILE"]

settings = QUIC::Settings.default.with(alpn: [TARGET_ALPN])
settings = if TARGET_CA_FILE.nil? || TARGET_CA_FILE.empty?
  settings.with(verify_mode: :none)
else
  settings.with(ca_file: TARGET_CA_FILE)
end

# Connect the socket to the address the client resolved, so both talk to the
# same peer (see examples/handshake_demo.rb).
client = QUIC::Connection::Client.new(
  host: TARGET_HOST, port: TARGET_PORT, address_family: :inet, settings: settings
)
addr = client.remote_address
sock = UDPSocket.new(Socket::AF_INET)
sock.connect(addr.ip_address, addr.ip_port)
client.bind(sock).run

stream = client.open_bidi_stream
puts "opened stream #{stream.id} (#{stream.initiator})"

payload = "hello quic stream\n"
stream.write(payload, fin: true)
puts "sent #{payload.bytesize} bytes + FIN"

response = stream.read
puts "received #{response.bytesize} bytes:"
puts response

client.close
sock.close
