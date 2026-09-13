# frozen_string_literal: true

require "test_helper"
require "socket"

# Stream echo round-trip against a local QUIC echo server.
# Skipped by default; set EXTERNAL=1 and have a server listening at
# QUIC_ECHO_HOST:QUIC_ECHO_PORT (defaults 127.0.0.1:4433) speaking ALPN
# QUIC_ECHO_ALPN (default "perf"). The ngtcp2 source tree's
# examples/server (built with --enable-examples) implements this.
#
# That server usually runs with a self-signed certificate, so the server
# certificate is not verified unless QUIC_ECHO_CA_FILE names a CA to trust.
# When it is set, the certificate must match QUIC_ECHO_HOST, which means an
# IP SAN of 127.0.0.1 with the default host.
class TestQUICEchoE2E < Minitest::Test
  TARGET_HOST = ENV.fetch("QUIC_ECHO_HOST", "127.0.0.1")
  TARGET_PORT = Integer(ENV.fetch("QUIC_ECHO_PORT", "4433"))
  TARGET_ALPN = ENV.fetch("QUIC_ECHO_ALPN", "perf")
  TARGET_CA_FILE = ENV["QUIC_ECHO_CA_FILE"]
  TIMEOUT_SEC = 10

  def setup
    skip "set EXTERNAL=1 to run E2E echo tests" unless ENV["EXTERNAL"] == "1"
  end

  def test_echo_round_trip
    addr = Addrinfo.getaddrinfo(TARGET_HOST, TARGET_PORT, Socket::AF_INET, Socket::SOCK_DGRAM).first
    sock = UDPSocket.new
    sock.connect(addr.ip_address, addr.ip_port)

    settings = QUIC::Settings.default.with(alpn: [TARGET_ALPN])
    settings = if TARGET_CA_FILE.nil? || TARGET_CA_FILE.empty?
      settings.with(verify_mode: :none)
    else
      settings.with(ca_file: TARGET_CA_FILE)
    end
    client = QUIC::Connection::Client._open(
      local_sockaddr: Addrinfo.udp("0.0.0.0", 0).to_sockaddr,
      remote_sockaddr: addr.to_sockaddr,
      server_name: TARGET_HOST,
      transport_params: QUIC::TransportParams.default,
      settings: settings
    )
    client.bind(sock).run

    stream = client.open_bidi_stream
    payload = "hello quic stream\n"
    stream.write(payload, fin: true)
    response = stream.read
    assert_equal payload, response
  ensure
    sock&.close
  end
end
