# frozen_string_literal: true

require "test_helper"
require "socket"

# A QUIC::Connection::Server in a thread and a Client in the main thread,
# talking over UDP on 127.0.0.1. No external server is involved, so this
# always runs. Pumping both ends from one thread would deadlock.
class TestQUICLoopbackE2E < Minitest::Test
  include TestCertificates

  ALPN = ["perf"].freeze
  JOIN_TIMEOUT = 15

  def test_echo_round_trip_small_payload
    echo_round_trip("hello quic loopback\n")
  end

  # Spans many packets, and stays within the default 256 KB stream flow
  # control window.
  def test_echo_round_trip_multi_packet_payload
    echo_round_trip(Random.new(42).bytes(100 * 1024))
  end

  # The client connects to 127.0.0.1 but expects example.com, which is not in
  # the server certificate's SAN. The client does not send CONNECTION_CLOSE
  # when verification fails, so the server waits out its handshake timeout,
  # shortened to one second here.
  def test_handshake_fails_on_hostname_mismatch
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = QUIC::Connection::Server.accept(
        sock: server_sock,
        certificate_path: creds.certificate_path,
        private_key_path: creds.private_key_path,
        settings: QUIC::Settings.default.with(alpn: ALPN, handshake_timeout: 1_000_000_000)
      )
      server.run
    end

    sock = UDPSocket.new(Socket::AF_INET)
    sock.connect("127.0.0.1", port)
    # Only _open takes a server_name that differs from the address.
    client = QUIC::Connection::Client._open(
      local_sockaddr: Addrinfo.udp("0.0.0.0", 0).to_sockaddr,
      remote_sockaddr: Addrinfo.udp("127.0.0.1", port).to_sockaddr,
      server_name: "example.com",
      transport_params: QUIC::TransportParams.default,
      settings: QUIC::Settings.default.with(alpn: ALPN, ca_file: creds.ca_file)
    )
    error = assert_raises(QUIC::Error::CertificateVerifyFailed) { client.bind(sock).run }
    assert_equal OpenSSL::X509::V_ERR_HOSTNAME_MISMATCH, error.verify_result
    assert_equal 42, error.tls_alert # bad_certificate

    assert_raises(QUIC::Error::HandshakeTimeout) { finish_server(server_thread) }
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  private

  # The client verifies the server certificate against the test CA, sends
  # payload with FIN, and reads the echo up to the server's FIN. The server
  # echoes one stream and pumps until the stream is closed, or until the
  # client's #close ends the connection first.
  def echo_round_trip(payload)
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = QUIC::Connection::Server.accept(
        sock: server_sock,
        certificate_path: creds.certificate_path,
        private_key_path: creds.private_key_path,
        settings: QUIC::Settings.default.with(alpn: ALPN)
      )
      server.run
      stream = server.accept_stream(timeout: 10)
      raise "no stream accepted within 10 seconds" if stream.nil?
      stream.write(stream.read, fin: true)
      begin
        server.pump_until { stream.closed? }
      rescue QUIC::Error::Closed
        # The client closed the connection before the stream finished.
      end
    end

    client = QUIC::Connection::Client.new(
      host: "127.0.0.1", port: port, address_family: :inet,
      settings: QUIC::Settings.default.with(alpn: ALPN, ca_file: creds.ca_file)
    )
    sock = UDPSocket.new(Socket::AF_INET)
    sock.connect(client.remote_address.ip_address, client.remote_address.ip_port)
    client.bind(sock).run

    stream = client.open_bidi_stream
    stream.write(payload, fin: true)
    assert_equal payload.b, stream.read
    client.close

    finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  def bind_server_socket
    sock = UDPSocket.new(Socket::AF_INET)
    sock.bind("127.0.0.1", 0)
    [sock, sock.addr[1]]
  end

  # Exceptions in the thread are collected by #finish_server rather than
  # reported when the thread dies.
  def start_server_thread
    Thread.new do
      Thread.current.report_on_exception = false
      yield
    end
  end

  # Wait for the server thread and return its value. Thread#join re-raises
  # whatever the thread raised.
  def finish_server(thread)
    flunk "server thread did not finish within #{JOIN_TIMEOUT} seconds" unless thread.join(JOIN_TIMEOUT)
    thread.value
  end

  # Cleanup after the sockets are closed. A server still blocked in
  # Server.accept (no datagram arrived) or in the I/O loop gets IOError from
  # the closed socket and ends. What it raised was either examined already
  # or is not the reason the test failed.
  def stop_server(thread)
    thread&.join(JOIN_TIMEOUT)
  rescue
    nil
  end
end
