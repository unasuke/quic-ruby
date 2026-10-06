# frozen_string_literal: true

require "test_helper"
require "socket"

# A QUIC::Connection::Server in a thread and a Client in the main thread,
# talking over UDP on 127.0.0.1. No external server is involved, so this
# always runs. Pumping both ends from one thread would deadlock.
class TestQUICLoopbackE2E < Minitest::Test
  include TestCertificates
  include TestLoopback

  ALPN = ["perf"].freeze

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

  # Three times the default initial_max_data (1 MiB) in each direction.
  # This only finishes if each end gives the peer credit back as the
  # application reads.
  def test_echo_round_trip_past_initial_max_data
    payload = Random.new(7).bytes(3 * 1024 * 1024)
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(server_sock, creds)
      stream = server.accept_stream(timeout: 10)
      raise "no stream accepted within 10 seconds" if stream.nil?
      write_in_chunks(stream, stream.read)
      begin
        server.pump_until { stream.closed? }
      rescue QUIC::Error::Closed
        # The client closed the connection before the stream finished.
      end
    end

    client, sock = connect_loopback_client(port, creds)
    stream = client.open_bidi_stream
    write_in_chunks(stream, payload)
    assert_equal payload.b, stream.read
    client.close

    finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  # The server allows only 4 concurrent bidirectional streams. Opening 10
  # one after another works only if the server raises the limit again as
  # each stream closes.
  def test_peer_opens_more_streams_than_initial_max_streams_bidi
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(
        server_sock, creds,
        transport_params: QUIC::TransportParams.default.with(initial_max_streams_bidi: 4)
      )
      10.times do
        stream = server.accept_stream(timeout: 10)
        raise "no stream accepted within 10 seconds" if stream.nil?
        stream.write(stream.read, fin: true)
      end
      begin
        server.pump_until { false }
      rescue QUIC::Error::Closed
        # The client closed the connection after its last stream.
      end
    end

    client, sock = connect_loopback_client(port, creds)
    10.times do |i|
      stream = open_bidi_stream_when_allowed(client)
      stream.write("stream #{i}", fin: true)
      assert_equal "stream #{i}", stream.read
    end
    client.close

    finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  # A stream the peer opens and closes again (STOP_SENDING makes the server
  # reset its side) waits in the server's accept queue with what it
  # carried. The peer gets no stream in its place until the server accepts
  # it; otherwise a peer could grow the queue without end.
  def test_streams_waiting_to_be_accepted_count_against_the_peers_limit
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    accept = Thread::Queue.new
    server_thread = start_server_thread do
      server = accept_loopback_server(
        server_sock, creds,
        transport_params: QUIC::TransportParams.default.with(initial_max_streams_bidi: 2)
      )
      server.pump_once(timeout: 0.05) while accept.empty?
      stream = server.accept_stream(timeout: 0)
      raise "no stream waiting to be accepted" if stream.nil?
      data = stream.read
      begin
        server.pump_until { false }
      rescue QUIC::Error::Closed
        # The client closed the connection.
      end
      data
    end

    client, sock = connect_loopback_client(port, creds)
    2.times do |i|
      stream = client.open_bidi_stream
      stream.write("stream #{i}", fin: true)
      stream.close_read
    end
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
    client.pump_once(timeout: 0.05) while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    error = assert_raises(QUIC::Error::Unknown) { client.open_bidi_stream }
    assert_includes error.message, "STREAM_ID_BLOCKED"

    accept << true
    open_bidi_stream_when_allowed(client)
    client.close

    assert_equal "stream 0", finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  # Ruby code inside an ngtcp2 callback that raises must not unwind through
  # ngtcp2. With the client's stream registry frozen, stream_open fails when
  # the server opens a stream, and the FrozenError comes out of read_pkt.
  def test_callback_exception_is_raised_from_read_pkt
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(server_sock, creds)
      stream = server.open_bidi_stream
      stream.write("from the server", fin: true)
      begin
        server.pump_until { false }
      rescue QUIC::Error::Closed
        # The client closed the connection after its callback failed.
      end
    end

    client, sock = connect_loopback_client(port, creds)
    client.instance_variable_get(:@streams).freeze
    assert_raises(FrozenError) { client.pump_until { false } }
    client.close

    finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  private

  # open_bidi_stream raises while the peer's stream limit is used up. Pump
  # until the peer raises it (MAX_STREAMS), for up to timeout seconds.
  def open_bidi_stream_when_allowed(client, timeout: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    begin
      client.open_bidi_stream
    rescue QUIC::Error::Unknown => e
      raise unless e.message.include?("STREAM_ID_BLOCKED")
      raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      client.pump_once(timeout: 0.1)
      retry
    end
  end

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
end
