# frozen_string_literal: true

require "test_helper"
require "pathname"
require "socket"

# A QUIC::Connection::Server in a thread and a Client in the main thread,
# talking over UDP on 127.0.0.1. No external server is involved, so this
# always runs. Pumping both ends from one thread would deadlock.
class TestQUICLoopbackE2E < Minitest::Test
  include TestCertificates
  include TestLoopback
  include TestQlog

  ALPN = ["perf"].freeze

  def test_echo_round_trip_small_payload
    echo_round_trip("hello quic loopback\n")
  end

  # Spans many packets, and stays within the default 256 KB stream flow
  # control window.
  def test_echo_round_trip_multi_packet_payload
    echo_round_trip(Random.new(42).bytes(100 * 1024))
  end

  # Each end writes its connection's qlog to <qlog_dir>/<its SCID in
  # hex>.sqlog. The echo makes far more qlog than stdio buffers, so the
  # first record has reached the file by the time the connection is done.
  def test_qlog_dir_gets_a_file_per_connection
    Dir.mktmpdir do |dir|
      server_dir = File.join(dir, "server")
      client_dir = File.join(dir, "client")
      Dir.mkdir(server_dir)
      Dir.mkdir(client_dir)

      echo_round_trip(
        Random.new(3).bytes(64 * 1024),
        server_settings: {qlog_dir: server_dir},
        client_settings: {qlog_dir: Pathname(client_dir)}
      )

      [server_dir, client_dir].each do |qlog_dir|
        files = Dir.children(qlog_dir)
        assert_equal 1, files.size, "one qlog file in #{qlog_dir}"
        assert_match(/\A\h{16}\.sqlog\z/, files.first)
        qlog = File.binread(File.join(qlog_dir, files.first))
        assert qlog.start_with?("\x1e".b), "qlog is a JSON text sequence"
        assert_includes qlog, "qlog_version"
      end
    end
  end

  # #close closes the Client's qlog file, and the CONNECTION_CLOSE that puts
  # the Server in its draining period closes the Server's, without waiting
  # for GC.
  def test_close_and_draining_close_the_qlog_files
    without_gc do
      Dir.mktmpdir do |dir|
        server_dir = File.join(dir, "server")
        client_dir = File.join(dir, "client")
        Dir.mkdir(server_dir)
        Dir.mkdir(client_dir)
        creds = loopback_credentials
        server_sock, port = bind_server_socket
        server_thread = start_server_thread do
          server = QUIC::Connection::Server.accept(
            sock: server_sock,
            certificate_path: creds.certificate_path,
            private_key_path: creds.private_key_path,
            settings: QUIC::Settings.default.with(alpn: ALPN, qlog_dir: server_dir)
          )
          server.run
          server.pump_until { false }
        rescue QUIC::Error::Closed
          # The client closed the connection.
        end

        client = QUIC::Connection::Client.new(
          host: "127.0.0.1", port: port, address_family: :inet,
          settings: QUIC::Settings.default.with(alpn: ALPN, ca_file: creds.ca_file, qlog_dir: client_dir)
        )
        sock = UDPSocket.new(Socket::AF_INET)
        sock.connect(client.remote_address.ip_address, client.remote_address.ip_port)
        client.bind(sock).run
        client.close
        assert_qlog_closed(File.join(client_dir, Dir.children(client_dir).first))

        finish_server(server_thread)
        assert_qlog_closed(File.join(server_dir, Dir.children(server_dir).first))
      ensure
        sock&.close
        server_sock&.close
        stop_server(server_thread)
      end
    end
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
      server.run
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
      server.run
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

  # The server stops reading a stream (STOP_SENDING) while most of what the
  # client queued for it is still unsent: the congestion window lets out
  # only a little before the first ACK. The client drops the rest, its
  # writes to the stream fail from then on, and another stream of the same
  # connection carries on.
  def test_stop_sending_drops_what_the_client_had_not_sent
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(server_sock, creds)
      server.run
      stopped = server.accept_stream(timeout: 10)
      raise "no stream accepted within 10 seconds" if stopped.nil?
      stopped.close_read
      echo = server.accept_stream(timeout: 10)
      raise "no second stream accepted within 10 seconds" if echo.nil?
      echo.write(echo.read, fin: true)
      begin
        server.pump_until { false }
      rescue QUIC::Error::Closed
        # The client closed the connection.
      end
    end

    client, sock = connect_loopback_client(port, creds)
    stream = client.open_bidi_stream
    queued = stream.write_nonblock(Random.new(5).bytes(1024 * 1024))
    assert_equal QUIC::TransportParams.default.initial_max_stream_data_bidi_remote, queued

    error = pump_until_stream_closed(client, stream)
    assert_equal "the peer asked to stop sending (error code 0)", error.message
    assert_raises(QUIC::Error::StreamClosed) { stream.write("more") }

    other = client.open_bidi_stream
    other.write("still connected", fin: true)
    assert_equal "still connected", other.read
    client.close

    finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  # A blocking #write waits for the peer's window to open. STOP_SENDING
  # means it never will, and the write gives up.
  def test_stop_sending_ends_a_write_waiting_for_the_window
    window = 64 * 1024
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(
        server_sock, creds,
        transport_params: QUIC::TransportParams.default.with(initial_max_stream_data_bidi_remote: window)
      )
      server.run
      stream = server.accept_stream(timeout: 10)
      raise "no stream accepted within 10 seconds" if stream.nil?
      stream.close_read
      begin
        server.pump_until { false }
      rescue QUIC::Error::Closed
        # The client closed the connection.
      end
    end

    client, sock = connect_loopback_client(port, creds)
    stream = client.open_bidi_stream
    stream.write("hello")
    error = assert_raises(QUIC::Error::StreamClosed) { stream.write("x" * window) }
    assert_equal "the peer asked to stop sending (error code 0)", error.message
    client.close

    finish_server(server_thread)
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  # #reset shuts the send side of a stream whose bytes are all still
  # queued. #write_pkt finds the send side shut, drops them, and another
  # stream of the same connection carries on.
  def test_reset_drops_what_the_client_had_not_sent
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(server_sock, creds)
      server.run
      # The reset stream never carried data, so it is never accepted.
      echo = server.accept_stream(timeout: 10)
      raise "no stream accepted within 10 seconds" if echo.nil?
      echo.write(echo.read, fin: true)
      begin
        server.pump_until { false }
      rescue QUIC::Error::Closed
        # The client closed the connection.
      end
    end

    client, sock = connect_loopback_client(port, creds)
    stream = client.open_bidi_stream
    stream.write_nonblock(Random.new(6).bytes(1024 * 1024))
    stream.reset

    other = client.open_bidi_stream
    other.write("still connected", fin: true)
    assert_equal "still connected", other.read
    client.close

    finish_server(server_thread)
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
      server.run
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

  # Pump until #write_nonblock on stream stops raising WaitWritable (its
  # window is full) and raises StreamClosed instead, for up to timeout
  # seconds. Returns the StreamClosed.
  def pump_until_stream_closed(client, stream, timeout: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      flunk "the stream was not closed within #{timeout} seconds" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      client.pump_once(timeout: 0.1)
      begin
        stream.write_nonblock("x")
      rescue QUIC::Error::WaitWritable
        next
      rescue QUIC::Error::StreamClosed => e
        return e
      end
      flunk "the stream's window opened"
    end
  end

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
  def echo_round_trip(payload, server_settings: {}, client_settings: {})
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = QUIC::Connection::Server.accept(
        sock: server_sock,
        certificate_path: creds.certificate_path,
        private_key_path: creds.private_key_path,
        settings: QUIC::Settings.default.with(alpn: ALPN, **server_settings)
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
      settings: QUIC::Settings.default.with(alpn: ALPN, ca_file: creds.ca_file, **client_settings)
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
