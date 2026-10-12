# frozen_string_literal: true

require "test_helper"

$LOAD_PATH.unshift File.expand_path("ext", __dir__)
begin
  require "quic_ext_echo"
rescue LoadError
  # Not built: `rake compile` builds it into test/ext/ next to quic.so.
end

# quic.so's C function table (quic/ext.h), driven by the test-only
# quic_ext_echo extension: a stream handler that sends every bidirectional
# stream back to the peer, standing in for the http3 gem.
class TestQUICExtAPI < Minitest::Test
  include TestCertificates
  include TestLoopback

  ALPN = ["echo"].freeze
  LOCAL_SOCKADDR = Addrinfo.udp("127.0.0.1", 4433).to_sockaddr
  REMOTE_SOCKADDR = Addrinfo.udp("127.0.0.1", 50000).to_sockaddr

  def setup
    skip "test/ext/quic_ext_echo is not built" unless defined?(QUICExtEcho)
    skip "quic/ext.h needs rb_ext_resolve_symbol (Ruby 3.3 or later)" unless QUICExtEcho::AVAILABLE
  end

  def test_get_api_answers_only_its_major_version
    assert QUICExtEcho.load_api(1)
    refute QUICExtEcho.load_api(0)
    refute QUICExtEcho.load_api(2)
  end

  def test_conn_get_raises_type_error_for_other_objects
    assert_raises(TypeError) { QUICExtEcho::Handler.attach(Object.new) }
  end

  def test_handler_owns_every_stream
    server = server_from_client_initial
    QUICExtEcho::Handler.attach(server)

    assert_raises(QUIC::Error::InvalidState) { server.open_bidi_stream }
    assert_raises(QUIC::Error::InvalidState) { server.open_uni_stream }
    assert_raises(QUIC::Error::InvalidState) { server.accept_stream_nonblock }
    assert_raises(QUIC::Error::InvalidState) { server.accept_stream(timeout: 0) }
  end

  # QUIC_EXT_ERR_INVALID_STATE (-1): a connection takes one handler, and none
  # once it has a QUIC::Stream.
  def test_set_stream_handler_refuses_a_second_handler
    server = server_from_client_initial
    QUICExtEcho::Handler.attach(server)
    error = assert_raises(RuntimeError) { QUICExtEcho::Handler.attach(server) }
    assert_equal "set_stream_handler failed: -1", error.message
  end

  def test_set_stream_handler_refuses_a_connection_with_streams
    server = server_from_client_initial
    server.instance_variable_get(:@streams)[0] = :a_stream
    error = assert_raises(RuntimeError) { QUICExtEcho::Handler.attach(server) }
    assert_equal "set_stream_handler failed: -1", error.message
  end

  def test_local_max_streams_bidi_reports_initial_max_streams_bidi
    server = server_from_client_initial(
      transport_params: QUIC::TransportParams.default.with(initial_max_streams_bidi: 7)
    )
    handler = QUICExtEcho::Handler.attach(server)
    assert_equal 7, handler.local_max_streams_bidi
  end

  # The handler and the connection mark each other, and the connection
  # follows the handler's owner object when it moves.
  def test_handler_survives_gc_compaction
    initial = client_initial
    server = server_from_client_initial(initial: initial)
    handler = QUICExtEcho::Handler.attach(server)

    GC.start
    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    server.read_pkt(initial, local_sockaddr: LOCAL_SOCKADDR, remote_sockaddr: REMOTE_SOCKADDR)
    refute_nil server.write_pkt
    assert_equal 100, handler.local_max_streams_bidi
  end

  # The client is in the QUIC::Stream mode; the server's streams belong to
  # the echo handler. 512 KiB is twice the client's stream window, so the
  # handler also sees its stream blocked and unblocked.
  def test_handler_echoes_streams_over_loopback
    payloads = [Random.new(3).bytes(512 * 1024), "a second stream\n"]
    creds = loopback_credentials
    server_sock, port = bind_server_socket
    server_thread = start_server_thread do
      server = accept_loopback_server(server_sock, creds)
      handler = QUICExtEcho::Handler.attach(server)
      server.run
      server.pump_until { handler.closed_streams >= payloads.size }
      handler
    end

    client, sock = connect_loopback_client(port, creds)
    payloads.each do |payload|
      stream = client.open_bidi_stream
      write_in_chunks(stream, payload)
      assert_equal payload.b, stream.read
    end
    # Keep acknowledging until the server has seen both streams close.
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + JOIN_TIMEOUT
    while server_thread.alive? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      client.pump_once(timeout: 0.05)
    end
    client.close

    handler = finish_server(server_thread)
    assert_equal 1, handler.handshakes
    assert_equal payloads.size, handler.closed_streams
  ensure
    sock&.close
    server_sock&.close
    stop_server(server_thread)
  end

  private

  def client_initial
    QUIC::Connection::Client.new(
      host: "127.0.0.1", port: 443, settings: QUIC::Settings.default.with(alpn: ALPN)
    ).write_pkt
  end

  # A Server built from a Client's first Initial, without sockets. No
  # stream exists yet, so a handler can be attached.
  def server_from_client_initial(initial: client_initial, transport_params: QUIC::TransportParams.default)
    QUIC::Connection::Server._accept(
      initial_packet: initial,
      local_sockaddr: LOCAL_SOCKADDR,
      remote_sockaddr: REMOTE_SOCKADDR,
      certificate_path: loopback_credentials.certificate_path,
      private_key_path: loopback_credentials.private_key_path,
      transport_params: transport_params,
      settings: QUIC::Settings.default.with(alpn: ALPN)
    )
  end
end
