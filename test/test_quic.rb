# frozen_string_literal: true

require "test_helper"

class TestQUIC < Minitest::Test
  include TestCertificates

  def test_that_it_has_a_version_number
    refute_nil ::QUIC::VERSION
  end

  # libcrypto comes from the host, so which of the two this reports depends on
  # where the extension was built. picotls's OpenSSL backend supports both.
  def test_library_versions_reports_host_libcrypto
    versions = QUIC.library_versions
    assert_kind_of String, versions[:ngtcp2]
    assert_match(/\A(OpenSSL|LibreSSL)\b/, versions[:openssl])
  end

  # picotls has no version macro and no releases, so extconf.rb bakes in the
  # commit it built against.
  def test_library_versions_reports_picotls_commit
    assert_match(/\A[0-9a-f]{40}\z/, QUIC.library_versions[:picotls])
  end

  def test_connection_client_initializes
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_instance_of QUIC::Connection::Client, client
  end

  def test_open_bidi_stream_raises_before_handshake
    # Without a completed handshake the server's transport parameters have
    # not arrived, so ngtcp2 reports NGTCP2_ERR_STREAM_ID_BLOCKED. This is
    # mapped to QUIC::Error::Unknown via the default switch arm.
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    err = assert_raises(QUIC::Error) { client.open_bidi_stream }
    assert_match(/STREAM_ID_BLOCKED/, err.message)
  end

  def test_open_uni_stream_raises_before_handshake
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    err = assert_raises(QUIC::Error) { client.open_uni_stream }
    assert_match(/STREAM_ID_BLOCKED/, err.message)
  end

  def test_transport_params_default_returns_data_instance
    tp = QUIC::TransportParams.default
    assert_kind_of QUIC::TransportParams, tp
    assert_kind_of Data, tp
    assert_equal 1_048_576, tp.initial_max_data
    assert_equal 100, tp.initial_max_streams_bidi
    assert_equal 30_000_000_000, tp.max_idle_timeout
  end

  def test_settings_default_returns_data_instance
    settings = QUIC::Settings.default
    assert_kind_of QUIC::Settings, settings
    assert_kind_of Data, settings
    assert_equal :cubic, settings.cc_algo
    assert_equal 10_000_000_000, settings.handshake_timeout
    assert_equal false, settings.no_pmtud
    assert_equal [], settings.alpn
  end

  def test_transport_params_with_overrides_one_field
    tp = QUIC::TransportParams.default.with(initial_max_data: 2**30)
    assert_equal 2**30, tp.initial_max_data
    assert_equal 100, tp.initial_max_streams_bidi
  end

  def test_write_pkt_returns_initial_packet
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    buf = client.write_pkt
    refute_nil buf
    assert_instance_of String, buf
    assert_predicate buf.bytesize, :positive?
    assert_equal Encoding::ASCII_8BIT, buf.encoding
    assert_equal 0xc0, buf.unpack1("C") & 0xc0
  end

  def test_write_pkt_returns_nil_after_draining_initial_flight
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    packets = []
    16.times do
      pkt = client.write_pkt
      break if pkt.nil?
      packets << pkt
    end
    refute_empty packets, "expected at least one Initial packet from the first flight"
    assert_nil client.write_pkt, "expected nil once the Initial flight is drained"
  end

  def test_write_pkt_reuses_provided_binary_buffer
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    buf = String.new(capacity: 1200, encoding: Encoding::BINARY)
    assert_same buf, client.write_pkt(buf)
  end

  def test_write_pkt_raises_on_utf8_buffer
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    buf = String.new("", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) { client.write_pkt(buf) }
  end

  def test_read_pkt_raises_on_utf8_packet
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sockaddr = Addrinfo.udp("127.0.0.1", 0).to_sockaddr
    utf8_packet = String.new("\x00", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) do
      client.read_pkt(utf8_packet, local_sockaddr: sockaddr, remote_sockaddr: sockaddr)
    end
  end

  def test_read_pkt_raises_on_utf8_local_sockaddr
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sockaddr = Addrinfo.udp("127.0.0.1", 0).to_sockaddr
    binary_packet = String.new("\x00", encoding: Encoding::BINARY)
    utf8_addr = String.new("invalid", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) do
      client.read_pkt(binary_packet, local_sockaddr: utf8_addr, remote_sockaddr: sockaddr)
    end
  end

  def test_read_pkt_raises_on_utf8_remote_sockaddr
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sockaddr = Addrinfo.udp("127.0.0.1", 0).to_sockaddr
    binary_packet = String.new("\x00", encoding: Encoding::BINARY)
    utf8_addr = String.new("invalid", encoding: Encoding::UTF_8)
    assert_raises(ArgumentError) do
      client.read_pkt(binary_packet, local_sockaddr: sockaddr, remote_sockaddr: utf8_addr)
    end
  end

  def test_settings_with_alpn_overrides_value
    settings = QUIC::Settings.default.with(alpn: ["h3"])
    assert_equal ["h3"], settings.alpn
  end

  def test_settings_default_verifies_peer
    settings = QUIC::Settings.default
    assert_equal :peer, settings.verify_mode
    assert_nil settings.ca_file
    assert_nil settings.ca_path
  end

  # Code written before the verification fields existed builds Settings
  # without them; it still gets the verifying defaults.
  def test_settings_new_without_verify_fields_uses_defaults
    settings = QUIC::Settings.new(
      cc_algo: :cubic, initial_rtt: 333_000_000, max_window: 0, max_stream_window: 0,
      handshake_timeout: 10_000_000_000, no_pmtud: false, alpn: []
    )
    assert_equal :peer, settings.verify_mode
    assert_nil settings.ca_file
    assert_nil settings.ca_path
  end

  def test_handshake_completed_is_false_initially
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_equal false, client.handshake_completed?
  end

  def test_in_closing_period_is_false_initially
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_equal false, client.in_closing_period?
  end

  def test_in_draining_period_is_false_initially
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_equal false, client.in_draining_period?
  end

  def test_expiry_returns_integer_after_init
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    expiry = client.expiry
    assert_kind_of Integer, expiry
    assert_predicate expiry, :positive?
  end

  def test_handle_expiry_does_not_raise_after_init
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_nil client.handle_expiry
  end

  def test_alpn_with_h3_does_not_raise_during_open
    settings = QUIC::Settings.default.with(alpn: ["h3"])
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443, settings: settings)
    assert_instance_of QUIC::Connection::Client, client
  end

  # Open a client through _open so server_name can differ from the address.
  # Nothing is sent, so no server is needed.
  def open_client(settings: QUIC::Settings.default, server_name: "example.com")
    QUIC::Connection::Client._open(
      local_sockaddr: Addrinfo.udp("0.0.0.0", 0).to_sockaddr,
      remote_sockaddr: Addrinfo.udp("127.0.0.1", 443).to_sockaddr,
      server_name: server_name,
      transport_params: QUIC::TransportParams.default,
      settings: settings
    )
  end

  # Long header, fixed bit set, Initial packet type (0b1100_xxxx).
  def assert_initial_packet(client)
    pkt = client.write_pkt
    refute_nil pkt
    assert_equal 0xc0, pkt.getbyte(0) & 0xf0
  end

  def test_open_with_default_store_produces_initial
    assert_initial_packet(open_client)
  end

  def test_open_with_ca_file_produces_initial
    Dir.mktmpdir do |dir|
      assert_initial_packet(open_client(settings: QUIC::Settings.default.with(ca_file: write_ca_file(dir))))
    end
  end

  def test_open_raises_on_missing_ca_file
    settings = QUIC::Settings.default.with(ca_file: "/nonexistent/quic-ruby-ca.pem")
    error = assert_raises(ArgumentError) { open_client(settings: settings) }
    assert_match(/failed to load ca_file/, error.message)
  end

  def test_open_raises_on_ca_file_without_certificates
    Dir.mktmpdir do |dir|
      path = File.join(dir, "empty.pem")
      File.write(path, "")
      error = assert_raises(ArgumentError) { open_client(settings: QUIC::Settings.default.with(ca_file: path)) }
      assert_match(/failed to load ca_file/, error.message)
    end
  end

  def test_open_raises_on_ca_path_not_directory
    Dir.mktmpdir do |dir|
      settings = QUIC::Settings.default.with(ca_path: write_ca_file(dir))
      error = assert_raises(ArgumentError) { open_client(settings: settings) }
      assert_match(/ca_path is not a directory/, error.message)
    end
  end

  # Every misconfiguration of the verification settings is an ArgumentError,
  # a wrong type included.
  def test_open_raises_on_non_path_ca_file
    error = assert_raises(ArgumentError) { open_client(settings: QUIC::Settings.default.with(ca_file: 1)) }
    assert_match(/ca_file must be a String or Pathname/, error.message)
  end

  def test_open_ignores_ca_file_with_verify_mode_none
    settings = QUIC::Settings.default.with(verify_mode: :none)
    assert_initial_packet(open_client(settings: settings.with(ca_file: "/nonexistent/quic-ruby-ca.pem")))
    assert_initial_packet(open_client(settings: settings.with(ca_file: 1)))
  end

  # An empty name would make OpenSSL skip the host name check entirely.
  def test_open_raises_on_empty_server_name_when_verifying
    error = assert_raises(ArgumentError) { open_client(server_name: "") }
    assert_match(/server_name must be a non-empty string/, error.message)
  end

  def test_open_raises_on_nul_in_server_name_when_verifying
    assert_raises(ArgumentError) { open_client(server_name: "example.com\0evil") }
  end

  def test_open_allows_empty_server_name_without_verification
    client = open_client(settings: QUIC::Settings.default.with(verify_mode: :none), server_name: "")
    assert_instance_of QUIC::Connection::Client, client
  end

  def test_open_raises_on_unknown_verify_mode
    assert_raises(ArgumentError) { open_client(settings: QUIC::Settings.default.with(verify_mode: :optional)) }
    assert_raises(ArgumentError) { open_client(settings: QUIC::Settings.default.with(verify_mode: "peer")) }
  end

  def test_certificate_verify_failed_is_a_crypto_error
    assert_operator QUIC::Error::CertificateVerifyFailed, :<, QUIC::Error::CryptoError
    error = QUIC::Error::CertificateVerifyFailed.new("certificate verify failed")
    assert_nil error.tls_alert
    assert_nil error.verify_result
    assert_nil QUIC::Error::CryptoError.new("ERR_CRYPTO").tls_alert
  end

  # Build a bare QUIC::Stream for tests that exercise the in-Ruby state
  # machine (initiator lookup, recv_buffer mutation, pending_chunks queue)
  # without needing a completed handshake. The C-side quic_stream_t is
  # zero-initialized by the alloc func; we only have to wire the Ruby ivars.
  def build_stream(id:, client: nil)
    QUIC::Stream.allocate.tap do |s|
      s.instance_variable_set(:@id, id)
      s.instance_variable_set(:@client, client)
      s.instance_variable_set(:@pending_chunks, [])
      s.instance_variable_set(:@recv_buffer, String.new(encoding: Encoding::BINARY))
    end
  end

  def test_stream_id_alias
    s = build_stream(id: 4)
    assert_equal 4, s.id
    assert_equal 4, s.stream_id
  end

  def test_stream_initiator_table
    assert_equal :client_bidi, build_stream(id: 0).initiator
    assert_equal :server_bidi, build_stream(id: 1).initiator
    assert_equal :client_uni, build_stream(id: 2).initiator
    assert_equal :server_uni, build_stream(id: 3).initiator
    # Same pattern repeats for higher IDs.
    assert_equal :client_bidi, build_stream(id: 4).initiator
  end

  def test_stream_eof_is_false_initially
    refute_predicate build_stream(id: 0), :eof?
  end

  def test_stream_read_nonblock_raises_wait_readable_when_empty
    err = assert_raises(QUIC::Error::WaitReadable) { build_stream(id: 0).read_nonblock(1024) }
    assert_kind_of IO::WaitReadable, err
  end

  def test_stream_write_returns_bytesize_and_queues_chunk
    s = build_stream(id: 0)
    assert_equal 5, s.write("hello")
    chunks = s.instance_variable_get(:@pending_chunks)
    assert_equal 1, chunks.length
    assert_equal "hello", chunks.first
    assert_equal Encoding::BINARY, chunks.first.encoding
  end

  def test_stream_write_with_fin_sets_state
    s = build_stream(id: 0)
    s.write("bye", fin: true)
    # Once FIN is queued, further writes raise StreamClosed.
    assert_raises(QUIC::Error::StreamClosed) { s.write("more") }
  end

  def test_client_run_raises_not_bound_without_bind
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_raises(QUIC::Error::NotBound) { client.run }
  end

  def test_client_bind_returns_self_and_records_socket
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    begin
      assert_same client, client.bind(sock)
      assert_same sock, client.bound_socket
    ensure
      sock.close
    end
  end

  # Build a Stream whose @client is a real (handshake-incomplete) Client so
  # the flow control window check kicks in. ngtcp2 reports
  # max_stream_data_left = 0 for unopened streams, which is exactly the
  # condition Stream#write_nonblock should turn into QUIC::Error::WaitWritable.
  def test_stream_write_nonblock_raises_wait_writable_when_window_zero
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    stream = QUIC::Stream.allocate
    stream.instance_variable_set(:@id, 0)
    stream.instance_variable_set(:@client, client)
    stream.instance_variable_set(:@pending_chunks, [])
    stream.instance_variable_set(:@recv_buffer, String.new(encoding: Encoding::BINARY))

    err = assert_raises(QUIC::Error::WaitWritable) { stream.write_nonblock("x") }
    assert_kind_of IO::WaitWritable, err
  end

  # Stream#write blocks by repeatedly calling @client.pump_once, which in
  # turn raises QUIC::Error::NotBound when no socket has been bound. We
  # surface that error verbatim from #write.
  def test_stream_write_raises_not_bound_when_client_not_bound
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    stream = QUIC::Stream.allocate
    stream.instance_variable_set(:@id, 0)
    stream.instance_variable_set(:@client, client)
    stream.instance_variable_set(:@pending_chunks, [])
    stream.instance_variable_set(:@recv_buffer, String.new(encoding: Encoding::BINARY))

    assert_raises(QUIC::Error::NotBound) { stream.write("x") }
  end

  # Stream#read must hand back whatever is already buffered before it goes
  # anywhere near the I/O loop. A bare Stream has no @client, so a read that
  # pumps first blows up with NoMethodError instead of returning the bytes.
  def test_stream_read_returns_buffered_bytes_without_pumping
    stream = build_stream(id: 0)
    stream.instance_variable_get(:@recv_buffer) << "hello"

    assert_equal "hel", stream.read(3)
    assert_equal "lo", stream.read(2)
  end

  def test_client_close_raises_not_bound_without_bind
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_raises(QUIC::Error::NotBound) { client.close }
  end

  # Before the handshake completes, ngtcp2_conn_write_connection_close
  # returns NGTCP2_ERR_INVALID_STATE. The spec treats this as best-effort,
  # so #close silently no-ops (returns nil without raising). The full
  # handshake -> close -> in_closing_period? path is exercised by the
  # EXTERNAL=1 cloudflare e2e test.
  def test_client_close_returns_nil_when_bound
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    sock.connect("127.0.0.1", 443)
    client.bind(sock)
    begin
      assert_nil client.close
    ensure
      sock.close
    end
  end

  def test_client_close_accepts_error_code_and_reason_kwargs
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    sock.connect("127.0.0.1", 443)
    client.bind(sock)
    begin
      assert_nil client.close(error_code: 42, reason: "bye")
    ensure
      sock.close
    end
  end

  def test_client_close_is_noop_when_already_closed
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    sock = UDPSocket.new
    sock.connect("127.0.0.1", 443)
    client.bind(sock)
    begin
      client.close
      # Second close should not emit another packet nor raise.
      assert_nil client.close
    ensure
      sock.close
    end
  end

  def test_client_remote_address_is_addrinfo
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_kind_of Addrinfo, client.remote_address
    assert_equal "127.0.0.1", client.remote_address.ip_address
    assert_equal 443, client.remote_address.ip_port
  end

  def test_client_address_family_inet_pins_ipv4
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443, address_family: :inet)
    assert_equal Socket::AF_INET, client.remote_address.afamily
  end

  def test_client_address_family_inet6_pins_ipv6
    client = QUIC::Connection::Client.new(host: "::1", port: 443, address_family: :inet6)
    assert_equal Socket::AF_INET6, client.remote_address.afamily
  end

  def test_client_address_family_nil_is_phase4_compatible
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443, address_family: nil)
    assert_instance_of QUIC::Connection::Client, client
    assert_equal Socket::AF_INET, client.remote_address.afamily
  end

  def test_client_address_family_unknown_raises_argument_error
    assert_raises(ArgumentError) do
      QUIC::Connection::Client.new(host: "127.0.0.1", port: 443, address_family: :bogus)
    end
  end

  # The Client TypedData holds a VALUE back-reference (owner) that ngtcp2
  # callbacks resolve through. quic_client_compact follows it via
  # rb_gc_location so GC.compact does not leave it stale. Build a live
  # Client with a couple of bare streams registered, force compaction with
  # reference verification, then confirm the object is still coherent.
  def test_client_survives_gc_compaction
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    streams = client.instance_variable_get(:@streams)
    streams[0] = build_stream(id: 0, client: client)
    streams[1] = build_stream(id: 1, client: client)

    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    assert_equal false, client.handshake_completed?
    assert_kind_of Integer, client.expiry
    assert_same client, streams[0].instance_variable_get(:@client)
  end

  # picotls keeps pointers into the ALPN list for the whole handshake, so the
  # client has to own that memory. Drop every Ruby-side reference to the ALPN
  # strings and the Settings by building them inline, force compaction, then
  # confirm an Initial packet is still produced.
  def test_alpn_list_survives_gc_compaction
    client = QUIC::Connection::Client.new(
      host: "127.0.0.1", port: 443,
      settings: QUIC::Settings.default.with(alpn: [+"h3", +"hq-interop"])
    )

    GC.start
    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    pkt = client.write_pkt
    refute_nil pkt
    # Long header, fixed bit set, Initial packet type (0b1100_xxxx).
    assert_equal 0xc0, pkt.getbyte(0) & 0xf0
    # ngtcp2 pads the client's first Initial to at least 1200 bytes.
    assert_operator pkt.bytesize, :>=, 1200
  end

  # The verifier and its X509_STORE reference live in the C struct, outside
  # Ruby's heap. Build a client that owns a store loaded from ca_file (the
  # file itself is gone by the time compaction runs), then make sure it is
  # still usable after compaction.
  def test_client_with_ca_file_survives_gc_compaction
    client = Dir.mktmpdir do |dir|
      open_client(settings: QUIC::Settings.default.with(ca_file: write_ca_file(dir)))
    end

    GC.start
    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    assert_initial_packet(client)
  end

  # A bare Stream (@client == nil) escapes the ngtcp2 call and only flips
  # the internal reset flag, mirroring #write's bare-Stream escape. After
  # #reset, the existing quic_stream_enqueue guard makes #write raise
  # QUIC::Error::StreamClosed.
  def test_stream_reset_marks_write_side_closed
    s = build_stream(id: 0)
    assert_nil s.reset
    assert_raises(QUIC::Error::StreamClosed) { s.write("data") }
  end

  def test_stream_reset_accepts_error_code
    s = build_stream(id: 0)
    assert_nil s.reset(42)
    assert_raises(QUIC::Error::StreamClosed) { s.write_nonblock("data") }
  end

  def test_stream_reset_is_idempotent
    s = build_stream(id: 0)
    s.reset
    # Second reset must not raise.
    assert_nil s.reset
  end

  def test_accept_stream_nonblock_raises_wait_readable_when_empty
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    err = assert_raises(QUIC::Error::WaitReadable) { client.accept_stream_nonblock }
    assert_kind_of IO::WaitReadable, err
  end

  def test_accept_stream_nonblock_returns_queued_stream
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    queue = client.instance_variable_get(:@accept_queue)
    server_stream = build_stream(id: 1, client: client)
    queue.push(server_stream)

    assert_same server_stream, client.accept_stream_nonblock
    # Queue is now drained.
    assert_raises(QUIC::Error::WaitReadable) { client.accept_stream_nonblock }
  end

  def test_accept_stream_with_zero_timeout_returns_nil_when_empty
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    assert_nil client.accept_stream(timeout: 0)
  end

  def test_accept_stream_returns_queued_stream_without_pumping
    client = QUIC::Connection::Client.new(host: "127.0.0.1", port: 443)
    queue = client.instance_variable_get(:@accept_queue)
    server_stream = build_stream(id: 1, client: client)
    queue.push(server_stream)

    # Queue non-empty: returns immediately, no #bind / pump needed.
    assert_same server_stream, client.accept_stream(timeout: nil)
  end
end
