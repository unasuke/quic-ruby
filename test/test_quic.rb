# frozen_string_literal: true

require "test_helper"

class TestQUIC < Minitest::Test
  include TestStreams

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

  def test_certificate_verify_failed_is_a_crypto_error
    assert_operator QUIC::Error::CertificateVerifyFailed, :<, QUIC::Error::CryptoError
    error = QUIC::Error::CertificateVerifyFailed.new("certificate verify failed")
    assert_nil error.tls_alert
    assert_nil error.verify_result
    assert_nil QUIC::Error::CryptoError.new("ERR_CRYPTO").tls_alert
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

  # Stream#read must hand back whatever is already buffered before it goes
  # anywhere near the I/O loop. A bare Stream has no @client, so a read that
  # pumps first blows up with NoMethodError instead of returning the bytes.
  def test_stream_read_returns_buffered_bytes_without_pumping
    stream = build_stream(id: 0)
    stream.instance_variable_get(:@recv_buffer) << "hello"

    assert_equal "hel", stream.read(3)
    assert_equal "lo", stream.read(2)
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
end
