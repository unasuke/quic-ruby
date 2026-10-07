# frozen_string_literal: true

require "test_helper"
require "pathname"

# QUIC::TLSContext.server on its own. The checks it shares with
# Connection::Server._accept are covered in test_quic_server.rb; here only
# what TLSContext.server adds.
class TestQUICTLSContext < Minitest::Test
  include TestCertificates

  def test_server_returns_tls_context
    assert_instance_of QUIC::TLSContext, QUIC::TLSContext.server(**server_args)
  end

  def test_server_accepts_pathname_paths
    context = QUIC::TLSContext.server(
      **server_args(
        certificate_path: Pathname(loopback_credentials.certificate_path),
        private_key_path: Pathname(loopback_credentials.private_key_path)
      )
    )
    assert_instance_of QUIC::TLSContext, context
  end

  # Only .server makes one: an object without a context behind it would be
  # unusable.
  def test_new_and_allocate_raise
    assert_raises(TypeError) { QUIC::TLSContext.new }
    assert_raises(TypeError) { QUIC::TLSContext.allocate }
  end

  def test_server_raises_on_missing_or_unknown_keywords
    error = assert_raises(ArgumentError) { QUIC::TLSContext.server }
    assert_equal "missing keywords: :certificate_path, :private_key_path, :alpn", error.message

    error = assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(verify_mode: :none)) }
    assert_equal "unknown keyword: :verify_mode", error.message

    error = assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(certificate_path: nil)) }
    assert_equal "certificate_path must not be nil", error.message
  end

  def test_server_raises_on_empty_alpn
    error = assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(alpn: [])) }
    assert_equal "alpn must not be empty for a server", error.message
  end

  def test_server_raises_on_oversized_alpn_entry
    error = assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(alpn: ["x" * 256])) }
    assert_equal "alpn entry must be 1-255 bytes (got 256)", error.message
  end

  def test_server_raises_on_missing_certificate
    Dir.mktmpdir do |dir|
      path = File.join(dir, "missing.pem")
      error = assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(certificate_path: path)) }
      assert_equal "failed to load certificate: #{path}", error.message
    end
  end

  def test_server_raises_on_mismatched_private_key
    Dir.mktmpdir do |dir|
      path = File.join(dir, "other.key")
      File.write(path, OpenSSL::PKey::EC.generate("prime256v1").private_to_pem)
      error = assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(private_key_path: path)) }
      assert_equal "private key does not match certificate: #{path}", error.message
    end
  end

  # A context whose construction raised part way (here with the ALPN list
  # copied but no certificate loaded) is released by the GC like a finished
  # one. Drive both through a collection and compaction, then build another.
  def test_contexts_survive_gc
    3.times { QUIC::TLSContext.server(**server_args) }
    Dir.mktmpdir do |dir|
      path = File.join(dir, "missing.pem")
      3.times do
        assert_raises(ArgumentError) { QUIC::TLSContext.server(**server_args(certificate_path: path)) }
      end
    end

    GC.start
    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    assert_instance_of QUIC::TLSContext, QUIC::TLSContext.server(**server_args)
  end

  private

  def server_args(**overrides)
    {
      certificate_path: loopback_credentials.certificate_path,
      private_key_path: loopback_credentials.private_key_path,
      alpn: ["h3"]
    }.merge(overrides)
  end
end
