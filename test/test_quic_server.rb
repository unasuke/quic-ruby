# frozen_string_literal: true

require "test_helper"
require "pathname"

# QUIC::Connection::Server._accept, driven without sockets or threads: an
# Initial packet from a Client goes straight into _accept and #read_pkt.
class TestQUICServer < Minitest::Test
  include TestCertificates

  LOCAL_SOCKADDR = Addrinfo.udp("127.0.0.1", 4433).to_sockaddr
  REMOTE_SOCKADDR = Addrinfo.udp("127.0.0.1", 50000).to_sockaddr

  def test_new_is_private
    assert_raises(NoMethodError) { QUIC::Connection::Server.new }
  end

  def test_accept_raises_on_missing_keywords
    keywords = "initial_packet, local_sockaddr, remote_sockaddr, certificate_path, " \
      "private_key_path, transport_params, settings"

    error = assert_raises(ArgumentError) { QUIC::Connection::Server._accept }
    assert_equal "missing keywords: #{keywords}", error.message

    error = assert_raises(ArgumentError) do
      QUIC::Connection::Server._accept(**accept_args(certificate_path: nil))
    end
    assert_equal "all keywords required: #{keywords}", error.message
  end

  # An empty datagram must not reach ngtcp2_pkt_decode_version_cid, which
  # asserts on it. A truncated Initial fails ngtcp2_accept's 1200-byte
  # minimum, and a short header packet cannot start a connection.
  def test_accept_raises_on_unacceptable_first_packet
    packets = ["".b, client_initial.byteslice(0, 100), "\x40".b + ("\x00" * 1199).b]
    packets.each do |packet|
      error = assert_raises(QUIC::Error::Proto) do
        QUIC::Connection::Server._accept(**accept_args(initial_packet: packet))
      end
      assert_equal "not an acceptable Initial packet", error.message
      assert_nil error.code
    end
  end

  def test_accept_raises_on_unsupported_version
    packet = client_initial
    packet[1, 4] = [0x1a2a3a4a].pack("N")

    error = assert_raises(QUIC::Error::Proto) do
      QUIC::Connection::Server._accept(**accept_args(initial_packet: packet))
    end
    assert_equal "unsupported QUIC version 0x1a2a3a4a (Version Negotiation is not implemented)", error.message
    assert_nil error.code
  end

  def test_accept_raises_on_empty_alpn
    error = assert_raises(ArgumentError) do
      QUIC::Connection::Server._accept(**accept_args(settings: QUIC::Settings.default))
    end
    assert_equal "alpn must not be empty for a server", error.message
  end

  def test_accept_raises_on_non_path_certificate_path
    error = assert_raises(ArgumentError) do
      QUIC::Connection::Server._accept(**accept_args(certificate_path: 1))
    end
    assert_equal "certificate_path must be a String or Pathname (got Integer)", error.message
  end

  def test_accept_raises_on_missing_certificate
    Dir.mktmpdir do |dir|
      path = File.join(dir, "missing.pem")
      error = assert_raises(ArgumentError) do
        QUIC::Connection::Server._accept(**accept_args(certificate_path: path))
      end
      assert_equal "failed to load certificate: #{path}", error.message
    end
  end

  def test_accept_raises_on_certificate_file_without_certificates
    path = loopback_credentials.private_key_path
    error = assert_raises(ArgumentError) do
      QUIC::Connection::Server._accept(**accept_args(certificate_path: path))
    end
    assert_equal "failed to load certificate: #{path}", error.message
  end

  def test_accept_raises_on_broken_certificate_chain
    Dir.mktmpdir do |dir|
      path = File.join(dir, "chain.pem")
      File.write(path, File.read(loopback_credentials.certificate_path) +
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
      error = assert_raises(ArgumentError) do
        QUIC::Connection::Server._accept(**accept_args(certificate_path: path))
      end
      assert_equal "failed to load certificate: #{path}", error.message
    end
  end

  def test_accept_raises_on_missing_private_key
    Dir.mktmpdir do |dir|
      path = File.join(dir, "missing.key")
      error = assert_raises(ArgumentError) do
        QUIC::Connection::Server._accept(**accept_args(private_key_path: path))
      end
      assert_equal "failed to load private key: #{path}", error.message
    end
  end

  def test_accept_raises_on_mismatched_private_key
    Dir.mktmpdir do |dir|
      path = File.join(dir, "other.key")
      File.write(path, OpenSSL::PKey::EC.generate("prime256v1").private_to_pem)
      error = assert_raises(ArgumentError) do
        QUIC::Connection::Server._accept(**accept_args(private_key_path: path))
      end
      assert_equal "private key does not match certificate: #{path}", error.message
    end
  end

  # picotls signs with RSA, P-256, P-384, P-521 and Ed25519 keys only, so a
  # certificate and key on secp256k1 get past the match check and then fail.
  def test_accept_raises_on_unsupported_private_key_type
    key = begin
      OpenSSL::PKey::EC.generate("secp256k1")
    rescue OpenSSL::PKey::PKeyError
      skip "the host libcrypto does not provide secp256k1"
    end

    Dir.mktmpdir do |dir|
      certificate_path = File.join(dir, "k1.pem")
      private_key_path = File.join(dir, "k1.key")
      File.write(certificate_path, self_signed_certificate_pem(key))
      File.write(private_key_path, key.private_to_pem)
      error = assert_raises(ArgumentError) do
        QUIC::Connection::Server._accept(
          **accept_args(certificate_path: certificate_path, private_key_path: private_key_path)
        )
      end
      assert_equal "unsupported private key type: #{private_key_path}", error.message
    end
  end

  def test_accept_returns_server
    server = QUIC::Connection::Server._accept(**accept_args)
    assert_instance_of QUIC::Connection::Server, server
    assert_equal false, server.handshake_completed?
  end

  def test_accept_accepts_pathname_paths
    server = QUIC::Connection::Server._accept(
      **accept_args(
        certificate_path: Pathname(loopback_credentials.certificate_path),
        private_key_path: Pathname(loopback_credentials.private_key_path)
      )
    )
    assert_instance_of QUIC::Connection::Server, server
  end

  # The server's first reply needs the certificate, the signature and the
  # ALPN choice, so this covers the whole TLS setup.
  def test_server_responds_to_client_initial
    initial = client_initial
    server = QUIC::Connection::Server._accept(**accept_args(initial_packet: initial))
    feed_initial(server, initial)

    pkt = server.write_pkt
    refute_nil pkt
    # Long header, fixed bit set, Initial packet type (0b1100_xxxx).
    assert_equal 0xc0, pkt.getbyte(0) & 0xf0
  end

  def test_server_rejects_client_without_common_alpn
    initial = client_initial(alpn: ["h3"])
    server = QUIC::Connection::Server._accept(**accept_args(initial_packet: initial))

    error = assert_raises(QUIC::Error::CryptoError) { feed_initial(server, initial) }
    assert_equal 120, error.tls_alert # no_application_protocol
  end

  # The ALPN copy, the certificate list and the signer live outside Ruby's
  # heap. Build them from settings nothing else references, compact, and
  # make sure the server can still answer.
  def test_server_survives_gc_compaction
    initial = client_initial
    server = QUIC::Connection::Server._accept(**accept_args(initial_packet: initial))

    GC.start
    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    feed_initial(server, initial)
    refute_nil server.write_pkt
  end

  private

  # The first Initial packet of a Client offering alpn. It has to share an
  # ALPN with the server for the handshake to get anywhere.
  def client_initial(alpn: ["perf"])
    QUIC::Connection::Client.new(
      host: "127.0.0.1", port: 443, settings: QUIC::Settings.default.with(alpn: alpn)
    ).write_pkt
  end

  def accept_args(**overrides)
    {
      initial_packet: client_initial,
      local_sockaddr: LOCAL_SOCKADDR,
      remote_sockaddr: REMOTE_SOCKADDR,
      certificate_path: loopback_credentials.certificate_path,
      private_key_path: loopback_credentials.private_key_path,
      transport_params: QUIC::TransportParams.default,
      settings: QUIC::Settings.default.with(alpn: ["perf"])
    }.merge(overrides)
  end

  def feed_initial(server, packet)
    server.read_pkt(packet, local_sockaddr: LOCAL_SOCKADDR, remote_sockaddr: REMOTE_SOCKADDR)
  end

  def self_signed_certificate_pem(key)
    name = OpenSSL::X509::Name.parse("/CN=localhost")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = name
    cert.issuer = name
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 86_400
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert.to_pem
  end
end
