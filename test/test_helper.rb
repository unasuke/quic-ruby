# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"

require "minitest/autorun"
require "openssl"
require "tmpdir"

module TestCertificates
  # A throwaway self-signed CA (EC P-256, valid for one day) that no real
  # server chains to. Returns the certificate as PEM.
  def self_signed_ca_pem(common_name: "quic-ruby test CA")
    key = OpenSSL::PKey::EC.generate("prime256v1")
    name = OpenSSL::X509::Name.parse("/CN=#{common_name}")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = name
    cert.issuer = name
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 86_400
    factory = OpenSSL::X509::ExtensionFactory.new(cert, cert)
    cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert.to_pem
  end

  # Writes #self_signed_ca_pem into dir and returns the file path.
  def write_ca_file(dir)
    File.join(dir, "ca.pem").tap { |path| File.write(path, self_signed_ca_pem) }
  end
end

module TestStreams
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
end
