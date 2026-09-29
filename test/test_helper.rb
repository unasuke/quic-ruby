# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"

require "minitest/autorun"
require "fileutils"
require "openssl"
require "tmpdir"

module TestCertificates
  LoopbackCredentials = Data.define(:ca_file, :certificate_path, :private_key_path)

  # A test CA (EC P-256) and a server certificate it signed for localhost and
  # 127.0.0.1, with the server's private key: file paths as a
  # LoopbackCredentials. Generated once per test run, whichever test class
  # asks first, and removed when the run ends.
  def loopback_credentials
    TestCertificates.loopback_credentials
  end

  def self.loopback_credentials
    @loopback_credentials ||= generate_loopback_credentials
  end

  def self.generate_loopback_credentials
    now = Time.now
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca_name = OpenSSL::X509::Name.parse("/CN=quic-ruby loopback test CA")
    ca_cert = OpenSSL::X509::Certificate.new
    ca_cert.version = 2
    ca_cert.serial = 1
    ca_cert.subject = ca_name
    ca_cert.issuer = ca_name
    ca_cert.public_key = ca_key
    ca_cert.not_before = now - 60
    ca_cert.not_after = now + 86_400
    factory = OpenSSL::X509::ExtensionFactory.new(ca_cert, ca_cert)
    ca_cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    ca_cert.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    ca_cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))

    server_key = OpenSSL::PKey::EC.generate("prime256v1")
    server_cert = OpenSSL::X509::Certificate.new
    server_cert.version = 2
    server_cert.serial = 2
    server_cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
    server_cert.issuer = ca_name
    server_cert.public_key = server_key
    server_cert.not_before = now - 60
    server_cert.not_after = now + 86_400
    factory = OpenSSL::X509::ExtensionFactory.new(ca_cert, server_cert)
    server_cert.add_extension(factory.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1"))
    server_cert.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
    server_cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))

    dir = Dir.mktmpdir("quic-ruby-loopback-")
    Minitest.after_run { FileUtils.remove_entry(dir) }
    credentials = LoopbackCredentials.new(
      ca_file: File.join(dir, "ca.pem"),
      certificate_path: File.join(dir, "server.pem"),
      private_key_path: File.join(dir, "server.key")
    )
    File.write(credentials.ca_file, ca_cert.to_pem)
    File.write(credentials.certificate_path, server_cert.to_pem)
    File.write(credentials.private_key_path, server_key.private_to_pem)
    credentials
  end
  private_class_method :generate_loopback_credentials

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
