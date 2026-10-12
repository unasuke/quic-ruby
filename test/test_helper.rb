# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"

require "minitest/autorun"
require "fileutils"
require "openssl"
require "socket"
require "tmpdir"

# A Server in a thread and a Client in the main thread, talking over UDP on
# 127.0.0.1. Pumping both ends from one thread would deadlock. ALPN defaults
# to the including test class's ALPN constant.
module TestLoopback
  JOIN_TIMEOUT = 15

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

  # Accept the first client on server_sock. The handshake is left to the
  # caller, so that it can attach a stream handler before any stream exists.
  def accept_loopback_server(server_sock, creds, alpn: self.class::ALPN, transport_params: nil)
    QUIC::Connection::Server.accept(
      sock: server_sock,
      certificate_path: creds.certificate_path,
      private_key_path: creds.private_key_path,
      transport_params: transport_params,
      settings: QUIC::Settings.default.with(alpn: alpn)
    )
  end

  # A Client verifying the test CA, bound to a connected socket, with the
  # handshake done.
  def connect_loopback_client(port, creds, alpn: self.class::ALPN)
    client = QUIC::Connection::Client.new(
      host: "127.0.0.1", port: port, address_family: :inet,
      settings: QUIC::Settings.default.with(alpn: alpn, ca_file: creds.ca_file)
    )
    sock = UDPSocket.new(Socket::AF_INET)
    sock.connect(client.remote_address.ip_address, client.remote_address.ip_port)
    client.bind(sock).run
    [client, sock]
  end

  # Stream#write waits until the whole payload fits in the peer's window,
  # which can be smaller than the payload, so write it piece by piece. FIN
  # goes with the last piece.
  def write_in_chunks(stream, data, chunk_size: 64 * 1024)
    offset = 0
    while offset < data.bytesize
      piece = data.byteslice(offset, chunk_size)
      offset += piece.bytesize
      stream.write(piece, fin: offset >= data.bytesize)
    end
  end
end

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
