# frozen_string_literal: true

# Echo server for examples/echo_demo.rb: accept one QUIC connection, echo
# every stream back to the client (read up to its FIN, then write it all
# back with FIN), and exit once the client closes the connection, goes away,
# or opens no new stream for 10 seconds.
#
# No certificate files are needed. A throwaway CA and a server certificate it
# signed are generated at startup, and the CA's path is printed; the files
# are removed when the server exits.
#
# echo_demo.rb reads the same env vars, so it connects without any setup:
#   QUIC_ECHO_HOST  address to bind (default 127.0.0.1); also added to the
#                   certificate's SAN
#   QUIC_ECHO_PORT  (default 4433)
#   QUIC_ECHO_ALPN  (default perf)
#
# Run with: bundle exec ruby examples/echo_server_demo.rb
# then, from another terminal: bundle exec ruby examples/echo_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "ipaddr"
require "openssl"
require "socket"
require "tmpdir"

BIND_HOST = ENV.fetch("QUIC_ECHO_HOST", "127.0.0.1")
BIND_PORT = Integer(ENV.fetch("QUIC_ECHO_PORT", "4433"))
ALPN = ENV.fetch("QUIC_ECHO_ALPN", "perf")
ACCEPT_TIMEOUT = 10

# localhost and 127.0.0.1, plus the bind address so that echo_demo.rb can
# verify the certificate against QUIC_ECHO_HOST.
def subject_alt_names(host)
  names = ["DNS:localhost", "IP:127.0.0.1"]
  entry = begin
    IPAddr.new(host)
    "IP:#{host}"
  rescue IPAddr::InvalidAddressError
    "DNS:#{host}"
  end
  names << entry unless names.include?(entry)
  names.join(",")
end

# Write a CA and a server certificate it signed (EC P-256, valid for one
# day), with the server's private key, into dir. Returns the three paths.
def generate_certificates(dir, host)
  now = Time.now

  ca_key = OpenSSL::PKey::EC.generate("prime256v1")
  ca_name = OpenSSL::X509::Name.parse("/CN=quic-ruby echo server demo CA")
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
  server_cert.add_extension(factory.create_extension("subjectAltName", subject_alt_names(host)))
  server_cert.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
  server_cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))

  paths = %w[ca.pem server.pem server.key].map { |name| File.join(dir, name) }
  File.write(paths[0], ca_cert.to_pem)
  File.write(paths[1], server_cert.to_pem)
  File.write(paths[2], server_key.private_to_pem)
  paths
end

Dir.mktmpdir("quic-echo-server-") do |dir|
  ca_file, certificate_path, private_key_path = generate_certificates(dir, BIND_HOST)

  sock = UDPSocket.new(Socket::AF_INET)
  sock.bind(BIND_HOST, BIND_PORT)
  puts "listening on #{sock.local_address.inspect_sockaddr} (UDP), ALPN #{ALPN}"
  puts "CA certificate: #{ca_file}"
  puts "try a verified connection with:"
  puts "  QUIC_ECHO_CA_FILE=#{ca_file} bundle exec ruby examples/echo_demo.rb"
  puts "(without QUIC_ECHO_CA_FILE, echo_demo.rb does not verify the certificate)"
  puts

  server = QUIC::Connection::Server.accept(
    sock: sock, certificate_path: certificate_path, private_key_path: private_key_path,
    settings: QUIC::Settings.default.with(alpn: [ALPN])
  )
  puts "accepted #{server.remote_address.inspect_sockaddr}"
  server.run
  puts "handshake completed"

  begin
    while (stream = server.accept_stream(timeout: ACCEPT_TIMEOUT))
      data = stream.read
      stream.write(data, fin: true)
      puts "stream #{stream.id}: echoed #{data.bytesize} bytes"
      server.pump_until { stream.closed? }
    end
    puts "no new stream for #{ACCEPT_TIMEOUT} seconds"
  rescue QUIC::Error::Closed
    puts "client closed the connection"
  rescue Errno::ECONNREFUSED
    # The socket is connected to the client, so once the client's socket is
    # gone without a CONNECTION_CLOSE, the ICMP port unreachable surfaces
    # here, from sending to it.
    puts "client went away without closing the connection"
  end

  server.close
  sock.close
end
