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
require "socket"
require "tmpdir"
require_relative "demo_certificates"

BIND_HOST = ENV.fetch("QUIC_ECHO_HOST", "127.0.0.1")
BIND_PORT = Integer(ENV.fetch("QUIC_ECHO_PORT", "4433"))
ALPN = ENV.fetch("QUIC_ECHO_ALPN", "perf")
ACCEPT_TIMEOUT = 10

Dir.mktmpdir("quic-echo-server-") do |dir|
  ca_file, certificate_path, private_key_path = DemoCertificates.generate(dir, BIND_HOST)

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
