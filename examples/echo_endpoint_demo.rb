# frozen_string_literal: true

# Echo server for examples/echo_demo.rb that serves many clients at once
# through QUIC::Endpoint: one UDP socket, an I/O loop this script owns, and
# the connections' non-blocking stream methods. Like echo_server_demo.rb, it
# echoes every stream back (reads up to its FIN, then writes it all back
# with FIN). It runs until Ctrl-C, which closes every connection.
#
# No certificate files are needed. A throwaway CA and a server certificate it
# signed are generated at startup (see demo_certificates.rb), and the CA's
# path is printed; the files are removed when the server exits.
#
# echo_demo.rb reads the same env vars, so it connects without any setup:
#   QUIC_ECHO_HOST      address to bind (default 127.0.0.1); also added to
#                       the certificate's SAN. Not 0.0.0.0: an Endpoint
#                       needs the address it serves.
#   QUIC_ECHO_PORT      (default 4433)
#   QUIC_ECHO_ALPN      (default perf)
#   QUIC_ECHO_QLOG_DIR  a directory to write each connection's qlog to
#                       (default unset: no qlog)
#
# Run with: bundle exec ruby examples/echo_endpoint_demo.rb
# then, from other terminals: bundle exec ruby examples/echo_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "socket"
require "tmpdir"
require_relative "demo_certificates"

BIND_HOST = ENV.fetch("QUIC_ECHO_HOST", "127.0.0.1")
BIND_PORT = Integer(ENV.fetch("QUIC_ECHO_PORT", "4433"))
ALPN = ENV.fetch("QUIC_ECHO_ALPN", "perf")
QLOG_DIR = ENV["QUIC_ECHO_QLOG_DIR"]
# Datagrams read in one round of the loop at most, so that a flood of them
# does not hold up the timers and the sending.
RECV_BATCH = 64

# One client stream: read it up to its FIN, then write it all back with FIN.
class EchoStream
  attr_reader :size

  def initialize(stream)
    @stream = stream
    @data = +""
    @reading = true
  end

  def id
    @stream.id
  end

  # Moves the echo on as far as it can without blocking. Returns true once
  # all of it, FIN included, is queued for sending.
  def step
    read while @reading
    write
  rescue QUIC::Error::WaitReadable, QUIC::Error::WaitWritable
    false
  end

  private

  def read
    @data << @stream.read_nonblock(65_536)
  rescue EOFError
    @reading = false
    @size = @data.bytesize
  end

  # write_nonblock queues as much as the client's flow control window has
  # room for, and sends the FIN only along with the last byte.
  def write
    loop do
      queued = @stream.write_nonblock(@data, fin: true)
      return true if queued == @data.bytesize

      @data = @data.byteslice(queued..)
    end
  end
end

# The streams conn's client has opened since the last call.
def accepted_streams(conn)
  streams = []
  loop { streams << conn.accept_stream_nonblock }
rescue QUIC::Error::WaitReadable
  streams
end

def now_ns
  Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
end

def flush(endpoint, sock)
  while (packet, to = endpoint.write_pkt)
    sock.send(packet, 0, to)
  end
end

Dir.mktmpdir("quic-echo-endpoint-") do |dir|
  ca_file, certificate_path, private_key_path = DemoCertificates.generate(dir, BIND_HOST)
  tls_context = QUIC::TLSContext.server(
    certificate_path: certificate_path, private_key_path: private_key_path, alpn: [ALPN]
  )
  settings = QUIC::Settings.default
  settings = settings.with(qlog_dir: QLOG_DIR) if QLOG_DIR

  sock = UDPSocket.new(Socket::AF_INET)
  sock.bind(BIND_HOST, BIND_PORT)
  endpoint = QUIC::Endpoint.new(local_address: sock.local_address, tls_context: tls_context, settings: settings)
  puts "listening on #{sock.local_address.inspect_sockaddr} (UDP), ALPN #{ALPN}"
  puts "CA certificate: #{ca_file}"
  puts "try a verified connection with:"
  puts "  QUIC_ECHO_CA_FILE=#{ca_file} bundle exec ruby examples/echo_demo.rb"
  puts "(without QUIC_ECHO_CA_FILE, echo_demo.rb does not verify the certificate)"
  puts "writing qlog to #{QLOG_DIR}" if QLOG_DIR
  puts

  peers = {} # connection => its client's address
  echoes = Hash.new { |hash, conn| hash[conn] = [] } # connection => its unfinished EchoStreams

  begin
    loop do
      expiry = endpoint.expiry
      timeout = expiry && [expiry - now_ns, 0].max / 1e9
      if IO.select([sock], nil, nil, timeout)
        RECV_BATCH.times do
          data, sender = sock.recvmsg_nonblock(65_535, exception: false)
          break if data == :wait_readable

          conn = endpoint.read_pkt(data, remote: sender.to_sockaddr)
          if conn && !peers.key?(conn)
            peers[conn] = sender.inspect_sockaddr
            puts "#{peers[conn]}: connected"
          end
        end
      end
      endpoint.handle_expiry

      # The connections have no socket of their own, so only their
      # non-blocking methods work.
      endpoint.connections.each do |conn|
        echoes[conn].concat(accepted_streams(conn).map { |stream| EchoStream.new(stream) })
        echoes[conn].reject! do |echo|
          next false unless echo.step

          puts "#{peers[conn]}: stream #{echo.id}: echoed #{echo.size} bytes"
          true
        end
      end

      flush(endpoint, sock)

      endpoint.take_closed.each do |conn|
        echoes.delete(conn)
        reason = conn.error ? " (#{conn.error.class}: #{conn.error.message})" : ""
        puts "#{peers.delete(conn)}: closed#{reason}"
      end
    end
  rescue Interrupt
    puts
    puts "closing #{endpoint.connections.size} connection(s)"
    endpoint.stop_accepting
    endpoint.connections.each(&:close)
    flush(endpoint, sock)
  end

  sock.close
end
