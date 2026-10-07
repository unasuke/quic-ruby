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

# A QUIC::Endpoint and any number of Clients, joined by datagrams handed over
# in memory instead of sockets, all in one thread. Each Client gets an
# address of its own, which is all the Endpoint tells them apart by. A test
# can drop what the Endpoint sends, and sees what each Client raised.
module TestEndpointNetwork
  def endpoint_network(tls_context, **endpoint_options)
    Network.new(
      QUIC::Endpoint.new(local_address: Network::SERVER_ADDRESS, tls_context: tls_context, **endpoint_options)
    )
  end

  # The server side of an echo over QUIC::Stream: send back whatever a
  # client stream carried, once it has ended. state carries the partial
  # reads from one call to the next.
  def echo_streams(endpoint, state)
    endpoint.connections.each do |conn|
      loop { state[conn.accept_stream_nonblock] = +"" }
    rescue QUIC::Error::WaitReadable
      next
    end
    state.each do |stream, received|
      next if received.frozen?

      loop { received << stream.read_nonblock(65_536) }
    rescue QUIC::Error::WaitReadable
      next
    rescue EOFError
      stream.write_nonblock(received, fin: true)
      received.freeze
    end
  end

  # All a stream carried, or nil until it has ended. buffer collects the
  # partial reads.
  def read_to_end(stream, buffer)
    loop { buffer << stream.read_nonblock(65_536) }
  rescue QUIC::Error::WaitReadable
    nil
  rescue EOFError
    buffer
  end

  class Network
    SERVER_ADDRESS = Addrinfo.udp("127.0.0.1", 4433)
    # Client.new makes 0.0.0.0:0 the local address of its path.
    CLIENT_LOCAL_SOCKADDR = Addrinfo.udp("0.0.0.0", 0).to_sockaddr
    TIMEOUT = 10

    attr_reader :endpoint
    # Called with each packet the Endpoint sends and the Client it is for;
    # true drops the packet.
    attr_accessor :drop

    def initialize(endpoint)
      @endpoint = endpoint
      @clients = {}
      @errors = {}
      @next_port = 50_000
    end

    # A new Client of the Endpoint, verifying ca_file. The handshake is left
    # to #run_until.
    def connect(alpn:, ca_file:)
      client = QUIC::Connection::Client.new(
        host: SERVER_ADDRESS.ip_address, port: SERVER_ADDRESS.ip_port,
        settings: QUIC::Settings.default.with(alpn: alpn, ca_file: ca_file)
      )
      @next_port += 1
      @clients[Addrinfo.udp("127.0.0.1", @next_port).to_sockaddr] = client
      client
    end

    # The sockaddr the Endpoint knows client by.
    def address_of(client)
      @clients.key(client)
    end

    # What client raised from #read_pkt, #write_pkt or #handle_expiry. The
    # network stops driving a client once it has raised.
    def error_of(client)
      @errors[client]
    end

    # Hand every waiting packet over once in each direction, then run the
    # timers that are due. Returns how many packets moved.
    def step
      moved = 0
      live_clients.each do |addr, client|
        guard(client) do
          while (pkt = client.write_pkt)
            moved += 1
            @endpoint.read_pkt(pkt, remote: addr)
          end
        end
      end
      while (pkt, to = @endpoint.write_pkt)
        moved += 1
        client = @clients[to]
        next if client.nil? || @errors.key?(client) || drop&.call(pkt, client)

        guard(client) do
          client.read_pkt(pkt, local_sockaddr: CLIENT_LOCAL_SOCKADDR, remote_sockaddr: SERVER_ADDRESS.to_sockaddr)
        end
      end
      run_timers
      moved
    end

    # #step until the block returns true, sleeping until the next timer
    # whenever nothing moved.
    def run_until(timeout: TIMEOUT)
      deadline = now + timeout * 1_000_000_000
      until yield
        raise "timed out (client errors: #{@errors.values.inspect})" if now > deadline

        sleep(idle_wait) if step.zero?
      end
    end

    private

    def live_clients
      @clients.reject { |_, client| @errors.key?(client) }
    end

    def guard(client)
      yield
    rescue QUIC::Error => e
      @errors[client] = e
    end

    def run_timers
      t = now
      live_clients.each_value do |client|
        guard(client) { client.handle_expiry if (expiry = client.expiry) && expiry <= t }
      end
      @endpoint.handle_expiry if (expiry = @endpoint.expiry) && expiry <= t
    end

    # Until the next timer, but no more than 10 ms, so that the condition
    # given to #run_until is looked at often.
    def idle_wait
      timers = [@endpoint.expiry, *live_clients.values.map(&:expiry)].compact
      return 0.01 if timers.empty?

      ((timers.min - now) / 1e9).clamp(0.0, 0.01)
    end

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
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

  # A new set of LoopbackCredentials under a CA of its own, for a test that
  # needs a second certificate nothing else trusts.
  def self.generate_loopback_credentials(ca_common_name: "quic-ruby loopback test CA")
    now = Time.now
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca_name = OpenSSL::X509::Name.parse("/CN=#{ca_common_name}")
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
