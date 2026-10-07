# frozen_string_literal: true

require "test_helper"

# QUIC::Endpoint with Clients joined in memory (TestEndpointNetwork), so that
# several clients, dropped packets and forged datagrams fit in one thread.
class TestQUICEndpoint < Minitest::Test
  include TestCertificates
  include TestEndpointNetwork

  ALPN = ["h3"].freeze

  def test_new_checks_its_arguments
    error = assert_raises(TypeError) { QUIC::Endpoint.new(local_address: "127.0.0.1", tls_context: tls_context) }
    assert_equal "local_address must be an Addrinfo (got String)", error.message
    assert_raises(TypeError) { QUIC::Endpoint.new(local_address: Addrinfo.udp("127.0.0.1", 0), tls_context: Object.new) }
    assert_raises(TypeError) { QUIC::Endpoint.allocate }
  end

  def test_serves_two_clients_at_once
    net = endpoint_network(tls_context)
    a = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    b = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    net.run_until { a.handshake_completed? && b.handshake_completed? }
    assert_equal 2, net.endpoint.connections.size

    stream_a = a.open_bidi_stream
    stream_a.write_nonblock("from a", fin: true)
    stream_b = b.open_bidi_stream
    stream_b.write_nonblock("from b", fin: true)

    state = {}
    reply_a = +""
    reply_b = +""
    net.run_until do
      echo_streams(net.endpoint, state)
      read_to_end(stream_a, reply_a) && read_to_end(stream_b, reply_b)
    end
    assert_equal "from a", reply_a
    assert_equal "from b", reply_b
  end

  # A failure inside one connection closes that connection only, and is
  # kept as its #error instead of raising from the Endpoint.
  def test_failure_of_one_connection_leaves_the_others_alone
    net = endpoint_network(tls_context)
    failing = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    healthy = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    net.run_until { failing.handshake_completed? && healthy.handshake_completed? }

    failing_server = net.endpoint.connections.first
    # stream_open then raises FrozenError inside ngtcp2's callback.
    failing_server.instance_variable_set(:@streams, {}.freeze)
    failing.open_bidi_stream.write_nonblock("boom", fin: true)
    stream = healthy.open_bidi_stream
    stream.write_nonblock("still here", fin: true)

    state = {}
    reply = +""
    net.run_until do
      echo_streams(net.endpoint, state)
      read_to_end(stream, reply) && net.error_of(failing)
    end
    assert_equal "still here", reply
    assert_instance_of FrozenError, failing_server.error
    assert_predicate failing_server, :in_closing_period?
    assert_instance_of QUIC::Error::Closed, net.error_of(failing)
    assert_nil net.endpoint.connections.last.error
  end

  def test_answers_unsupported_version_with_version_negotiation
    net = endpoint_network(tls_context)
    client = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    initial = client.write_pkt
    initial[1, 4] = [0x1a2a3a4a].pack("N")

    assert_nil net.endpoint.read_pkt(initial, remote: net.address_of(client))
    pkt, to = net.endpoint.write_pkt
    assert_equal net.address_of(client), to
    assert_nil net.endpoint.write_pkt
    assert_empty net.endpoint.connections

    assert_equal 0x80, pkt.getbyte(0) & 0x80 # long header
    assert_equal 0, pkt.byteslice(1, 4).unpack1("N") # Version Negotiation
    dcid, scid, rest = long_header_cids(pkt)
    initial_dcid, initial_scid, = long_header_cids(initial)
    assert_equal initial_scid, dcid
    assert_equal initial_dcid, scid
    versions = rest.unpack("N*")
    assert_includes versions, 1
    assert(versions.any? { |v| v & 0x0f0f0f0f == 0x0a0a0a0a }, "a reserved version is listed")
  end

  def test_closed_connections_come_out_of_take_closed
    net = endpoint_network(tls_context)
    client = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    net.run_until { client.handshake_completed? && net.endpoint.connections.first&.handshake_completed? }
    server = net.endpoint.connections.first
    assert_empty net.endpoint.take_closed

    server.close(error_code: 0x100, reason: "bye")
    assert_predicate server, :in_closing_period?
    assert_nil server.close # already closing
    closed = []
    net.run_until { closed.concat(net.endpoint.take_closed).any? }
    assert_equal [server], closed
    assert_empty net.endpoint.take_closed
    assert_empty net.endpoint.connections
    assert_nil server.error
    assert_nil server.close # no longer in the table
    # The client saw the CONNECTION_CLOSE.
    assert_instance_of QUIC::Error::Closed, net.error_of(client)
  end

  # A handshake that fails (here: no common ALPN) sends its CONNECTION_CLOSE
  # and leaves nothing behind.
  def test_failed_handshake_leaves_no_connection
    net = endpoint_network(tls_context)
    client = net.connect(alpn: ["other"], ca_file: loopback_credentials.ca_file)
    net.run_until { net.error_of(client) }
    assert_empty net.endpoint.connections
    assert_empty net.endpoint.take_closed
  end

  def test_read_pkt_requires_an_inet_sockaddr
    endpoint = endpoint_network(tls_context).endpoint
    good = Addrinfo.udp("127.0.0.1", 50_000).to_sockaddr
    ["x".b * 256, "".b, Addrinfo.unix("/tmp/quic.sock").to_sockaddr].each do |bad|
      error = assert_raises(ArgumentError) { endpoint.read_pkt("\x40".b, remote: bad) }
      assert_equal "remote must be an AF_INET or AF_INET6 sockaddr (Addrinfo#to_sockaddr)", error.message
      error = assert_raises(ArgumentError) { endpoint.read_pkt("\x40".b, remote: good, local: bad) }
      assert_equal "local must be an AF_INET or AF_INET6 sockaddr (Addrinfo#to_sockaddr)", error.message
    end
    assert_nil endpoint.read_pkt("\x40".b, remote: Addrinfo.udp("::1", 50_000).to_sockaddr)
  end

  def test_endpoint_drops_what_it_cannot_parse
    endpoint = endpoint_network(tls_context).endpoint
    remote = Addrinfo.udp("127.0.0.1", 50_000).to_sockaddr
    assert_nil endpoint.read_pkt("".b, remote: remote)
    assert_nil endpoint.read_pkt("\x40".b + "\x00".b * 10, remote: remote)
    assert_nil endpoint.write_pkt
  end

  # The CID table holds Connection::Server objects and follows them through
  # compaction.
  def test_survives_gc_compaction
    net = endpoint_network(tls_context)
    client = net.connect(alpn: ALPN, ca_file: loopback_credentials.ca_file)
    net.run_until { client.handshake_completed? }

    GC.start
    GC.verify_compaction_references(expand_heap: true, toward: :empty)

    stream = client.open_bidi_stream
    stream.write_nonblock("after compaction", fin: true)
    state = {}
    reply = +""
    net.run_until do
      echo_streams(net.endpoint, state)
      read_to_end(stream, reply)
    end
    assert_equal "after compaction", reply
  end

  private

  def tls_context
    QUIC::TLSContext.server(
      certificate_path: loopback_credentials.certificate_path,
      private_key_path: loopback_credentials.private_key_path,
      alpn: ALPN
    )
  end

  # The DCID and SCID of a long header packet, and what follows them.
  def long_header_cids(pkt)
    dcid_len = pkt.getbyte(5)
    dcid = pkt.byteslice(6, dcid_len)
    scid_len = pkt.getbyte(6 + dcid_len)
    scid = pkt.byteslice(7 + dcid_len, scid_len)
    [dcid, scid, pkt.byteslice(7 + dcid_len + scid_len..)]
  end
end
