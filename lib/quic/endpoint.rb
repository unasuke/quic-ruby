# frozen_string_literal: true

require "socket"

module QUIC
  # Many server connections on one UDP socket. The Endpoint routes each
  # datagram to its connection by connection ID, makes connections for new
  # clients and answers what no connection can (Version Negotiation,
  # Stateless Reset, CONNECTION_REFUSED). The socket and the I/O loop stay
  # with the caller:
  #
  #   loop do
  #     data, addr = sock.recvfrom(65_535)            # or recvmsg_nonblock
  #     endpoint.read_pkt(data, remote: addr.to_sockaddr)
  #     endpoint.handle_expiry                         # when endpoint.expiry is due
  #     while (pkt, to = endpoint.write_pkt)
  #       sock.send(pkt, 0, to)
  #     end
  #     endpoint.take_closed.each { |conn| ... }
  #   end
  #
  # The socket must not be connected, and must be bound to the address it
  # serves (not 0.0.0.0): every path's local address is local_address.
  #
  # The Endpoint's own answers wait for #write_pkt in a queue of at most
  # 1024; any beyond are dropped, so call #write_pkt often under load.
  #
  # A connection's failure never raises from the Endpoint's methods. It
  # closes that connection alone, and Connection#error tells why. The
  # connections have no socket, so only their non-blocking methods work;
  # #close queues its CONNECTION_CLOSE for #write_pkt.
  class Endpoint
    attr_reader :local_address

    # tls_context is a QUIC::TLSContext; its ALPN list is the server's, and
    # settings.alpn is not read. max_connections counts connections in their
    # closing or draining period too.
    def self.new(local_address:, tls_context:, transport_params: nil, settings: nil, max_connections: 1024)
      raise TypeError, "local_address must be an Addrinfo (got #{local_address.class})" unless local_address.is_a?(Addrinfo)
      unless max_connections.is_a?(Integer)
        raise TypeError, "max_connections must be an Integer (got #{max_connections.class})"
      end
      settings ||= QUIC::Settings.default
      settings.check_qlog_dir

      endpoint = _new(
        local_sockaddr: local_address.to_sockaddr,
        tls_context: tls_context,
        transport_params: transport_params || QUIC::TransportParams.default,
        settings: settings,
        max_connections: max_connections
      )
      endpoint.instance_variable_set(:@local_address, local_address)
      endpoint
    end
  end
end
