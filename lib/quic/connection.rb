# frozen_string_literal: true

require "socket"

module QUIC
  module Connection
    # The Ruby side of the I/O loop, shared by Client and Server. It is an
    # internal implementation detail: not meant to be included in other
    # classes, and the ivars and methods it relies on are not a public
    # contract.
    module Pump
      # Attach an IO.select / #send / #recvfrom-compatible UDP socket so that
      # #run and Stream blocking I/O can drive the wire transparently. Caller
      # is responsible for socket lifetime; we do not close it. The socket
      # must already be #connect'd to the peer (we read #remote_address).
      def bind(sock)
        @sock = sock
        self
      end

      def bound_socket
        @sock
      end

      # Drive the handshake to completion using the bound socket. Raises
      # QUIC::Error::NotBound if #bind has not been called. Propagates any
      # QUIC::Error subclass raised by #read_pkt / #handle_expiry.
      def run
        raise QUIC::Error::NotBound, "#{self.class}#bind(sock) has not been called" if @sock.nil?

        pump_until { handshake_completed? }
      end

      # One iteration of the I/O loop: drain any outgoing packets via
      # #write_pkt, then wait up to `timeout` (or the next ngtcp2 expiry,
      # whichever is sooner) for either an incoming datagram or the timer to
      # fire. Public-ish so Stream blocking ops can share it; documented as
      # "internal" for users.
      def pump_once(timeout: nil)
        raise QUIC::Error::NotBound, "#{self.class}#bind(sock) has not been called" if @sock.nil?

        while (pkt = write_pkt)
          @sock.send(pkt, 0)
        end

        wait_for = pump_timeout(timeout)
        ready = IO.select([@sock], nil, nil, wait_for)
        if ready
          data, _addr = @sock.recvfrom(2048)
          # Reuse the same path tuple the connection was built with so the
          # read_pkt path matches the stored connection path. A Client leaves
          # @local_sockaddr unset, so local is 0.0.0.0:0 (Client.new
          # convention); remote comes from the connected socket (assumes
          # #connect was used).
          read_pkt(
            data,
            local_sockaddr: pump_local_sockaddr,
            remote_sockaddr: pump_remote_sockaddr
          )
        else
          handle_expiry
        end
      end

      # Iterate pump_once until `pred` returns truthy. Public so Stream
      # blocking methods can share it.
      def pump_until(&pred)
        pump_once until pred.call
      end

      # Pop the next peer-initiated stream off the accept queue, driving the
      # I/O loop until one arrives. The queue is fed by the recv_stream_data
      # callback the first time a peer-initiated stream carries data.
      #
      # timeout: nil      block until a stream is available (requires #bind)
      # timeout: 0        return immediately; nil if the queue is empty
      # timeout: Numeric  block up to that many seconds, then return nil
      #
      # Returns a QUIC::Stream, or nil on timeout.
      def accept_stream(timeout: nil)
        stream = @accept_queue.shift
        return stream unless stream.nil?
        return nil if timeout == 0

        deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          if deadline
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            return nil if remaining <= 0.0
            pump_once(timeout: remaining)
          else
            pump_once
          end
          stream = @accept_queue.shift
          return stream unless stream.nil?
        end
      end

      # Non-blocking variant of #accept_stream. Returns the next queued
      # peer-initiated stream, or raises QUIC::Error::WaitReadable
      # (IO::WaitReadable mixin) when the queue is empty. Does not require
      # #bind.
      def accept_stream_nonblock
        stream = @accept_queue.shift
        raise QUIC::Error::WaitReadable, "no peer-initiated stream available" if stream.nil?
        stream
      end

      private

      def pump_timeout(caller_timeout)
        ngtcp2_expiry_ns = expiry
        if ngtcp2_expiry_ns.nil?
          return caller_timeout
        end
        now_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        expiry_secs = [(ngtcp2_expiry_ns - now_ns) / 1_000_000_000.0, 0.0].max
        return expiry_secs if caller_timeout.nil?
        [caller_timeout, expiry_secs].min
      end

      def pump_local_sockaddr
        @local_sockaddr ||= Addrinfo.udp("0.0.0.0", 0).to_sockaddr
      end

      def pump_remote_sockaddr
        @remote_sockaddr ||= @sock.remote_address.to_sockaddr
      end
    end

    class Client
      include Pump

      attr_reader :remote_address

      # Build a Client and pin a single peer address. address_family takes a
      # Symbol (:inet for IPv4, :inet6 for IPv6) or nil to defer family
      # selection to Addrinfo.udp's implicit resolution. Pin the resolved
      # Addrinfo into @remote_address so callers can match their UDPSocket's
      # connected sockaddr (otherwise DNS round-robin between Client.new and
      # sock.connect can produce a path that ngtcp2 silently drops).
      def self.new(host:, port:, address_family: nil, transport_params: nil, settings: nil)
        family = case address_family
        when nil then nil
        when :inet then Socket::AF_INET
        when :inet6 then Socket::AF_INET6
        else
          raise ArgumentError, "unknown address_family: #{address_family.inspect}"
        end

        remote_address = if family
          Addrinfo.getaddrinfo(host, port, family, :DGRAM, Socket::IPPROTO_UDP).first
        else
          Addrinfo.udp(host, port)
        end

        remote_sockaddr = remote_address.to_sockaddr
        local_sockaddr = Addrinfo.udp("0.0.0.0", 0).to_sockaddr

        client = _open(
          local_sockaddr: local_sockaddr,
          remote_sockaddr: remote_sockaddr,
          server_name: host,
          transport_params: transport_params || QUIC::TransportParams.default,
          settings: settings || QUIC::Settings.default
        )
        client.instance_variable_set(:@host, host)
        client.instance_variable_set(:@port, port)
        client.instance_variable_set(:@remote_address, remote_address)
        client
      end
    end

    # One server-side connection. Built by Server._accept from the first
    # datagram a client sent; there is no public Server.new, since an object
    # without an ngtcp2 connection behind it would be unusable.
    class Server
      include Pump

      attr_reader :remote_address

      private_class_method :new
    end
  end
end
