# frozen_string_literal: true

module QUIC
  # QUIC::Stream is defined in the C extension (ext/quic/stream.c); this file
  # reopens it to add the bits that are easier to express in Ruby:
  # #initiator (a tiny lookup over @id) and the blocking #read which wraps
  # the C #read_nonblock with an internal #pump_once loop on the owning
  # connection (@client, a Client or Server).
  class Stream
    INITIATORS = %i[client_bidi server_bidi client_uni server_uni].freeze

    attr_reader :id
    alias_method :stream_id, :id

    # RFC 9000 §2.1: the lowest two bits of stream_id encode the initiator
    # (LSB) and direction (bit 1).
    def initiator
      INITIATORS[@id & 0b11]
    end

    # IO#read-compatible blocking read. Requires the owning connection to
    # have been #bind'ed to a socket (raised via its #pump_once otherwise).
    #
    #   read(length): block until at least 1 byte is available or EOF,
    #                 return up to `length` bytes, return nil at EOF.
    #   read(nil):    block until EOF, return everything that was received
    #                 (an empty String if nothing arrived before FIN).
    #
    # Both branches drain first and pump only when there is nothing to drain.
    # #read_nonblock already distinguishes the two states we care about --
    # QUIC::Error::WaitReadable for "nothing buffered yet" and EOFError for
    # "nothing buffered and FIN seen" -- so the loop needs no separate
    # predicate over @recv_buffer / #eof?.
    def read(length = nil)
      if length.nil?
        out = +""
        out.force_encoding(Encoding::BINARY)
        loop do
          out << read_nonblock(4096)
        rescue QUIC::Error::WaitReadable
          @client.pump_once
        rescue EOFError
          break
        end
        out
      else
        loop do
          return read_nonblock(length)
        rescue QUIC::Error::WaitReadable
          @client.pump_once
        rescue EOFError
          return nil
        end
      end
    end
  end
end
