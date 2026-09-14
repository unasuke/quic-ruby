# frozen_string_literal: true

# Caller-owned I/O loop demo: the same DNS over QUIC query as
# examples/doq_demo.rb, but without Client#bind / #run or the blocking
# Stream#read / #write. The script owns the socket and the loop, and calls the
# packet-level primitives itself:
#
#   Client#write_pkt       the next datagram to send, or nil when there is
#                          nothing more to send right now
#   Client#read_pkt        feed one received datagram to the connection
#   Client#expiry          the next timer deadline (CLOCK_MONOTONIC in
#                          nanoseconds), or nil
#   Client#handle_expiry   run the connection's timers (retransmission,
#                          idle timeout, ...)
#   Stream#write_nonblock  queue stream data; raises QUIC::Error::WaitWritable
#                          when the peer's flow control window is full
#   Stream#read_nonblock   take received stream data; raises
#                          QUIC::Error::WaitReadable when none has arrived,
#                          EOFError once the peer has finished
#
# None of these touch the network. Every step that has to wait goes through
# #pump below, which flushes outgoing packets and then waits for a datagram or
# the next timer, whichever comes first. That is the part to adapt when the
# loop has to live inside something else, such as an event loop that also
# serves other sockets.
#
# Run with: bundle exec ruby examples/io_loop_demo.rb [name]
#
# Override the resolver via env vars:
#   DOQ_HOST  (default dns.quad9.net)
#   DOQ_PORT  (default 853)

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "resolv"
require "socket"

TARGET_HOST = ENV.fetch("DOQ_HOST", "dns.quad9.net")
TARGET_PORT = Integer(ENV.fetch("DOQ_PORT", "853"))
QUERY_NAME = ARGV[0] || "example.com"
TIMEOUT_SEC = 10

client = QUIC::Connection::Client.new(
  host: TARGET_HOST, port: TARGET_PORT, address_family: :inet,
  settings: QUIC::Settings.default.with(alpn: ["doq"])
)
addr = client.remote_address
sock = UDPSocket.new(Socket::AF_INET)
sock.connect(addr.ip_address, addr.ip_port)

# read_pkt needs the network path a datagram arrived on, and it has to match
# the path the connection was created with. Client.new creates it with an
# unspecified local address (0.0.0.0:0) and the resolved remote address.
LOCAL_SOCKADDR = Addrinfo.udp("0.0.0.0", 0).to_sockaddr
REMOTE_SOCKADDR = addr.to_sockaddr

# One turn of the loop: send everything the connection has queued, then wait
# until a datagram arrives or the next timer is due, and hand that over.
def pump(client, sock, deadline, stats)
  while (pkt = client.write_pkt)
    sock.send(pkt, 0)
    stats[:sent] += 1
  end

  now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  abort "timed out after #{TIMEOUT_SEC}s" if now > deadline
  wait = deadline - now
  if (expiry = client.expiry)
    until_expiry = (expiry - Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)) / 1e9
    wait = until_expiry.clamp(0.0, wait)
  end

  if IO.select([sock], nil, nil, wait)
    data, = sock.recvfrom(2048)
    client.read_pkt(data, local_sockaddr: LOCAL_SOCKADDR, remote_sockaddr: REMOTE_SOCKADDR)
    stats[:received] += 1
  else
    client.handle_expiry
    stats[:timers] += 1
  end
end

stats = Hash.new(0)
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + TIMEOUT_SEC

puts "resolver: #{TARGET_HOST} (#{addr.ip_address}:#{addr.ip_port}), alpn doq"
puts "query:    #{QUERY_NAME} A"
puts

pump(client, sock, deadline, stats) until client.handshake_completed?
puts "handshake completed: #{stats[:sent]} datagrams sent, #{stats[:received]} received"

# RFC 9250: DNS Message ID 0, framed with a 2-octet length prefix, one
# bidirectional stream per query, FIN after the query.
query = Resolv::DNS::Message.new(0)
query.rd = 1
query.add_question(QUERY_NAME, Resolv::DNS::Resource::IN::A)
wire = query.encode
pending = [wire.bytesize].pack("n") + wire

stream = client.open_bidi_stream
# write_nonblock queues as much as the flow control window allows and returns
# that count. FIN only goes out with the last byte, so keep passing fin: true
# for whatever is left.
until pending.empty?
  begin
    queued = stream.write_nonblock(pending, fin: true)
    pending = pending.byteslice(queued..)
  rescue QUIC::Error::WaitWritable
    pump(client, sock, deadline, stats)
  end
end
puts "queued #{wire.bytesize + 2} bytes + FIN on stream #{stream.id}"

# Nothing has been sent yet: the query leaves on the next pump, which happens
# here as soon as read_nonblock finds nothing to read.
response = String.new(encoding: Encoding::BINARY)
loop do
  response << stream.read_nonblock(4096)
rescue QUIC::Error::WaitReadable
  pump(client, sock, deadline, stats)
rescue EOFError
  break
end

abort "resolver closed the stream without a response" if response.bytesize < 2
length = response.unpack1("n")
body = response.byteslice(2, length)
abort "truncated response" if body.nil? || body.bytesize < length

answer = Resolv::DNS::Message.decode(body)
puts "received #{body.bytesize} bytes, rcode #{answer.rcode}"
puts "loop totals: #{stats[:sent]} datagrams sent, #{stats[:received]} received, #{stats[:timers]} timer runs"
puts

answer.each_answer do |name, ttl, data|
  next unless data.is_a?(Resolv::DNS::Resource::IN::A)
  puts format("%-34s %6d  A      %s", name, ttl, data.address)
end

# Client#close writes the CONNECTION_CLOSE datagram to a bound socket itself,
# so bind the socket now, only for that.
client.bind(sock).close
sock.close
