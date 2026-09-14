# frozen_string_literal: true

# DNS over QUIC (RFC 9250) demo: send one DNS query to a public DoQ resolver
# and print the answers. This exercises the pieces a real protocol needs --
# ALPN negotiation, a client-initiated bidirectional stream, a half-close via
# FIN, and reading until the peer closes its side.
#
# Three rules from RFC 9250 shape the code below:
#
#   * ALPN is "doq" and the default port is 853 (RFC 9250 section 4.1.1, 4.1.2).
#   * Each query/response pair gets its own bidirectional stream, and the
#     client signals FIN after the query (section 4.2).
#   * The DNS message is framed with a 2-octet length prefix, as in DNS over
#     TCP, and the DNS Message ID must be 0 (section 4.2.1). QUIC stream IDs
#     already correlate a response with its query, so the DNS-level ID is
#     redundant and carrying one would leak an identifier.
#
# The query is built and parsed with Resolv::DNS::Message from the standard
# library, so this needs no gems beyond quic itself. It also does not add
# EDNS(0) padding, which RFC 9250 section 5.5.2 recommends for privacy.
#
# Run with: bundle exec ruby examples/doq_demo.rb [name] [type]
#   bundle exec ruby examples/doq_demo.rb ruby-lang.org AAAA
#
# Override the resolver via env vars:
#   DOQ_HOST  (default dns.quad9.net)
#   DOQ_PORT  (default 853)
#
# Other resolvers this was checked against: dns.adguard-dns.com and
# unfiltered.adguard-dns.com.

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "resolv"
require "socket"

TARGET_HOST = ENV.fetch("DOQ_HOST", "dns.quad9.net")
TARGET_PORT = Integer(ENV.fetch("DOQ_PORT", "853"))
QUERY_NAME = ARGV[0] || "example.com"
QUERY_TYPE = ARGV[1] || "A"

# Resolv only gives well-known names to a handful of resource classes; the
# rest arrive as Resolv::DNS::Resource::TypeNN_ClassNN. Map the numeric type
# back to a name for display, falling back to the RFC 3597 TYPENN form.
TYPE_NAMES = %w[A NS CNAME SOA PTR MX TXT AAAA SRV].to_h { |name|
  [Resolv::DNS::Resource::IN.const_get(name)::TypeValue, name]
}.freeze

resource_class = begin
  Resolv::DNS::Resource::IN.const_get(QUERY_TYPE)
rescue NameError
  abort "unknown query type: #{QUERY_TYPE}"
end

# Pin the lookup to one IPv4 address and connect the socket to the address
# the client resolved, so both talk to the same peer. See
# examples/handshake_demo.rb for why that matters.
client = QUIC::Connection::Client.new(
  host: TARGET_HOST, port: TARGET_PORT, address_family: :inet,
  settings: QUIC::Settings.default.with(alpn: ["doq"])
)
addr = client.remote_address
sock = UDPSocket.new(Socket::AF_INET)
sock.connect(addr.ip_address, addr.ip_port)

puts "resolver: #{TARGET_HOST} (#{addr.ip_address}:#{addr.ip_port}), alpn doq"
puts "query:    #{QUERY_NAME} #{QUERY_TYPE}"
puts

t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
client.bind(sock).run
handshake_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(1)
puts "handshake completed in #{handshake_ms}ms"

# Message ID 0, recursion desired.
query = Resolv::DNS::Message.new(0)
query.rd = 1
query.add_question(QUERY_NAME, resource_class)
wire = query.encode

stream = client.open_bidi_stream
# The 2-octet length prefix and the message go out together, with FIN: the
# client has nothing more to send on this stream.
stream.write([wire.bytesize].pack("n") + wire, fin: true)
puts "sent #{wire.bytesize} bytes on stream #{stream.id}, half-closed"

# The server answers and closes its side, so read until EOF. With no length,
# Stream#read returns everything received, or an empty String if nothing was.
response = stream.read
abort "resolver closed the stream without a response" if response.bytesize < 2

length = response.unpack1("n")
body = response.byteslice(2, length)
if body.nil? || body.bytesize < length
  abort "truncated response: length prefix says #{length}, got #{response.bytesize - 2}"
end

answer = Resolv::DNS::Message.decode(body)
rcode = answer.rcode
total_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(1)
puts "received #{body.bytesize} bytes, rcode #{rcode} (#{total_ms}ms total)"
puts

if answer.answer.empty?
  puts "(no answer records)"
else
  answer.each_answer do |name, ttl, data|
    value = case data
    when Resolv::DNS::Resource::IN::A, Resolv::DNS::Resource::IN::AAAA then data.address.to_s
    when Resolv::DNS::Resource::IN::CNAME, Resolv::DNS::Resource::IN::NS,
      Resolv::DNS::Resource::IN::PTR then data.name.to_s
    when Resolv::DNS::Resource::IN::MX then "#{data.preference} #{data.exchange}"
    when Resolv::DNS::Resource::IN::TXT then data.strings.join(" ")
    else data.inspect
    end
    type_value = data.class::TypeValue
    puts format("%-34s %6d  %-6s %s", name, ttl, TYPE_NAMES.fetch(type_value, "TYPE#{type_value}"), value)
  end
end

client.close
sock.close
