# frozen_string_literal: true

# Sample script: drive a real QUIC + TLS 1.3 handshake against a public
# HTTP/3 server (cloudflare-quic.com:443) using Client#bind + Client#run, and
# print the library versions the extension was built with.
#
# address_family: :inet pins the lookup to a single IPv4 address, and the
# socket is connected to client.remote_address so that it talks to the same
# peer as the connection path ngtcp2 holds. Cloudflare returns several A/AAAA
# records; a second, independent lookup could pick another one, and ngtcp2
# would then drop every reply as coming from an unknown path.
#
# Run with: bundle exec ruby examples/handshake_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "socket"

TARGET_HOST = "cloudflare-quic.com"
TARGET_PORT = 443

client = QUIC::Connection::Client.new(
  host: TARGET_HOST, port: TARGET_PORT, address_family: :inet,
  settings: QUIC::Settings.default.with(alpn: ["h3"])
)
addr = client.remote_address
sock = UDPSocket.new(Socket::AF_INET)
sock.connect(addr.ip_address, addr.ip_port)

puts "ngtcp2: #{QUIC.library_versions[:ngtcp2]}"
puts "picotls: #{QUIC.library_versions[:picotls]}"
puts "libcrypto: #{QUIC.library_versions[:openssl]}"
puts "Target: #{TARGET_HOST} (#{addr.ip_address}:#{addr.ip_port})"
puts

t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
client.bind(sock).run
elapsed_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(1)

puts "handshake_completed? #{client.handshake_completed?} (#{elapsed_ms}ms)"

client.close
sock.close
