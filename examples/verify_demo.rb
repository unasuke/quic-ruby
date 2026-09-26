# frozen_string_literal: true

# Server certificate verification demo: handshake with a public QUIC server
# under a few QUIC::Settings verification configurations and report how each
# one ends.
#
#   1. The defaults: verify_mode :peer against the system CA store.
#   2. ca_file holding only a throwaway CA generated on the spot. The server's
#      chain does not lead to it, so the handshake fails with
#      QUIC::Error::CertificateVerifyFailed.
#   3. verify_mode :none, which skips verification entirely.
#   4. ca_file from VERIFY_CA_FILE, when that variable is set.
#
# Override the target via env vars:
#   VERIFY_HOST     (default cloudflare-quic.com)
#   VERIFY_PORT     (default 443)
#   VERIFY_ALPN     (default h3)
#   VERIFY_CA_FILE  (default unset: step 4 is skipped)
#
# Each attempt connects its socket to the address its client resolved, so
# both talk to the same peer (see examples/handshake_demo.rb).
#
# Run with: bundle exec ruby examples/verify_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "quic"
require "socket"
require "openssl"
require "tmpdir"

TARGET_HOST = ENV.fetch("VERIFY_HOST", "cloudflare-quic.com")
TARGET_PORT = Integer(ENV.fetch("VERIFY_PORT", "443"))
TARGET_ALPN = ENV.fetch("VERIFY_ALPN", "h3")
TARGET_CA_FILE = ENV["VERIFY_CA_FILE"]

# A self-signed CA that no real server chains to, written as PEM into dir.
def write_untrusted_ca(dir)
  key = OpenSSL::PKey::EC.generate("prime256v1")
  name = OpenSSL::X509::Name.parse("/CN=quic-ruby verify_demo CA")
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = name
  cert.issuer = name
  cert.public_key = key
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 3600
  factory = OpenSSL::X509::ExtensionFactory.new(cert, cert)
  cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
  cert.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
  cert.sign(key, OpenSSL::Digest.new("SHA256"))
  File.join(dir, "untrusted-ca.pem").tap { |path| File.write(path, cert.to_pem) }
end

# verify_result is an X509_V_ERR_* value; show the matching Ruby constant.
def verify_result_name(value)
  name = OpenSSL::X509.constants.grep(/\AV_ERR_/).find { |c| OpenSSL::X509.const_get(c) == value }
  name ? "OpenSSL::X509::#{name}" : "unknown"
end

def handshake(label, settings)
  client = QUIC::Connection::Client.new(
    host: TARGET_HOST, port: TARGET_PORT, address_family: :inet, settings: settings
  )
  addr = client.remote_address
  sock = UDPSocket.new(Socket::AF_INET)
  sock.connect(addr.ip_address, addr.ip_port)

  puts "== #{label} (#{addr.ip_address}:#{addr.ip_port})"
  puts "   verify_mode=#{settings.verify_mode.inspect} ca_file=#{settings.ca_file.inspect} ca_path=#{settings.ca_path.inspect}"
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  client.bind(sock).run
  elapsed_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(1)
  puts "   handshake completed (#{elapsed_ms}ms)"
  client.close
rescue QUIC::Error::CertificateVerifyFailed => e
  puts "   #{e.class}: #{e.message}"
  puts "   verify_result=#{e.verify_result.inspect} (#{verify_result_name(e.verify_result)})"
  puts "   tls_alert=#{e.tls_alert.inspect}"
rescue QUIC::Error::CryptoError => e
  puts "   #{e.class}: #{e.message} (tls_alert=#{e.tls_alert.inspect})"
rescue QUIC::Error => e
  puts "   #{e.class}: #{e.message}"
ensure
  sock&.close
  puts
end

puts "libcrypto: #{QUIC.library_versions[:openssl]}"
puts "Target: #{TARGET_HOST}:#{TARGET_PORT}, alpn #{TARGET_ALPN}"
puts

base = QUIC::Settings.default.with(alpn: [TARGET_ALPN])

handshake("system CA store (default)", base)

Dir.mktmpdir do |dir|
  handshake("ca_file with an unrelated CA", base.with(ca_file: write_untrusted_ca(dir)))
end

handshake("verify_mode :none (not verified)", base.with(verify_mode: :none))

if TARGET_CA_FILE && !TARGET_CA_FILE.empty?
  handshake("ca_file from VERIFY_CA_FILE", base.with(ca_file: TARGET_CA_FILE))
end
