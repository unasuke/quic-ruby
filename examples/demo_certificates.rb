# frozen_string_literal: true

# Throwaway certificates for the server demos (echo_server_demo.rb and
# echo_endpoint_demo.rb), so that they run without any certificate files.

require "ipaddr"
require "openssl"

module DemoCertificates
  # Write a CA and a server certificate it signed (EC P-256, valid for one
  # day), with the server's private key, into dir. The server certificate
  # names localhost, 127.0.0.1 and host. Returns the paths of the CA, the
  # server certificate and the key.
  def self.generate(dir, host)
    now = Time.now

    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca_name = OpenSSL::X509::Name.parse("/CN=quic-ruby echo server demo CA")
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
    server_cert.add_extension(factory.create_extension("subjectAltName", subject_alt_names(host)))
    server_cert.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
    server_cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))

    paths = %w[ca.pem server.pem server.key].map { |name| File.join(dir, name) }
    File.write(paths[0], ca_cert.to_pem)
    File.write(paths[1], server_cert.to_pem)
    File.write(paths[2], server_key.private_to_pem)
    paths
  end

  # localhost and 127.0.0.1, plus the bind address so that echo_demo.rb can
  # verify the certificate against QUIC_ECHO_HOST.
  def self.subject_alt_names(host)
    names = ["DNS:localhost", "IP:127.0.0.1"]
    entry = begin
      IPAddr.new(host)
      "IP:#{host}"
    rescue IPAddr::InvalidAddressError
      "DNS:#{host}"
    end
    names << entry unless names.include?(entry)
    names.join(",")
  end
  private_class_method :subject_alt_names
end
