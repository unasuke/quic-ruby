# frozen_string_literal: true

module QUIC
  Settings = Data.define(
    :cc_algo,
    :initial_rtt,
    :max_window,
    :max_stream_window,
    :handshake_timeout,
    :no_pmtud,
    :alpn,
    :verify_mode,
    :ca_file,
    :ca_path
  )

  class Settings
    # verify_mode (:peer or :none), ca_file and ca_path control server
    # certificate verification. They default here so that callers building a
    # Settings without them keep working.
    #
    # With verify_mode :peer and both ca_file and ca_path nil, the system
    # default store is used, and SSL_CERT_FILE / SSL_CERT_DIR are honoured.
    # That store is loaded once per process, the first time a connection needs
    # it; later changes to those variables or to the CA bundle are not picked
    # up. Setting ca_file or ca_path trusts only the certificates found there.
    # With verify_mode :none, ca_file and ca_path are ignored.
    def initialize(verify_mode: :peer, ca_file: nil, ca_path: nil, **rest)
      super
    end

    def self.default
      new(
        cc_algo: :cubic,
        initial_rtt: 333_000_000,
        max_window: 0,
        max_stream_window: 0,
        handshake_timeout: 10_000_000_000,
        no_pmtud: false,
        alpn: [],
        verify_mode: :peer,
        ca_file: nil,
        ca_path: nil
      )
    end
  end
end
