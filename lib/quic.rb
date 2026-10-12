# frozen_string_literal: true

require_relative "quic/version"
require_relative "quic/ext_include"

module QUIC
  class Error < StandardError
    attr_reader :code
  end
end

require "quic/quic"
require_relative "quic/transport_params"
require_relative "quic/settings"
require_relative "quic/connection"
require_relative "quic/stream"
