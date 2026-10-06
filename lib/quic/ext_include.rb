# frozen_string_literal: true

module QUIC
  # The directory holding quic/ext.h, the C function table other native
  # extensions build against. An extconf.rb adds it to its include path:
  #
  #   require "quic/ext_include"
  #   append_cppflags("-I#{QUIC::EXT_INCLUDE_DIR}")
  #
  # This file does not load the extension, so extconf.rb can require it.
  EXT_INCLUDE_DIR = File.expand_path("../../ext/quic/include", __dir__)
end
