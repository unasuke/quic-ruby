# frozen_string_literal: true

# A test-only extension that drives quic.so's C function table (quic/ext.h)
# with an echo stream handler, the way the http3 gem does. Built by
# `rake compile` into test/ext/, never shipped in the gem.

require "mkmf"
require_relative "../../../lib/quic/ext_include"

append_cppflags("-I#{QUIC::EXT_INCLUDE_DIR}")
append_cflags("-fvisibility=hidden")

# rb_ext_resolve_symbol exists since Ruby 3.3. Without it the extension still
# builds, reports QUICExtEcho::AVAILABLE = false, and its tests skip.
have_func("rb_ext_resolve_symbol", "ruby.h")

create_makefile("quic_ext_echo")
