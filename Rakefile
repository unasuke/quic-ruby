# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

Minitest::TestTask.create

require "standard/rake"

require "rake/extensiontask"

task build: :compile

GEMSPEC = Gem::Specification.load("quic.gemspec")

Rake::ExtensionTask.new("quic", GEMSPEC) do |ext|
  ext.lib_dir = "lib/quic"
end

# A test-only extension that drives quic/ext.h like the http3 gem does
# (test/test_quic_ext_api.rb). It lands in test/ext/ and is never packaged.
Rake::ExtensionTask.new("quic_ext_echo") do |ext|
  ext.ext_dir = "test/ext/quic_ext_echo"
  ext.lib_dir = "test/ext"
end

task default: %i[clobber compile test standard]
