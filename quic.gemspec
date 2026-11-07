# frozen_string_literal: true

require_relative "lib/quic/version"

Gem::Specification.new do |spec|
  spec.name = "quic"
  spec.version = QUIC::VERSION
  spec.authors = ["Yusuke Nakamura"]
  spec.email = ["yusuke1994525@gmail.com"]

  spec.summary = "Thin Ruby binding around ngtcp2 for the QUIC transport protocol, using picotls for TLS 1.3 over the system OpenSSL."
  spec.description = "A thin Ruby binding around ngtcp2 for the QUIC transport protocol, using picotls for TLS 1.3. " \
    "ngtcp2 and picotls are vendored via mini_portile2 at install time and linked statically; the crypto primitives " \
    "and X.509 come from the host's OpenSSL (or LibreSSL), linked dynamically, so the process shares one libcrypto " \
    "with Ruby's openssl extension. " \
    "The API is intentionally optimized for synchronous I/O and String-based buffers. " \
    "Public API is not yet stable."
  spec.homepage = "https://github.com/unasuke/quic-ruby"
  spec.license = "MIT"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/unasuke/quic-ruby"
  spec.metadata["changelog_uri"] = "https://github.com/unasuke/quic-ruby/blob/main/CHANGELOG.md"
  # Owner actions and API-key pushes require MFA. Trusted publishing (OIDC) is not
  # an API key, so the release workflow is unaffected; a manual push is not.
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .github/ .standard.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/quic/extconf.rb"]

  # ngtcp2 and picotls are downloaded and built from source via mini_portile2
  # at install time.
  spec.add_dependency "mini_portile2"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
