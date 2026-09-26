# frozen_string_literal: true

require "mkmf"
require "mini_portile2"
require "shellwords"
require "fileutils"

NGTCP2_VERSION = "1.22.1"
NGTCP2_SHA256 = "063d80531acac0ddbbc1b9d12829a824edc2abe8dba2e632fd1ce15cfd5632f9"
# The picotls revision that ngtcp2 1.22.1 is tested against (see ngtcp2's README).
PICOTLS_COMMIT = "b84869f41414b6d0148db7728f1cf12f5b544874"
PICOTLS_SHA256 = "abdb190f022d2ee2a3f3dd20e7303a226d7ec4e82f2221c0ab243d9a2e8ceaaf"
# Bump when ext/quic/patches/picotls/ changes; installed? only checks for the archive.
PICOTLS_PATCH_LEVEL = "p1"

# Locate the host's libcrypto. ngtcp2 and picotls are vendored and statically
# linked, but the crypto primitives and X.509 come from whatever OpenSSL (or
# LibreSSL) the system provides, linked dynamically. Sharing one libcrypto with
# Ruby's own openssl extension is the point: two copies in one process
# interpose on each other's global symbols.
#
# Everything downstream resolves OpenSSL through pkg-config -- this file,
# ngtcp2's configure, and the `openssl` entry in libngtcp2_crypto_picotls.pc's
# Requires.private -- so --with-openssl-dir is honoured by putting its prefix
# on PKG_CONFIG_PATH once, here. That keeps all three agreeing on one install
# instead of each making its own choice.
_openssl_incdir, openssl_libdir = dir_config("openssl")
if openssl_libdir
  ENV["PKG_CONFIG_PATH"] =
    [File.join(openssl_libdir, "pkgconfig"), ENV["PKG_CONFIG_PATH"]].compact.join(File::PATH_SEPARATOR)
end

unless pkg_config("openssl")
  abort "OpenSSL not found. Install its development package (libssl-dev, " \
        "openssl-devel, ...), or point at a prefix whose lib/pkgconfig holds " \
        "openssl.pc with --with-openssl-dir=/path."
end
# picotls is compiled by hand below and needs the include path on its own.
openssl_cflags = pkg_config("openssl", "cflags-only-I").to_s.strip

# picotls has no release tarballs, and its CMake build needs the picotest
# submodule, which GitHub archive tarballs do not contain. Build only the two
# libraries we need (core + OpenSSL-API backend) into a single libpicotls.a.
class PicotlsRecipe < MiniPortile
  SOURCES = %w[lib/picotls.c lib/hpke.c lib/pembase64.c lib/openssl.c].freeze

  attr_accessor :openssl_cflags

  def configure
  end

  def configured?
    true
  end

  def compile
    cflags = %w[-std=gnu99 -O2 -fPIC -fvisibility=hidden -Iinclude] + openssl_cflags.to_s.shellsplit
    objects = SOURCES.map do |src|
      obj = File.basename(src, ".c") + ".o"
      execute("compile", [*cc_cmd.shellsplit, *cflags, "-c", src, "-o", obj])
      obj
    end
    ar = (ENV["AR"] || RbConfig::CONFIG["AR"] || "ar").shellsplit
    execute("compile", [*ar, "rcs", "libpicotls.a", *objects])
  end

  def install
    FileUtils.mkdir_p([lib_path, include_path])
    FileUtils.cp(File.join(work_path, "libpicotls.a"), lib_path)
    FileUtils.cp_r(Dir.glob(File.join(work_path, "include", "*")), include_path)
  end

  def installed?
    File.exist?(File.join(lib_path, "libpicotls.a"))
  end
end

picotls = PicotlsRecipe.new("picotls", "#{PICOTLS_COMMIT[0, 7]}-#{PICOTLS_PATCH_LEVEL}")
picotls.files = [{
  url: "https://github.com/h2o/picotls/archive/#{PICOTLS_COMMIT}.tar.gz",
  sha256: PICOTLS_SHA256
}]
picotls.patch_files = Dir.glob(File.join(__dir__, "patches", "picotls", "*.patch")).sort
picotls.openssl_cflags = openssl_cflags
picotls.cook
# Deliberately no picotls.activate: mkmf_config passes -I/-L below, and not
# activating keeps the extra directory out of CPATH.

ngtcp2 = MiniPortile.new("ngtcp2", NGTCP2_VERSION)
ngtcp2.files = [{
  url: "https://github.com/ngtcp2/ngtcp2/releases/download/v#{NGTCP2_VERSION}/ngtcp2-#{NGTCP2_VERSION}.tar.gz",
  sha256: NGTCP2_SHA256
}]
ngtcp2.configure_options = [
  "--enable-lib-only",
  "--disable-shared",
  "--with-pic",
  # Skip the quictls/libressl/ossl helpers; only libngtcp2_crypto_picotls.
  "--without-openssl",
  "--with-picotls",
  # crypto/picotls declares lib_LIBRARIES, not lib_LTLIBRARIES, so it is built
  # by plain ar rather than libtool and --with-pic does not reach it. Without
  # -fPIC the archive cannot be linked into quic.so.
  "CFLAGS=-g -O2 -fPIC",
  "PICOTLS_CFLAGS=-I#{picotls.include_path}",
  "PICOTLS_LIBS=-L#{picotls.lib_path} -lpicotls"
]
# ngtcp2 still probes for OpenSSL under --without-openssl: its picotls check
# links the conftest against libcrypto. It finds it through the same
# PKG_CONFIG_PATH set above, which the configure subprocess inherits.
ngtcp2.cook
ngtcp2.activate

# Wire the vendored static archives into mkmf in reverse dependency order.
# mkmf_config prepends to $libs, so the leftmost entry on the final link line
# ends up being the last one added here, satisfying static-link ordering:
# ngtcp2_crypto_picotls -> ngtcp2 -> picotls -> the -lssl -lcrypto that
# pkg_config("openssl") already put there.
#
# Deliberately not the `pkg:` form. Resolving libngtcp2_crypto_picotls.pc
# would follow its `Requires.private: libngtcp2, openssl` with
# `pkg-config --static`, which drags in the host libcrypto's own static
# dependency list (on Ubuntu: -l:libjitterentropy.a -lz -lzstd). Those belong
# to a static libcrypto we are not linking, and the archives they name are
# often not even installed. The recipe's own include/lib paths are all we
# need.
picotls.mkmf_config(static: "picotls")
ngtcp2.mkmf_config(static: "ngtcp2")
ngtcp2.mkmf_config(static: "ngtcp2_crypto_picotls")

# picotls's OpenSSL backend, and the X25519 patch in ext/quic/patches/picotls/,
# both need the raw public key API introduced in OpenSSL 1.1.1. LibreSSL
# reports 0x20000000L here, so one check covers both.
abort "OpenSSL 1.1.1 or later is required" unless try_compile(<<~C)
  #include <openssl/opensslv.h>
  #if OPENSSL_VERSION_NUMBER < 0x10101000L
  #error OpenSSL is too old
  #endif
  int main(void) { return 0; }
C
abort "ngtcp2 header missing" unless have_header("ngtcp2/ngtcp2.h")
abort "picotls header missing" unless have_header("picotls.h")
abort "picotls/openssl.h missing" unless have_header("picotls/openssl.h")
abort "ngtcp2_crypto_picotls header missing" unless have_header("ngtcp2/ngtcp2_crypto_picotls.h")
abort "picotls was built without X25519 (patch not applied?)" unless try_compile(<<~C)
  #include <picotls/openssl.h>
  #if !PTLS_OPENSSL_HAVE_X25519
  #error X25519 unavailable
  #endif
C
# ngtcp2_conn_client_new and most other ngtcp2 entry points are exposed as
# ABI-versioned macros, so use non-macro symbols for link verification.
abort "libngtcp2 not linkable" unless have_func("ngtcp2_version", "ngtcp2/ngtcp2.h")
abort "libngtcp2_crypto_picotls not linkable" unless
  have_func("ngtcp2_crypto_picotls_configure_client_context", %w[picotls.h ngtcp2/ngtcp2_crypto_picotls.h])
abort "libcrypto not linkable" unless have_func("OpenSSL_version", "openssl/crypto.h")

# picotls has neither a version macro nor releases, so QUIC.library_versions
# reports the commit the extension was built against.
append_cflags("-DQUIC_PICOTLS_COMMIT=\\\"#{PICOTLS_COMMIT}\\\"")
append_cflags("-fvisibility=hidden")
append_ldflags("-Wl,--exclude-libs,ALL")  # Unexport symbols from statically linked libraries

create_makefile("quic/quic")
