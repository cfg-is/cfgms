#!/usr/bin/env bash
# Build the Rust ETW consumer staticlib (#2571) and stage it — plus the
# windows-sys umbrella import lib it depends on — into rust/link/, where the cgo
# `dexrust` build (consume_rust_link_windows.go) links them via -L${SRCDIR}/rust/link.
#
# Prereq: a Rust GNU toolchain (`rustup default stable-x86_64-pc-windows-gnu`) so
# the .a links against the same mingw gcc cgo uses. Then, from the repo root:
#   bash features/steward/dex/rust/build.sh
#   go test -c -tags "dexconsume dexrust" ./features/steward/dex/
#
# The exact Rust-std native libs to pass in the cgo LDFLAGS come from:
#   cargo rustc --release --lib -- --print native-static-libs
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release
mkdir -p link
cp target/release/libdexetw.a link/

# windows-sys 0.59 pulls its Win32 import symbols from a bundled umbrella lib in
# the windows_x86_64_gnu crate. Locate it by glob so a patch-version bump still works.
umbrella=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" \
    -path '*windows_x86_64_gnu*/lib/libwindows.0.52.0.a' 2>/dev/null | head -1)
if [[ -z "${umbrella}" || ! -f "${umbrella}" ]]; then
    echo "ERROR: could not find libwindows.0.52.0.a (windows_x86_64_gnu crate). If the" >&2
    echo "windows-sys version changed, update the -lwindows.* flag in" >&2
    echo "consume_rust_link_windows.go to match." >&2
    exit 1
fi
cp "${umbrella}" link/

echo "staged into rust/link/: $(ls link/)"
