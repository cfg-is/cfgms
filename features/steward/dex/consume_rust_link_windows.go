// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume && dexrust

// consume_rust_link_windows.go — links the Rust variant of the ETW consumer
// (features/steward/dex/rust/) instead of the C one, under the `dexrust` build
// tag. The Rust staticlib exports the identical cfgms_* C ABI, so the Go wrapper
// (consume_windows.go) is reused unchanged — only the native implementation and
// its link flags differ. consume_etw_windows.c is excluded under this tag
// (`//go:build ... && !dexrust`) so there is no duplicate-symbol clash.
//
// Build the staticlib first: (cd rust && cargo build --release), stage its .a
// plus the windows-sys umbrella import lib into rust/link/, then
//
//	go test -c -tags "dexconsume dexrust" ./features/steward/dex/
//
// The libs Rust std needs come from `cargo rustc -- --print native-static-libs`.
package dex

// #cgo LDFLAGS: -L${SRCDIR}/rust/link -ldexetw -lwindows.0.52.0 -lntdll -luserenv -lws2_32 -ldbghelp
import "C"
