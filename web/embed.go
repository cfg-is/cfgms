// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package web provides the embedded SPA assets served by the controller.
// The //go:embed directive reads the filesystem at build time regardless of git
// status: a committed dist/index.html placeholder keeps go build self-contained
// with no Node toolchain; a local npm run build output under dist/ is embedded
// when present and produces the real SPA.
package web

import "embed"

//go:embed all:dist
var Assets embed.FS
