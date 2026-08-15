// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package web provides the embedded SPA assets served by the controller.
// The //go:embed directive reads the filesystem at build time regardless of git
// status: the committed dist/index.html placeholder keeps go build self-contained
// with no Node toolchain, and npm run build output under dist/app/ is embedded
// when present and produces the real SPA.
//
// The placeholder is never a servable SPA — it carries the CFGMS_DIST_PLACEHOLDER
// sentinel, and the controller refuses to route "/" when that is all it finds,
// rather than serving a shell that never loads the application (Issue #3043).
package web

import "embed"

//go:embed all:dist
var Assets embed.FS
