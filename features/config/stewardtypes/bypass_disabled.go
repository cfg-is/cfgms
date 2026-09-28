//go:build !cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package stewardtypes

// moduleTrustBypassBuildAllowed is false in every normal build. module_trust.mode:
// bypass disables all module signature verification (Issue #4324) — the CLAUDE.md
// threat model requires it to be structurally absent, not merely runtime-disabled,
// from a release steward binary. Mirrors the cfgms_test_endpoints pattern in
// features/controller/api/test_endpoints_{enabled,disabled}.go.
const moduleTrustBypassBuildAllowed = false
