//go:build cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package stewardtypes

// moduleTrustBypassBuildAllowed is true only in a binary deliberately built with
// -tags cfgms_dev_bypass (development use only — never a release build). See
// bypass_disabled.go for the default.
const moduleTrustBypassBuildAllowed = true
