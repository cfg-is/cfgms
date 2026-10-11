// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package contract

// baselineEnvNames are the variables every module process receives from the
// parent when the parent has them set (Linux and macOS).
var baselineEnvNames = []string{"PATH", "HOME", "TMPDIR", "LANG"}

// envMatchKey returns the key names are compared by. Names are case-sensitive
// on Linux and macOS.
func envMatchKey(name string) string { return name }
