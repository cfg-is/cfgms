// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package package_module

import "testing"

// newTestChocoStagingBase returns a staging base for tests that run the real
// bootstrap. bootstrapChocoReal refuses to run off Windows, so a plain
// temporary directory is enough here.
func newTestChocoStagingBase(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
