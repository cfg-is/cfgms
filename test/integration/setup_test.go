// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package integration

import (
	"os"
	"testing"
)

// skipIfShortMode skips the test if running in short/fast mode
// Integration tests requiring infrastructure should call this at the start
func skipIfShortMode(t *testing.T) {
	t.Helper()
	if os.Getenv("CFGMS_TEST_SHORT") == "1" {
		t.Skip("Skipping integration test in short mode - requires infrastructure")
	}
}
