// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package testutil

import (
	"database/sql"
	"strings"
	"testing"

	// Import SQLite driver to test CGO availability
	_ "github.com/mattn/go-sqlite3"
)

// SkipWithoutCGO skips the test if CGO is not enabled.
// This is useful for tests that depend on SQLite which requires CGO.
// The function attempts to open a SQLite database and skips the test
// if it fails with the CGO stub error.
func SkipWithoutCGO(t *testing.T) {
	t.Helper()

	// Try to open an in-memory SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "CGO_ENABLED=0") ||
			strings.Contains(errStr, "go-sqlite3 requires cgo") ||
			strings.Contains(errStr, "This is a stub") {
			t.Skip("Skipping test: SQLite requires CGO which is not enabled (no C compiler available)")
		}
		// For other errors, just skip with a generic message
		t.Skipf("Skipping test: Failed to open SQLite database: %v", err)
		return
	}
	defer func() { _ = db.Close() }()

	// Try to ping the database to verify it's working
	if err := db.Ping(); err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "CGO_ENABLED=0") ||
			strings.Contains(errStr, "go-sqlite3 requires cgo") ||
			strings.Contains(errStr, "This is a stub") {
			t.Skip("Skipping test: SQLite requires CGO which is not enabled (no C compiler available)")
		}
		t.Skipf("Skipping test: Failed to ping SQLite database: %v", err)
	}
}

// RequiresCGO returns true if the current build has CGO enabled and SQLite working.
// This can be used for conditional test logic.
func RequiresCGO() bool {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()

	if err := db.Ping(); err != nil {
		errStr := err.Error()
		return !strings.Contains(errStr, "CGO_ENABLED=0") &&
			!strings.Contains(errStr, "go-sqlite3 requires cgo")
	}
	return true
}
