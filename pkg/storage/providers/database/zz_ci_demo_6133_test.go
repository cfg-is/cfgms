//go:build integration

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// THROWAWAY — Issue #6133 CI demonstration only. Never merge.
// This test reaches the real Postgres and then fails on purpose, to show that
// the `Postgres Integration Tests (PR)` job runs the suite and fails the job
// when a test fails.
package database

import "testing"

func TestCIDemo6133_DeliberateFailure(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	if err := db.Ping(); err != nil {
		t.Fatalf("real Postgres not reachable: %v", err)
	}
	t.Fatalf("DELIBERATE FAILURE (Issue #6133 CI demo): real Postgres reached; this assertion must fail the job")
}
