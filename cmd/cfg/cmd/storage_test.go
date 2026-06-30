// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStorageMigrateValidation verifies that runStorageMigrate returns a clear
// error when required flags or backend configuration are missing.
//
// When the "storage" migrator is registered (via pkg/migrate/storage imported
// from cmd/cfg/cmd/migrate.go), runStorageMigrate delegates to that migrator.
// The test cases therefore use backend names and error strings that match the
// new migrator's validation rather than the legacy git-inline fallback.
func TestStorageMigrateValidation(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		to             string
		wantErrContain string
	}{
		{
			// "git" is not a supported backend in the registered storage migrator.
			name:           "git backend unsupported",
			from:           "git",
			to:             "oss",
			wantErrContain: "git",
		},
		{
			// Neither "git" nor "memory" are supported backends; the first
			// unknown backend ("git") is what we detect in the error message.
			name:           "unsupported from and to backends",
			from:           "git",
			to:             "memory",
			wantErrContain: "git",
		},
		{
			// database backend without DSN must fail with a clear message.
			name:           "database backend missing DSN",
			from:           "database",
			to:             "oss",
			wantErrContain: "CFGMS_STORAGE_CLUSTER_POSTGRES_DSN",
		},
		{
			// oss backend without env vars must fail with a clear message.
			name:           "oss backend missing flatfile root",
			from:           "oss",
			to:             "database",
			wantErrContain: "CFGMS_STORAGE_FLATFILE_ROOT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear oss-related env vars to trigger the expected error.
			t.Setenv("CFGMS_STORAGE_FLATFILE_ROOT", "")
			t.Setenv("CFGMS_STORAGE_SQLITE_PATH", "")
			t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")

			// Save and restore global flags.
			origFrom := migrateFrom
			origTo := migrateTo
			defer func() {
				migrateFrom = origFrom
				migrateTo = origTo
			}()

			migrateFrom = tt.from
			migrateTo = tt.to

			err := runStorageMigrate(nil, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrContain)
		})
	}
}

// TestStorageMigrateGitBackendRejected verifies that attempting to use the
// legacy "git" backend through runStorageMigrate now returns an unsupported-backend
// error from the storage migrator (the git-inline fallback is no longer reached
// once the "storage" migrator is registered).
func TestStorageMigrateGitBackendRejected(t *testing.T) {
	t.Setenv("CFGMS_STORAGE_FLATFILE_ROOT", "")
	t.Setenv("CFGMS_STORAGE_SQLITE_PATH", "")
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")

	origFrom := migrateFrom
	origTo := migrateTo
	origGitRoot := migrateGitRoot
	origFlatfileRoot := migrateFlatfileRoot
	defer func() {
		migrateFrom = origFrom
		migrateTo = origTo
		migrateGitRoot = origGitRoot
		migrateFlatfileRoot = origFlatfileRoot
	}()

	migrateFrom = "git"
	migrateTo = "oss"
	migrateGitRoot = t.TempDir()
	migrateFlatfileRoot = t.TempDir()

	err := runStorageMigrate(nil, nil)
	require.Error(t, err)
	// The registered storage migrator reports "git" as an unknown backend.
	assert.Contains(t, err.Error(), "git")
}
