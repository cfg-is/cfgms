// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageMigrateValidation(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		to             string
		gitRoot        string
		flatfileRoot   string
		wantErrContain string
	}{
		{
			name:           "unsupported source provider",
			from:           "database",
			to:             "flatfile",
			gitRoot:        "/tmp/test",
			flatfileRoot:   "/tmp/out",
			wantErrContain: "unsupported source provider",
		},
		{
			name:           "unsupported target provider",
			from:           "git",
			to:             "memory",
			gitRoot:        "/tmp/test",
			flatfileRoot:   "/tmp/out",
			wantErrContain: "unsupported target provider",
		},
		{
			name:           "missing git root",
			from:           "git",
			to:             "flatfile",
			gitRoot:        "",
			flatfileRoot:   "/tmp/out",
			wantErrContain: "--git-root is required",
		},
		{
			name:           "missing flatfile root for flatfile target",
			from:           "git",
			to:             "flatfile",
			gitRoot:        "/tmp/test",
			flatfileRoot:   "",
			wantErrContain: "--flatfile-root is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags
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

			migrateFrom = tt.from
			migrateTo = tt.to
			migrateGitRoot = tt.gitRoot
			migrateFlatfileRoot = tt.flatfileRoot

			err := runStorageMigrate(nil, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrContain)
		})
	}
}

func TestStorageMigrateGitProviderNotAvailable(t *testing.T) {
	// Save and restore global flags
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
	migrateTo = "flatfile"
	migrateGitRoot = t.TempDir()
	migrateFlatfileRoot = t.TempDir()

	// The git provider is not registered in this binary (it was removed).
	// runStorageMigrate must return a clear error rather than panic.
	err := runStorageMigrate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git storage provider not available")
}
