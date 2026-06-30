// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
)

// TestMigrateCmd_UnknownProviderErrors verifies that an unknown --provider value
// returns a non-zero error that names all currently registered providers.
func TestMigrateCmd_UnknownProviderErrors(t *testing.T) {
	// Register a sentinel provider so the error always names at least one entry.
	migrate.Register("sentinel-provider", func(_, _ string) (migrate.Migrator, error) {
		return nil, nil
	})

	migrateProvider = "definitely-not-a-real-provider"
	migrateFrom2 = "src"
	migrateTo2 = "dst"
	migrateDryRun = false

	err := runMigrate(migrateCmd, nil)
	require.Error(t, err, "unknown provider must return an error")
	assert.Contains(t, err.Error(), "definitely-not-a-real-provider",
		"error must name the unknown provider")
	assert.Contains(t, err.Error(), "sentinel-provider",
		"error must list the registered providers")
}

// TestMigrateCmd_DryRunDoesNotCallRun verifies that --dry-run invokes Plan rather than Run.
func TestMigrateCmd_DryRunDoesNotCallRun(t *testing.T) {
	runCalled := false
	planCalled := false

	migrate.Register("dry-run-test", func(_, _ string) (migrate.Migrator, error) {
		return &fakeMigrator{
			planFn: func(_ context.Context) (migrate.Report, error) {
				planCalled = true
				return migrate.Report{Counts: map[string]int{"k": 1}, Errors: map[string]error{}}, nil
			},
			runFn: func(_ context.Context) (migrate.Report, error) {
				runCalled = true
				return migrate.Report{}, nil
			},
		}, nil
	})

	migrateProvider = "dry-run-test"
	migrateFrom2 = "src"
	migrateTo2 = "dst"
	migrateDryRun = true

	err := runMigrate(migrateCmd, nil)
	require.NoError(t, err)
	assert.True(t, planCalled, "Plan must be called in dry-run mode")
	assert.False(t, runCalled, "Run must not be called in dry-run mode")
}

// TestMigrateCmd_RunExecutesMigration verifies that without --dry-run, Run is invoked.
func TestMigrateCmd_RunExecutesMigration(t *testing.T) {
	runCalled := false

	migrate.Register("run-test", func(_, _ string) (migrate.Migrator, error) {
		return &fakeMigrator{
			planFn: func(_ context.Context) (migrate.Report, error) {
				return migrate.Report{}, nil
			},
			runFn: func(_ context.Context) (migrate.Report, error) {
				runCalled = true
				return migrate.Report{Counts: map[string]int{"config_store": 3}, Errors: map[string]error{}}, nil
			},
		}, nil
	})

	migrateProvider = "run-test"
	migrateFrom2 = "src"
	migrateTo2 = "dst"
	migrateDryRun = false

	err := runMigrate(migrateCmd, nil)
	require.NoError(t, err)
	assert.True(t, runCalled, "Run must be called when --dry-run is false")
}

// fakeMigrator is a test-only Migrator backed by function fields.
type fakeMigrator struct {
	planFn func(context.Context) (migrate.Report, error)
	runFn  func(context.Context) (migrate.Report, error)
}

func (f *fakeMigrator) Plan(ctx context.Context) (migrate.Report, error) { return f.planFn(ctx) }
func (f *fakeMigrator) Run(ctx context.Context) (migrate.Report, error)  { return f.runFn(ctx) }
