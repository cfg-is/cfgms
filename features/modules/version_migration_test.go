// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package modules

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultVersionMigrator_CanMigrate(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	versions := []string{"1.0.0", "1.1.0", "2.0.0"}
	for _, version := range versions {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     version,
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))
	}

	tests := []struct {
		name        string
		moduleName  string
		fromVersion string
		toVersion   string
		expectErr   bool
		errContains string
	}{
		{
			name:        "valid upgrade",
			moduleName:  "test-module",
			fromVersion: "1.0.0",
			toVersion:   "1.1.0",
			expectErr:   false,
		},
		{
			name:        "valid downgrade",
			moduleName:  "test-module",
			fromVersion: "2.0.0",
			toVersion:   "1.0.0",
			expectErr:   false,
		},
		{
			name:        "same version",
			moduleName:  "test-module",
			fromVersion: "1.0.0",
			toVersion:   "1.0.0",
			expectErr:   true,
			errContains: "same",
		},
		{
			name:        "non-existent from version",
			moduleName:  "test-module",
			fromVersion: "0.9.0",
			toVersion:   "1.0.0",
			expectErr:   true,
			errContains: "is not installed",
		},
		{
			name:        "non-existent to version",
			moduleName:  "test-module",
			fromVersion: "1.0.0",
			toVersion:   "3.0.0",
			expectErr:   true,
			errContains: "is not installed",
		},
		{
			name:        "invalid from version format",
			moduleName:  "test-module",
			fromVersion: "invalid",
			toVersion:   "1.0.0",
			expectErr:   true,
			errContains: "invalid from version",
		},
		{
			name:        "invalid to version format",
			moduleName:  "test-module",
			fromVersion: "1.0.0",
			toVersion:   "invalid",
			expectErr:   true,
			errContains: "invalid to version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canMigrate, err := migrator.CanMigrate(tt.moduleName, tt.fromVersion, tt.toVersion)

			if tt.expectErr {
				assert.False(t, canMigrate)
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.True(t, canMigrate)
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultVersionMigrator_GetMigrationPath(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	versions := []string{"1.0.0", "1.1.0", "2.0.0", "3.0.0"}
	for _, version := range versions {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     version,
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))
	}

	tests := []struct {
		name                   string
		fromVersion            string
		toVersion              string
		expectedComplexity     VersionMigrationComplexity
		expectedRequiresBackup bool
		minSteps               int
	}{
		{
			name:                   "patch upgrade",
			fromVersion:            "1.0.0",
			toVersion:              "1.1.0",
			expectedComplexity:     MigrationComplexityMedium,
			expectedRequiresBackup: true,
			minSteps:               5,
		},
		{
			name:                   "major upgrade",
			fromVersion:            "1.0.0",
			toVersion:              "2.0.0",
			expectedComplexity:     MigrationComplexityHigh,
			expectedRequiresBackup: true,
			minSteps:               6,
		},
		{
			name:                   "major downgrade",
			fromVersion:            "3.0.0",
			toVersion:              "1.0.0",
			expectedComplexity:     MigrationComplexityHigh,
			expectedRequiresBackup: true,
			minSteps:               6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := migrator.GetMigrationPath("test-module", tt.fromVersion, tt.toVersion)
			require.NoError(t, err)
			assert.NotNil(t, path)

			// Verify basic path properties
			assert.Equal(t, "test-module", path.ModuleName)
			assert.Equal(t, tt.fromVersion, path.FromVersion)
			assert.Equal(t, tt.toVersion, path.ToVersion)
			assert.Equal(t, tt.expectedComplexity, path.Complexity)
			assert.Equal(t, tt.expectedRequiresBackup, path.RequiresBackup)
			assert.True(t, path.RollbackSupported)
			assert.NotEmpty(t, path.ID)
			assert.False(t, path.CreatedAt.IsZero())

			// Verify steps
			assert.GreaterOrEqual(t, len(path.Steps), tt.minSteps)

			// First step should be validation
			assert.Equal(t, MigrationStepValidation, path.Steps[0].Type)

			// Last step should be cleanup
			lastStep := path.Steps[len(path.Steps)-1]
			assert.Equal(t, MigrationStepCleanup, lastStep.Type)

			// Verify step IDs are unique
			stepIDs := make(map[string]bool)
			for _, step := range path.Steps {
				assert.False(t, stepIDs[step.ID], "Duplicate step ID: %s", step.ID)
				stepIDs[step.ID] = true
				assert.NotEmpty(t, step.Description)
				assert.Greater(t, step.EstimatedTime, time.Duration(0))
			}

			// Verify estimated time is calculated
			assert.Greater(t, path.EstimatedTime, time.Duration(0))

			// Complex migrations should have warnings
			if path.Complexity >= MigrationComplexityMedium {
				assert.NotEmpty(t, path.Warnings)
			}
		})
	}
}

func TestDefaultVersionMigrator_ValidateMigrationPath(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	metadata2 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.1.0",
		Description: "Test module v1.1.0",
	}
	require.NoError(t, registry.RegisterVersion(metadata1))
	require.NoError(t, registry.RegisterVersion(metadata2))

	t.Run("valid path", func(t *testing.T) {
		path, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)

		err = migrator.ValidateMigrationPath(path)
		assert.NoError(t, err)
	})

	t.Run("nil path", func(t *testing.T) {
		err := migrator.ValidateMigrationPath(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("empty module name", func(t *testing.T) {
		path := &MigrationPath{
			ModuleName:  "",
			FromVersion: "1.0.0",
			ToVersion:   "1.1.0",
			Steps:       []MigrationStep{{ID: "test", Description: "test"}},
		}

		err := migrator.ValidateMigrationPath(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "module name is required")
	})

	t.Run("empty from version", func(t *testing.T) {
		path := &MigrationPath{
			ModuleName:  "test-module",
			FromVersion: "",
			ToVersion:   "1.1.0",
			Steps:       []MigrationStep{{ID: "test", Description: "test"}},
		}

		err := migrator.ValidateMigrationPath(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "from and to versions are required")
	})

	t.Run("no steps", func(t *testing.T) {
		path := &MigrationPath{
			ModuleName:  "test-module",
			FromVersion: "1.0.0",
			ToVersion:   "1.1.0",
			Steps:       []MigrationStep{},
		}

		err := migrator.ValidateMigrationPath(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must have at least one step")
	})

	t.Run("step with empty ID", func(t *testing.T) {
		path := &MigrationPath{
			ModuleName:  "test-module",
			FromVersion: "1.0.0",
			ToVersion:   "1.1.0",
			Steps: []MigrationStep{
				{ID: "", Description: "test"},
			},
		}

		err := migrator.ValidateMigrationPath(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "step ID is required")
	})

	t.Run("step with empty description", func(t *testing.T) {
		path := &MigrationPath{
			ModuleName:  "test-module",
			FromVersion: "1.0.0",
			ToVersion:   "1.1.0",
			Steps: []MigrationStep{
				{ID: "test", Description: ""},
			},
		}

		err := migrator.ValidateMigrationPath(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "step description is required")
	})
}

func TestDefaultVersionMigrator_ExecuteMigration(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	metadata2 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.1.0",
		Description: "Test module v1.1.0",
	}
	require.NoError(t, registry.RegisterVersion(metadata1))
	require.NoError(t, registry.RegisterVersion(metadata2))

	t.Run("successful migration execution", func(t *testing.T) {
		path, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, path)
		require.NoError(t, err)
		assert.NotNil(t, result)

		assert.Equal(t, path.ID, result.ID)
		assert.Equal(t, path, result.Path)
		assert.Equal(t, MigrationStatusRunning, result.Status)
		assert.False(t, result.StartTime.IsZero())

		// Wait for migration to complete deterministically
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, migrator.WaitForMigration(waitCtx, result.ID))

		status, err := migrator.GetMigrationStatus(result.ID)
		require.NoError(t, err)
		assert.Equal(t, MigrationStatusCompleted, status.Status)
		assert.Equal(t, 1.0, status.Progress)
	})

	t.Run("invalid migration path", func(t *testing.T) {
		invalidPath := &MigrationPath{
			ModuleName:  "",
			FromVersion: "1.0.0",
			ToVersion:   "1.1.0",
		}

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, invalidPath)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid migration path")
	})

	t.Run("concurrent migration for same module", func(t *testing.T) {
		// Inject a fake running execution to test the concurrency guard deterministically.
		// This avoids relying on goroutine scheduling timing.
		path, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)

		blockCtx, blockCancel := context.WithCancel(context.Background())
		fakeExec := &MigrationExecution{
			Path:       path,
			Status:     MigrationStatusRunning,
			StartTime:  time.Now(),
			Context:    blockCtx,
			CancelFunc: blockCancel,
		}
		migrator.mu.Lock()
		migrator.activeMigrations[path.ID] = fakeExec
		migrator.mu.Unlock()

		path2, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)

		// Second migration for same module must be rejected
		result2, err := migrator.ExecuteMigration(context.Background(), path2)
		assert.Nil(t, result2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "migration already in progress")

		// Remove fake execution and verify a fresh migration can now start
		blockCancel()
		migrator.mu.Lock()
		delete(migrator.activeMigrations, path.ID)
		migrator.mu.Unlock()

		path3, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)
		result3, err := migrator.ExecuteMigration(context.Background(), path3)
		require.NoError(t, err)
		assert.NotNil(t, result3)

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, migrator.WaitForMigration(waitCtx, result3.ID))
	})
}

func TestDefaultVersionMigrator_GetMigrationStatus(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	metadata2 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.1.0",
		Description: "Test module v1.1.0",
	}
	require.NoError(t, registry.RegisterVersion(metadata1))
	require.NoError(t, registry.RegisterVersion(metadata2))

	t.Run("active migration status", func(t *testing.T) {
		path, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, path)
		require.NoError(t, err)

		// Wait for completion deterministically
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, migrator.WaitForMigration(waitCtx, result.ID))

		// Verify completed status fields
		status, err := migrator.GetMigrationStatus(result.ID)
		require.NoError(t, err)
		assert.NotNil(t, status)
		assert.Equal(t, result.ID, status.ID)
		assert.Equal(t, "test-module", status.ModuleName)
		assert.Equal(t, "1.0.0", status.FromVersion)
		assert.Equal(t, "1.1.0", status.ToVersion)
		assert.Equal(t, len(path.Steps), status.TotalSteps)
		assert.Equal(t, MigrationStatusCompleted, status.Status)
		assert.Equal(t, 1.0, status.Progress)
		assert.Greater(t, status.ElapsedTime, time.Duration(0))
	})

	t.Run("non-existent migration", func(t *testing.T) {
		_, err := migrator.GetMigrationStatus("non-existent-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestDefaultVersionMigrator_ListActiveMigrations(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test modules
	for i := 0; i < 3; i++ {
		for version := range []string{"1.0.0", "1.1.0"} {
			metadata := &ModuleMetadata{
				Name:        fmt.Sprintf("test-module-%d", i),
				Version:     []string{"1.0.0", "1.1.0"}[version],
				Description: "Test module",
			}
			require.NoError(t, registry.RegisterVersion(metadata))
		}
	}

	t.Run("no active migrations", func(t *testing.T) {
		activeMigrations, err := migrator.ListActiveMigrations()
		require.NoError(t, err)
		assert.Empty(t, activeMigrations)
	})

	t.Run("completed migrations removed from active list", func(t *testing.T) {
		var ids []string
		for i := 0; i < 3; i++ {
			modName := fmt.Sprintf("test-module-%d", i)
			path, err := migrator.GetMigrationPath(modName, "1.0.0", "1.1.0")
			require.NoError(t, err)
			result, err := migrator.ExecuteMigration(context.Background(), path)
			require.NoError(t, err)
			ids = append(ids, result.ID)
		}

		// Wait for all to complete deterministically
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, id := range ids {
			require.NoError(t, migrator.WaitForMigration(waitCtx, id))
		}

		// Completed migrations must not appear in the active list
		active, err := migrator.ListActiveMigrations()
		require.NoError(t, err)
		activeIDs := make(map[string]bool)
		for _, s := range active {
			activeIDs[s.ID] = true
		}
		for _, id := range ids {
			assert.False(t, activeIDs[id], "completed migration %s must not be in active list", id)
		}
	})

	t.Run("terminal-status migration still in map is excluded", func(t *testing.T) {
		// Reproduces the race in executeMigrationSteps: the terminal status is
		// set before the cleanup defer removes the activeMigrations entry, so a
		// caller that observed completion via WaitForMigration could otherwise
		// still see the migration listed as active. ListActiveMigrations must
		// classify by status, not by raw map membership.
		terminalStates := []MigrationExecutionStatus{
			MigrationStatusCompleted,
			MigrationStatusFailed,
			MigrationStatusCancelled,
			MigrationStatusRolledBack,
		}
		for _, st := range terminalStates {
			id := fmt.Sprintf("terminal-%s", st)

			migrator.mu.Lock()
			migrator.activeMigrations[id] = &MigrationExecution{
				Path: &MigrationPath{
					ID:          id,
					ModuleName:  "terminal-module",
					FromVersion: "1.0.0",
					ToVersion:   "1.1.0",
				},
				Status:    st,
				StartTime: time.Now(),
			}
			migrator.mu.Unlock()

			active, err := migrator.ListActiveMigrations()
			require.NoError(t, err)
			for _, s := range active {
				assert.NotEqual(t, id, s.ID,
					"terminal-status migration %s must not be reported as active", id)
			}

			migrator.mu.Lock()
			delete(migrator.activeMigrations, id)
			migrator.mu.Unlock()
		}
	})
}

func TestDefaultVersionMigrator_RollbackMigration(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	metadata2 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.1",
		Description: "Test module v1.0.1",
	}
	require.NoError(t, registry.RegisterVersion(metadata1))
	require.NoError(t, registry.RegisterVersion(metadata2))

	t.Run("rollback completed migration", func(t *testing.T) {
		path, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.0.1")
		require.NoError(t, err)

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, path)
		require.NoError(t, err)

		// Wait for completion deterministically
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, migrator.WaitForMigration(waitCtx, result.ID))

		status, err := migrator.GetMigrationStatus(result.ID)
		require.NoError(t, err)
		assert.Equal(t, MigrationStatusCompleted, status.Status)

		// Now rollback
		rollbackResult, err := migrator.RollbackMigration(ctx, result.ID)
		require.NoError(t, err)
		assert.NotNil(t, rollbackResult)
		assert.NotEqual(t, result.ID, rollbackResult.ID)
		assert.Equal(t, MigrationStatusRunning, rollbackResult.Status)

		// Wait for rollback to complete deterministically
		waitCtx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		require.NoError(t, migrator.WaitForMigration(waitCtx2, rollbackResult.ID))

		rollbackStatus, err := migrator.GetMigrationStatus(rollbackResult.ID)
		require.NoError(t, err)
		assert.Equal(t, MigrationStatusCompleted, rollbackStatus.Status)
	})

	t.Run("rollback non-existent migration", func(t *testing.T) {
		ctx := context.Background()
		_, err := migrator.RollbackMigration(ctx, "non-existent-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found in history")
	})

	t.Run("rollback not supported", func(t *testing.T) {
		// Inject a completed migration that has RollbackSupported=false
		migrator.mu.Lock()
		migrator.migrationHistory = append(migrator.migrationHistory, &MigrationResult{
			ID:     "no-rollback-id",
			Status: MigrationStatusCompleted,
			Path: &MigrationPath{
				ID:                "no-rollback-id",
				ModuleName:        "test-module",
				FromVersion:       "1.0.0",
				ToVersion:         "1.0.1",
				RollbackSupported: false,
			},
		})
		migrator.mu.Unlock()

		ctx := context.Background()
		_, err := migrator.RollbackMigration(ctx, "no-rollback-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "rollback")
	})
}

func TestWaitForMigration(t *testing.T) {
	t.Run("returns nil when migration completes successfully", func(t *testing.T) {
		registry := NewDefaultModuleVersionRegistry()
		require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "wm", Version: "1.0.0", Description: "v1"}))
		require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "wm", Version: "2.0.0", Description: "v2"}))
		migrator := NewDefaultVersionMigrator(registry)

		path, err := migrator.GetMigrationPath("wm", "1.0.0", "2.0.0")
		require.NoError(t, err)
		result, err := migrator.ExecuteMigration(context.Background(), path)
		require.NoError(t, err)

		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		assert.NoError(t, migrator.WaitForMigration(waitCtx, result.ID))
	})

	t.Run("returns context error when context cancelled before completion", func(t *testing.T) {
		migrator := NewDefaultVersionMigrator(nil)

		// Inject a running migration so WaitForMigration loops
		ctx, cancelExec := context.WithCancel(context.Background())
		migrator.mu.Lock()
		migrator.activeMigrations["stuck-id"] = &MigrationExecution{
			Path:       &MigrationPath{ID: "stuck-id", ModuleName: "wm"},
			Status:     MigrationStatusRunning,
			StartTime:  time.Now(),
			Context:    ctx,
			CancelFunc: cancelExec,
		}
		migrator.mu.Unlock()

		waitCtx, cancelWait := context.WithCancel(context.Background())
		cancelWait() // already cancelled

		err := migrator.WaitForMigration(waitCtx, "stuck-id")
		assert.ErrorIs(t, err, context.Canceled)

		// Cleanup
		cancelExec()
		migrator.mu.Lock()
		delete(migrator.activeMigrations, "stuck-id")
		migrator.mu.Unlock()
	})

	t.Run("returns error for failed migration", func(t *testing.T) {
		migrator := NewDefaultVersionMigrator(nil)
		migrator.mu.Lock()
		migrator.migrationHistory = append(migrator.migrationHistory, &MigrationResult{
			ID:     "failed-id",
			Status: MigrationStatusFailed,
			Path:   &MigrationPath{ID: "failed-id", ModuleName: "wm"},
		})
		migrator.mu.Unlock()

		err := migrator.WaitForMigration(context.Background(), "failed-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed")
	})

	t.Run("returns error for cancelled migration", func(t *testing.T) {
		migrator := NewDefaultVersionMigrator(nil)
		migrator.mu.Lock()
		migrator.migrationHistory = append(migrator.migrationHistory, &MigrationResult{
			ID:     "cancelled-id",
			Status: MigrationStatusCancelled,
			Path:   &MigrationPath{ID: "cancelled-id", ModuleName: "wm"},
		})
		migrator.mu.Unlock()

		err := migrator.WaitForMigration(context.Background(), "cancelled-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cancelled")
	})
}

func TestMigrationComplexityCalculation(t *testing.T) {
	migrator := NewDefaultVersionMigrator(nil) // Don't need registry for this test

	tests := []struct {
		name               string
		fromVersion        string
		toVersion          string
		expectedComplexity VersionMigrationComplexity
	}{
		{
			name:               "patch change",
			fromVersion:        "1.0.0",
			toVersion:          "1.0.1",
			expectedComplexity: MigrationComplexityLow,
		},
		{
			name:               "minor change",
			fromVersion:        "1.0.0",
			toVersion:          "1.1.0",
			expectedComplexity: MigrationComplexityMedium,
		},
		{
			name:               "major change",
			fromVersion:        "1.0.0",
			toVersion:          "2.0.0",
			expectedComplexity: MigrationComplexityHigh,
		},
		{
			name:               "multiple major changes",
			fromVersion:        "1.0.0",
			toVersion:          "3.0.0",
			expectedComplexity: MigrationComplexityHigh,
		},
		{
			name:               "downgrade major",
			fromVersion:        "2.0.0",
			toVersion:          "1.0.0",
			expectedComplexity: MigrationComplexityHigh,
		},
		{
			name:               "downgrade minor",
			fromVersion:        "1.2.0",
			toVersion:          "1.1.0",
			expectedComplexity: MigrationComplexityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fromSemVer, err := ParseVersion(tt.fromVersion)
			require.NoError(t, err)

			toSemVer, err := ParseVersion(tt.toVersion)
			require.NoError(t, err)

			complexity := migrator.calculateMigrationComplexity(fromSemVer, toSemVer)
			assert.Equal(t, tt.expectedComplexity, complexity)
		})
	}
}

func TestMigrationStepGeneration(t *testing.T) {
	migrator := NewDefaultVersionMigrator(nil)

	tests := []struct {
		name             string
		fromVersion      string
		toVersion        string
		isUpgrade        bool
		complexity       VersionMigrationComplexity
		expectedMinSteps int
		expectedMaxSteps int
	}{
		{
			name:             "simple upgrade",
			fromVersion:      "1.0.0",
			toVersion:        "1.0.1",
			isUpgrade:        true,
			complexity:       MigrationComplexityLow,
			expectedMinSteps: 6,
			expectedMaxSteps: 8,
		},
		{
			name:             "complex upgrade",
			fromVersion:      "1.0.0",
			toVersion:        "2.0.0",
			isUpgrade:        true,
			complexity:       MigrationComplexityHigh,
			expectedMinSteps: 7,
			expectedMaxSteps: 10,
		},
		{
			name:             "downgrade",
			fromVersion:      "2.0.0",
			toVersion:        "1.0.0",
			isUpgrade:        false,
			complexity:       MigrationComplexityHigh,
			expectedMinSteps: 7,
			expectedMaxSteps: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps := migrator.generateMigrationSteps("test-module", tt.fromVersion, tt.toVersion, tt.isUpgrade, tt.complexity)

			assert.GreaterOrEqual(t, len(steps), tt.expectedMinSteps)
			assert.LessOrEqual(t, len(steps), tt.expectedMaxSteps)

			// First step should be validation
			assert.Equal(t, MigrationStepValidation, steps[0].Type)

			// Last step should be cleanup
			assert.Equal(t, MigrationStepCleanup, steps[len(steps)-1].Type)

			// Check that all steps have required fields
			for i, step := range steps {
				assert.NotEmpty(t, step.ID, "Step %d has empty ID", i)
				assert.NotEmpty(t, step.Description, "Step %d has empty description", i)
				assert.Greater(t, step.EstimatedTime, time.Duration(0), "Step %d has no estimated time", i)
				assert.Equal(t, tt.fromVersion, step.FromVersion, "Step %d has wrong from version", i)
				assert.Equal(t, tt.toVersion, step.ToVersion, "Step %d has wrong to version", i)
			}

			// Check for backup step in complex migrations
			if tt.complexity >= MigrationComplexityMedium {
				hasBackup := false
				for _, step := range steps {
					if step.Type == MigrationStepBackup {
						hasBackup = true
						break
					}
				}
				assert.True(t, hasBackup, "Complex migration should have backup step")
			}

			// Check for data migration step in high complexity migrations
			if tt.complexity >= MigrationComplexityHigh {
				hasDataMigration := false
				for _, step := range steps {
					if step.Type == MigrationStepDataMigration {
						hasDataMigration = true
						break
					}
				}
				assert.True(t, hasDataMigration, "High complexity migration should have data migration step")
			}

			// Check main step type
			hasMainStep := false
			for _, step := range steps {
				if (tt.isUpgrade && step.Type == MigrationStepUpgrade) ||
					(!tt.isUpgrade && step.Type == MigrationStepDowngrade) {
					hasMainStep = true
					assert.Equal(t, tt.complexity >= MigrationComplexityMedium, step.RequiresRestart)
					break
				}
			}
			assert.True(t, hasMainStep, "Migration should have main upgrade/downgrade step")
		})
	}
}

func TestMigrationWarningGeneration(t *testing.T) {
	migrator := NewDefaultVersionMigrator(nil)

	tests := []struct {
		name                string
		complexity          VersionMigrationComplexity
		isUpgrade           bool
		expectedMinWarnings int
	}{
		{
			name:                "low complexity upgrade",
			complexity:          MigrationComplexityLow,
			isUpgrade:           true,
			expectedMinWarnings: 0,
		},
		{
			name:                "medium complexity upgrade",
			complexity:          MigrationComplexityMedium,
			isUpgrade:           true,
			expectedMinWarnings: 1,
		},
		{
			name:                "medium complexity downgrade",
			complexity:          MigrationComplexityMedium,
			isUpgrade:           false,
			expectedMinWarnings: 2, // Service restart + feature loss
		},
		{
			name:                "high complexity upgrade",
			complexity:          MigrationComplexityHigh,
			isUpgrade:           true,
			expectedMinWarnings: 2,
		},
		{
			name:                "high complexity downgrade",
			complexity:          MigrationComplexityHigh,
			isUpgrade:           false,
			expectedMinWarnings: 3, // Changes + disk space + data loss
		},
		{
			name:                "critical complexity",
			complexity:          MigrationComplexityCritical,
			isUpgrade:           true,
			expectedMinWarnings: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := migrator.generateMigrationWarnings(tt.complexity, tt.isUpgrade)

			assert.GreaterOrEqual(t, len(warnings), tt.expectedMinWarnings)

			for _, warning := range warnings {
				assert.NotEmpty(t, warning, "Warning should not be empty")
			}

			// Check for specific warning patterns based on complexity
			if tt.complexity >= MigrationComplexityMedium {
				hasRestartWarning := false
				for _, warning := range warnings {
					if contains(warning, "restart") {
						hasRestartWarning = true
						break
					}
				}
				assert.True(t, hasRestartWarning, "Medium+ complexity should warn about restart")
			}

			if tt.complexity >= MigrationComplexityCritical {
				hasCriticalWarning := false
				for _, warning := range warnings {
					if contains(warning, "CRITICAL") {
						hasCriticalWarning = true
						break
					}
				}
				assert.True(t, hasCriticalWarning, "Critical complexity should have CRITICAL warning")
			}

			if !tt.isUpgrade && tt.complexity >= MigrationComplexityMedium {
				hasDowngradeWarning := false
				for _, warning := range warnings {
					if contains(warning, "Downgrade") || contains(warning, "loss") {
						hasDowngradeWarning = true
						break
					}
				}
				assert.True(t, hasDowngradeWarning, "Downgrade should warn about potential loss")
			}
		})
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(str, substr string) bool {
	return len(str) >= len(substr) &&
		(str == substr ||
			len(str) > len(substr) &&
				(str[:len(substr)] == substr ||
					str[len(str)-len(substr):] == substr ||
					containsInMiddle(str, substr)))
}

func containsInMiddle(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// newStepRegistry registers two versions of "mod" and returns the registry and migrator.
func newStepRegistry(t *testing.T) (*DefaultModuleVersionRegistry, *DefaultVersionMigrator) {
	t.Helper()
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)
	require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "mod", Version: "1.0.0", Description: "v1"}))
	require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "mod", Version: "2.0.0", Description: "v2"}))
	return registry, migrator
}

// historyLen returns the number of transitions recorded for moduleName.
func historyLen(t *testing.T, registry *DefaultModuleVersionRegistry, moduleName string) int {
	t.Helper()
	h, err := registry.GetVersionHistory(moduleName)
	require.NoError(t, err)
	return len(h.Transitions)
}

func TestExecuteStep_Validation(t *testing.T) {
	_, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "validate-mod-1.0.0-2.0.0",
		Type:        MigrationStepValidation,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Validate",
	}

	t.Run("succeeds with both versions installed", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.Empty(t, result.ErrorMessage)
		assert.NotEmpty(t, result.Output)
	})

	t.Run("idempotent on repeated calls", func(t *testing.T) {
		r1 := migrator.executeStep(context.Background(), step)
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r1.Status)
		assert.Equal(t, StepStatusCompleted, r2.Status)
	})

	t.Run("fails when from version not installed", func(t *testing.T) {
		bad := step
		bad.FromVersion = "9.9.9"
		result := migrator.executeStep(context.Background(), bad)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "validation")
		assert.Contains(t, result.ErrorMessage, "9.9.9")
	})

	t.Run("fails when to version not installed", func(t *testing.T) {
		bad := step
		bad.ToVersion = "9.9.9"
		result := migrator.executeStep(context.Background(), bad)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "validation")
	})

	t.Run("cancelled context returns failed step", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := migrator.executeStep(ctx, step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "cancelled")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "validation")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})
}

func TestExecuteStep_Backup(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "backup-mod-1.0.0-2.0.0",
		Type:        MigrationStepBackup,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Backup",
	}

	t.Run("records backup in registry history", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)

		history, err := registry.GetVersionHistory("mod")
		require.NoError(t, err)
		found := false
		for _, tr := range history.Transitions {
			if tr.Metadata["step_id"] == step.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "backup step transition not recorded in history")
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		history, err := registry.GetVersionHistory("mod")
		require.NoError(t, err)
		countBefore := len(history.Transitions)

		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)

		history, err = registry.GetVersionHistory("mod")
		require.NoError(t, err)
		assert.Equal(t, countBefore, len(history.Transitions), "idempotent run must not add a second record")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "backup")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})

	t.Run("fails when module not registered in registry", func(t *testing.T) {
		emptyRegistry := NewDefaultModuleVersionRegistry()
		emptyMigrator := NewDefaultVersionMigrator(emptyRegistry)
		result := emptyMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "backup")
	})
}

func TestExecuteStep_Preprocess(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "preprocess-mod-1.0.0-2.0.0",
		Type:        MigrationStepPreprocess,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Preprocess",
	}

	t.Run("records preprocessing", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "preprocess")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})

	t.Run("fails when module not registered in registry", func(t *testing.T) {
		emptyMigrator := NewDefaultVersionMigrator(NewDefaultModuleVersionRegistry())
		result := emptyMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "preprocess")
	})
}

func TestExecuteStep_Upgrade(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "upgrade-mod-1.0.0-2.0.0",
		Type:        MigrationStepUpgrade,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Upgrade",
	}

	t.Run("records upgrade transition", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)

		history, err := registry.GetVersionHistory("mod")
		require.NoError(t, err)
		found := false
		for _, tr := range history.Transitions {
			if tr.Metadata["step_id"] == step.ID && tr.TransitionType == TransitionUpgrade {
				found = true
				break
			}
		}
		assert.True(t, found, "upgrade transition not recorded in history")
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails when target is not newer", func(t *testing.T) {
		bad := step
		bad.ToVersion = "1.0.0"
		bad.FromVersion = "2.0.0"
		result := migrator.executeStep(context.Background(), bad)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "upgrade")
		assert.Contains(t, result.ErrorMessage, "not newer")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "upgrade")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})
}

func TestExecuteStep_Downgrade(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "downgrade-mod-2.0.0-1.0.0",
		Type:        MigrationStepDowngrade,
		ModuleName:  "mod",
		FromVersion: "2.0.0",
		ToVersion:   "1.0.0",
		Description: "Downgrade",
	}

	t.Run("records downgrade transition", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)

		history, err := registry.GetVersionHistory("mod")
		require.NoError(t, err)
		found := false
		for _, tr := range history.Transitions {
			if tr.Metadata["step_id"] == step.ID && tr.TransitionType == TransitionDowngrade {
				found = true
				break
			}
		}
		assert.True(t, found, "downgrade transition not recorded in history")
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails when target is not older", func(t *testing.T) {
		bad := step
		bad.ToVersion = "2.0.0"
		bad.FromVersion = "1.0.0"
		result := migrator.executeStep(context.Background(), bad)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "downgrade")
		assert.Contains(t, result.ErrorMessage, "not older")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "downgrade")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})
}

func TestExecuteStep_DataMigration(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "data-migration-mod-1.0.0-2.0.0",
		Type:        MigrationStepDataMigration,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Data migration",
	}

	t.Run("records data migration", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails when from version not installed", func(t *testing.T) {
		bad := step
		bad.FromVersion = "9.9.9"
		result := migrator.executeStep(context.Background(), bad)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "data_migration")
		assert.Contains(t, result.ErrorMessage, "9.9.9")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "data_migration")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})
}

func TestExecuteStep_ConfigUpdate(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "config-update-mod-1.0.0-2.0.0",
		Type:        MigrationStepConfigUpdate,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Config update",
		Metadata:    map[string]interface{}{"setting_key": "new_value"},
	}

	t.Run("records config update with metadata", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "config_update")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})

	t.Run("fails when module not registered in registry", func(t *testing.T) {
		emptyMigrator := NewDefaultVersionMigrator(NewDefaultModuleVersionRegistry())
		result := emptyMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "config_update")
	})
}

func TestExecuteStep_Postprocess(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "postprocess-mod-1.0.0-2.0.0",
		Type:        MigrationStepPostprocess,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Postprocess",
	}

	t.Run("succeeds when to version is installed", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails when to version not installed", func(t *testing.T) {
		bad := step
		bad.ToVersion = "9.9.9"
		result := migrator.executeStep(context.Background(), bad)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "postprocess")
		assert.Contains(t, result.ErrorMessage, "9.9.9")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "postprocess")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})

	t.Run("fails when module has no history (record transition fails)", func(t *testing.T) {
		// Register toVersion under a module that has history, then try postprocess on an
		// unregistered module — IsVersionInstalled returns false → structured error.
		emptyMigrator := NewDefaultVersionMigrator(NewDefaultModuleVersionRegistry())
		unregistered := step
		unregistered.ModuleName = "ghost-module"
		result := emptyMigrator.executeStep(context.Background(), unregistered)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "postprocess")
	})
}

func TestExecuteStep_Cleanup(t *testing.T) {
	registry, migrator := newStepRegistry(t)
	step := MigrationStep{
		ID:          "cleanup-mod-1.0.0-2.0.0",
		Type:        MigrationStepCleanup,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Cleanup",
	}

	t.Run("records cleanup completion", func(t *testing.T) {
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status)
		assert.NotEmpty(t, result.Output)
	})

	t.Run("idempotent — does not double-record", func(t *testing.T) {
		before := historyLen(t, registry, "mod")
		r2 := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, r2.Status)
		assert.Equal(t, before, historyLen(t, registry, "mod"), "idempotent run must not add a second record")
	})

	t.Run("fails with nil registry", func(t *testing.T) {
		nilMigrator := NewDefaultVersionMigrator(nil)
		result := nilMigrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "cleanup")
		assert.Contains(t, result.ErrorMessage, "registry not available")
	})

	t.Run("fails when GetVersionHistory fails", func(t *testing.T) {
		// Use an unregistered module name — GetVersionHistory will return "no history found"
		emptyMigrator := NewDefaultVersionMigrator(NewDefaultModuleVersionRegistry())
		unregistered := step
		unregistered.ModuleName = "unregistered-module"
		result := emptyMigrator.executeStep(context.Background(), unregistered)
		assert.Equal(t, StepStatusFailed, result.Status)
		assert.Contains(t, result.ErrorMessage, "cleanup")
		assert.Contains(t, result.ErrorMessage, "failed to get version history")
	})
}

func TestExecuteStep_StructuredError(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "mod", Version: "2.0.0", Description: "v2"}))
	migrator := NewDefaultVersionMigrator(registry)

	// Only toVersion is installed; fromVersion missing → validation must fail
	step := MigrationStep{
		ID:          "validate-mod-1.0.0-2.0.0",
		Type:        MigrationStepValidation,
		ModuleName:  "mod",
		FromVersion: "1.0.0",
		ToVersion:   "2.0.0",
		Description: "Validate",
	}

	result := migrator.executeStep(context.Background(), step)
	assert.Equal(t, StepStatusFailed, result.Status)
	// Error message must encode both step type and reason
	assert.Contains(t, result.ErrorMessage, "validation", "error message must include step type")
	assert.Contains(t, result.ErrorMessage, "1.0.0", "error message must include reason (missing version)")
}

func TestExecuteStep_AllStepTypesDispatch(t *testing.T) {
	// End-to-end: run a full high-complexity migration and assert every step type
	// reaches a real implementation (StepStatusCompleted, non-empty output).
	registry := NewDefaultModuleVersionRegistry()
	require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "e2e", Version: "1.0.0", Description: "v1"}))
	require.NoError(t, registry.RegisterVersion(&ModuleMetadata{Name: "e2e", Version: "2.0.0", Description: "v2"}))
	migrator := NewDefaultVersionMigrator(registry)

	path, err := migrator.GetMigrationPath("e2e", "1.0.0", "2.0.0")
	require.NoError(t, err)

	// Collect which step types appear
	typeSeen := make(map[MigrationStepType]bool)
	for _, step := range path.Steps {
		typeSeen[step.Type] = true
		result := migrator.executeStep(context.Background(), step)
		assert.Equal(t, StepStatusCompleted, result.Status,
			"step %s (%s) failed: %s", step.ID, step.Type, result.ErrorMessage)
		assert.NotEmpty(t, result.Output, "step %s must produce output", step.ID)
	}

	// A major-version upgrade path must exercise all step types
	expectedTypes := []MigrationStepType{
		MigrationStepValidation,
		MigrationStepBackup,
		MigrationStepPreprocess,
		MigrationStepUpgrade,
		MigrationStepDataMigration,
		MigrationStepConfigUpdate,
		MigrationStepPostprocess,
		MigrationStepCleanup,
	}
	for _, st := range expectedTypes {
		assert.True(t, typeSeen[st], "step type %s not present in major-version migration path", st)
	}
}

// Benchmark tests
func BenchmarkMigrationPath_Generation(b *testing.B) {
	registry := NewDefaultModuleVersionRegistry()
	migrator := NewDefaultVersionMigrator(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{Name: "bench-module", Version: "1.0.0", Description: "Bench"}
	metadata2 := &ModuleMetadata{Name: "bench-module", Version: "2.0.0", Description: "Bench"}
	_ = registry.RegisterVersion(metadata1) // Ignore error in benchmark setup
	_ = registry.RegisterVersion(metadata2) // Ignore error in benchmark setup

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = migrator.GetMigrationPath("bench-module", "1.0.0", "2.0.0") // Ignore error in benchmark
	}
}

func BenchmarkMigrationStep_Generation(b *testing.B) {
	migrator := NewDefaultVersionMigrator(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		migrator.generateMigrationSteps("bench-module", "1.0.0", "2.0.0", true, MigrationComplexityHigh)
	}
}
