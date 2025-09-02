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
		name                 string
		fromVersion          string
		toVersion            string
		expectedComplexity   VersionMigrationComplexity
		expectedRequiresBackup bool
		minSteps             int
	}{
		{
			name:                 "patch upgrade",
			fromVersion:          "1.0.0",
			toVersion:            "1.1.0",
			expectedComplexity:   MigrationComplexityMedium,
			expectedRequiresBackup: true,
			minSteps:             5,
		},
		{
			name:                 "major upgrade",
			fromVersion:          "1.0.0",
			toVersion:            "2.0.0",
			expectedComplexity:   MigrationComplexityHigh,
			expectedRequiresBackup: true,
			minSteps:             6,
		},
		{
			name:                 "major downgrade",
			fromVersion:          "3.0.0",
			toVersion:            "1.0.0",
			expectedComplexity:   MigrationComplexityHigh,
			expectedRequiresBackup: true,
			minSteps:             6,
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

		// Reduce step times for faster testing
		for i := range path.Steps {
			path.Steps[i].EstimatedTime = 100 * time.Millisecond
		}

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, path)
		require.NoError(t, err)
		assert.NotNil(t, result)

		assert.Equal(t, path.ID, result.ID)
		assert.Equal(t, path, result.Path)
		assert.Equal(t, MigrationStatusRunning, result.Status)
		assert.False(t, result.StartTime.IsZero())

		// Wait for migration to complete
		time.Sleep(2 * time.Second)

		// Check migration status
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
		path1, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)
		
		path2, err := migrator.GetMigrationPath("test-module", "1.1.0", "1.0.0")
		require.NoError(t, err)

		// Make migrations take a reasonable amount of time for this test
		for i := range path1.Steps {
			path1.Steps[i].EstimatedTime = 100 * time.Millisecond
		}
		for i := range path2.Steps {
			path2.Steps[i].EstimatedTime = 100 * time.Millisecond
		}

		ctx := context.Background()
		
		// Start first migration
		_, err = migrator.ExecuteMigration(ctx, path1)
		require.NoError(t, err)

		// Try to start second migration (should fail)
		result2, err := migrator.ExecuteMigration(ctx, path2)
		assert.Nil(t, result2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "migration already in progress")

		// Wait for first migration to complete with polling
		timeout := time.Now().Add(5 * time.Second)
		for time.Now().Before(timeout) {
			status, err := migrator.GetMigrationStatus("test-module")
			if err == nil && status.Status == MigrationStatusCompleted {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Now second migration should succeed
		result3, err := migrator.ExecuteMigration(ctx, path2)
		assert.NoError(t, err)
		assert.NotNil(t, result3)
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

		// Make migration take longer for status testing
		for i := range path.Steps {
			path.Steps[i].EstimatedTime = 1 * time.Second
		}

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, path)
		require.NoError(t, err)

		// Get status while migration is running
		time.Sleep(100 * time.Millisecond) // Let it start
		status, err := migrator.GetMigrationStatus(result.ID)
		require.NoError(t, err)
		assert.NotNil(t, status)

		assert.Equal(t, result.ID, status.ID)
		assert.Equal(t, "test-module", status.ModuleName)
		assert.Equal(t, "1.0.0", status.FromVersion)
		assert.Equal(t, "1.1.0", status.ToVersion)
		assert.Equal(t, len(path.Steps), status.TotalSteps)
		assert.GreaterOrEqual(t, status.Progress, 0.0)
		assert.LessOrEqual(t, status.Progress, 1.0)
		assert.Greater(t, status.ElapsedTime, time.Duration(0))

		if status.Progress > 0 {
			assert.Greater(t, status.EstimatedETA, time.Duration(0))
		}

		// Wait for completion and check again
		time.Sleep(10 * time.Second)
		
		finalStatus, err := migrator.GetMigrationStatus(result.ID)
		require.NoError(t, err)
		assert.Equal(t, MigrationStatusCompleted, finalStatus.Status)
		assert.Equal(t, 1.0, finalStatus.Progress)
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

	t.Run("multiple active migrations", func(t *testing.T) {
		var migrationIDs []string

		// Start multiple migrations
		for i := 0; i < 3; i++ {
			moduleName := fmt.Sprintf("test-module-%d", i)
			path, err := migrator.GetMigrationPath(moduleName, "1.0.0", "1.1.0")
			require.NoError(t, err)

			// Make migrations take a reasonable time for testing
			for j := range path.Steps {
				path.Steps[j].EstimatedTime = 200 * time.Millisecond
			}

			ctx := context.Background()
			result, err := migrator.ExecuteMigration(ctx, path)
			require.NoError(t, err)
			migrationIDs = append(migrationIDs, result.ID)
		}

		// List active migrations
		time.Sleep(200 * time.Millisecond) // Let them start
		activeMigrations, err := migrator.ListActiveMigrations()
		require.NoError(t, err)
		assert.Equal(t, 3, len(activeMigrations))

		// Verify all our migrations are in the list
		foundIDs := make(map[string]bool)
		for _, status := range activeMigrations {
			foundIDs[status.ID] = true
			assert.NotEmpty(t, status.ModuleName)
			assert.Equal(t, MigrationStatusRunning, status.Status)
		}

		for _, id := range migrationIDs {
			assert.True(t, foundIDs[id], "Migration ID %s not found in active list", id)
		}

		// Wait for migrations to complete with polling
		timeout := time.Now().Add(10 * time.Second)
		for time.Now().Before(timeout) {
			activeMigrations, err := migrator.ListActiveMigrations()
			require.NoError(t, err)
			if len(activeMigrations) == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Should have no active migrations now
		activeMigrations, err = migrator.ListActiveMigrations()
		require.NoError(t, err)
		assert.Empty(t, activeMigrations)
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
		// First, complete a migration
		path, err := migrator.GetMigrationPath("test-module", "1.0.0", "1.0.1")
		require.NoError(t, err)

		// Make migration quick for testing
		for i := range path.Steps {
			path.Steps[i].EstimatedTime = 100 * time.Millisecond
		}

		ctx := context.Background()
		result, err := migrator.ExecuteMigration(ctx, path)
		require.NoError(t, err)

		// Wait for completion
		time.Sleep(2 * time.Second)

		// Verify it's completed
		status, err := migrator.GetMigrationStatus(result.ID)
		require.NoError(t, err)
		assert.Equal(t, MigrationStatusCompleted, status.Status)

		// Now rollback
		rollbackResult, err := migrator.RollbackMigration(ctx, result.ID)
		require.NoError(t, err)
		assert.NotNil(t, rollbackResult)

		// Rollback should be a new migration
		assert.NotEqual(t, result.ID, rollbackResult.ID)
		assert.Equal(t, MigrationStatusRunning, rollbackResult.Status)

		// Wait for rollback to complete
		time.Sleep(3 * time.Second)

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
		name              string
		complexity        VersionMigrationComplexity
		isUpgrade         bool
		expectedMinWarnings int
	}{
		{
			name:              "low complexity upgrade",
			complexity:        MigrationComplexityLow,
			isUpgrade:         true,
			expectedMinWarnings: 0,
		},
		{
			name:              "medium complexity upgrade",
			complexity:        MigrationComplexityMedium,
			isUpgrade:         true,
			expectedMinWarnings: 1,
		},
		{
			name:              "medium complexity downgrade",
			complexity:        MigrationComplexityMedium,
			isUpgrade:         false,
			expectedMinWarnings: 2, // Service restart + feature loss
		},
		{
			name:              "high complexity upgrade",
			complexity:        MigrationComplexityHigh,
			isUpgrade:         true,
			expectedMinWarnings: 2,
		},
		{
			name:              "high complexity downgrade",
			complexity:        MigrationComplexityHigh,
			isUpgrade:         false,
			expectedMinWarnings: 3, // Changes + disk space + data loss
		},
		{
			name:              "critical complexity",
			complexity:        MigrationComplexityCritical,
			isUpgrade:         true,
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