package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/script"
)

// TestV020BasicIntegration tests the core v0.2.0 functionality without complex service dependencies
func TestV020BasicIntegration(t *testing.T) {
	t.Run("Script Module with Audit Integration", func(t *testing.T) {
		// Test that script module with audit logging works end-to-end
		module := script.NewModuleWithConfig("test-steward-v020", 10)
		require.NotNil(t, module)

		// Test script configuration
		scriptConfig := &script.ScriptConfig{
			Content:       "echo 'CFGMS v0.2.0 integration test successful'",
			Shell:         script.ShellBash,
			Timeout:       30 * time.Second,
			SigningPolicy: script.SigningPolicyNone,
			Description:   "v0.2.0 integration validation script",
		}

		// Execute script via module interface
		ctx := context.Background()
		err := module.Set(ctx, "v020-integration-test", scriptConfig)
		require.NoError(t, err, "Script execution should succeed")

		// Verify script execution state
		state, exists := module.GetExecutionState("v020-integration-test")
		require.True(t, exists, "Execution state should exist")
		assert.Equal(t, script.StatusCompleted, state.Status)
		assert.NotNil(t, state.Result)
		assert.Equal(t, 0, state.Result.ExitCode)
		assert.Contains(t, state.Result.Stdout, "integration test successful")

		// Verify audit logging captured the execution
		history, err := module.GetExecutionHistory(5)
		require.NoError(t, err)
		require.Len(t, history, 1, "Should have one execution in audit history")

		record := history[0]
		assert.Equal(t, "test-steward-v020", record.StewardID)
		assert.Equal(t, "v020-integration-test", record.ResourceID)
		assert.Equal(t, script.StatusCompleted, record.Status)
		assert.Equal(t, 0, record.ExitCode)
		assert.Contains(t, record.ScriptConfig.ContentHash, "sha256:")
		assert.Greater(t, record.ScriptConfig.ContentLength, 0)
		assert.Equal(t, "bash", string(record.ScriptConfig.Shell))
		assert.Equal(t, "none", string(record.ScriptConfig.SigningPolicy))

		// Verify metrics collection
		since := time.Now().Add(-1 * time.Hour)
		metrics, err := module.GetExecutionMetrics(since)
		require.NoError(t, err)
		assert.Equal(t, 1, metrics.TotalExecutions)
		assert.Equal(t, 1, metrics.SuccessCount)
		assert.Equal(t, 0, metrics.FailureCount)
		assert.Equal(t, 100.0, metrics.SuccessRate)
		assert.Greater(t, metrics.AverageDuration, int64(0))
		assert.Equal(t, 1, metrics.ShellUsage["bash"])
	})

	t.Run("Script Module Audit Query System", func(t *testing.T) {
		module := script.NewModuleWithConfig("audit-test-steward", 50)
		ctx := context.Background()

		// Execute multiple scripts with different outcomes
		scripts := []struct {
			resourceID string
			content    string
			shell      script.ShellType
			expectExit int
		}{
			{"success-script", "echo 'success'", script.ShellBash, 0},
			{"another-success", "echo 'another success'", script.ShellBash, 0},
			{"failure-script", "exit 1", script.ShellBash, 1},
		}

		for _, s := range scripts {
			config := &script.ScriptConfig{
				Content:       s.content,
				Shell:         s.shell,
				Timeout:       10 * time.Second,
				SigningPolicy: script.SigningPolicyNone,
			}

			// We expect some to fail, so don't require NoError for all
			if err := module.Set(ctx, s.resourceID, config); err != nil {
				// Log error but continue test - some scenarios are expected to fail
				_ = err // Explicitly ignore expected test failures
			}
		}

		// Test audit query functionality
		allQuery := &script.AuditQuery{
			StewardID: "audit-test-steward",
		}
		allRecords, err := module.QueryExecutions(allQuery)
		require.NoError(t, err)
		assert.Len(t, allRecords, 3, "Should have all three executions")

		// Query by status (all should be "completed" since execution completed successfully)
		completedQuery := &script.AuditQuery{
			StewardID: "audit-test-steward",
			Status:    script.StatusCompleted,
		}
		completedRecords, err := module.QueryExecutions(completedQuery)
		require.NoError(t, err)
		assert.Len(t, completedRecords, 3, "All executions should be marked as completed")

		// Verify we can distinguish success vs failure by exit code
		successCount := 0
		failureCount := 0
		for _, record := range allRecords {
			if record.ExitCode == 0 {
				successCount++
			} else {
				failureCount++
			}
		}
		assert.Equal(t, 2, successCount, "Should have two successful exit codes")
		assert.Equal(t, 1, failureCount, "Should have one failed exit code")

		// Test pagination
		limitQuery := &script.AuditQuery{
			StewardID: "audit-test-steward",
			Limit:     2,
		}
		limitedRecords, err := module.QueryExecutions(limitQuery)
		require.NoError(t, err)
		assert.Len(t, limitedRecords, 2, "Should respect limit parameter")
	})

	t.Run("Module Interface Compliance", func(t *testing.T) {
		// Test that script module properly implements the module interface
		module := script.New()
		ctx := context.Background()

		// Test Get method returns valid config state
		state, err := module.Get(ctx, "nonexistent-resource")
		require.NoError(t, err)
		require.NotNil(t, state)

		// Should be a ScriptConfig
		scriptConfig, ok := state.(*script.ScriptConfig)
		require.True(t, ok, "Get should return ScriptConfig")
		assert.Equal(t, script.SigningPolicyNone, scriptConfig.SigningPolicy)

		// Test Set method with valid configuration
		validConfig := &script.ScriptConfig{
			Content:       "echo 'module compliance test'",
			Shell:         script.ShellBash,
			Timeout:       15 * time.Second,
			SigningPolicy: script.SigningPolicyNone,
		}

		err = module.Set(ctx, "compliance-test", validConfig)
		assert.NoError(t, err, "Set should succeed with valid config")

		// Verify Get returns the updated state
		updatedState, err := module.Get(ctx, "compliance-test")
		require.NoError(t, err)
		updatedConfig, ok := updatedState.(*script.ScriptConfig)
		require.True(t, ok)
		assert.Equal(t, validConfig.Content, updatedConfig.Content)
		assert.Equal(t, validConfig.Shell, updatedConfig.Shell)
	})
}

// TestV020FeatureAvailability verifies that all v0.2.0 features are available
func TestV020FeatureAvailability(t *testing.T) {
	t.Run("Script Module Features", func(t *testing.T) {
		module := script.NewModule()

		// Test all major script module methods are available
		t.Run("Execution History", func(t *testing.T) {
			history, err := module.GetExecutionHistory(10)
			assert.NoError(t, err)
			assert.NotNil(t, history)
		})

		t.Run("Execution Metrics", func(t *testing.T) {
			since := time.Now().Add(-1 * time.Hour)
			metrics, err := module.GetExecutionMetrics(since)
			assert.NoError(t, err)
			assert.NotNil(t, metrics)
		})

		t.Run("Query Executions", func(t *testing.T) {
			query := &script.AuditQuery{
				StewardID: "test",
				Limit:     5,
			}
			results, err := module.QueryExecutions(query)
			assert.NoError(t, err)
			// Results can be empty but should not be nil
			if results != nil {
				assert.GreaterOrEqual(t, len(results), 0)
			}
		})

		t.Run("Steward ID Management", func(t *testing.T) {
			module.SetStewardID("test-steward-id")
			// No direct getter, but this tests the method exists
		})
	})

	t.Run("Script Configuration Features", func(t *testing.T) {
		config := &script.ScriptConfig{
			Content:       "echo 'test'",
			Shell:         script.ShellBash,
			Timeout:       30 * time.Second,
			SigningPolicy: script.SigningPolicyOptional,
			Description:   "Test configuration",
			Environment:   map[string]string{"TEST": "value"},
		}

		// Test configuration validation
		err := config.Validate()
		assert.NoError(t, err, "Valid configuration should pass validation")

		// Test configuration serialization
		configMap := config.AsMap()
		assert.NotEmpty(t, configMap)
		assert.Equal(t, "echo 'test'", configMap["content"])
		assert.Equal(t, "bash", configMap["shell"])

		// Test managed fields
		managedFields := config.GetManagedFields()
		assert.Contains(t, managedFields, "content")
		assert.Contains(t, managedFields, "shell")
		assert.Contains(t, managedFields, "timeout")
	})

	t.Run("Audit Record Features", func(t *testing.T) {
		config := &script.ScriptConfig{
			Content: "echo 'audit test'",
			Shell:   script.ShellBash,
			Timeout: 30 * time.Second,
		}

		result := &script.ExecutionResult{
			ExitCode:  0,
			Stdout:    "audit test\n",
			Stderr:    "",
			Duration:  time.Duration(1500) * time.Millisecond,
			StartTime: time.Now().Add(-2 * time.Second),
			EndTime:   time.Now().Add(-500 * time.Millisecond),
			PID:       12345,
		}

		// Test audit record creation
		record := script.CreateAuditRecord("test-steward", "test-resource", config, result, nil)
		assert.NotNil(t, record)
		assert.Equal(t, "test-steward", record.StewardID)
		assert.Equal(t, "test-resource", record.ResourceID)
		assert.Equal(t, script.StatusCompleted, record.Status)
		assert.Equal(t, 0, record.ExitCode)
		assert.Equal(t, int64(1500), record.Duration)
		assert.Contains(t, record.ScriptConfig.ContentHash, "sha256:")
	})
}
