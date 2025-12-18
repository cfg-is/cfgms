// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package rollback_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database" // Register database provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"      // Register git provider
	teststorage "github.com/cfgis/cfgms/pkg/testing/storage"
)

// Test helper to create a storage-backed rollback store
func createTestStorageStore(t *testing.T) (rollback.RollbackStore, func()) {
	t.Helper()

	// Create test storage fixture
	fixture := teststorage.NewStorageTestFixture(t)

	// Get git provider (always available for testing)
	provider, err := interfaces.GetStorageProvider("git")
	require.NoError(t, err, "Git provider should be available")

	// Get git config
	gitConfig, exists := fixture.GetProviderConfig("git")
	require.True(t, exists, "Git config should exist")

	// Create config store
	configStore, err := provider.CreateConfigStore(gitConfig.Config)
	require.NoError(t, err, "ConfigStore creation should succeed")
	require.NotNil(t, configStore, "ConfigStore should not be nil")

	// Create storage rollback store
	store := rollback.NewStorageRollbackStore(configStore)

	cleanup := func() {
		if closer, ok := configStore.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		fixture.Cleanup()
	}

	return store, cleanup
}

// Test helper to create a sample rollback operation
func createSampleOperation() *rollback.RollbackOperation {
	now := time.Now()
	return &rollback.RollbackOperation{
		ID: uuid.New().String(),
		Request: rollback.RollbackRequest{
			TargetType:   rollback.TargetTypeDevice,
			TargetID:     "device-123",
			RollbackType: rollback.RollbackTypeFull,
			RollbackTo:   "abc123def456",
			Reason:       "Test rollback operation",
			Emergency:    false,
		},
		Status:      rollback.RollbackStatusPending,
		InitiatedBy: "test-user",
		InitiatedAt: now,
		Progress: rollback.RollbackProgress{
			Stage:      "initializing",
			Percentage: 0,
		},
		AuditTrail: []rollback.AuditEntry{
			{
				Timestamp: now,
				EventType: "rollback_initiated",
				Actor:     "test-user",
				Action:    "Rollback operation initiated",
				Result:    "success",
			},
		},
	}
}

func TestStorageRollbackStore_SaveOperation(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()

	// Test successful save
	err := store.SaveOperation(ctx, operation)
	assert.NoError(t, err, "SaveOperation should succeed")

	// Verify operation can be retrieved
	retrieved, err := store.GetOperation(ctx, operation.ID)
	assert.NoError(t, err, "GetOperation should succeed")
	assert.NotNil(t, retrieved, "Retrieved operation should not be nil")
	assert.Equal(t, operation.ID, retrieved.ID)
	assert.Equal(t, operation.Status, retrieved.Status)
	assert.Equal(t, operation.InitiatedBy, retrieved.InitiatedBy)
	assert.Equal(t, operation.Request.TargetID, retrieved.Request.TargetID)
}

func TestStorageRollbackStore_SaveOperation_EmptyID(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()
	operation.ID = "" // Invalid ID

	// Test that saving with empty ID fails
	err := store.SaveOperation(ctx, operation)
	assert.Error(t, err, "SaveOperation should fail with empty ID")
	assert.Contains(t, err.Error(), "operation ID cannot be empty")
}

func TestStorageRollbackStore_GetOperation_NotFound(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Test getting non-existent operation
	operation, err := store.GetOperation(ctx, "non-existent-id")
	assert.NoError(t, err, "GetOperation should not error for non-existent ID")
	assert.Nil(t, operation, "Operation should be nil for non-existent ID")
}

func TestStorageRollbackStore_UpdateOperation(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()

	// Save initial operation
	err := store.SaveOperation(ctx, operation)
	require.NoError(t, err, "SaveOperation should succeed")

	// Update operation status
	operation.Status = rollback.RollbackStatusInProgress
	operation.Progress.Stage = "executing"
	operation.Progress.Percentage = 50

	err = store.UpdateOperation(ctx, operation)
	assert.NoError(t, err, "UpdateOperation should succeed")

	// Verify updates persisted
	retrieved, err := store.GetOperation(ctx, operation.ID)
	assert.NoError(t, err, "GetOperation should succeed")
	assert.NotNil(t, retrieved, "Retrieved operation should not be nil")
	assert.Equal(t, rollback.RollbackStatusInProgress, retrieved.Status)
	assert.Equal(t, "executing", retrieved.Progress.Stage)
	assert.Equal(t, 50, retrieved.Progress.Percentage)
}

func TestStorageRollbackStore_UpdateOperation_NotFound(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()

	// Try to update non-existent operation
	err := store.UpdateOperation(ctx, operation)
	assert.Error(t, err, "UpdateOperation should fail for non-existent operation")
	assert.Contains(t, err.Error(), "operation not found")
}

func TestStorageRollbackStore_UpdateOperation_EmptyID(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()
	operation.ID = ""

	// Try to update with empty ID
	err := store.UpdateOperation(ctx, operation)
	assert.Error(t, err, "UpdateOperation should fail with empty ID")
	assert.Contains(t, err.Error(), "operation ID cannot be empty")
}

func TestStorageRollbackStore_AddAuditEntry(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()

	// Save initial operation
	err := store.SaveOperation(ctx, operation)
	require.NoError(t, err, "SaveOperation should succeed")

	// Add audit entry
	auditEntry := rollback.AuditEntry{
		Timestamp: time.Now(),
		EventType: "rollback_progress",
		Actor:     "test-user",
		Action:    "Progress update",
		Details: map[string]interface{}{
			"stage":      "validating",
			"percentage": 25,
		},
		Result: "success",
	}

	err = store.AddAuditEntry(ctx, operation.ID, auditEntry)
	assert.NoError(t, err, "AddAuditEntry should succeed")

	// Verify audit entry was added
	retrieved, err := store.GetOperation(ctx, operation.ID)
	assert.NoError(t, err, "GetOperation should succeed")
	assert.NotNil(t, retrieved, "Retrieved operation should not be nil")
	assert.Len(t, retrieved.AuditTrail, 2, "Should have 2 audit entries")
	assert.Equal(t, "rollback_progress", retrieved.AuditTrail[1].EventType)
}

func TestStorageRollbackStore_AddAuditEntry_NotFound(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	auditEntry := rollback.AuditEntry{
		Timestamp: time.Now(),
		EventType: "test_event",
		Actor:     "test-user",
		Action:    "Test action",
		Result:    "success",
	}

	// Try to add audit entry to non-existent operation
	err := store.AddAuditEntry(ctx, "non-existent-id", auditEntry)
	assert.Error(t, err, "AddAuditEntry should fail for non-existent operation")
	assert.Contains(t, err.Error(), "operation not found")
}

func TestStorageRollbackStore_ListOperations_Empty(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// List operations with no filters
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Empty(t, operations, "Should return empty list")
}

func TestStorageRollbackStore_ListOperations_Basic(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create and save multiple operations
	op1 := createSampleOperation()
	op1.Request.TargetID = "device-1"
	op1.Status = rollback.RollbackStatusCompleted

	op2 := createSampleOperation()
	op2.Request.TargetID = "device-2"
	op2.Status = rollback.RollbackStatusInProgress

	op3 := createSampleOperation()
	op3.Request.TargetID = "device-3"
	op3.Status = rollback.RollbackStatusCompleted

	err := store.SaveOperation(ctx, op1)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)

	// List all operations
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 3, "Should return 3 operations")
}

func TestStorageRollbackStore_ListOperations_ByStatus(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create operations with different statuses
	op1 := createSampleOperation()
	op1.Status = rollback.RollbackStatusCompleted

	op2 := createSampleOperation()
	op2.Status = rollback.RollbackStatusInProgress

	op3 := createSampleOperation()
	op3.Status = rollback.RollbackStatusCompleted

	err := store.SaveOperation(ctx, op1)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)

	// Filter by completed status
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{
		Status: rollback.RollbackStatusCompleted,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 2, "Should return 2 completed operations")

	// Filter by in-progress status
	operations, err = store.ListOperations(ctx, rollback.RollbackFilters{
		Status: rollback.RollbackStatusInProgress,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 1, "Should return 1 in-progress operation")
}

func TestStorageRollbackStore_ListOperations_ByTargetType(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create operations with different target types
	op1 := createSampleOperation()
	op1.Request.TargetType = rollback.TargetTypeDevice

	op2 := createSampleOperation()
	op2.Request.TargetType = rollback.TargetTypeGroup

	op3 := createSampleOperation()
	op3.Request.TargetType = rollback.TargetTypeDevice

	err := store.SaveOperation(ctx, op1)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)

	// Filter by device target type
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{
		TargetType: rollback.TargetTypeDevice,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 2, "Should return 2 device operations")

	// Filter by group target type
	operations, err = store.ListOperations(ctx, rollback.RollbackFilters{
		TargetType: rollback.TargetTypeGroup,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 1, "Should return 1 group operation")
}

func TestStorageRollbackStore_ListOperations_ByTargetID(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create operations for different targets
	op1 := createSampleOperation()
	op1.Request.TargetID = "device-123"

	op2 := createSampleOperation()
	op2.Request.TargetID = "device-456"

	op3 := createSampleOperation()
	op3.Request.TargetID = "device-123"

	err := store.SaveOperation(ctx, op1)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)

	// Filter by specific target ID
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{
		TargetID: "device-123",
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 2, "Should return 2 operations for device-123")
}

func TestStorageRollbackStore_ListOperations_ByInitiatedBy(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create operations by different users
	op1 := createSampleOperation()
	op1.InitiatedBy = "user1"

	op2 := createSampleOperation()
	op2.InitiatedBy = "user2"

	op3 := createSampleOperation()
	op3.InitiatedBy = "user1"

	err := store.SaveOperation(ctx, op1)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)

	// Filter by initiator
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{
		InitiatedBy: "user1",
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 2, "Should return 2 operations by user1")
}

func TestStorageRollbackStore_ListOperations_WithLimit(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple operations
	for i := 0; i < 10; i++ {
		op := createSampleOperation()
		err := store.SaveOperation(ctx, op)
		require.NoError(t, err)
	}

	// List with limit
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{
		Limit: 5,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.LessOrEqual(t, len(operations), 5, "Should return at most 5 operations")
}

func TestStorageRollbackStore_ListOperations_TimeFilter(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create operations at different times
	past := time.Now().Add(-24 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	op1 := createSampleOperation()
	op1.InitiatedAt = past

	op2 := createSampleOperation()
	op2.InitiatedAt = recent

	op3 := createSampleOperation()
	op3.InitiatedAt = time.Now()

	err := store.SaveOperation(ctx, op1)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)

	// Filter by start time (operations after recent)
	afterRecent := recent.Add(-30 * time.Minute)
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{
		StartTime: &afterRecent,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.GreaterOrEqual(t, len(operations), 2, "Should return at least 2 recent operations")

	// Filter by end time (operations before now)
	beforeNow := time.Now().Add(-30 * time.Minute)
	operations, err = store.ListOperations(ctx, rollback.RollbackFilters{
		EndTime: &beforeNow,
	})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.GreaterOrEqual(t, len(operations), 1, "Should return at least 1 older operation")
}

func TestStorageRollbackStore_ListOperations_SortedByTime(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create operations at different times
	now := time.Now()
	op1 := createSampleOperation()
	op1.InitiatedAt = now.Add(-2 * time.Hour)

	op2 := createSampleOperation()
	op2.InitiatedAt = now.Add(-1 * time.Hour)

	op3 := createSampleOperation()
	op3.InitiatedAt = now

	// Save in random order
	err := store.SaveOperation(ctx, op2)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op3)
	require.NoError(t, err)
	err = store.SaveOperation(ctx, op1)
	require.NoError(t, err)

	// List should return in newest-first order
	operations, err := store.ListOperations(ctx, rollback.RollbackFilters{})
	assert.NoError(t, err, "ListOperations should succeed")
	assert.Len(t, operations, 3, "Should return 3 operations")

	// Verify sorted by newest first
	for i := 0; i < len(operations)-1; i++ {
		assert.True(t,
			operations[i].InitiatedAt.After(operations[i+1].InitiatedAt) ||
				operations[i].InitiatedAt.Equal(operations[i+1].InitiatedAt),
			"Operations should be sorted newest first")
	}
}

func TestStorageRollbackStore_ConcurrentAuditEntries(t *testing.T) {
	store, cleanup := createTestStorageStore(t)
	defer cleanup()

	ctx := context.Background()
	operation := createSampleOperation()

	// Save initial operation
	err := store.SaveOperation(ctx, operation)
	require.NoError(t, err, "SaveOperation should succeed")

	// Add multiple audit entries concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(index int) {
			entry := rollback.AuditEntry{
				Timestamp: time.Now(),
				EventType: "concurrent_test",
				Actor:     "test-user",
				Action:    "Concurrent audit entry",
				Details: map[string]interface{}{
					"index": index,
				},
				Result: "success",
			}
			err := store.AddAuditEntry(ctx, operation.ID, entry)
			assert.NoError(t, err, "AddAuditEntry should succeed")
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all audit entries were added
	retrieved, err := store.GetOperation(ctx, operation.ID)
	assert.NoError(t, err, "GetOperation should succeed")
	assert.NotNil(t, retrieved, "Retrieved operation should not be nil")
	assert.Len(t, retrieved.AuditTrail, 11, "Should have 11 audit entries (1 initial + 10 concurrent)")
}

func TestStorageRollbackStore_PersistenceAfterReload(t *testing.T) {
	// This test verifies durability by creating a new store instance
	fixture := teststorage.NewStorageTestFixture(t)
	defer fixture.Cleanup()

	// Get git provider
	provider, err := interfaces.GetStorageProvider("git")
	require.NoError(t, err, "Git provider should be available")

	gitConfig, exists := fixture.GetProviderConfig("git")
	require.True(t, exists, "Git config should exist")

	// Create first store instance
	configStore1, err := provider.CreateConfigStore(gitConfig.Config)
	require.NoError(t, err, "ConfigStore creation should succeed")
	store1 := rollback.NewStorageRollbackStore(configStore1)

	ctx := context.Background()
	operation := createSampleOperation()

	// Save operation with first store
	err = store1.SaveOperation(ctx, operation)
	require.NoError(t, err, "SaveOperation should succeed")

	// Close first store
	if closer, ok := configStore1.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	// Create second store instance (simulating controller restart)
	configStore2, err := provider.CreateConfigStore(gitConfig.Config)
	require.NoError(t, err, "ConfigStore creation should succeed")
	defer func() {
		if closer, ok := configStore2.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()
	store2 := rollback.NewStorageRollbackStore(configStore2)

	// Retrieve operation with second store
	retrieved, err := store2.GetOperation(ctx, operation.ID)
	assert.NoError(t, err, "GetOperation should succeed after reload")
	assert.NotNil(t, retrieved, "Operation should persist after reload")
	assert.Equal(t, operation.ID, retrieved.ID)
	assert.Equal(t, operation.Status, retrieved.Status)
	assert.Equal(t, operation.InitiatedBy, retrieved.InitiatedBy)
}
