package script

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutionQueueBasics(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:   "exec-001",
		ScriptID:      "script-123",
		ScriptVersion: "1.0.0",
		ScriptContent: "echo 'test'",
		Shell:         ShellBash,
		Timeout:       5 * time.Minute,
	}

	// Queue an execution
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Check queue depth
	depth := queue.GetQueueDepth("device-001")
	assert.Equal(t, 1, depth)

	// Peek at queue
	peeked := queue.PeekForDevice("device-001")
	require.Len(t, peeked, 1)
	assert.Equal(t, "exec-001", peeked[0].ExecutionID)

	// Dequeue for device
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)
	assert.Equal(t, "exec-001", dequeued[0].ExecutionID)

	// Queue should be empty now
	depth = queue.GetQueueDepth("device-001")
	assert.Equal(t, 0, depth)
}

func TestExecutionQueueMultipleDevices(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	// Queue executions for multiple devices
	for i := 1; i <= 3; i++ {
		for j := 1; j <= 2; j++ {
			execution := &QueuedExecution{
				ExecutionID:   fmt.Sprintf("exec-%d-%d", i, j),
				ScriptID:      "script-123",
				ScriptVersion: "1.0.0",
				ScriptContent: "echo 'test'",
				Shell:         ShellBash,
			}
			err := queue.QueueExecution(fmt.Sprintf("device-%03d", i), execution)
			require.NoError(t, err)
		}
	}

	// Check total queue depth
	totalDepth := queue.GetTotalQueueDepth()
	assert.Equal(t, 6, totalDepth) // 3 devices * 2 executions

	// Check individual depths
	for i := 1; i <= 3; i++ {
		depth := queue.GetQueueDepth(fmt.Sprintf("device-%03d", i))
		assert.Equal(t, 2, depth)
	}

	// Dequeue for one device
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 2)

	// Total should be reduced
	totalDepth = queue.GetTotalQueueDepth()
	assert.Equal(t, 4, totalDepth)
}

func TestExecutionQueueExpiration(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 100*time.Millisecond, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:   "exec-001",
		ScriptID:      "script-123",
		ScriptVersion: "1.0.0",
		ScriptContent: "echo 'test'",
		Shell:         ShellBash,
	}

	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Dequeue should return empty (expired)
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 0)
}

func TestExecutionQueueCancellation(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	// Queue multiple executions
	for i := 1; i <= 3; i++ {
		execution := &QueuedExecution{
			ExecutionID:   fmt.Sprintf("exec-%03d", i),
			ScriptID:      "script-123",
			ScriptVersion: "1.0.0",
			ScriptContent: "echo 'test'",
			Shell:         ShellBash,
		}
		err := queue.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	assert.Equal(t, 3, queue.GetQueueDepth("device-001"))

	// Cancel one execution
	err := queue.CancelExecution("device-001", "exec-002")
	require.NoError(t, err)

	// Should have 2 remaining
	assert.Equal(t, 2, queue.GetQueueDepth("device-001"))

	// Dequeue and verify correct executions remain
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 2)

	ids := []string{dequeued[0].ExecutionID, dequeued[1].ExecutionID}
	assert.Contains(t, ids, "exec-001")
	assert.Contains(t, ids, "exec-003")
	assert.NotContains(t, ids, "exec-002")
}

func TestExecutionQueueCancelNonExistent(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	// Try to cancel from empty queue
	err := queue.CancelExecution("device-001", "exec-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no queued executions")

	// Queue one execution
	execution := &QueuedExecution{
		ExecutionID:   "exec-001",
		ScriptID:      "script-123",
		ScriptVersion: "1.0.0",
		ScriptContent: "echo 'test'",
		Shell:         ShellBash,
	}
	err = queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Try to cancel different execution
	err = queue.CancelExecution("device-001", "exec-999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in queue")
}

func TestPrepareExecutionWithoutAPIKey(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:    "exec-001",
		ScriptID:       "script-123",
		ScriptVersion:  "1.0.0",
		ScriptContent:  "echo 'test'",
		Shell:          ShellBash,
		Timeout:        5 * time.Minute,
		GenerateAPIKey: false, // No API key
		Environment: map[string]string{
			"TEST_VAR": "test_value",
		},
	}

	prepared, err := queue.PrepareExecutionForDevice(
		context.Background(),
		"device-001",
		"tenant-123",
		execution,
	)

	require.NoError(t, err)
	assert.Equal(t, "exec-001", prepared.ExecutionID)
	assert.Equal(t, "script-123", prepared.ScriptID)
	assert.Equal(t, ShellBash, prepared.Shell)
	assert.Equal(t, "test_value", prepared.Environment["TEST_VAR"])
	assert.Empty(t, prepared.EphemeralKey) // No key generated
}

func TestPrepareExecutionWithAPIKey(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:       "exec-001",
		ScriptID:          "script-123",
		ScriptVersion:     "1.0.0",
		ScriptContent:     "echo 'test'",
		Shell:             ShellBash,
		Timeout:           5 * time.Minute,
		GenerateAPIKey:    true,
		APIKeyTTL:         30 * time.Minute,
		APIKeyPermissions: []string{"script:callback", "script:log"},
		Environment: map[string]string{
			"CUSTOM_VAR": "custom_value",
		},
	}

	prepared, err := queue.PrepareExecutionForDevice(
		context.Background(),
		"device-001",
		"tenant-123",
		execution,
	)

	require.NoError(t, err)
	assert.Equal(t, "exec-001", prepared.ExecutionID)
	assert.NotEmpty(t, prepared.EphemeralKey) // Key generated
	assert.False(t, prepared.KeyExpiresAt.IsZero())

	// Check environment has both custom and injected variables
	assert.Equal(t, "custom_value", prepared.Environment["CUSTOM_VAR"])
	assert.Equal(t, prepared.EphemeralKey, prepared.Environment["CFGMS_API_KEY"])
	assert.Equal(t, "exec-001", prepared.Environment["CFGMS_EXECUTION_ID"])
	assert.Equal(t, "device-001", prepared.Environment["CFGMS_DEVICE_ID"])
	assert.Equal(t, "tenant-123", prepared.Environment["CFGMS_TENANT_ID"])

	// Validate the generated key works
	validated, err := keyManager.ValidateKey(prepared.EphemeralKey)
	require.NoError(t, err)
	assert.Equal(t, "script-123", validated.ScriptID)
	assert.Equal(t, "exec-001", validated.ExecutionID)
	assert.Equal(t, "tenant-123", validated.TenantID)
	assert.Equal(t, "device-001", validated.DeviceID)
}

func TestPrepareExecutionDefaultAPIKeySettings(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:    "exec-001",
		ScriptID:       "script-123",
		ScriptVersion:  "1.0.0",
		ScriptContent:  "echo 'test'",
		Shell:          ShellBash,
		GenerateAPIKey: true,
		// No TTL or permissions specified - should use defaults
	}

	prepared, err := queue.PrepareExecutionForDevice(
		context.Background(),
		"device-001",
		"tenant-123",
		execution,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, prepared.EphemeralKey)

	// Verify default TTL (1 hour)
	expectedExpiry := time.Now().Add(1 * time.Hour)
	timeDiff := prepared.KeyExpiresAt.Sub(expectedExpiry)
	assert.True(t, timeDiff < 5*time.Second && timeDiff > -5*time.Second,
		"Key expiry should be ~1 hour from now")

	// Verify default permissions (ScriptCallbackPermissions)
	validated, err := keyManager.ValidateKey(prepared.EphemeralKey)
	require.NoError(t, err)
	assert.Contains(t, validated.Permissions, "script:callback")
	assert.Contains(t, validated.Permissions, "script:status")
	assert.Contains(t, validated.Permissions, "script:log")
}

func TestQueueStatistics(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 100*time.Millisecond, "https://localhost:8080")

	// Queue some executions
	for i := 1; i <= 3; i++ {
		execution := &QueuedExecution{
			ExecutionID:   fmt.Sprintf("exec-%03d", i),
			ScriptID:      "script-123",
			ScriptVersion: "1.0.0",
			ScriptContent: "echo 'test'",
			Shell:         ShellBash,
		}
		err := queue.QueueExecution(fmt.Sprintf("device-%03d", i), execution)
		require.NoError(t, err)
	}

	// Add one more to device-001
	execution := &QueuedExecution{
		ExecutionID:   "exec-004",
		ScriptID:      "script-123",
		ScriptVersion: "1.0.0",
		ScriptContent: "echo 'test'",
		Shell:         ShellBash,
	}
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	stats := queue.GetStatistics()
	assert.Equal(t, 3, stats.TotalDevicesWithQueue)
	assert.Equal(t, 4, stats.TotalQueuedExecutions)
	assert.Equal(t, 2, stats.DeviceQueueDepths["device-001"])
	assert.Equal(t, 1, stats.DeviceQueueDepths["device-002"])
	assert.Equal(t, 1, stats.DeviceQueueDepths["device-003"])
	assert.Equal(t, 0, stats.ExpiredExecutions)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	stats = queue.GetStatistics()
	assert.Equal(t, 4, stats.ExpiredExecutions) // All should be expired
}

func TestListQueuedExecutions(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	// Queue executions
	for i := 1; i <= 2; i++ {
		for j := 1; j <= 2; j++ {
			execution := &QueuedExecution{
				ExecutionID:   fmt.Sprintf("exec-%d-%d", i, j),
				ScriptID:      "script-123",
				ScriptVersion: "1.0.0",
				ScriptContent: "echo 'test'",
				Shell:         ShellBash,
			}
			err := queue.QueueExecution(fmt.Sprintf("device-%03d", i), execution)
			require.NoError(t, err)
		}
	}

	all := queue.ListQueuedExecutions()
	assert.Len(t, all, 2) // 2 devices
	assert.Len(t, all["device-001"], 2)
	assert.Len(t, all["device-002"], 2)

	// Verify we get a copy (modification doesn't affect queue)
	all["device-001"][0].ExecutionID = "modified"
	peeked := queue.PeekForDevice("device-001")
	assert.NotEqual(t, "modified", peeked[0].ExecutionID)
}

func TestCleanupExpired(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 100*time.Millisecond, "https://localhost:8080")

	// Queue executions with short expiry
	for i := 1; i <= 5; i++ {
		execution := &QueuedExecution{
			ExecutionID:   fmt.Sprintf("exec-%03d", i),
			ScriptID:      "script-123",
			ScriptVersion: "1.0.0",
			ScriptContent: "echo 'test'",
			Shell:         ShellBash,
		}
		err := queue.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, queue.GetQueueDepth("device-001"))

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup manually
	queue.performCleanup()

	// All should be cleaned up
	assert.Equal(t, 0, queue.GetQueueDepth("device-001"))
	assert.Equal(t, 0, queue.GetTotalQueueDepth())
}

func TestDequeuePartialExpiration(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	// Queue 3 executions
	for i := 1; i <= 3; i++ {
		execution := &QueuedExecution{
			ExecutionID:   fmt.Sprintf("exec-%03d", i),
			ScriptID:      "script-123",
			ScriptVersion: "1.0.0",
			ScriptContent: "echo 'test'",
			Shell:         ShellBash,
			QueuedAt:      time.Now(),
		}

		// Make the second one already expired
		if i == 2 {
			execution.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired
		} else {
			execution.ExpiresAt = time.Now().Add(1 * time.Hour) // Valid
		}

		err := queue.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	// Dequeue should return only valid executions
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 2)

	// Verify the expired one is not included
	ids := []string{dequeued[0].ExecutionID, dequeued[1].ExecutionID}
	assert.Contains(t, ids, "exec-001")
	assert.Contains(t, ids, "exec-003")
	assert.NotContains(t, ids, "exec-002")
}

func TestQueueExecutionAutoTimestamps(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 2*time.Hour, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:   "exec-001",
		ScriptID:      "script-123",
		ScriptVersion: "1.0.0",
		ScriptContent: "echo 'test'",
		Shell:         ShellBash,
		// No QueuedAt or ExpiresAt set
	}

	before := time.Now()
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)
	after := time.Now()

	peeked := queue.PeekForDevice("device-001")
	require.Len(t, peeked, 1)

	// QueuedAt should be set automatically
	assert.True(t, peeked[0].QueuedAt.After(before) || peeked[0].QueuedAt.Equal(before))
	assert.True(t, peeked[0].QueuedAt.Before(after) || peeked[0].QueuedAt.Equal(after))

	// ExpiresAt should be QueuedAt + maxAge (2 hours)
	expectedExpiry := peeked[0].QueuedAt.Add(2 * time.Hour)
	timeDiff := peeked[0].ExpiresAt.Sub(expectedExpiry)
	assert.True(t, timeDiff < 1*time.Second && timeDiff > -1*time.Second)
}

func TestPeekReturnsDeepCopy(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")

	execution := &QueuedExecution{
		ExecutionID:   "exec-001",
		ScriptID:      "script-123",
		ScriptVersion: "1.0.0",
		ScriptContent: "echo 'test'",
		Shell:         ShellBash,
	}

	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Peek and modify
	peeked := queue.PeekForDevice("device-001")
	peeked[0].ExecutionID = "modified"

	// Peek again - should not be modified
	peeked2 := queue.PeekForDevice("device-001")
	assert.Equal(t, "exec-001", peeked2[0].ExecutionID)
}
