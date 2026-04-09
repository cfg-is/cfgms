// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

// testScriptRepo is a real in-memory ScriptRepository for queue tests.
// It is NOT a mock — it implements the full ScriptRepository contract.
type testScriptRepo struct {
	scripts map[string]*VersionedScript // id → latest
}

func newTestScriptRepo() *testScriptRepo {
	return &testScriptRepo{scripts: make(map[string]*VersionedScript)}
}

func (r *testScriptRepo) Create(script *VersionedScript) error {
	r.scripts[script.Metadata.ID] = script
	return nil
}

func (r *testScriptRepo) Get(id string, _ string) (*VersionedScript, error) {
	s, ok := r.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script %q not found", id)
	}
	return s, nil
}

func (r *testScriptRepo) List(_ *ScriptFilter) ([]*ScriptMetadata, error) {
	out := make([]*ScriptMetadata, 0, len(r.scripts))
	for _, s := range r.scripts {
		out = append(out, s.Metadata)
	}
	return out, nil
}

func (r *testScriptRepo) Update(script *VersionedScript) error {
	r.scripts[script.Metadata.ID] = script
	return nil
}

func (r *testScriptRepo) Delete(id string, _ string) error {
	delete(r.scripts, id)
	return nil
}

func (r *testScriptRepo) ListVersions(id string) ([]*Version, error) {
	s, ok := r.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script %q not found", id)
	}
	return []*Version{s.Metadata.Version}, nil
}

func (r *testScriptRepo) GetLatestVersion(id string) (*Version, error) {
	s, ok := r.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script %q not found", id)
	}
	return s.Metadata.Version, nil
}

func (r *testScriptRepo) Rollback(_ string, _ string) error { return nil }

// testScript creates a VersionedScript for test use.
func testScript(id, content string) *VersionedScript {
	return &VersionedScript{
		Metadata: &ScriptMetadata{
			ID:       id,
			Name:     id,
			Version:  &Version{Major: 1, Minor: 0, Patch: 0},
			Shell:    ShellBash,
			Platform: []string{"linux"},
		},
		Content: content,
		Hash:    fmt.Sprintf("%x", id), // simplified hash for tests
	}
}

// newTestQueue creates an ExecutionQueue backed by an InMemoryQueueStore.
// It is the standard helper for all existing tests to maintain API parity.
func newTestQueue(monitor *ExecutionMonitor, keyManager *EphemeralKeyManager, maxAge time.Duration, controllerURL string) *ExecutionQueue {
	return NewExecutionQueue(monitor, keyManager, maxAge, controllerURL, nil, nil, 0)
}

// newQueuedExec creates a minimal QueuedExecution for tests.
func newQueuedExec(executionID, scriptRef string) *QueuedExecution {
	return &QueuedExecution{
		ExecutionID: executionID,
		ScriptID:    scriptRef,
		ScriptRef:   scriptRef,
		Shell:       ShellBash,
		Timeout:     5 * time.Minute,
	}
}

// ----------------------------------------------------------------------------
// Existing API tests (updated for new QueuedExecution shape)
// ----------------------------------------------------------------------------

func TestExecutionQueueBasics(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-123")

	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	depth := queue.GetQueueDepth("device-001")
	assert.Equal(t, 1, depth)

	peeked := queue.PeekForDevice("device-001")
	require.Len(t, peeked, 1)
	assert.Equal(t, "exec-001", peeked[0].ExecutionID)

	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)
	assert.Equal(t, "exec-001", dequeued[0].ExecutionID)

	// After dequeue the entry is in dispatched state, still counted in active depth
	depth = queue.GetQueueDepth("device-001")
	assert.Equal(t, 1, depth) // dispatched entry still active

	// Acknowledge completion — entry moves out of active queue
	err = queue.AcknowledgeCompletion("exec-001", "device-001", QueueStateCompleted, nil)
	require.NoError(t, err)

	depth = queue.GetQueueDepth("device-001")
	assert.Equal(t, 0, depth)
}

func TestExecutionQueueMultipleDevices(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	for i := 1; i <= 3; i++ {
		for j := 1; j <= 2; j++ {
			execID := fmt.Sprintf("exec-%d-%d", i, j)
			execution := &QueuedExecution{
				ExecutionID: execID,
				ScriptID:    fmt.Sprintf("script-%d-%d", i, j), // distinct script per execution
				ScriptRef:   fmt.Sprintf("script-%d-%d", i, j),
				Shell:       ShellBash,
			}
			err := queue.QueueExecution(fmt.Sprintf("device-%03d", i), execution)
			require.NoError(t, err)
		}
	}

	totalDepth := queue.GetTotalQueueDepth()
	assert.Equal(t, 6, totalDepth)

	for i := 1; i <= 3; i++ {
		depth := queue.GetQueueDepth(fmt.Sprintf("device-%03d", i))
		assert.Equal(t, 2, depth)
	}

	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 2)

	// device-001 entries are now dispatched (still counted as active)
	totalDepth = queue.GetTotalQueueDepth()
	assert.Equal(t, 6, totalDepth)

	// Acknowledge all device-001 completions — entries leave active queue
	for _, d := range dequeued {
		require.NoError(t, queue.AcknowledgeCompletion(d.ExecutionID, "device-001", QueueStateCompleted, nil))
	}

	totalDepth = queue.GetTotalQueueDepth()
	assert.Equal(t, 4, totalDepth, "after completion, only device-002 and device-003 entries remain")
}

func TestExecutionQueueExpiration(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	// Set ExpiresAt directly to a past time to avoid time.Sleep
	execution := &QueuedExecution{
		ExecutionID: "exec-001",
		ScriptID:    "script-123",
		ScriptRef:   "script-123",
		Shell:       ShellBash,
		QueuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // already expired
	}

	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Dequeue should return empty (entry is expired)
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 0)
}

func TestExecutionQueueCancellation(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	for i := 1; i <= 3; i++ {
		// Distinct scripts to avoid dedup
		execution := newQueuedExec(fmt.Sprintf("exec-%03d", i), fmt.Sprintf("script-%03d", i))
		err := queue.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	assert.Equal(t, 3, queue.GetQueueDepth("device-001"))

	err := queue.CancelExecution("device-001", "exec-002")
	require.NoError(t, err)

	assert.Equal(t, 2, queue.GetQueueDepth("device-001"))

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

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	err := queue.CancelExecution("device-001", "exec-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no queued executions")

	execution := newQueuedExec("exec-001", "script-123")
	err = queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	err = queue.CancelExecution("device-001", "exec-999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in queue")
}

func TestPrepareExecutionWithoutAPIKey(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := &QueuedExecution{
		ExecutionID:    "exec-001",
		ScriptID:       "script-123",
		ScriptRef:      "script-123",
		Shell:          ShellBash,
		Timeout:        5 * time.Minute,
		GenerateAPIKey: false,
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
	assert.Empty(t, prepared.EphemeralKey)
}

func TestPrepareExecutionWithAPIKey(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := &QueuedExecution{
		ExecutionID:       "exec-001",
		ScriptID:          "script-123",
		ScriptRef:         "script-123",
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
	assert.NotEmpty(t, prepared.EphemeralKey)
	assert.False(t, prepared.KeyExpiresAt.IsZero())

	assert.Equal(t, "custom_value", prepared.Environment["CUSTOM_VAR"])
	assert.Equal(t, prepared.EphemeralKey, prepared.Environment["CFGMS_API_KEY"])
	assert.Equal(t, "exec-001", prepared.Environment["CFGMS_EXECUTION_ID"])
	assert.Equal(t, "device-001", prepared.Environment["CFGMS_DEVICE_ID"])
	assert.Equal(t, "tenant-123", prepared.Environment["CFGMS_TENANT_ID"])

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

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := &QueuedExecution{
		ExecutionID:    "exec-001",
		ScriptID:       "script-123",
		ScriptRef:      "script-123",
		Shell:          ShellBash,
		GenerateAPIKey: true,
	}

	prepared, err := queue.PrepareExecutionForDevice(
		context.Background(),
		"device-001",
		"tenant-123",
		execution,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, prepared.EphemeralKey)

	expectedExpiry := time.Now().Add(1 * time.Hour)
	timeDiff := prepared.KeyExpiresAt.Sub(expectedExpiry)
	assert.True(t, timeDiff < 5*time.Second && timeDiff > -5*time.Second,
		"Key expiry should be ~1 hour from now")

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

	queue := newTestQueue(monitor, keyManager, 100*time.Millisecond, "https://localhost:8080")
	defer queue.Stop()

	for i := 1; i <= 3; i++ {
		execution := newQueuedExec(fmt.Sprintf("exec-%03d", i), fmt.Sprintf("script-%03d", i))
		err := queue.QueueExecution(fmt.Sprintf("device-%03d", i), execution)
		require.NoError(t, err)
	}

	// Add a second execution to device-001 with a different script
	execution := newQueuedExec("exec-004", "script-004")
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	stats := queue.GetStatistics()
	assert.Equal(t, 3, stats.TotalDevicesWithQueue)
	assert.Equal(t, 4, stats.TotalQueuedExecutions)
	assert.Equal(t, 2, stats.DeviceQueueDepths["device-001"])
	assert.Equal(t, 1, stats.DeviceQueueDepths["device-002"])
	assert.Equal(t, 1, stats.DeviceQueueDepths["device-003"])
	assert.Equal(t, 0, stats.ExpiredExecutions)

	// Mark all entries as expired by direct store manipulation (avoids time.Sleep)
	inMemStore := queue.store.(*InMemoryQueueStore)
	inMemStore.mu.Lock()
	for _, entry := range inMemStore.entries {
		entry.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
	inMemStore.mu.Unlock()

	queue.performMaintenance()

	stats = queue.GetStatistics()
	assert.Equal(t, 4, stats.ExpiredExecutions)
}

func TestListQueuedExecutions(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	for i := 1; i <= 2; i++ {
		for j := 1; j <= 2; j++ {
			// Distinct scripts to avoid dedup
			execution := newQueuedExec(fmt.Sprintf("exec-%d-%d", i, j), fmt.Sprintf("script-%d-%d", i, j))
			err := queue.QueueExecution(fmt.Sprintf("device-%03d", i), execution)
			require.NoError(t, err)
		}
	}

	all := queue.ListQueuedExecutions()
	assert.Len(t, all, 2)
	assert.Len(t, all["device-001"], 2)
	assert.Len(t, all["device-002"], 2)

	// Verify returned copy is isolated from internal state
	all["device-001"][0].ExecutionID = "modified"
	peeked := queue.PeekForDevice("device-001")
	assert.NotEqual(t, "modified", peeked[0].ExecutionID)
}

func TestCleanupExpired(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 100*time.Millisecond, "https://localhost:8080")
	defer queue.Stop()

	for i := 1; i <= 5; i++ {
		// Distinct scripts to avoid dedup
		execution := newQueuedExec(fmt.Sprintf("exec-%03d", i), fmt.Sprintf("script-%03d", i))
		err := queue.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, queue.GetQueueDepth("device-001"))

	// Expire all entries by direct store manipulation (avoids time.Sleep)
	inMemStore := queue.store.(*InMemoryQueueStore)
	inMemStore.mu.Lock()
	for _, entry := range inMemStore.entries {
		entry.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
	inMemStore.mu.Unlock()

	queue.performMaintenance()

	assert.Equal(t, 0, queue.GetQueueDepth("device-001"))
	assert.Equal(t, 0, queue.GetTotalQueueDepth())
}

func TestDequeuePartialExpiration(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	for i := 1; i <= 3; i++ {
		scriptRef := fmt.Sprintf("script-%03d", i) // distinct scripts to avoid dedup
		execution := &QueuedExecution{
			ExecutionID: fmt.Sprintf("exec-%03d", i),
			ScriptID:    scriptRef,
			ScriptRef:   scriptRef,
			Shell:       ShellBash,
			QueuedAt:    time.Now(),
		}
		if i == 2 {
			execution.ExpiresAt = time.Now().Add(-1 * time.Hour) // already expired
		} else {
			execution.ExpiresAt = time.Now().Add(1 * time.Hour)
		}

		err := queue.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 2)

	ids := []string{dequeued[0].ExecutionID, dequeued[1].ExecutionID}
	assert.Contains(t, ids, "exec-001")
	assert.Contains(t, ids, "exec-003")
	assert.NotContains(t, ids, "exec-002")
}

func TestQueueExecutionAutoTimestamps(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 2*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-123")

	before := time.Now()
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)
	after := time.Now()

	peeked := queue.PeekForDevice("device-001")
	require.Len(t, peeked, 1)

	assert.True(t, peeked[0].QueuedAt.After(before) || peeked[0].QueuedAt.Equal(before))
	assert.True(t, peeked[0].QueuedAt.Before(after) || peeked[0].QueuedAt.Equal(after))

	expectedExpiry := peeked[0].QueuedAt.Add(2 * time.Hour)
	timeDiff := peeked[0].ExpiresAt.Sub(expectedExpiry)
	assert.True(t, timeDiff < 1*time.Second && timeDiff > -1*time.Second)
}

func TestPeekReturnsDeepCopy(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-123")

	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	peeked := queue.PeekForDevice("device-001")
	peeked[0].ExecutionID = "modified"

	peeked2 := queue.PeekForDevice("device-001")
	assert.Equal(t, "exec-001", peeked2[0].ExecutionID)
}

// ----------------------------------------------------------------------------
// New tests: durable queue acceptance criteria
// ----------------------------------------------------------------------------

// TestDurablePersistenceAcrossRestart verifies that queued executions survive
// an ExecutionQueue restart (controller restart simulation) by sharing the same
// QueueStore.
func TestDurablePersistenceAcrossRestart(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	store := NewInMemoryQueueStore()

	// First queue instance — simulate initial controller
	queue1 := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, 0)
	defer queue1.Stop()

	for i := 1; i <= 3; i++ {
		// Distinct scripts to avoid dedup
		execution := newQueuedExec(fmt.Sprintf("exec-%03d", i), fmt.Sprintf("script-abc-%03d", i))
		err := queue1.QueueExecution("device-001", execution)
		require.NoError(t, err)
	}

	require.Equal(t, 3, queue1.GetQueueDepth("device-001"))

	// Simulate controller restart: create a new ExecutionQueue over the same store
	queue2 := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, 0)
	defer queue2.Stop()

	// All executions must still be present after "restart"
	depth := queue2.GetQueueDepth("device-001")
	assert.Equal(t, 3, depth, "queued executions must survive controller restart")

	dequeued, err := queue2.DequeueForDevice("device-001")
	require.NoError(t, err)
	assert.Len(t, dequeued, 3)
}

// TestDedup verifies that identical (scriptRef + deviceID + params) executions
// are deduplicated: only one entry is kept in the queued state.
// Different params produce distinct executions.
func TestDedup(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	base := &QueuedExecution{
		ExecutionID: "exec-001",
		ScriptID:    "script-dedup",
		ScriptRef:   "script-dedup",
		Shell:       ShellBash,
		Parameters:  map[string]string{"key": "value"},
	}

	// First enqueue succeeds
	err := queue.QueueExecution("device-001", base)
	require.NoError(t, err)
	assert.Equal(t, 1, queue.GetQueueDepth("device-001"))

	// Duplicate enqueue (same script + device + params) is silently ignored
	dup := &QueuedExecution{
		ExecutionID: "exec-002", // different ID, same content
		ScriptID:    "script-dedup",
		ScriptRef:   "script-dedup",
		Shell:       ShellBash,
		Parameters:  map[string]string{"key": "value"},
	}
	err = queue.QueueExecution("device-001", dup)
	require.NoError(t, err, "duplicate enqueue must not return error (silently ignored)")
	assert.Equal(t, 1, queue.GetQueueDepth("device-001"), "duplicate must not add a second entry")

	// Different params create a distinct execution
	differentParams := &QueuedExecution{
		ExecutionID: "exec-003",
		ScriptID:    "script-dedup",
		ScriptRef:   "script-dedup",
		Shell:       ShellBash,
		Parameters:  map[string]string{"key": "other-value"},
	}
	err = queue.QueueExecution("device-001", differentParams)
	require.NoError(t, err)
	assert.Equal(t, 2, queue.GetQueueDepth("device-001"), "different params must create distinct execution")
}

// TestParamHashDeterminism verifies ComputeParamHash is deterministic
// regardless of map insertion order.
func TestParamHashDeterminism(t *testing.T) {
	params1 := map[string]string{"a": "1", "b": "2", "c": "3"}
	params2 := map[string]string{"c": "3", "a": "1", "b": "2"}
	params3 := map[string]string{"b": "2", "c": "3", "a": "1"}

	h1 := ComputeParamHash("script-ref", "device-001", params1)
	h2 := ComputeParamHash("script-ref", "device-001", params2)
	h3 := ComputeParamHash("script-ref", "device-001", params3)

	assert.Equal(t, h1, h2, "param hash must be deterministic regardless of map order")
	assert.Equal(t, h1, h3)

	// Different params → different hash
	different := map[string]string{"a": "1", "b": "9", "c": "3"}
	hDiff := ComputeParamHash("script-ref", "device-001", different)
	assert.NotEqual(t, h1, hDiff)
}

// TestLatestVersionResolution verifies that PrepareExecutionForDevice resolves
// the latest script content from the repository at dispatch time.
func TestLatestVersionResolution(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	repo := newTestScriptRepo()
	repo.scripts["script-abc"] = testScript("script-abc", "echo initial-version")

	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", nil, repo, 0)
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-abc")
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Update script to a new version in the repo (simulates script update before device reconnects)
	repo.scripts["script-abc"] = testScript("script-abc", "echo latest-version")

	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)

	// PrepareExecutionForDevice must resolve the current (latest) content
	prepared, err := queue.PrepareExecutionForDevice(context.Background(), "device-001", "tenant-001", dequeued[0])
	require.NoError(t, err)

	assert.Equal(t, "echo latest-version", prepared.ScriptContent,
		"latest version must be resolved at dispatch time, not at queue time")
}

// TestDispatchedRequeuedOnTimeout verifies that dispatched executions whose
// DispatchedAt exceeds the dispatch timeout are reverted to queued state.
func TestDispatchedRequeuedOnTimeout(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	store := NewInMemoryQueueStore()
	dispatchTimeout := 1 * time.Hour
	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, dispatchTimeout)
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-xyz")
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Dispatch the execution
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)
	assert.Equal(t, QueueStateDispatched, dequeued[0].State)

	// Simulate the dispatch timeout by backdating DispatchedAt directly (no time.Sleep needed)
	inMemStore := store.(*InMemoryQueueStore)
	inMemStore.mu.Lock()
	pastTime := time.Now().Add(-2 * time.Hour)
	inMemStore.entries["exec-001"].DispatchedAt = &pastTime
	inMemStore.mu.Unlock()

	// Trigger stale requeue
	count, err := store.RequeueStale(dispatchTimeout)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "timed-out dispatched execution must be re-queued")

	// Peek confirms entry is back in queued state
	peeked := queue.PeekForDevice("device-001")
	require.Len(t, peeked, 1)
	assert.Equal(t, QueueStateQueued, peeked[0].State,
		"entry must be in queued state after timeout revert")
}

// TestRedispatchOnStewardReconnect verifies that when a steward reconnects
// without having reported completion for a dispatched execution, the controller
// re-dispatches it.
func TestRedispatchOnStewardReconnect(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-reconnect")
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// First connect: dispatch the execution
	dispatched, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dispatched, 1)

	// Steward disconnects without calling AcknowledgeCompletion

	// Second connect (steward reconnects): controller must re-dispatch
	redispatched, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, redispatched, 1, "execution must be re-dispatched on steward reconnect")
	assert.Equal(t, "exec-001", redispatched[0].ExecutionID)
}

// TestCompletionAcknowledgment verifies the full completion lifecycle:
// queued → dispatched → completed.
func TestCompletionAcknowledgment(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	store := NewInMemoryQueueStore()
	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, 0)
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-ack")
	err := queue.QueueExecution("device-001", execution)
	require.NoError(t, err)

	// Dispatch
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)

	// Confirm dispatched state is visible
	assert.Equal(t, 1, queue.GetQueueDepth("device-001"), "dispatched entry still active")

	// Acknowledge success
	err = queue.AcknowledgeCompletion("exec-001", "device-001", QueueStateCompleted, nil)
	require.NoError(t, err)

	// Entry removed from active queue
	assert.Equal(t, 0, queue.GetQueueDepth("device-001"), "completed entry must leave active queue")

	// Entry retained in store (for audit)
	storeStats, err := store.GetStats()
	require.NoError(t, err)
	assert.Equal(t, 1, storeStats.CompletedCount, "completed entry must be retained in store")
	assert.Equal(t, 0, storeStats.QueuedCount+storeStats.DispatchedCount)
}

// TestFailedCompletionRetained verifies that failed executions are retained in
// the store for audit purposes.
func TestFailedCompletionRetained(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	store := NewInMemoryQueueStore()
	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, 0)
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-fail")
	require.NoError(t, queue.QueueExecution("device-001", execution))

	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)

	err = queue.AcknowledgeCompletion("exec-001", "device-001", QueueStateFailed, nil)
	require.NoError(t, err)

	storeStats, err := store.GetStats()
	require.NoError(t, err)
	assert.Equal(t, 1, storeStats.FailedCount, "failed entry must be retained in store")
}

// TestAcknowledgeCompletionErrors tests error paths in AcknowledgeCompletion.
func TestAcknowledgeCompletionErrors(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	// Unknown execution
	err := queue.AcknowledgeCompletion("unknown-exec", "device-001", QueueStateCompleted, nil)
	assert.Error(t, err)

	// Queue an execution but don't dispatch it — can't acknowledge a queued entry
	execution := newQueuedExec("exec-001", "script-err")
	require.NoError(t, queue.QueueExecution("device-001", execution))

	err = queue.AcknowledgeCompletion("exec-001", "device-001", QueueStateCompleted, nil)
	assert.Error(t, err, "acknowledging a queued (not dispatched) entry must fail")
}

// TestAcknowledgeCompletionInvalidState verifies that AcknowledgeCompletion
// rejects invalid terminal states (B4: missing error path coverage).
func TestAcknowledgeCompletionInvalidState(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	store := NewInMemoryQueueStore()
	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, 0)
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-invalid-state")
	require.NoError(t, queue.QueueExecution("device-001", execution))

	// Dispatch first
	_, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)

	// Passing a non-terminal state (e.g., QueueStateQueued) must fail
	err = store.AcknowledgeCompletion("exec-001", "device-001", QueueStateQueued, nil)
	assert.Error(t, err, "AcknowledgeCompletion must reject non-terminal state QueueStateQueued")

	// Passing a dispatched state must also fail
	err = store.AcknowledgeCompletion("exec-001", "device-001", QueueStateDispatched, nil)
	assert.Error(t, err, "AcknowledgeCompletion must reject QueueStateDispatched")
}

// TestCancelDispatchedEntry verifies that a dispatched (in-flight) execution
// can be cancelled (B5: missing dispatched-cancel coverage).
func TestCancelDispatchedEntry(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	queue := newTestQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080")
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-cancel-dispatched")
	require.NoError(t, queue.QueueExecution("device-001", execution))

	// Dispatch the execution
	dequeued, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.Len(t, dequeued, 1)
	assert.Equal(t, QueueStateDispatched, dequeued[0].State)

	// Cancel while dispatched — must succeed
	err = queue.CancelExecution("device-001", "exec-001")
	require.NoError(t, err, "cancelling a dispatched execution must succeed")

	// Entry no longer in active queue
	assert.Equal(t, 0, queue.GetQueueDepth("device-001"), "cancelled entry must leave active queue")
}

// TestCancelTerminalStateEntry verifies that cancelling a completed/failed entry
// returns an error (B6: missing terminal-state cancel error path).
func TestCancelTerminalStateEntry(t *testing.T) {
	monitor := NewExecutionMonitor()
	keyManager := NewEphemeralKeyManager()
	defer keyManager.Stop()

	store := NewInMemoryQueueStore()
	queue := NewExecutionQueue(monitor, keyManager, 1*time.Hour, "https://localhost:8080", store, nil, 0)
	defer queue.Stop()

	execution := newQueuedExec("exec-001", "script-terminal-cancel")
	require.NoError(t, queue.QueueExecution("device-001", execution))

	// Dispatch and complete
	_, err := queue.DequeueForDevice("device-001")
	require.NoError(t, err)
	require.NoError(t, queue.AcknowledgeCompletion("exec-001", "device-001", QueueStateCompleted, nil))

	// Attempting to cancel a completed entry must fail (no active entries for device)
	err = queue.CancelExecution("device-001", "exec-001")
	assert.Error(t, err, "cancelling a completed entry must return an error")
}
