// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
)

// staticFleetQuery is a real FleetQuery implementation that returns a fixed set
// of StewardResults. Used in synthesis tests to avoid mocks.
type staticFleetQuery struct {
	results []fleet.StewardResult
}

func (q *staticFleetQuery) Search(_ context.Context, _ fleet.Filter) ([]fleet.StewardResult, error) {
	return q.results, nil
}

func (q *staticFleetQuery) Count(_ context.Context, _ fleet.Filter) (int, error) {
	return len(q.results), nil
}

// newTestExecutionQueue creates a real ExecutionQueue backed by an InMemoryQueueStore.
func newTestExecutionQueue() *scriptmodule.ExecutionQueue {
	monitor := scriptmodule.NewExecutionMonitor()
	keyManager := scriptmodule.NewEphemeralKeyManager()
	return scriptmodule.NewExecutionQueue(monitor, keyManager, 0, "", nil, nil, 0)
}

// newTestSynthesisManager creates a Manager backed by an in-memory SQLite store.
func newTestSynthesisManager(t *testing.T) *Manager {
	t.Helper()
	store := newTestRunStore(t)
	return NewManager(store, nil)
}

// ---- SynthesizeScriptRun tests ----------------------------------------------

func TestSynthesizeScriptRun_TwoDevices_CreatesTwoJobs(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-001", TenantID: "tenant-abc"},
			{ID: "device-002", TenantID: "tenant-abc"},
		},
	}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/deploy.sh", "v1.0.0",
		scriptmodule.ShellBash,
		map[string]string{"env": "prod"},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, runID)

	// Run record must exist and have status=running
	run, err := manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunStatusRunning, run.Status)
	assert.Equal(t, 2, run.JobCount)
	assert.Equal(t, "tenant-abc", run.TenantID)
	assert.Equal(t, "user-1", run.CreatedBy)
	assert.Equal(t, "scripts/deploy.sh", run.ScriptRef)
	assert.Equal(t, "tenant-abc", run.Filter.TenantID, "filter.TenantID must be scoped to tenantID")

	// Two job records must exist, one per device
	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	deviceIDs := map[string]bool{}
	for _, j := range jobs {
		assert.Equal(t, runID, j.RunID)
		assert.NotEmpty(t, j.JobID)
		assert.NotEmpty(t, j.ExecutionID)
		assert.Equal(t, JobStatusPending, j.Status)
		deviceIDs[j.DeviceID] = true
	}
	assert.True(t, deviceIDs["device-001"], "job for device-001 must exist")
	assert.True(t, deviceIDs["device-002"], "job for device-002 must exist")

	// Two executions must be queued — one per device
	exec1 := queue.PeekForDevice("device-001")
	exec2 := queue.PeekForDevice("device-002")
	require.Len(t, exec1, 1, "device-001 must have one queued execution")
	require.Len(t, exec2, 1, "device-002 must have one queued execution")

	// Metadata must carry the workflow_run_id and job_id
	for _, e := range []*scriptmodule.QueuedExecution{exec1[0], exec2[0]} {
		assert.Equal(t, runID, e.Metadata["workflow_run_id"], "workflow_run_id must be the run ID")
		assert.NotEmpty(t, e.Metadata["job_id"], "job_id must be set")
	}
}

func TestSynthesizeScriptRun_QueuedExecutionIDs_MatchJobRecords(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-A", TenantID: "tenant-test"},
		},
	}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-test", "user-x",
		fleet.Filter{},
		"scripts/check.sh", "",
		scriptmodule.ShellBash,
		nil, nil, nil, nil,
	)
	require.NoError(t, err)

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	queued := queue.PeekForDevice("device-A")
	require.Len(t, queued, 1)

	// The execution_id in the queue must match the job record
	assert.Equal(t, jobs[0].ExecutionID, queued[0].ExecutionID,
		"execution_id in queue must match the job record")
	assert.Equal(t, jobs[0].JobID, queued[0].Metadata["job_id"],
		"job_id in queue metadata must match the job record")
}

func TestSynthesizeScriptRun_NoDevices_CreatesEmptyRun(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{results: []fleet.StewardResult{}}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/noop.sh", "",
		scriptmodule.ShellBash,
		nil, nil, nil, nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, runID)

	run, err := manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, 0, run.JobCount)
	assert.Equal(t, RunStatusRunning, run.Status)

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	assert.Empty(t, jobs)
}

func TestSynthesizeScriptRun_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	// Use a RunStoreSQL directly so we can inspect stored runs.
	sqlStore := newTestRunStore(t)
	manager := NewManager(sqlStore, nil)
	queue := newTestExecutionQueue()

	// Even if caller passes an empty filter, tenant scoping must be applied.
	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-isolated", TenantID: "tenant-xyz"},
		},
	}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-xyz", "user-2",
		fleet.Filter{}, // no explicit tenantID
		"scripts/test.sh", "",
		scriptmodule.ShellBash,
		nil, nil, nil, nil,
	)
	require.NoError(t, err)

	// The stored run must belong to tenant-xyz and filter.TenantID must be set.
	run, err := sqlStore.GetRun(runID)
	require.NoError(t, err)
	assert.Equal(t, "tenant-xyz", run.TenantID)
	assert.Equal(t, "tenant-xyz", run.Filter.TenantID,
		"filter.TenantID must be overwritten with tenantID even when filter was empty")
}

// ---- SynthesizeCommandRun tests ---------------------------------------------

func TestSynthesizeCommandRun_TwoDevices_CreatesTwoJobs(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-cmd-1", TenantID: "tenant-abc"},
			{ID: "device-cmd-2", TenantID: "tenant-abc"},
		},
	}

	runID, err := SynthesizeCommandRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"#!/bin/bash\necho hello",
		scriptmodule.ShellBash,
		nil,
		nil,
		nil, "", time.Time{}, 0,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, runID)

	run, err := manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunStatusRunning, run.Status)
	assert.Equal(t, 2, run.JobCount)
	assert.Equal(t, "#!/bin/bash\necho hello", run.InlineContent)
	assert.Empty(t, run.ScriptRef, "script_ref must be empty for command runs")

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	// Inline content must be stored in queue metadata
	for _, deviceID := range []string{"device-cmd-1", "device-cmd-2"} {
		queued := queue.PeekForDevice(deviceID)
		require.Len(t, queued, 1, "device %s must have one queued execution", deviceID)
		assert.Equal(t, "#!/bin/bash\necho hello",
			queued[0].Metadata["inline_script_content"],
			"inline content must be in queue metadata for device %s", deviceID)
		assert.Equal(t, runID, queued[0].Metadata["workflow_run_id"])
	}
}

func TestSynthesizeCommandRunForDevices_WebAuthnProofAndPerDeviceManifest(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()
	devices := []fleet.StewardResult{{ID: "dev-a", TenantID: "t"}, {ID: "dev-b", TenantID: "t"}}
	sig := &CommandSignature{
		WebAuthnAuthenticatorData: "YXV0aA==", WebAuthnClientDataJSON: "Y2xpZW50",
		WebAuthnSignature: "c2ln", WebAuthnCredentialID: "Y3JlZA==",
	}
	manifests := map[string]string{"dev-a": "manifest-a", "dev-b": "manifest-b"}

	_, err := SynthesizeCommandRunForDevices(ctx, manager, queue, devices, "t", "u", fleet.Filter{},
		"echo hi", scriptmodule.ShellBash, nil, sig, manifests, []string{"dev-a", "dev-b"}, "n1", time.Now().Add(time.Minute), 0)
	require.NoError(t, err)

	for _, id := range []string{"dev-a", "dev-b"} {
		queued := queue.PeekForDevice(id)
		require.Len(t, queued, 1)
		md := queued[0].Metadata
		assert.Equal(t, sig.WebAuthnAuthenticatorData, md["webauthn_authenticator_data"])
		assert.Equal(t, sig.WebAuthnClientDataJSON, md["webauthn_client_data_json"])
		assert.Equal(t, sig.WebAuthnSignature, md["webauthn_signature"])
		assert.Equal(t, sig.WebAuthnCredentialID, md["webauthn_credential_id"])
		assert.Equal(t, manifests[id], md["webauthn_manifest"])
		assert.Equal(t, []string{"dev-a", "dev-b"}, md["targets"])
	}
}

func TestSynthesizeCommandRunForDevices_RefusesPartialWebAuthnSet(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()
	devices := []fleet.StewardResult{{ID: "dev-a", TenantID: "t"}, {ID: "dev-b", TenantID: "t"}}
	exp := time.Now().Add(time.Minute)

	partial := &CommandSignature{WebAuthnAuthenticatorData: "YQ==", WebAuthnClientDataJSON: "Yg=="}
	_, err := SynthesizeCommandRunForDevices(ctx, manager, queue, devices, "t", "u", fleet.Filter{},
		"echo hi", scriptmodule.ShellBash, nil, partial, map[string]string{"dev-a": "m", "dev-b": "m"}, nil, "n", exp, 0)
	require.Error(t, err)

	full := &CommandSignature{WebAuthnAuthenticatorData: "YQ==", WebAuthnClientDataJSON: "Yg==", WebAuthnSignature: "Yw==", WebAuthnCredentialID: "ZA=="}
	_, err = SynthesizeCommandRunForDevices(ctx, manager, queue, devices, "t", "u", fleet.Filter{},
		"echo hi", scriptmodule.ShellBash, nil, full, map[string]string{"dev-a": "m"}, nil, "n", exp, 0)
	require.Error(t, err, "a device without a manifest must refuse the whole run")

	assert.Empty(t, queue.PeekForDevice("dev-a"))
	assert.Empty(t, queue.PeekForDevice("dev-b"))
}

// TestSynthesizeScriptRun_ResolveParamsPerDevice verifies that when scriptMeta is
// provided, each device's QueuedExecution.Parameters reflects that device's DNA
// attributes, with runtime overrides still taking priority.
func TestSynthesizeScriptRun_ResolveParamsPerDevice(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{
				ID:            "device-linux",
				TenantID:      "tenant-abc",
				DNAAttributes: map[string]string{"device.os": "linux"},
			},
			{
				ID:            "device-windows",
				TenantID:      "tenant-abc",
				DNAAttributes: map[string]string{"device.os": "windows"},
			},
		},
	}

	meta := &scriptmodule.ScriptMetadata{
		ID:       "script-dna",
		Name:     "DNA Param Script",
		Version:  &scriptmodule.Version{Major: 1},
		Shell:    scriptmodule.ShellBash,
		Platform: []string{"linux", "windows"},
		Parameters: []scriptmodule.ScriptParameter{
			{Name: "os", Type: "string", DNAPath: "device.os"},
			{Name: "env", Type: "string", Required: true},
		},
	}

	_, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/dna.sh", "",
		scriptmodule.ShellBash,
		map[string]string{"env": "prod"},
		meta, nil, nil,
	)
	require.NoError(t, err)

	// Each device must get its own resolved os value from DNA
	linuxExecs := queue.PeekForDevice("device-linux")
	require.Len(t, linuxExecs, 1)
	assert.Equal(t, "linux", linuxExecs[0].Parameters["os"],
		"device-linux must get os=linux from DNA")
	assert.Equal(t, "prod", linuxExecs[0].Parameters["env"],
		"runtime override must still apply")

	windowsExecs := queue.PeekForDevice("device-windows")
	require.Len(t, windowsExecs, 1)
	assert.Equal(t, "windows", windowsExecs[0].Parameters["os"],
		"device-windows must get os=windows from DNA")
}

// TestSynthesizeScriptRun_IdempotentMetadata verifies that idempotent scripts
// carry idempotent=true in QueuedExecution.Metadata.
func TestSynthesizeScriptRun_IdempotentMetadata(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-idem", TenantID: "tenant-abc"},
		},
	}

	meta := &scriptmodule.ScriptMetadata{
		ID:         "script-idem",
		Name:       "Idempotent Script",
		Version:    &scriptmodule.Version{Major: 1},
		Shell:      scriptmodule.ShellBash,
		Platform:   []string{"linux"},
		Idempotent: true,
	}

	_, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/idem.sh", "",
		scriptmodule.ShellBash,
		nil, meta, nil, nil,
	)
	require.NoError(t, err)

	execs := queue.PeekForDevice("device-idem")
	require.Len(t, execs, 1)
	isIdempotent, _ := execs[0].Metadata["idempotent"].(bool)
	assert.True(t, isIdempotent, "idempotent script must carry idempotent=true in metadata")
}

// TestSynthesizeScriptRun_MissingRequiredParam_Fails verifies that synthesis fails
// fast when a required parameter has no value from any source.
func TestSynthesizeScriptRun_MissingRequiredParam_Fails(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-req", TenantID: "tenant-abc"},
		},
	}

	meta := &scriptmodule.ScriptMetadata{
		ID:       "script-req",
		Name:     "Required Param Script",
		Version:  &scriptmodule.Version{Major: 1},
		Shell:    scriptmodule.ShellBash,
		Platform: []string{"linux"},
		Parameters: []scriptmodule.ScriptParameter{
			{Name: "must_have", Type: "string", Required: true},
		},
	}

	_, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/req.sh", "",
		scriptmodule.ShellBash,
		nil, meta, nil, nil,
	)
	require.Error(t, err, "synthesis must fail when required param has no value")
	assert.Contains(t, err.Error(), "must_have",
		"error must identify the missing required parameter")
}

func TestSynthesizeCommandRun_QueuedExecutionIDs_MatchJobRecords(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-cmd-A", TenantID: "tenant-test"},
		},
	}

	runID, err := SynthesizeCommandRun(
		ctx, manager, queue, fq,
		"tenant-test", "user-cmd",
		fleet.Filter{},
		"echo test",
		scriptmodule.ShellBash,
		nil,
		nil,
		nil, "", time.Time{}, 0,
	)
	require.NoError(t, err)

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	queued := queue.PeekForDevice("device-cmd-A")
	require.Len(t, queued, 1)

	assert.Equal(t, jobs[0].ExecutionID, queued[0].ExecutionID,
		"execution_id in queue must match the job record")
	assert.Equal(t, jobs[0].JobID, queued[0].Metadata["job_id"])
}

// ---- rollback tests ----------------------------------------------------------

// failingEnqueueStore embeds the real in-memory queue store and fails Enqueue on
// its failOn-th call (1-based).
type failingEnqueueStore struct {
	scriptmodule.QueueStore
	failOn int
	calls  int
}

func (s *failingEnqueueStore) Enqueue(entry *scriptmodule.QueueEntry) error {
	s.calls++
	if s.calls == s.failOn {
		return errors.New("injected enqueue failure")
	}
	return s.QueueStore.Enqueue(entry)
}

func newFailingQueue(failOn int) *scriptmodule.ExecutionQueue {
	store := &failingEnqueueStore{QueueStore: scriptmodule.NewInMemoryQueueStore(), failOn: failOn}
	return scriptmodule.NewExecutionQueue(scriptmodule.NewExecutionMonitor(), scriptmodule.NewEphemeralKeyManager(), 0, "", store, nil, 0)
}

func rollbackDevices() []fleet.StewardResult {
	return []fleet.StewardResult{
		{ID: "device-001", TenantID: "t", DNAAttributes: map[string]string{"os.name": "linux"}},
		{ID: "device-002", TenantID: "t"},
	}
}

func assertRolledBack(t *testing.T, manager *Manager, queue *scriptmodule.ExecutionQueue, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "injected enqueue failure")

	runs, lerr := manager.store.ListRuns("t", 10, 0)
	require.NoError(t, lerr)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)

	jobs, lerr := manager.ListRunJobs(context.Background(), runs[0].RunID)
	require.NoError(t, lerr)
	require.Len(t, jobs, 2)
	for _, j := range jobs {
		assert.Equal(t, JobStatusCancelled, j.Status)
	}
	assert.Empty(t, queue.PeekForDevice("device-001"), "first device's execution must be cancelled")
	assert.Empty(t, queue.PeekForDevice("device-002"))
}

func TestSynthesizeScriptRunForDevices_ResolveFailure_CreatesNothing(t *testing.T) {
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()
	meta := &scriptmodule.ScriptMetadata{Parameters: []scriptmodule.ScriptParameter{
		{Name: "os", Required: true, DNAPath: "os.name"},
	}}

	_, err := SynthesizeScriptRunForDevices(context.Background(), manager, queue, rollbackDevices(), "t", "u",
		fleet.Filter{}, "scripts/a.sh", "v1", scriptmodule.ShellBash, nil, meta, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device-002")

	runs, lerr := manager.store.ListRuns("t", 10, 0)
	require.NoError(t, lerr)
	assert.Empty(t, runs, "no run may be created")
	assert.Empty(t, queue.PeekForDevice("device-001"), "nothing may be queued for the first device")
	assert.Empty(t, queue.PeekForDevice("device-002"))
}

func TestSynthesizeScriptRunForDevices_EnqueueFailure_RollsBack(t *testing.T) {
	manager := newTestSynthesisManager(t)
	queue := newFailingQueue(2)

	_, err := SynthesizeScriptRunForDevices(context.Background(), manager, queue, rollbackDevices(), "t", "u",
		fleet.Filter{}, "scripts/a.sh", "v1", scriptmodule.ShellBash, nil, nil, nil, nil)
	assertRolledBack(t, manager, queue, err)
}

func TestSynthesizeCommandRunForDevices_EnqueueFailure_RollsBack(t *testing.T) {
	manager := newTestSynthesisManager(t)
	queue := newFailingQueue(2)

	_, err := SynthesizeCommandRunForDevices(context.Background(), manager, queue, rollbackDevices(), "t", "u",
		fleet.Filter{}, "echo hi", scriptmodule.ShellBash, nil, nil, nil, nil, "", time.Time{}, 0)
	assertRolledBack(t, manager, queue, err)
}

func TestSynthesizeActionRunForDevices_EnqueueFailure_RollsBack(t *testing.T) {
	manager := newTestSynthesisManager(t)
	queue := newFailingQueue(2)
	sig := &CommandSignature{Algorithm: "ed25519", Value: "v", PublicKey: "k"}

	_, err := SynthesizeActionRunForDevices(context.Background(), manager, queue, rollbackDevices(), "t", "u",
		fleet.Filter{}, scriptmodule.StewardActionSpec{Verb: "stop", TargetKind: "service", TargetName: "svc"},
		sig, nil, "nonce", time.Now().Add(time.Hour))
	assertRolledBack(t, manager, queue, err)
}

// TestSynthesizeCommandRunForDevices_SetsQueuedTimeout verifies the requested
// timeout reaches QueuedExecution.Timeout (Issue #5393).
func TestSynthesizeCommandRunForDevices_SetsQueuedTimeout(t *testing.T) {
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()
	devices := []fleet.StewardResult{{ID: "dev-t", TenantID: "t"}}

	_, err := SynthesizeCommandRunForDevices(context.Background(), manager, queue, devices, "t", "u", fleet.Filter{},
		"echo hi", scriptmodule.ShellBash, nil, nil, nil, nil, "", time.Time{}, 170*time.Second)
	require.NoError(t, err)

	queued := queue.PeekForDevice("dev-t")
	require.Len(t, queued, 1)
	assert.Equal(t, 170*time.Second, queued[0].Timeout)
}
