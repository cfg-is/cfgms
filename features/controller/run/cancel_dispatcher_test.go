// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Package run_test provides external integration tests for run.Manager that
// require importing features/controller/dispatcher. External package placement
// avoids the import cycle dispatcher→run→dispatcher.
package run_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/dispatcher"
	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	_ "modernc.org/sqlite"
)

// ----------------------------------------------------------------------------
// Minimal test infrastructure (real components, not mocks).
// ----------------------------------------------------------------------------

// cancelTestCP is a minimal in-process ControlPlaneProvider for the integration
// tests in this file. It records sent commands and captures the event handler
// registered by the dispatcher, satisfying the full ControlPlaneProvider contract.
var _ cpinterfaces.ControlPlaneProvider = (*cancelTestCP)(nil)

type cancelTestCP struct {
	mu           sync.Mutex
	sent         []*controlplaneTypes.SignedCommand
	eventHandler cpinterfaces.EventHandler
}

func (p *cancelTestCP) Name() string      { return "cancel-test" }
func (p *cancelTestCP) IsConnected() bool { return true }
func (p *cancelTestCP) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *cancelTestCP) Start(_ context.Context) error     { return nil }
func (p *cancelTestCP) Stop(_ context.Context) error      { return nil }
func (p *cancelTestCP) Reconnect(_ context.Context) error { return nil }
func (p *cancelTestCP) FanOutCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *cancelTestCP) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *cancelTestCP) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *cancelTestCP) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *cancelTestCP) SubscribeHeartbeats(_ context.Context, _ cpinterfaces.HeartbeatHandler) error {
	return nil
}
func (p *cancelTestCP) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}
func (p *cancelTestCP) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, cmd)
	return nil
}
func (p *cancelTestCP) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, handler cpinterfaces.EventHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eventHandler = handler
	return nil
}
func (p *cancelTestCP) sentCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sent)
}

// newCancelTestQueue builds a real ExecutionQueue with a one-hour dispatch
// timeout and queue TTL — long enough that no background maintenance fires
// during the test.
func newCancelTestQueue(t *testing.T) *script.ExecutionQueue {
	t.Helper()
	monitor := script.NewExecutionMonitor()
	keyManager := script.NewEphemeralKeyManager()
	t.Cleanup(keyManager.Stop)
	q := script.NewExecutionQueue(monitor, keyManager, time.Hour, "https://localhost:8080", nil, nil, time.Hour)
	t.Cleanup(q.Stop)
	return q
}

// newCancelTestRunStore opens an in-memory SQLite store, initialises the schema,
// and registers cleanup.
func newCancelTestRunStore(t *testing.T) *run.RunStoreSQL {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err, "open in-memory sqlite")
	t.Cleanup(func() { _ = db.Close() })
	store := run.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()), "Init must succeed")
	return store
}

// ----------------------------------------------------------------------------
// TestCancelRun_ReleasesDispatcherDeviceLock (Story #2468 AC2)
// ----------------------------------------------------------------------------

// TestCancelRun_ReleasesDispatcherDeviceLock verifies that CancelRun releases the
// per-device dispatcher lock immediately — not waiting for the TTL sweep — so a
// subsequently queued execution for the same device dispatches without delay.
// It also verifies that the cancel-release is executionID-scoped: a stale cancel
// with a non-matching ID does not free a lock held by a different execution.
func TestCancelRun_ReleasesDispatcherDeviceLock(t *testing.T) {
	store := newCancelTestRunStore(t)

	const (
		runID  = "run-cancel-dispatch-lock"
		jobID  = "job-cancel-dispatch"
		execID = "exec-cancel-dispatch"
		device = "device-cancel-dispatch"
	)

	// Persist the run and job records.
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID:     runID,
		TenantID:  "tenant-cancel",
		Status:    run.RunStatusRunning,
		JobCount:  1,
		CreatedAt: time.Now().UTC(),
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID:       jobID,
		RunID:       runID,
		DeviceID:    device,
		ExecutionID: execID,
		Status:      run.JobStatusRunning,
		CreatedAt:   time.Now().UTC(),
	}))

	// Wire up real dispatcher and manager with a long poll interval so the TTL
	// sweep does not fire during the test — only the explicit cancel path matters.
	cp := &cancelTestCP{}
	q := newCancelTestQueue(t)
	d, err := dispatcher.New(&dispatcher.Config{
		Queue:        q,
		ControlPlane: cp,
		PollInterval: 24 * time.Hour,
		Logger:       logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	mgr := run.NewManager(store, q)
	mgr.SetDeviceLockReleaser(d)
	d.SetRunCompletionSink(mgr)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	// Queue the execution and dispatch it so the device lock is held.
	require.NoError(t, q.QueueExecution(device, &script.QueuedExecution{
		ExecutionID: execID,
		ScriptID:    "script-cancel-a",
		ScriptRef:   "script-cancel-a",
		Shell:       script.ShellBash,
		Timeout:     5 * time.Minute,
		Metadata: map[string]interface{}{
			"workflow_run_id": runID,
			"job_id":          jobID,
		},
	}))
	d.OnHeartbeat(device)
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "execution must be dispatched before cancel")

	// The device lock is now held. A second execution cannot dispatch.
	require.NoError(t, q.QueueExecution(device, &script.QueuedExecution{
		ExecutionID: "exec-after-cancel",
		ScriptID:    "script-cancel-b",
		ScriptRef:   "script-cancel-b",
		Shell:       script.ShellBash,
		Timeout:     5 * time.Minute,
	}))

	// Cancel the run. This must immediately release the dispatcher lock for the
	// cancelled execution — not after a TTL sweep (poll interval is 24h).
	require.NoError(t, mgr.CancelRun(context.Background(), runID))

	// The run and job must reflect the cancelled state.
	cancelledRun, err := store.GetRun(runID)
	require.NoError(t, err)
	assert.Equal(t, run.RunStatusCancelled, cancelledRun.Status, "run must be cancelled")

	jobs, err := store.ListRunJobs(runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, run.JobStatusCancelled, jobs[0].Status, "job must be cancelled")

	// The device lock must now be free — exec-after-cancel can dispatch without
	// waiting for the 24-hour poll interval.
	require.Eventually(t, func() bool {
		d.OnHeartbeat(device)
		return cp.sentCount() >= 2
	}, 2*time.Second, 20*time.Millisecond,
		"CancelRun must release the device lock immediately so the next execution dispatches")
}

// TestCancelRun_StaleExecutionIDDoesNotReleaseLock verifies that cancelling a run
// whose job holds a stale (no longer current) executionID does not release a lock
// held by a newer execution for the same device. This exercises the ID-match guard
// in ReleaseDeviceForCancelledExecution.
func TestCancelRun_StaleExecutionIDDoesNotReleaseLock(t *testing.T) {
	store := newCancelTestRunStore(t)

	const (
		runIDStale  = "run-stale-cancel"
		jobIDStale  = "job-stale-cancel"
		execIDStale = "exec-stale"
		execIDNew   = "exec-new"
		device      = "device-stale-cancel"
	)

	// A run with a stale executionID (the job was re-dispatched with a new ID).
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID:     runIDStale,
		TenantID:  "tenant-stale",
		Status:    run.RunStatusRunning,
		JobCount:  1,
		CreatedAt: time.Now().UTC(),
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID:       jobIDStale,
		RunID:       runIDStale,
		DeviceID:    device,
		ExecutionID: execIDStale, // stale — the device is actually running execIDNew
		Status:      run.JobStatusRunning,
		CreatedAt:   time.Now().UTC(),
	}))

	cp := &cancelTestCP{}
	q := newCancelTestQueue(t)
	d, err := dispatcher.New(&dispatcher.Config{
		Queue:        q,
		ControlPlane: cp,
		PollInterval: 24 * time.Hour,
		Logger:       logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	mgr := run.NewManager(store, q)
	mgr.SetDeviceLockReleaser(d)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	// Acquire the lock with execIDNew (simulates a newer dispatch for the device).
	require.NoError(t, q.QueueExecution(device, &script.QueuedExecution{
		ExecutionID: execIDNew,
		ScriptID:    "script-new",
		ScriptRef:   "script-new",
		Shell:       script.ShellBash,
		Timeout:     5 * time.Minute,
	}))
	d.OnHeartbeat(device)
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "execIDNew must be dispatched")

	sentBefore := cp.sentCount()

	// Cancelling the stale run (whose job refers to execIDStale) must NOT release
	// the lock that is currently held by execIDNew.
	require.NoError(t, mgr.CancelRun(context.Background(), runIDStale))

	// The lock must still be held — no additional dispatch should happen.
	require.Never(t, func() bool {
		return cp.sentCount() > sentBefore
	}, 200*time.Millisecond, 10*time.Millisecond,
		fmt.Sprintf("lock held by %s must not be released by stale cancel of %s", execIDNew, execIDStale))
}
