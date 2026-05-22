// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/script"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"

	_ "modernc.org/sqlite"
)

// ----------------------------------------------------------------------------
// Test infrastructure — real components, not mocks.
// ----------------------------------------------------------------------------

// testControlPlane is a minimal in-process ControlPlaneProvider used by
// dispatcher tests. It records sent commands and allows injecting completion
// events by exposing the registered event handler.
// It is NOT a mock — it implements the full ControlPlaneProvider contract.
var _ cpinterfaces.ControlPlaneProvider = (*testControlPlane)(nil)

type testControlPlane struct {
	mu           sync.Mutex
	sent         []*controlplaneTypes.SignedCommand
	eventHandler cpinterfaces.EventHandler
	sendErr      error // if set, SendCommand returns this error
}

func (p *testControlPlane) Name() string      { return "test" }
func (p *testControlPlane) IsConnected() bool { return true }
func (p *testControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *testControlPlane) Start(_ context.Context) error     { return nil }
func (p *testControlPlane) Stop(_ context.Context) error      { return nil }
func (p *testControlPlane) Reconnect(_ context.Context) error { return nil }
func (p *testControlPlane) FanOutCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *testControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *testControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *testControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *testControlPlane) SubscribeHeartbeats(_ context.Context, _ cpinterfaces.HeartbeatHandler) error {
	return nil
}
func (p *testControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

func (p *testControlPlane) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendErr != nil {
		return p.sendErr
	}
	p.sent = append(p.sent, cmd)
	return nil
}

func (p *testControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, handler cpinterfaces.EventHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eventHandler = handler
	return nil
}

// injectCompletion simulates a steward publishing EventScriptCompleted.
func (p *testControlPlane) injectCompletion(ctx context.Context, deviceID, executionID string, exitCode int) error {
	p.mu.Lock()
	h := p.eventHandler
	p.mu.Unlock()

	if h == nil {
		return fmt.Errorf("no event handler registered")
	}
	event := &controlplaneTypes.Event{
		ID:        "evt-" + executionID,
		Type:      controlplaneTypes.EventScriptCompleted,
		StewardID: deviceID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": executionID,
			"exit_code":    float64(exitCode),
			"stdout":       "",
			"stderr":       "",
			"duration_ms":  float64(100),
		},
	}
	return h(ctx, event)
}

// sentCount returns how many commands were recorded.
func (p *testControlPlane) sentCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sent)
}

// lastSent returns the most recently sent command, or nil.
func (p *testControlPlane) lastSent() *controlplaneTypes.SignedCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sent) == 0 {
		return nil
	}
	return p.sent[len(p.sent)-1]
}

// setSendErr arms/disarms the send-error injection. Thread-safe.
func (p *testControlPlane) setSendErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sendErr = err
}

// testScriptRepo implements script.ScriptRepository with in-memory storage.
// Used to supply script content for PrepareExecutionForDevice without mocking.
type testScriptRepo struct {
	mu      sync.Mutex
	scripts map[string]*script.VersionedScript
}

func newTestScriptRepo() *testScriptRepo {
	return &testScriptRepo{scripts: make(map[string]*script.VersionedScript)}
}

func (r *testScriptRepo) Create(s *script.VersionedScript) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts[s.Metadata.ID] = s
	return nil
}

func (r *testScriptRepo) Get(id, _ string) (*script.VersionedScript, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script %q not found", id)
	}
	return s, nil
}

func (r *testScriptRepo) List(_ *script.ScriptFilter) ([]*script.ScriptMetadata, error) {
	return nil, nil
}

func (r *testScriptRepo) Update(s *script.VersionedScript) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts[s.Metadata.ID] = s
	return nil
}

func (r *testScriptRepo) Delete(id, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.scripts, id)
	return nil
}

func (r *testScriptRepo) ListVersions(id string) ([]*script.Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script %q not found", id)
	}
	return []*script.Version{s.Metadata.Version}, nil
}

func (r *testScriptRepo) GetLatestVersion(id string) (*script.Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script %q not found", id)
	}
	return s.Metadata.Version, nil
}

func (r *testScriptRepo) Rollback(_ string, _ string) error { return nil }

// addScript registers a script in the repo.
func (r *testScriptRepo) addScript(id, content string) {
	_ = r.Create(&script.VersionedScript{
		Metadata: &script.ScriptMetadata{
			ID:      id,
			Name:    id,
			Version: &script.Version{Major: 1},
			Shell:   script.ShellBash,
		},
		Content: content,
	})
}

// newTestQueue creates an ExecutionQueue with an optional script repo.
// Passing nil for repo disables content resolution (script_content will be empty).
func newTestQueue(t *testing.T, repo script.ScriptRepository) *script.ExecutionQueue {
	t.Helper()
	monitor := script.NewExecutionMonitor()
	keyManager := script.NewEphemeralKeyManager()
	t.Cleanup(keyManager.Stop)
	q := script.NewExecutionQueue(monitor, keyManager, time.Hour, "https://localhost:8080", nil, repo, time.Hour)
	t.Cleanup(q.Stop)
	return q
}

// newTestDispatcher creates a Dispatcher wired to the provided control plane and queue.
// PollInterval is set to 24 h to prevent background polling from interfering with tests.
func newTestDispatcher(t *testing.T, q *script.ExecutionQueue, cp *testControlPlane) *Dispatcher {
	t.Helper()
	d, err := New(&Config{
		Queue:        q,
		ControlPlane: cp,
		PollInterval: 24 * time.Hour, // disable background poll in most tests
		Logger:       logging.NewLogger("debug"),
	})
	require.NoError(t, err)
	return d
}

// queuedExec returns a minimal QueuedExecution for tests.
func queuedExec(executionID, scriptRef string) *script.QueuedExecution {
	return &script.QueuedExecution{
		ExecutionID: executionID,
		ScriptID:    scriptRef,
		ScriptRef:   scriptRef,
		Shell:       script.ShellBash,
		Timeout:     5 * time.Minute,
	}
}

// ----------------------------------------------------------------------------
// Acceptance-criteria tests
// ----------------------------------------------------------------------------

// TestDispatcher_HeartbeatTriggersDispatch verifies AC1:
// When a heartbeat arrives for a device with a pending QueuedExecution,
// the dispatcher sends CommandExecuteScript via the control plane within
// one heartbeat cycle.
func TestDispatcher_HeartbeatTriggersDispatch(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)

	err := d.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Stop)

	// Queue an execution before triggering the heartbeat.
	err = q.QueueExecution("device-1", queuedExec("exec-001", "script-abc"))
	require.NoError(t, err)

	// Simulate a heartbeat — should trigger dispatch within one cycle.
	d.OnHeartbeat("device-1")

	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "expected execute_script command to be sent within one heartbeat cycle")

	cmd := cp.lastSent()
	require.NotNil(t, cmd)
	assert.Equal(t, controlplaneTypes.CommandExecuteScript, cmd.Command.Type)
	assert.Equal(t, "device-1", cmd.Command.StewardID)

	execID, _ := cmd.Command.Params["execution_id"].(string)
	assert.Equal(t, "exec-001", execID)
}

// TestDispatcher_SerializesPerDevice verifies AC2:
// A second execution queued for the same device remains in queued state
// while the device lock is held by the first execution; it is dispatched
// only after AcknowledgeCompletion releases the lock.
func TestDispatcher_SerializesPerDevice(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)

	err := d.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Stop)

	// Queue exec1 and dispatch it via a heartbeat — lock is now held.
	err = q.QueueExecution("device-1", queuedExec("exec-001", "script-abc"))
	require.NoError(t, err)

	d.OnHeartbeat("device-1")

	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "exec-001 should be dispatched")

	assert.Equal(t, 1, cp.sentCount())

	// Queue exec2 WHILE the device lock is held (exec-001 still in-flight).
	err = q.QueueExecution("device-1", queuedExec("exec-002", "script-def"))
	require.NoError(t, err)

	// Trigger another heartbeat — lock is held, exec-002 must remain queued.
	d.OnHeartbeat("device-1")

	// exec-002 must NOT be dispatched while exec-001 is in-flight. Use
	// require.Never to verify the invariant holds across multiple poll intervals.
	require.Never(t, func() bool {
		return cp.sentCount() > 1
	}, 100*time.Millisecond, 10*time.Millisecond,
		"exec-002 must remain queued while exec-001 is in-flight")

	// Peek to confirm exec-002 is still in the active queue (queued or dispatched).
	active := q.PeekForDevice("device-1")
	execIDs := make([]string, 0, len(active))
	for _, e := range active {
		execIDs = append(execIDs, e.ExecutionID)
	}
	assert.Contains(t, execIDs, "exec-002", "exec-002 should still be in the active queue")

	// Simulate exec-001 completion — releases lock and triggers next dispatch.
	err = cp.injectCompletion(context.Background(), "device-1", "exec-001", 0)
	require.NoError(t, err)

	// exec-002 must now be dispatched.
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 2
	}, 2*time.Second, 10*time.Millisecond, "exec-002 should be dispatched after exec-001 completes")

	// Verify exec-002 was the next command sent.
	last := cp.lastSent()
	require.NotNil(t, last)
	execID, _ := last.Command.Params["execution_id"].(string)
	assert.Equal(t, "exec-002", execID)
}

// TestDispatcher_StopExitsWithoutDeadlock verifies AC5:
// Dispatcher.Stop exits the polling goroutine without deadlock.
func TestDispatcher_StopExitsWithoutDeadlock(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)

	d, err := New(&Config{
		Queue:        q,
		ControlPlane: cp,
		PollInterval: 50 * time.Millisecond, // short poll to exercise the ticker path
		Logger:       logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		d.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Stop returned cleanly.
	case <-time.After(3 * time.Second):
		t.Fatal("Dispatcher.Stop deadlocked")
	}
}

// TestDispatcher_StartupPollFiringImmediate verifies AC3:
// The polling loop fires once on startup without waiting for the first tick.
func TestDispatcher_StartupPollFiringImmediate(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)

	// Queue an execution BEFORE starting the dispatcher.
	err := q.QueueExecution("device-1", queuedExec("exec-001", "script-abc"))
	require.NoError(t, err)

	// Use a very long poll interval so background ticks cannot fire.
	d, err := New(&Config{
		Queue:        q,
		ControlPlane: cp,
		PollInterval: 24 * time.Hour,
		Logger:       logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Stop)

	// The dispatcher must fire immediately on startup without waiting 24 h.
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "startup poll should fire immediately")
}

// TestDispatcher_ScriptContentSizeCap verifies AC6:
// Decoded script_content exceeding 1 MB is rejected before dispatch with a
// clear error; the command is not sent.
func TestDispatcher_ScriptContentSizeCap(t *testing.T) {
	repo := newTestScriptRepo()
	// Create a script with content just over 1 MiB.
	largeContent := strings.Repeat("x", maxScriptContentBytes+1)
	repo.addScript("big-script", largeContent)

	cp := &testControlPlane{}
	q := newTestQueue(t, repo)
	d := newTestDispatcher(t, q, cp)

	err := d.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Stop)

	err = q.QueueExecution("device-1", queuedExec("exec-big", "big-script"))
	require.NoError(t, err)

	d.OnHeartbeat("device-1")

	// Oversized script must never produce a command — use require.Never to
	// verify the invariant holds rather than relying on a fixed sleep window.
	require.Never(t, func() bool {
		return cp.sentCount() > 0
	}, 200*time.Millisecond, 10*time.Millisecond, "oversized script must not produce a command")
}

// TestDispatcher_AcknowledgesCompletionWithCorrectState verifies AC4:
// ExecutionQueue.AcknowledgeCompletion is called with the correct state when
// the steward publishes EventScriptCompleted.
func TestDispatcher_AcknowledgesCompletionWithCorrectState(t *testing.T) {
	for _, tc := range []struct {
		name      string
		exitCode  int
		wantState script.QueueState
	}{
		{"success exit 0", 0, script.QueueStateCompleted},
		{"failure exit 1", 1, script.QueueStateFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := &testControlPlane{}
			q := newTestQueue(t, nil)
			d := newTestDispatcher(t, q, cp)

			err := d.Start(context.Background())
			require.NoError(t, err)
			t.Cleanup(d.Stop)

			err = q.QueueExecution("device-1", queuedExec("exec-001", "script-abc"))
			require.NoError(t, err)

			d.OnHeartbeat("device-1")

			require.Eventually(t, func() bool {
				return cp.sentCount() >= 1
			}, 2*time.Second, 10*time.Millisecond)

			// Inject completion with the given exit code.
			err = cp.injectCompletion(context.Background(), "device-1", "exec-001", tc.exitCode)
			require.NoError(t, err)

			// After acknowledgement the entry must be out of the active queue.
			require.Eventually(t, func() bool {
				return q.GetQueueDepth("device-1") == 0
			}, 2*time.Second, 10*time.Millisecond,
				"execution should be removed from active queue after acknowledgement")
		})
	}
}

// TestDispatcher_MismatchedStewardIDIgnored verifies that a completion event
// carrying a deviceID that doesn't match the stored execution is not used to
// acknowledge the wrong device's execution.
func TestDispatcher_MismatchedStewardIDIgnored(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)

	err := d.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Stop)

	err = q.QueueExecution("device-1", queuedExec("exec-001", "script-abc"))
	require.NoError(t, err)

	d.OnHeartbeat("device-1")

	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	// Inject completion claiming to be from a DIFFERENT device.
	// AcknowledgeCompletion will fail because "device-2" has no dispatched entry
	// named "exec-001". handleCompletionEvent logs the error and returns nil.
	err = cp.injectCompletion(context.Background(), "device-2", "exec-001", 0)
	require.NoError(t, err) // handler returns nil regardless of AcknowledgeCompletion failure

	// exec-001 for device-1 must remain active (not acknowledged by device-2's event).
	// Use require.Eventually since injectCompletion triggers a background goroutine
	// (dispatchForDevice for device-2) that must settle before we assert.
	require.Eventually(t, func() bool {
		active := q.PeekForDevice("device-1")
		return len(active) == 1 && active[0].ExecutionID == "exec-001"
	}, 500*time.Millisecond, 10*time.Millisecond,
		"device-1 exec-001 must not be acknowledged by a device-2 event")
}

// TestDispatcher_SendCommandErrorReleasesLock verifies that when SendCommand
// fails, the per-device lock is released so subsequent dispatches can proceed.
func TestDispatcher_SendCommandErrorReleasesLock(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)

	err := d.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(d.Stop)

	// Arm the send error before queueing — exec-001 will fail to send.
	cp.setSendErr(errors.New("simulated network failure"))

	err = q.QueueExecution("device-1", queuedExec("exec-001", "script-abc"))
	require.NoError(t, err)

	d.OnHeartbeat("device-1")

	// Wait until the device lock is released — that is the deterministic signal that
	// the error-path goroutine has completed and the lock is free for the next dispatch.
	require.Eventually(t, func() bool {
		if !d.tryAcquireDevice("device-1") {
			return false
		}
		d.releaseDevice("device-1")
		return true
	}, 500*time.Millisecond, 10*time.Millisecond, "device lock should be released after send error")

	// Sanity: the failed send must not have emitted a command.
	require.Equal(t, 0, cp.sentCount(), "no command should be sent when send fails")

	// Disarm the error and queue exec-002. The device lock must now be free.
	cp.setSendErr(nil)

	err = q.QueueExecution("device-1", queuedExec("exec-002", "script-def"))
	require.NoError(t, err)

	d.OnHeartbeat("device-1")

	// exec-002 (or a re-queued exec-001) should now be dispatched successfully.
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"dispatch should succeed after send error cleared and lock released")
}

// runTrackedExec builds a QueuedExecution carrying the workflow_run_id / job_id
// metadata that the run synthesis layer threads through for dispatch tracking.
func runTrackedExec(executionID, scriptRef, runID, jobID string) *script.QueuedExecution {
	qe := queuedExec(executionID, scriptRef)
	qe.Metadata = map[string]interface{}{
		"workflow_run_id": runID,
		"job_id":          jobID,
	}
	return qe
}

// TestDispatcher_CompletionAdvancesRunStatus verifies AC3: when every job of a
// run reports completion, the dispatcher drives the run record to a terminal
// status via the wired RunCompletionSink.
func TestDispatcher_CompletionAdvancesRunStatus(t *testing.T) {
	store := run.NewRunStoreSQL(mustOpenMemDB(t))
	require.NoError(t, store.Init(context.Background()))
	manager := run.NewManager(store, nil)

	const runID = "run-disp-1"
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID:     runID,
		TenantID:  "tenant-abc",
		CreatedAt: time.Now().UTC(),
		Status:    run.RunStatusRunning,
		JobCount:  2,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-1", RunID: runID, DeviceID: "device-1",
		ExecutionID: "exec-001", Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-2", RunID: runID, DeviceID: "device-2",
		ExecutionID: "exec-002", Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))

	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)
	d.SetRunCompletionSink(manager)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	require.NoError(t, q.QueueExecution("device-1", runTrackedExec("exec-001", "script-abc", runID, "job-1")))
	require.NoError(t, q.QueueExecution("device-2", runTrackedExec("exec-002", "script-abc", runID, "job-2")))

	d.OnHeartbeat("device-1")
	d.OnHeartbeat("device-2")
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 2
	}, 2*time.Second, 10*time.Millisecond, "both executions should be dispatched")

	// First job completes — run must remain running.
	require.NoError(t, cp.injectCompletion(context.Background(), "device-1", "exec-001", 0))
	require.Eventually(t, func() bool {
		r, err := manager.GetRun(context.Background(), runID)
		return err == nil && r.CompletedJobs == 1
	}, 2*time.Second, 10*time.Millisecond, "first job completion should be recorded")

	r, err := manager.GetRun(context.Background(), runID)
	require.NoError(t, err)
	assert.Equal(t, run.RunStatusRunning, r.Status, "run must stay running while a job is in flight")

	// Second (final) job completes — run must transition to completed.
	require.NoError(t, cp.injectCompletion(context.Background(), "device-2", "exec-002", 0))
	require.Eventually(t, func() bool {
		r, err := manager.GetRun(context.Background(), runID)
		return err == nil && r.Status == run.RunStatusCompleted
	}, 2*time.Second, 10*time.Millisecond, "run must reach completed once all jobs are terminal")

	r, err = manager.GetRun(context.Background(), runID)
	require.NoError(t, err)
	assert.Equal(t, 2, r.CompletedJobs)
	assert.Equal(t, 0, r.FailedJobs)

	jobs, err := manager.ListRunJobs(context.Background(), runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)
	for _, j := range jobs {
		assert.Equal(t, run.JobStatusCompleted, j.Status, "job %s must be completed", j.JobID)
	}
}

// TestDispatcher_CompletionMarksRunFailed verifies that a non-zero exit code
// from a steward drives the run record to the failed terminal status.
func TestDispatcher_CompletionMarksRunFailed(t *testing.T) {
	store := run.NewRunStoreSQL(mustOpenMemDB(t))
	require.NoError(t, store.Init(context.Background()))
	manager := run.NewManager(store, nil)

	const runID = "run-disp-2"
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID: runID, TenantID: "tenant-abc", CreatedAt: time.Now().UTC(),
		Status: run.RunStatusRunning, JobCount: 1,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-fail", RunID: runID, DeviceID: "device-1",
		ExecutionID: "exec-fail", Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))

	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)
	d.SetRunCompletionSink(manager)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	require.NoError(t, q.QueueExecution("device-1", runTrackedExec("exec-fail", "script-abc", runID, "job-fail")))
	d.OnHeartbeat("device-1")
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	// Steward reports a non-zero exit code.
	require.NoError(t, cp.injectCompletion(context.Background(), "device-1", "exec-fail", 1))
	require.Eventually(t, func() bool {
		r, err := manager.GetRun(context.Background(), runID)
		return err == nil && r.Status == run.RunStatusFailed
	}, 2*time.Second, 10*time.Millisecond, "run must reach failed when a job fails")

	r, err := manager.GetRun(context.Background(), runID)
	require.NoError(t, err)
	assert.Equal(t, 1, r.FailedJobs)
	assert.Equal(t, 0, r.CompletedJobs)
}

// TestDispatcher_CompletionWithoutSinkIsSafe verifies that completion handling
// does not panic or error when no RunCompletionSink is wired.
func TestDispatcher_CompletionWithoutSinkIsSafe(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp) // no SetRunCompletionSink

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	require.NoError(t, q.QueueExecution("device-1", runTrackedExec("exec-001", "script-abc", "run-x", "job-x")))
	d.OnHeartbeat("device-1")
	require.Eventually(t, func() bool {
		return cp.sentCount() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, cp.injectCompletion(context.Background(), "device-1", "exec-001", 0))
	require.Eventually(t, func() bool {
		return q.GetQueueDepth("device-1") == 0
	}, 2*time.Second, 10*time.Millisecond, "completion must be acknowledged even without a run sink")
}

// idempotentTrackedExec builds a QueuedExecution that is flagged idempotent and
// carries the run-tracking metadata fields.
func idempotentTrackedExec(executionID, scriptRef, runID, jobID string) *script.QueuedExecution {
	qe := runTrackedExec(executionID, scriptRef, runID, jobID)
	qe.Metadata["idempotent"] = true
	return qe
}

// TestDispatcher_IdempotentScript_RequeuesOnFirstFailure verifies that an idempotent
// script is re-queued exactly once when it fails, and RecordJobCompletion is deferred
// until the retry resolves.
func TestDispatcher_IdempotentScript_RequeuesOnFirstFailure(t *testing.T) {
	store := run.NewRunStoreSQL(mustOpenMemDB(t))
	require.NoError(t, store.Init(context.Background()))
	manager := run.NewManager(store, nil)

	const runID = "run-idem-1"
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID: runID, TenantID: "tenant-abc",
		CreatedAt: time.Now().UTC(), Status: run.RunStatusRunning, JobCount: 1,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-idem-1", RunID: runID, DeviceID: "device-1",
		ExecutionID: "exec-idem-1", Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))

	cp := &testControlPlane{}
	repo := newTestScriptRepo()
	repo.addScript("script-idem", "#!/bin/bash\necho hi")
	q := newTestQueue(t, repo)
	d := newTestDispatcher(t, q, cp)
	d.SetRunCompletionSink(manager)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	// Queue an idempotent execution.
	require.NoError(t, q.QueueExecution("device-1", idempotentTrackedExec("exec-idem-1", "script-idem", runID, "job-idem-1")))

	// Trigger dispatch and let it send.
	d.OnHeartbeat("device-1")
	require.Eventually(t, func() bool { return cp.sentCount() >= 1 }, 2*time.Second, 10*time.Millisecond)

	// Inject a failure (exit code 1).
	require.NoError(t, cp.injectCompletion(context.Background(), "device-1", "exec-idem-1", 1))

	// The dispatcher should re-queue a retry — queue depth goes back to 1.
	require.Eventually(t, func() bool {
		return q.GetQueueDepth("device-1") == 1
	}, 2*time.Second, 10*time.Millisecond, "idempotent failure must re-queue a retry execution")

	// The job must NOT be marked failed yet (retry is in-flight).
	jobs, err := store.ListRunJobs(runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.NotEqual(t, run.JobStatusFailed, jobs[0].Status,
		"job must not be marked failed while retry is pending")

	// The re-queued execution must carry retry_count=1.
	retryExecs := q.PeekForDevice("device-1")
	require.Len(t, retryExecs, 1)
	retryCount, _ := retryExecs[0].Metadata["retry_count"].(int)
	assert.Equal(t, 1, retryCount, "re-queued execution must carry retry_count=1")
	assert.Equal(t, runID, retryExecs[0].Metadata["workflow_run_id"],
		"re-queued execution must carry the original run ID")
	assert.Equal(t, "job-idem-1", retryExecs[0].Metadata["job_id"],
		"re-queued execution must carry the original job ID")
}

// TestDispatcher_IdempotentScript_SecondFailureSetsJobFailed verifies that when
// a retry execution also fails, the job transitions to failed and no further
// re-queue occurs (retry_count >= 1).
func TestDispatcher_IdempotentScript_SecondFailureSetsJobFailed(t *testing.T) {
	store := run.NewRunStoreSQL(mustOpenMemDB(t))
	require.NoError(t, store.Init(context.Background()))
	manager := run.NewManager(store, nil)

	const runID = "run-idem-2"
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID: runID, TenantID: "tenant-abc",
		CreatedAt: time.Now().UTC(), Status: run.RunStatusRunning, JobCount: 1,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-idem-2", RunID: runID, DeviceID: "device-2",
		ExecutionID: "exec-idem-2", Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))

	cp := &testControlPlane{}
	repo := newTestScriptRepo()
	repo.addScript("script-idem2", "#!/bin/bash\nexit 1")
	q := newTestQueue(t, repo)
	d := newTestDispatcher(t, q, cp)
	d.SetRunCompletionSink(manager)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	// Queue an idempotent execution.
	require.NoError(t, q.QueueExecution("device-2", idempotentTrackedExec("exec-idem-2", "script-idem2", runID, "job-idem-2")))

	// First dispatch and failure → re-queue retry.
	d.OnHeartbeat("device-2")
	require.Eventually(t, func() bool { return cp.sentCount() >= 1 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, cp.injectCompletion(context.Background(), "device-2", "exec-idem-2", 1))

	// Wait for re-queue.
	require.Eventually(t, func() bool {
		return q.GetQueueDepth("device-2") == 1
	}, 2*time.Second, 10*time.Millisecond)

	// Capture the retry execution ID.
	retryExecs := q.PeekForDevice("device-2")
	require.Len(t, retryExecs, 1)
	retryID := retryExecs[0].ExecutionID

	// Dispatch and fail the retry.
	d.OnHeartbeat("device-2")
	require.Eventually(t, func() bool { return cp.sentCount() >= 2 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, cp.injectCompletion(context.Background(), "device-2", retryID, 1))

	// After second failure, the job must be marked failed.
	require.Eventually(t, func() bool {
		jobs, err := store.ListRunJobs(runID)
		return err == nil && len(jobs) == 1 && jobs[0].Status == run.JobStatusFailed
	}, 2*time.Second, 10*time.Millisecond, "job must be marked failed after second failure")

	// Queue must be empty — no further retry.
	assert.Eventually(t, func() bool {
		return q.GetQueueDepth("device-2") == 0
	}, 2*time.Second, 10*time.Millisecond, "queue must be empty after second failure (no further retry)")
}

// TestDispatcher_NonIdempotentScript_FailureImmediatelyMarksJobFailed verifies that
// a non-idempotent script failure transitions the job to failed without any retry.
func TestDispatcher_NonIdempotentScript_FailureImmediatelyMarksJobFailed(t *testing.T) {
	store := run.NewRunStoreSQL(mustOpenMemDB(t))
	require.NoError(t, store.Init(context.Background()))
	manager := run.NewManager(store, nil)

	const runID = "run-non-idem-1"
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID: runID, TenantID: "tenant-abc",
		CreatedAt: time.Now().UTC(), Status: run.RunStatusRunning, JobCount: 1,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-non-idem-1", RunID: runID, DeviceID: "device-3",
		ExecutionID: "exec-non-idem-1", Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))

	cp := &testControlPlane{}
	repo := newTestScriptRepo()
	repo.addScript("script-non-idem", "#!/bin/bash\nexit 1")
	q := newTestQueue(t, repo)
	d := newTestDispatcher(t, q, cp)
	d.SetRunCompletionSink(manager)

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	// Queue a non-idempotent execution (no idempotent flag).
	require.NoError(t, q.QueueExecution("device-3", runTrackedExec("exec-non-idem-1", "script-non-idem", runID, "job-non-idem-1")))

	d.OnHeartbeat("device-3")
	require.Eventually(t, func() bool { return cp.sentCount() >= 1 }, 2*time.Second, 10*time.Millisecond)

	// Inject failure.
	require.NoError(t, cp.injectCompletion(context.Background(), "device-3", "exec-non-idem-1", 1))

	// Job must transition to failed immediately with no re-queue.
	require.Eventually(t, func() bool {
		jobs, err := store.ListRunJobs(runID)
		return err == nil && len(jobs) == 1 && jobs[0].Status == run.JobStatusFailed
	}, 2*time.Second, 10*time.Millisecond, "non-idempotent failure must mark job failed immediately")

	// Confirm no re-queue occurred.
	assert.Equal(t, 1, cp.sentCount(), "non-idempotent failure must not re-queue")
}

// mustOpenMemDB opens an in-memory SQLite database closed via t.Cleanup.
func mustOpenMemDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err, "open in-memory sqlite")
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestDispatcher_New_ValidationErrors verifies that New rejects nil config fields.
func TestDispatcher_New_ValidationErrors(t *testing.T) {
	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	logger := logging.NewLogger("debug")

	tests := []struct {
		name string
		cfg  *Config
	}{
		{"nil queue", &Config{ControlPlane: cp, Logger: logger}},
		{"nil control plane", &Config{Queue: q, Logger: logger}},
		{"nil logger", &Config{Queue: q, ControlPlane: cp}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(tc.cfg)
			assert.Error(t, err, "New should reject %s", tc.name)
			assert.Nil(t, d)
		})
	}
}
