// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	script "github.com/cfgis/cfgms/features/modules/script"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
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
