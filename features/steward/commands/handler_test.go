// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// ---------------------------------------------------------------------------
// In-memory CommandStore for tests (real implementation, no mocks)
// ---------------------------------------------------------------------------

// memCommandStore is a minimal in-memory CommandStore backed by maps.
// It is a real implementation — not a mock.
type memCommandStore struct {
	mu          sync.Mutex
	records     map[string]*interfaces.CommandRecord
	transitions map[string][]*interfaces.CommandTransition

	// updateErr, if non-nil, is returned by UpdateCommandStatus calls.
	// Used for error-path testing.
	updateErr error
}

func newMemCommandStore() *memCommandStore {
	return &memCommandStore{
		records:     make(map[string]*interfaces.CommandRecord),
		transitions: make(map[string][]*interfaces.CommandTransition),
	}
}

func (m *memCommandStore) CreateCommandRecord(_ context.Context, rec *interfaces.CommandRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec == nil {
		return fmt.Errorf("record is nil")
	}
	if rec.ID == "" {
		return interfaces.ErrCommandIDRequired
	}
	if rec.StewardID == "" {
		return interfaces.ErrCommandStewardIDRequired
	}
	if _, exists := m.records[rec.ID]; exists {
		return fmt.Errorf("duplicate command ID: %s", rec.ID)
	}
	cp := *rec
	cp.Status = interfaces.CommandStatusPending
	if cp.IssuedAt.IsZero() {
		cp.IssuedAt = time.Now()
	}
	m.records[rec.ID] = &cp
	m.transitions[rec.ID] = append(m.transitions[rec.ID], &interfaces.CommandTransition{
		CommandID: rec.ID,
		Status:    interfaces.CommandStatusPending,
		Timestamp: cp.IssuedAt,
	})
	return nil
}

func (m *memCommandStore) UpdateCommandStatus(_ context.Context, id string, status interfaces.CommandStatus, result map[string]interface{}, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	rec, ok := m.records[id]
	if !ok {
		return interfaces.ErrCommandNotFound
	}
	rec.Status = status
	rec.ErrorMessage = errMsg
	rec.Result = result
	now := time.Now()
	switch status {
	case interfaces.CommandStatusExecuting:
		rec.StartedAt = &now
	case interfaces.CommandStatusCompleted, interfaces.CommandStatusFailed, interfaces.CommandStatusCancelled:
		rec.CompletedAt = &now
	}
	m.transitions[id] = append(m.transitions[id], &interfaces.CommandTransition{
		CommandID:    id,
		Status:       status,
		Timestamp:    now,
		ErrorMessage: errMsg,
	})
	return nil
}

func (m *memCommandStore) GetCommandRecord(_ context.Context, id string) (*interfaces.CommandRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return nil, interfaces.ErrCommandNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *memCommandStore) ListCommandRecords(_ context.Context, filter *interfaces.CommandFilter) ([]*interfaces.CommandRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*interfaces.CommandRecord
	for _, rec := range m.records {
		if filter != nil {
			if filter.Status != "" && rec.Status != filter.Status {
				continue
			}
			if filter.StewardID != "" && rec.StewardID != filter.StewardID {
				continue
			}
		}
		cp := *rec
		out = append(out, &cp)
	}
	return out, nil
}

func (m *memCommandStore) ListCommandsByDevice(ctx context.Context, stewardID string) ([]*interfaces.CommandRecord, error) {
	return m.ListCommandRecords(ctx, &interfaces.CommandFilter{StewardID: stewardID})
}

func (m *memCommandStore) ListCommandsByStatus(ctx context.Context, status interfaces.CommandStatus) ([]*interfaces.CommandRecord, error) {
	return m.ListCommandRecords(ctx, &interfaces.CommandFilter{Status: status})
}

func (m *memCommandStore) GetCommandAuditTrail(_ context.Context, commandID string) ([]*interfaces.CommandTransition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	transitions := m.transitions[commandID]
	out := make([]*interfaces.CommandTransition, len(transitions))
	copy(out, transitions)
	return out, nil
}

func (m *memCommandStore) PurgeExpiredRecords(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *memCommandStore) HealthCheck(_ context.Context) error { return nil }
func (m *memCommandStore) Close() error                        { return nil }

// Compile-time assertion.
var _ interfaces.CommandStore = (*memCommandStore)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger("debug")
}

func noopStatus(_ context.Context, _ *cpTypes.Event) {}

func newTestHandler(t *testing.T, store interfaces.CommandStore) *Handler {
	t.Helper()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		Store:     store,
	})
	require.NoError(t, err)
	return h
}

func testCommand(id string, cmdType cpTypes.CommandType) *cpTypes.Command {
	return &cpTypes.Command{
		ID:        id,
		Type:      cmdType,
		StewardID: "steward-test",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNew_RequiresStewardID(t *testing.T) {
	_, err := New(&Config{
		OnStatus: noopStatus,
		Logger:   newTestLogger(t),
	})
	require.Error(t, err)
}

func TestNew_RequiresOnStatus(t *testing.T) {
	_, err := New(&Config{
		StewardID: "s1",
		Logger:    newTestLogger(t),
	})
	require.Error(t, err)
}

func TestNew_RequiresLogger(t *testing.T) {
	_, err := New(&Config{
		StewardID: "s1",
		OnStatus:  noopStatus,
	})
	require.Error(t, err)
}

func TestNew_NilStoreAllowed(t *testing.T) {
	h, err := New(&Config{
		StewardID: "s1",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		Store:     nil,
	})
	require.NoError(t, err)
	assert.NotNil(t, h)
}

// ---------------------------------------------------------------------------
// Startup sweep test
// ---------------------------------------------------------------------------

func TestNew_SweepsStaleExecutingCommands(t *testing.T) {
	store := newMemCommandStore()
	ctx := context.Background()

	// Pre-populate an executing record to simulate a crashed previous run.
	rec := &interfaces.CommandRecord{
		ID:        "stale-cmd",
		Type:      "sync_config",
		StewardID: "steward-test",
	}
	require.NoError(t, store.CreateCommandRecord(ctx, rec))
	require.NoError(t, store.UpdateCommandStatus(ctx, "stale-cmd",
		interfaces.CommandStatusExecuting, nil, ""))

	// Creating the handler should trigger the startup sweep.
	_, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  noopStatus,
		Logger:    newTestLogger(t),
		Store:     store,
	})
	require.NoError(t, err)

	got, err := store.GetCommandRecord(ctx, "stale-cmd")
	require.NoError(t, err)
	assert.Equal(t, interfaces.CommandStatusFailed, got.Status)
	assert.Equal(t, "controller_restart", got.ErrorMessage)
}

// ---------------------------------------------------------------------------
// HandleCommand / executeCommand tests
// Use h.Wait() for deterministic synchronization — no time.Sleep.
// ---------------------------------------------------------------------------

func TestHandleCommand_PersistsRecord(t *testing.T) {
	store := newMemCommandStore()
	h := newTestHandler(t, store)
	ctx := context.Background()

	cmd := testCommand("hc-001", cpTypes.CommandSyncConfig)

	// Register a no-op handler so execution succeeds.
	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait() // synchronise with the goroutine

	got, err := store.GetCommandRecord(ctx, "hc-001")
	require.NoError(t, err)
	assert.Equal(t, interfaces.CommandStatusCompleted, got.Status)
}

func TestHandleCommand_NoHandlerMarkedFailed(t *testing.T) {
	store := newMemCommandStore()
	h := newTestHandler(t, store)
	ctx := context.Background()

	cmd := testCommand("hc-002", cpTypes.CommandSyncConfig)
	// No handler registered — should fail.
	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait()

	got, err := store.GetCommandRecord(ctx, "hc-002")
	require.NoError(t, err)
	assert.Equal(t, interfaces.CommandStatusFailed, got.Status)
}

func TestHandleCommand_HandlerErrorMarkedFailed(t *testing.T) {
	store := newMemCommandStore()
	h := newTestHandler(t, store)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return fmt.Errorf("something went wrong")
	})

	cmd := testCommand("hc-003", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait()

	got, err := store.GetCommandRecord(ctx, "hc-003")
	require.NoError(t, err)
	assert.Equal(t, interfaces.CommandStatusFailed, got.Status)
	assert.Contains(t, got.ErrorMessage, "something went wrong")
}

// ---------------------------------------------------------------------------
// UpdateCommandStatus error-path tests
// Verifies the handler does not panic or swallow store errors silently.
// ---------------------------------------------------------------------------

func TestHandleCommand_StoreUpdateErrorOnExecuting_DoesNotPanic(t *testing.T) {
	store := newMemCommandStore()
	// Inject a store error — UpdateCommandStatus will fail after CreateCommandRecord succeeds.
	store.updateErr = fmt.Errorf("store unavailable")

	h := newTestHandler(t, store)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	cmd := testCommand("err-001", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait() // must not panic even when store returns errors
}

func TestHandleCommand_StoreUpdateErrorOnFailed_DoesNotPanic(t *testing.T) {
	store := newMemCommandStore()
	store.updateErr = fmt.Errorf("store unavailable")

	h := newTestHandler(t, store)
	ctx := context.Background()
	// No handler registered; will try to write "failed" to store.
	cmd := testCommand("err-002", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait()
}

func TestHandleCommand_StoreUpdateErrorOnCompleted_DoesNotPanic(t *testing.T) {
	store := newMemCommandStore()
	store.updateErr = fmt.Errorf("store unavailable")

	h := newTestHandler(t, store)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	cmd := testCommand("err-003", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait()
}

// ---------------------------------------------------------------------------
// executionContext retains only CancelFunc — behavioral verification
// ---------------------------------------------------------------------------

func TestExecutionContext_CancelFuncIsInvokable(t *testing.T) {
	// Verify that an executionContext's Cancel function can be invoked and cancels
	// a context derived from context.WithCancel. This tests the actual runtime
	// behaviour of the cancel mechanism, not struct field layout.
	ctx, cancel := context.WithCancel(context.Background())
	ec := &executionContext{Cancel: cancel}

	// The context should not be cancelled yet.
	select {
	case <-ctx.Done():
		t.Fatal("context should not be done before Cancel() is called")
	default:
	}

	ec.Cancel()

	// After Cancel(), the context must be done.
	select {
	case <-ctx.Done():
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context was not cancelled after executionContext.Cancel() was called")
	}
}

// ---------------------------------------------------------------------------
// CancelCommand / GetExecutingCommands
// ---------------------------------------------------------------------------

func TestCancelCommand_NotFound(t *testing.T) {
	h := newTestHandler(t, nil)
	err := h.CancelCommand("nonexistent")
	require.Error(t, err)
}

func TestGetExecutingCommands_Empty(t *testing.T) {
	h := newTestHandler(t, nil)
	cmds := h.GetExecutingCommands()
	assert.Empty(t, cmds)
}

func TestHandleCommand_NilStore_StillWorks(t *testing.T) {
	// When store is nil the handler must operate normally without panicking.
	h := newTestHandler(t, nil)
	ctx := context.Background()

	h.RegisterHandler(cpTypes.CommandSyncConfig, func(ctx context.Context, c *cpTypes.Command) error {
		return nil
	})

	cmd := testCommand("no-store-001", cpTypes.CommandSyncConfig)
	require.NoError(t, h.HandleCommand(ctx, cmd))
	h.Wait() // deterministic synchronization — no panic
}
