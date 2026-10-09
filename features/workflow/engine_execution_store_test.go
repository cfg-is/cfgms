// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

const executionTestTenant = "tenant-exec"

// openSQLiteExecutionStore opens the registered sqlite provider's execution store
// over path. A second call over the same path is a new handle over the same file,
// which is what another controller node (or a restart) sees.
func openSQLiteExecutionStore(t *testing.T, path string) business.WorkflowExecutionStore {
	t.Helper()
	provider, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := provider.CreateWorkflowExecutionStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	if closer, ok := store.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	return store
}

func newExecutionStoreEngine(t *testing.T, store business.WorkflowExecutionStore, opts ...EngineOption) *Engine {
	t.Helper()
	all := append([]EngineOption{WithExecutionStore(store)}, opts...)
	e := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil, all...)
	t.Cleanup(e.Shutdown)
	return e
}

func execStoreCtx(tenant string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, tenant)
}

// twoStepWorkflow completes with two recorded step results.
func twoStepWorkflow(name string) Workflow {
	return Workflow{
		Name: name,
		Steps: []Step{
			{Name: "first", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}},
			{Name: "second", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}},
		},
	}
}

func runToCompletion(t *testing.T, e *Engine, ctx context.Context, wf Workflow) *WorkflowExecution {
	t.Helper()
	exec, err := e.ExecuteWorkflow(ctx, wf, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 5*time.Second)
	return exec
}

func TestExecutionReadableFromSecondEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	engineA := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))
	engineB := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))

	exec := runToCompletion(t, engineA, execStoreCtx(executionTestTenant), twoStepWorkflow("shared-wf"))
	require.Equal(t, StatusCompleted, exec.GetStatus())

	onA, err := engineA.GetExecution(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err)
	onB, err := engineB.GetExecution(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err, "a node that never ran the workflow must still answer")

	assert.Equal(t, StatusCompleted, onB.GetStatus())
	assert.Equal(t, "shared-wf", onB.WorkflowName)
	assert.Equal(t, executionTestTenant, onB.TenantID)
	require.NotNil(t, onB.GetEndTime())
	assert.Len(t, onB.GetStepResults(), 2)
	for key, want := range onA.GetStepResults() {
		got, ok := onB.GetStepResults()[key]
		require.True(t, ok, "step %s missing on the second node", key)
		assert.Equal(t, want.Status, got.Status)
	}

	list, err := engineB.ListExecutions(context.Background(), executionTestTenant)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, exec.ID, list[0].ID)
}

func TestExecutionSurvivesEngineRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	first := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))
	exec := runToCompletion(t, first, execStoreCtx(executionTestTenant), twoStepWorkflow("restart-wf"))
	first.Shutdown()

	restarted := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))
	got, err := restarted.GetExecution(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, got.GetStatus())
	assert.Len(t, got.GetStepResults(), 2)
}

func TestExecutionStoreIsTenantScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	engineA := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))
	engineB := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))
	exec := runToCompletion(t, engineA, execStoreCtx(executionTestTenant), twoStepWorkflow("scoped-wf"))

	for name, e := range map[string]*Engine{"owner": engineA, "other node": engineB} {
		_, err := e.GetExecution(context.Background(), "tenant-other", exec.ID)
		assert.True(t, errors.Is(err, ErrExecutionNotFound), "%s must not read another tenant's run: %v", name, err)
		list, err := e.ListExecutions(context.Background(), "tenant-other")
		require.NoError(t, err)
		assert.Empty(t, list, name)
	}
}

func TestExecutionStoreRecordsRejectedInputsRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	engineA := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))
	engineB := newExecutionStoreEngine(t, openSQLiteExecutionStore(t, path))

	wf := twoStepWorkflow("inputs-wf")
	wf.Inputs = []InputSpec{{Name: "required_in", Type: "string", Required: true}}
	exec, err := engineA.ExecuteWorkflow(execStoreCtx(executionTestTenant), wf, nil)
	require.Error(t, err)
	require.NotNil(t, exec)

	got, err := engineB.GetExecution(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, got.GetStatus())
	assert.NotEmpty(t, got.GetError())
}

// TestExecutionStoreDoesNotPersistVariables proves resolved run variables, which may
// carry secrets, never reach the store — not in the payload and not through the
// variable state a failure attaches.
func TestExecutionStoreDoesNotPersistVariables(t *testing.T) {
	store := openSQLiteExecutionStore(t, filepath.Join(t.TempDir(), "cfgms.db"))
	e := newExecutionStoreEngine(t, store)

	wf := Workflow{
		Name:      "secret-vars-wf",
		Variables: map[string]interface{}{"api_token": "sentinel-secret-value"},
		Steps:     []Step{{Name: "boom", Type: StepTypeTask, Module: "no-such-module"}},
	}
	exec := runToCompletion(t, e, execStoreCtx(executionTestTenant), wf)
	require.Equal(t, StatusFailed, exec.GetStatus())

	rec, err := store.Get(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err)
	assert.NotContains(t, string(rec.Payload), "sentinel-secret-value")
	assert.Equal(t, "failed", rec.Status)
	assert.True(t, json.Valid(rec.Payload))
}

func TestExecutionRetentionBoundsTerminalRecords(t *testing.T) {
	store := openSQLiteExecutionStore(t, filepath.Join(t.TempDir(), "cfgms.db"))
	e := newExecutionStoreEngine(t, store, WithExecutionRetention(2))

	var last *WorkflowExecution
	for i := 0; i < 4; i++ {
		last = runToCompletion(t, e, execStoreCtx(executionTestTenant), twoStepWorkflow("retained-wf"))
		time.Sleep(2 * time.Millisecond) // distinct start times
	}
	recs, err := store.List(context.Background(), executionTestTenant, "", 0)
	require.NoError(t, err)
	assert.Len(t, recs, 2, "only the newest two terminal executions are retained")
	assert.Equal(t, last.ID, recs[0].ExecutionID)
}

func TestExecutionRetentionDefault(t *testing.T) {
	assert.Equal(t, 1000, DefaultExecutionRetention)
	e := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	t.Cleanup(e.Shutdown)
	assert.Equal(t, DefaultExecutionRetention, e.executionRetention)
	WithExecutionRetention(5)(e)
	assert.Equal(t, 5, e.executionRetention)
	WithExecutionRetention(0)(e)
	assert.Equal(t, 5, e.executionRetention, "a non-positive limit is ignored")
}

// failingExecutionStore always fails, to prove a store outage never fails a run.
type failingExecutionStore struct{ saves int }

func (f *failingExecutionStore) Save(context.Context, *business.WorkflowExecutionRecord) error {
	f.saves++
	return errors.New("store unavailable\ninjected")
}
func (f *failingExecutionStore) Get(context.Context, string, string) (*business.WorkflowExecutionRecord, error) {
	return nil, errors.New("store unavailable")
}
func (f *failingExecutionStore) List(context.Context, string, string, int) ([]*business.WorkflowExecutionRecord, error) {
	return nil, errors.New("store unavailable")
}
func (f *failingExecutionStore) Prune(context.Context, string, int) (int, error) {
	return 0, errors.New("store unavailable")
}

func TestExecutionStoreWriteFailureNeverFailsRun(t *testing.T) {
	failing := &failingExecutionStore{}
	e := newExecutionStoreEngine(t, failing)

	exec := runToCompletion(t, e, execStoreCtx(executionTestTenant), twoStepWorkflow("failing-store-wf"))
	assert.Equal(t, StatusCompleted, exec.GetStatus())
	assert.Greater(t, failing.saves, 0, "the engine must have attempted to persist")

	// The live in-memory state still answers while the store is down.
	got, err := e.GetExecution(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, got.GetStatus())

	// An id the node does not own surfaces the store failure, not "not found".
	_, err = e.GetExecution(context.Background(), executionTestTenant, "unknown")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrExecutionNotFound))
}

func TestGetExecutionWithoutStoreIsNodeLocal(t *testing.T) {
	e := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	t.Cleanup(e.Shutdown)
	exec := runToCompletion(t, e, execStoreCtx(executionTestTenant), twoStepWorkflow("local-wf"))

	_, err := e.GetExecution(context.Background(), executionTestTenant, exec.ID)
	require.NoError(t, err)
	_, err = e.GetExecution(context.Background(), "tenant-other", exec.ID)
	assert.True(t, errors.Is(err, ErrExecutionNotFound))
	_, err = e.GetExecution(context.Background(), executionTestTenant, "missing")
	assert.True(t, errors.Is(err, ErrExecutionNotFound))
}

func TestCancelExecutionOfUnownedRecordIsNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	store := openSQLiteExecutionStore(t, path)
	require.NoError(t, store.Save(context.Background(), &business.WorkflowExecutionRecord{
		TenantID: executionTestTenant, ExecutionID: "exec-elsewhere", WorkflowName: "wf",
		Status: "running", StartTime: time.Now().UTC(), Payload: []byte(`{}`),
	}))
	e := newExecutionStoreEngine(t, store)

	got, err := e.GetExecution(context.Background(), executionTestTenant, "exec-elsewhere")
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, got.GetStatus())
	assert.True(t, errors.Is(e.CancelExecution("exec-elsewhere"), ErrExecutionNotFound))
}
