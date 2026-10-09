// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const approvalTestTenant = "tenant-a"

// approvalHarness is a real flatfile approval store and a real encrypted secret
// store shared by every engine a test starts, as controller nodes share theirs.
type approvalHarness struct {
	t         *testing.T
	storeRoot string
	store     business.ApprovalStore
	secrets   secretsif.SecretStore
}

func newApprovalHarness(t *testing.T) *approvalHarness {
	t.Helper()
	storeRoot := t.TempDir()
	store := openFlatfileApprovalStore(t, storeRoot)
	secrets, err := (&steward.StewardProvider{}).CreateSecretStore(map[string]interface{}{
		"secrets_dir": t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = secrets.Close() })
	return &approvalHarness{t: t, storeRoot: storeRoot, store: store, secrets: secrets}
}

// openFlatfileApprovalStore opens the registered flatfile provider's approval
// store over root. A second call over the same root is a new handle over the
// same files, which is what a controller restart sees.
func openFlatfileApprovalStore(t *testing.T, root string) business.ApprovalStore {
	t.Helper()
	provider, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	store, err := provider.CreateApprovalStore(map[string]interface{}{"root": root})
	require.NoError(t, err)
	return store
}

// engine starts a new engine over the shared stores and shuts it down at test end.
func (h *approvalHarness) engine(opts ...EngineOption) *Engine {
	h.t.Helper()
	all := append([]EngineOption{WithApprovalStore(h.store)}, opts...)
	e := NewEngine(createTestFactory(), logging.NewNoopLogger(), h.secrets, nil, nil, nil, nil, all...)
	h.t.Cleanup(e.Shutdown)
	return e
}

func tenantCtx() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, approvalTestTenant)
}

func delayStep(name string, d time.Duration) Step {
	return Step{Name: name, Type: StepTypeDelay, Delay: &DelayConfig{Duration: d}}
}

func gateStep(name string, timeout time.Duration) Step {
	return Step{Name: name, Type: StepTypeApproval, Approval: &ApprovalConfig{
		Message: "ship it?", ApproverPermission: "workflow:approve", Timeout: timeout,
	}}
}

func gatedWorkflow(tail time.Duration) Workflow {
	return Workflow{
		Name: "gated",
		Steps: []Step{
			delayStep("before", time.Millisecond),
			gateStep("gate", time.Hour),
			delayStep("after", tail),
		},
	}
}

// runToGate runs wf until it suspends and returns the execution and its approval.
func (h *approvalHarness) runToGate(e *Engine, wf Workflow, vars map[string]interface{}) (*WorkflowExecution, *business.WorkflowApproval) {
	h.t.Helper()
	exec, err := e.ExecuteWorkflow(tenantCtx(), wf, vars)
	require.NoError(h.t, err)
	waitForWorkflowCompletion(h.t, exec, 5*time.Second)
	require.Equal(h.t, StatusAwaitingApproval, exec.GetStatus(), "error: %s", exec.GetError())
	pending, err := h.store.ListPending(context.Background(), approvalTestTenant)
	require.NoError(h.t, err)
	for _, p := range pending {
		if p.ExecutionID == exec.ID {
			return exec, p
		}
	}
	h.t.Fatalf("no pending approval for execution %s", exec.ID)
	return nil, nil
}

func (h *approvalHarness) decide(rec *business.WorkflowApproval, status string) {
	h.t.Helper()
	require.NoError(h.t, h.store.DecideApproval(context.Background(), rec.TenantID, rec.ApprovalID, status, "alice", "because", time.Now()))
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 10*time.Second, 10*time.Millisecond, what)
}

func execStatus(e *Engine, id string) ExecutionStatus {
	ex, err := e.GetExecution(context.Background(), approvalTestTenant, id)
	if err != nil {
		return ""
	}
	return ex.Status
}

func TestApproval_GateSuspendsRunWithPendingRecord(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()

	exec, rec := h.runToGate(e, gatedWorkflow(time.Millisecond), nil)

	// No goroutine is held: the run's Done channel is already closed.
	select {
	case <-exec.Done:
	default:
		t.Fatal("run still holds its goroutine at the gate")
	}
	assert.Nil(t, exec.GetEndTime(), "a waiting run has not ended")
	assert.Equal(t, business.ApprovalStatusPending, rec.Status)
	assert.Equal(t, "ship it?", rec.Message)
	assert.Equal(t, "workflow:approve", rec.ApproverPermission)
	assert.Equal(t, "gated", rec.WorkflowName)
	assert.Equal(t, "s1", rec.StepID)
	assert.False(t, rec.ExpiresAt.IsZero())
	assert.NotEmpty(t, rec.CheckpointRef)
	assert.Equal(t, StatusAwaitingApproval, exec.GetStepResults()["s1"].Status)
	_, afterRan := exec.GetStepResults()["s2"]
	assert.False(t, afterRan, "steps after the gate must not run before a decision")
}

func TestApproval_ApproveResumesOnlyStepsAfterGate(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()

	exec, rec := h.runToGate(e, gatedWorkflow(time.Millisecond), nil)
	beforeStart := exec.GetStepResults()["s0"].StartTime
	h.decide(rec, business.ApprovalStatusApproved)

	resumed, err := e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, resumed, 5*time.Second)

	assert.Equal(t, exec.ID, resumed.ID, "resume keeps the ExecutionID")
	assert.Equal(t, StatusCompleted, resumed.GetStatus(), "error: %s", resumed.GetError())
	results := resumed.GetStepResults()
	assert.True(t, beforeStart.Equal(results["s0"].StartTime), "step before the gate must not run again")
	assert.Equal(t, StatusCompleted, results["s1"].Status)
	assert.Equal(t, true, results["s1"].Output["approved"])
	assert.Equal(t, StatusCompleted, results["s2"].Status, "step after the gate runs")

	got, err := h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	assert.False(t, got.ResumedAt.IsZero(), "approval is marked resumed")
	_, err = h.secrets.GetSecret(context.Background(), rec.CheckpointRef)
	assert.Error(t, err, "checkpoint is dropped once the run finished")

	// A second resume is refused: the approval is already resumed.
	_, err = e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	assert.ErrorIs(t, err, business.ErrApprovalAlreadyClaimed)
}

func TestApproval_ResumeBeforeDecisionIsRefused(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	_, rec := h.runToGate(e, gatedWorkflow(time.Millisecond), nil)

	_, err := e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	assert.ErrorIs(t, err, business.ErrApprovalNotDecided)
}

func TestApproval_RejectFailsRun(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	exec, rec := h.runToGate(e, gatedWorkflow(time.Millisecond), nil)
	h.decide(rec, business.ApprovalStatusRejected)

	resumed, err := e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, resumed, 5*time.Second)

	assert.Equal(t, exec.ID, resumed.ID)
	assert.Equal(t, StatusFailed, resumed.GetStatus())
	assert.Contains(t, resumed.GetError(), "approval rejected by alice: because")
	_, afterRan := resumed.GetStepResults()["s2"]
	assert.False(t, afterRan, "a rejected run must not run later steps")
	got, err := h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	assert.False(t, got.ResumedAt.IsZero())
}

func TestApproval_RejectWithOnFailureContinueRunsTail(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	wf := gatedWorkflow(time.Millisecond)
	wf.Steps[1].OnFailure = ActionContinue
	_, rec := h.runToGate(e, wf, nil)
	h.decide(rec, business.ApprovalStatusRejected)

	resumed, err := e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, resumed, 5*time.Second)

	assert.Equal(t, StatusCompleted, resumed.GetStatus())
	assert.Equal(t, StatusFailed, resumed.GetStepResults()["s1"].Status, "the rejected gate stays recorded as failed")
	assert.Equal(t, StatusCompleted, resumed.GetStepResults()["s2"].Status)
}

func TestApproval_ExpiryWithoutRestartFailsRunViaSweep(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	e.StartApprovalRecovery(context.Background(), 20*time.Millisecond)

	wf := Workflow{Name: "short", Steps: []Step{gateStep("gate", 80*time.Millisecond), delayStep("after", time.Millisecond)}}
	exec, rec := h.runToGate(e, wf, nil)

	eventually(t, "sweep fails the expired run", func() bool { return execStatus(e, exec.ID) == StatusFailed })
	got, err := e.GetExecution(context.Background(), approvalTestTenant, exec.ID)
	require.NoError(t, err)
	assert.Contains(t, got.Error, "timed out")
	rec2, err := h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	assert.Equal(t, business.ApprovalStatusExpired, rec2.Status)
	_, afterRan := got.StepResults["s1"]
	assert.False(t, afterRan)
}

func TestApproval_KilledResumeIsReclaimedAndCompletesOnce(t *testing.T) {
	h := newApprovalHarness(t)
	lease := 200 * time.Millisecond
	e1 := h.engine(WithApprovalLease(lease), WithNodeID("node-1"))
	_, rec := h.runToGate(e1, gatedWorkflow(600*time.Millisecond), nil)
	h.decide(rec, business.ApprovalStatusApproved)

	resumed1, err := e1.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	eventually(t, "resume is running the tail", func() bool { return resumed1.GetStatus() == StatusRunning })
	e1.Shutdown() // the resuming engine dies mid-run

	waitForWorkflowCompletion(t, resumed1, 5*time.Second)
	assert.Equal(t, StatusCancelled, resumed1.GetStatus(), "the killed run did not complete")
	got, err := h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	assert.True(t, got.ResumedAt.IsZero(), "a killed run is not marked resumed")

	e2 := h.engine(WithApprovalLease(lease), WithNodeID("node-2"))
	// Within the lease the claim holds: nothing is resumed.
	require.NoError(t, e2.RecoverApprovals(context.Background()))
	_, err = e2.GetExecution(context.Background(), approvalTestTenant, rec.ExecutionID)
	assert.Error(t, err, "a live claim must not be taken over")

	time.Sleep(lease + 50*time.Millisecond)
	require.NoError(t, e2.RecoverApprovals(context.Background()))
	eventually(t, "second engine completes the run", func() bool { return execStatus(e2, rec.ExecutionID) == StatusCompleted })

	got, err = h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	assert.False(t, got.ResumedAt.IsZero())
	assert.Equal(t, "node-2", got.ResumeClaimedBy)

	// Once resumed, no later sweep runs it again.
	require.NoError(t, e2.RecoverApprovals(context.Background()))
	unresumed, err := h.store.ListUnresumed(context.Background(), time.Now().Add(time.Hour), lease)
	require.NoError(t, err)
	assert.Empty(t, unresumed)
}

func TestApproval_CheckpointSecretsNeverReachApprovalStore(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	const canary = "cfgms-canary-api-token-7f3a"

	_, rec := h.runToGate(e, gatedWorkflow(time.Millisecond), map[string]interface{}{"api_token": canary})

	assert.NotContains(t, rec.CheckpointRef, canary)
	for _, v := range []string{rec.Message, rec.StepName, rec.WorkflowName, rec.CheckpointRef} {
		assert.NotContains(t, v, canary)
	}
	var scanned int
	require.NoError(t, filepath.Walk(h.storeRoot, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() {
			return nil
		}
		scanned++
		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.NotContains(t, string(data), canary, "approval store file %s holds checkpoint contents", path)
		return nil
	}))
	assert.Positive(t, scanned, "the approval store must have written a file to scan")

	secret, err := h.secrets.GetSecret(context.Background(), rec.CheckpointRef)
	require.NoError(t, err)
	assert.Contains(t, secret.Value, canary, "the checkpoint is readable through the secrets provider")
}

func TestApproval_RestartThenApproveCompletes(t *testing.T) {
	h := newApprovalHarness(t)
	e1 := h.engine()
	exec, rec := h.runToGate(e1, gatedWorkflow(time.Millisecond), map[string]interface{}{"region": "eu"})
	e1.Shutdown()

	// A restart: a new engine, and a new store handle over the same files.
	reopened := openFlatfileApprovalStore(t, h.storeRoot)
	e2 := NewEngine(createTestFactory(), logging.NewNoopLogger(), h.secrets, nil, nil, nil, nil, WithApprovalStore(reopened))
	t.Cleanup(e2.Shutdown)

	require.NoError(t, e2.RecoverApprovals(context.Background()))
	pending, err := reopened.ListPending(context.Background(), approvalTestTenant)
	require.NoError(t, err)
	require.Len(t, pending, 1, "the pending approval survived the restart")

	require.NoError(t, reopened.DecideApproval(context.Background(), rec.TenantID, rec.ApprovalID, business.ApprovalStatusApproved, "alice", "", time.Now()))
	require.NoError(t, e2.RecoverApprovals(context.Background()))

	eventually(t, "restarted engine completes the run", func() bool { return execStatus(e2, exec.ID) == StatusCompleted })
	got, err := e2.GetExecution(context.Background(), approvalTestTenant, exec.ID)
	require.NoError(t, err)
	assert.Equal(t, "eu", got.Variables["region"], "steps after the gate see the checkpointed variables")
}

func TestApproval_TimedOutApprovalIsRejectedDuringRecovery(t *testing.T) {
	h := newApprovalHarness(t)
	e1 := h.engine()
	wf := Workflow{Name: "timeout", Steps: []Step{gateStep("gate", 40*time.Millisecond), delayStep("after", time.Millisecond)}}
	exec, rec := h.runToGate(e1, wf, nil)
	e1.Shutdown()
	time.Sleep(80 * time.Millisecond)

	e2 := h.engine()
	require.NoError(t, e2.RecoverApprovals(context.Background()))

	got, err := e2.GetExecution(context.Background(), approvalTestTenant, exec.ID)
	require.NoError(t, err, "the run stays visible after restart")
	assert.Equal(t, StatusFailed, got.Status)
	assert.Contains(t, got.Error, "timed out")
	assert.Equal(t, approvalTestTenant, got.TenantID)
	rec2, err := h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	assert.Equal(t, business.ApprovalStatusExpired, rec2.Status)
	_, err = h.secrets.GetSecret(context.Background(), rec.CheckpointRef)
	assert.Error(t, err, "checkpoint of an expired approval is dropped")
}

func TestApproval_ResumedRunKeepsRecordTenant(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	hostile := map[string]interface{}{"tenant_id": "tenant-evil", "TenantID": "tenant-evil", "tenant": "tenant-evil"}
	exec, rec := h.runToGate(e, gatedWorkflow(time.Millisecond), hostile)
	require.Equal(t, approvalTestTenant, exec.TenantID)
	h.decide(rec, business.ApprovalStatusApproved)

	resumed, err := e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, resumed, 5*time.Second)

	assert.Equal(t, approvalTestTenant, resumed.TenantID)
	assert.Equal(t, approvalTestTenant, resumed.Context.Value(ctxkeys.TenantID))
	assert.Equal(t, "tenant-evil", resumed.GetVariables()["tenant_id"], "variables are data, not identity")
}

func TestApproval_UnrestorableCheckpointFailsRunVisibly(t *testing.T) {
	for name, corrupt := range map[string]func(t *testing.T, h *approvalHarness, ref string){
		"deleted": func(t *testing.T, h *approvalHarness, ref string) {
			require.NoError(t, h.secrets.DeleteSecret(context.Background(), ref))
		},
		"garbled": func(t *testing.T, h *approvalHarness, ref string) {
			require.NoError(t, h.secrets.StoreSecret(context.Background(), &secretsif.SecretRequest{
				Key: ref, Value: "not json", TenantID: approvalTestTenant, CreatedBy: "test",
			}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newApprovalHarness(t)
			e1 := h.engine()
			exec, rec := h.runToGate(e1, gatedWorkflow(time.Millisecond), nil)
			e1.Shutdown()
			corrupt(t, h, rec.CheckpointRef)
			h.decide(rec, business.ApprovalStatusApproved)

			e2 := h.engine()
			require.NoError(t, e2.RecoverApprovals(context.Background()))

			got, err := e2.GetExecution(context.Background(), approvalTestTenant, exec.ID)
			require.NoError(t, err, "the run must not disappear")
			assert.Equal(t, StatusFailed, got.Status)
			assert.Contains(t, got.Error, "checkpoint could not be restored")
			assert.Equal(t, approvalTestTenant, got.TenantID)
			list, err := e2.ListExecutions(context.Background(), approvalTestTenant)
			require.NoError(t, err)
			var listed bool
			for _, l := range list {
				listed = listed || l.ID == exec.ID
			}
			assert.True(t, listed, "the failed run stays in the executions list")

			// It is not retried forever.
			stored, err := h.store.GetApproval(context.Background(), rec.TenantID, rec.ApprovalID)
			require.NoError(t, err)
			assert.False(t, stored.ResumedAt.IsZero())
		})
	}
}

func TestApproval_ConcurrentResumeRunsOnce(t *testing.T) {
	h := newApprovalHarness(t)
	e1 := h.engine(WithNodeID("node-1"))
	e2 := h.engine(WithNodeID("node-2"))
	_, rec := h.runToGate(e1, gatedWorkflow(100*time.Millisecond), nil)
	h.decide(rec, business.ApprovalStatusApproved)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var won int
	for _, e := range []*Engine{e1, e2, e1, e2} {
		wg.Add(1)
		go func(e *Engine) {
			defer wg.Done()
			if _, err := e.ResumeFromApproval(context.Background(), rec.TenantID, rec.ApprovalID); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}(e)
	}
	wg.Wait()
	assert.Equal(t, 1, won, "exactly one resume wins the claim")
}

func TestApproval_StepFailsWithoutApprovalStore(t *testing.T) {
	e := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	t.Cleanup(e.Shutdown)
	exec, err := e.ExecuteWorkflow(tenantCtx(), gatedWorkflow(time.Millisecond), nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 5*time.Second)
	assert.Equal(t, StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "approval store")
}

func TestApproval_StepFailsWithoutTenant(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	exec, err := e.ExecuteWorkflow(context.Background(), gatedWorkflow(time.Millisecond), nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 5*time.Second)
	assert.Equal(t, StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "tenant")
}

func TestApproval_NestedStepFailsAtRuntime(t *testing.T) {
	h := newApprovalHarness(t)
	e := h.engine()
	wf := Workflow{Name: "nested", Steps: []Step{{
		Name: "seq", Type: StepTypeSequential, Steps: []Step{gateStep("gate", time.Hour)},
	}}}
	exec, err := e.ExecuteWorkflow(tenantCtx(), wf, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 5*time.Second)
	assert.Equal(t, StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "approval steps must be top-level")
	pending, err := h.store.ListPending(context.Background(), approvalTestTenant)
	require.NoError(t, err)
	assert.Empty(t, pending)
}

func TestApprovalParser_RejectsNestedApproval(t *testing.T) {
	approval := func() Step { return gateStep("gate", time.Hour) }
	cases := map[string]Step{
		"parallel":    {Name: "outer", Type: StepTypeParallel, Steps: []Step{approval()}},
		"sequential":  {Name: "outer", Type: StepTypeSequential, Steps: []Step{approval()}},
		"conditional": {Name: "outer", Type: StepTypeConditional, Condition: &Condition{Type: ConditionTypeVariable, Variable: "x", Operator: OperatorExists}, Steps: []Step{approval()}},
		"loop":        {Name: "outer", Type: StepTypeFor, Loop: &LoopConfig{}, Steps: []Step{approval()}},
		"try":         {Name: "outer", Type: StepTypeTry, Try: &TryConfig{Try: []Step{approval()}}},
		"catch":       {Name: "outer", Type: StepTypeTry, Try: &TryConfig{Catch: []CatchBlock{{Steps: []Step{approval()}}}}},
		"finally":     {Name: "outer", Type: StepTypeTry, Try: &TryConfig{Finally: []Step{approval()}}},
		"switch":      {Name: "outer", Type: StepTypeSwitch, Switch: &SwitchConfig{Cases: []SwitchCase{{Value: 1, Steps: []Step{approval()}}}}},
		"deep":        {Name: "outer", Type: StepTypeSequential, Steps: []Step{{Name: "mid", Type: StepTypeParallel, Steps: []Step{approval()}}}},
		"fallback":    {Name: "outer", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Second}, ErrorHandling: &ErrorHandlingConfig{FallbackStep: stepPtr(approval())}},
	}
	for name, outer := range cases {
		t.Run(name, func(t *testing.T) {
			err := NewParser().ValidateWorkflow(Workflow{Name: "w", Steps: []Step{outer}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "approval steps must be top-level")
		})
	}
}

func stepPtr(s Step) *Step { return &s }

func TestApprovalParser_ValidatesApprovalConfig(t *testing.T) {
	p := NewParser()
	validate := func(s Step) error { return p.ValidateWorkflow(Workflow{Name: "w", Steps: []Step{s}}) }

	assert.NoError(t, validate(gateStep("gate", time.Hour)))
	assert.ErrorContains(t, validate(Step{Name: "g", Type: StepTypeApproval}), "approval configuration is required")
	assert.ErrorContains(t, validate(Step{Name: "g", Type: StepTypeApproval, Approval: &ApprovalConfig{Timeout: time.Hour}}), "message is required")
	assert.ErrorContains(t, validate(Step{Name: "g", Type: StepTypeApproval, Approval: &ApprovalConfig{Message: "m"}}), "timeout must be positive")
	assert.ErrorContains(t, validate(Step{Name: "g", Type: StepTypeApproval, Approval: &ApprovalConfig{Message: "m", Timeout: -time.Second}}), "timeout must be positive")
}

func TestApprovalParser_YAMLRoundTrip(t *testing.T) {
	wf, err := NewParser().ParseYAML([]byte(`
workflow:
  name: deploy
  steps:
    - name: prep
      type: delay
      delay:
        duration: 1s
    - name: sign-off
      type: approval
      on_failure: continue
      approval:
        message: Deploy to production?
        approver_permission: workflow:approve
        timeout: 4h
`))
	require.NoError(t, err)
	require.Len(t, wf.Steps, 2)
	gate := wf.Steps[1]
	assert.Equal(t, StepTypeApproval, gate.Type)
	require.NotNil(t, gate.Approval)
	assert.Equal(t, "Deploy to production?", gate.Approval.Message)
	assert.Equal(t, "workflow:approve", gate.Approval.ApproverPermission)
	assert.Equal(t, 4*time.Hour, gate.Approval.Timeout)
	assert.Equal(t, ActionContinue, gate.OnFailure)

	_, err = NewParser().ParseYAML([]byte(`
workflow:
  name: bad
  steps:
    - name: sign-off
      type: approval
      approval:
        message: ok?
        timeout: soon
`))
	assert.ErrorContains(t, err, "invalid approval timeout")

	_, err = NewParser().ParseYAML([]byte(`
workflow:
  name: nested
  steps:
    - name: outer
      type: parallel
      steps:
        - name: sign-off
          type: approval
          approval:
            message: ok?
            timeout: 1h
`))
	assert.ErrorContains(t, err, "approval steps must be top-level")
}
