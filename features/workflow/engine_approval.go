// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultApprovalLease is how long a node's claim on resuming a decided approval
// holds before another node may re-claim it. It must exceed the longest run of
// steps after a gate: a claim that outlives its lease while the steps are still
// running lets a second node run them again.
const defaultApprovalLease = 10 * time.Minute

// approvalCheckpointVersion is bumped when approvalCheckpoint changes shape.
const approvalCheckpointVersion = 1

// approvalStoreTimeout bounds each store or secrets call made outside a request.
const approvalStoreTimeout = 30 * time.Second

// EngineOption configures optional Engine collaborators at construction.
type EngineOption func(*Engine)

// WithApprovalStore gives the engine the durable store for approval gates.
func WithApprovalStore(store business.ApprovalStore) EngineOption {
	return func(e *Engine) { e.approvalStore = store }
}

// WithApprovalLease sets how long a resume claim holds before it can be re-claimed.
func WithApprovalLease(lease time.Duration) EngineOption {
	return func(e *Engine) {
		if lease > 0 {
			e.approvalLease = lease
		}
	}
}

// WithNodeID names this engine in resume claims. Distinct controller nodes must use
// distinct IDs; the default is unique per engine.
func WithNodeID(nodeID string) EngineOption {
	return func(e *Engine) {
		if nodeID != "" {
			e.nodeID = nodeID
		}
	}
}

// ApprovalStore returns the engine's approval store, or nil when none is configured.
func (e *Engine) ApprovalStore() business.ApprovalStore { return e.approvalStore }

func defaultApprovalNodeID() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("%s-%d-%d", host, os.Getpid(), executionIDCounter.Add(1))
}

// awaitingApprovalError is returned by the approval step to unwind the step loop
// without being treated as a failure. The run is then suspended by
// suspendAtApprovalGate.
type awaitingApprovalError struct {
	stepID string
}

func (a *awaitingApprovalError) Error() string {
	return "awaiting approval at step " + a.stepID
}

func isAwaitingApproval(err error) bool {
	var a *awaitingApprovalError
	return errors.As(err, &a)
}

// approvalCheckpoint is the run state held, encrypted, in the secrets provider
// while a run waits at a gate. It carries workflow variables and step outputs,
// which may include credentials, so it is never logged and never written to the
// approval store.
type approvalCheckpoint struct {
	Version          int                   `json:"version"`
	Workflow         Workflow              `json:"workflow"`
	GateIndex        int                   `json:"gate_index"`
	GateStepID       string                `json:"gate_step_id"`
	Variables        map[string]any        `json:"variables"`
	StepResults      map[string]StepResult `json:"step_results"`
	CompletedStepIDs []string              `json:"completed_step_ids"`
	StartTime        time.Time             `json:"start_time"`
}

func approvalID(executionID, stepID string) string {
	return "appr-" + executionID + "-" + stepID
}

func checkpointKey(tenantID, approvalID string) string {
	return tenantID + "/workflow-approvals/" + approvalID + "/checkpoint"
}

// executeApprovalStep validates the gate and unwinds the step loop. The gate is
// persisted by suspendAtApprovalGate, which has the workflow snapshot.
func (e *Engine) executeApprovalStep(step Step) error {
	if e.approvalStore == nil || e.secrets == nil {
		return fmt.Errorf("approval steps require an approval store and a secrets provider")
	}
	if step.ID == "" || strings.Contains(step.ID, ".") {
		return fmt.Errorf("approval steps must be top-level")
	}
	if step.Approval == nil || step.Approval.Timeout <= 0 {
		return fmt.Errorf("approval step requires a configuration with a positive timeout")
	}
	return &awaitingApprovalError{stepID: step.ID}
}

// suspendAtApprovalGate checkpoints the run at the gate it just reached, records a
// pending approval, and leaves the execution in StatusAwaitingApproval. No goroutine
// is held afterwards. Any failure to persist fails the run: a gate that cannot be
// resumed must not look like a waiting run.
func (e *Engine) suspendAtApprovalGate(execution *WorkflowExecution, workflow Workflow) {
	if err := e.persistApprovalGate(execution, workflow); err != nil {
		e.failExecution(execution, fmt.Errorf("approval gate could not be recorded: %w", err))
		return
	}
	execution.SetStatus(StatusAwaitingApproval)
	e.persistExecution(execution)
	execution.Cancel() // releases the execution context; nothing runs until a decision
	e.logger.WithTenant(execution.TenantID).Info("Workflow execution awaiting approval",
		"execution_id", execution.ID,
		"workflow", logging.SanitizeLogValue(workflow.Name))
}

func (e *Engine) persistApprovalGate(execution *WorkflowExecution, workflow Workflow) error {
	if execution.TenantID == "" {
		return fmt.Errorf("approval steps require a tenant context")
	}
	gateStepID := execution.GetCurrentStep()
	gateIndex := -1
	for i := range workflow.Steps {
		if workflow.Steps[i].ID == gateStepID {
			gateIndex = i
			break
		}
	}
	if gateIndex < 0 || workflow.Steps[gateIndex].Approval == nil {
		return fmt.Errorf("approval gate %q is not a top-level step", gateStepID)
	}
	gate := workflow.Steps[gateIndex]

	results := execution.GetStepResults()
	completed := make([]string, 0, len(results))
	for id, r := range results {
		if r.Status == StatusCompleted {
			completed = append(completed, id)
		}
	}
	payload, err := json.Marshal(approvalCheckpoint{
		Version:          approvalCheckpointVersion,
		Workflow:         workflow,
		GateIndex:        gateIndex,
		GateStepID:       gateStepID,
		Variables:        execution.GetVariables(),
		StepResults:      results,
		CompletedStepIDs: completed,
		StartTime:        execution.StartTime,
	})
	if err != nil {
		return fmt.Errorf("checkpoint could not be encoded: %w", err)
	}

	id := approvalID(execution.ID, gateStepID)
	ref := checkpointKey(execution.TenantID, id)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(execution.Context), approvalStoreTimeout)
	defer cancel()
	if err := e.secrets.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:         ref,
		Value:       string(payload),
		CreatedBy:   "workflow-engine",
		TenantID:    execution.TenantID,
		Description: "workflow approval checkpoint",
	}); err != nil {
		return fmt.Errorf("checkpoint could not be stored: %w", err)
	}

	requestedBy, _ := execution.Context.Value(ctxkeys.UserIDKey).(string)
	now := time.Now()
	record := &business.WorkflowApproval{
		ApprovalID:         id,
		TenantID:           execution.TenantID,
		WorkflowName:       workflow.Name,
		ExecutionID:        execution.ID,
		StepID:             gateStepID,
		StepName:           gate.Name,
		Message:            gate.Approval.Message,
		ApproverPermission: gate.Approval.ApproverPermission,
		RequestedBy:        requestedBy,
		Status:             business.ApprovalStatusPending,
		RequestedAt:        now,
		ExpiresAt:          now.Add(gate.Approval.Timeout),
		CheckpointRef:      ref,
	}
	if err := e.approvalStore.CreateApproval(ctx, record); err != nil {
		e.deleteCheckpoint(ref)
		return fmt.Errorf("approval could not be stored: %w", err)
	}
	return nil
}

// failExecution ends execution as failed with cause. Variable state is deliberately
// not attached: checkpoint contents are never surfaced.
func (e *Engine) failExecution(execution *WorkflowExecution, cause error) {
	wfErr := NewWorkflowError(ErrorCodeStepExecution, cause.Error(), execution.GetCurrentStep(), StepTypeApproval, nil)
	execution.SetError(wfErr.Error())
	execution.SetErrorDetails(wfErr)
	endTime := time.Now()
	execution.SetEndTime(&endTime)
	execution.SetStatus(StatusFailed)
	e.persistExecution(execution)
	e.logger.WithTenant(execution.TenantID).Warn("Workflow execution failed",
		"execution_id", execution.ID,
		"error", logging.SanitizeLogValue(cause.Error()))
}

func (e *Engine) deleteCheckpoint(ref string) {
	if ref == "" || e.secrets == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), approvalStoreTimeout)
	defer cancel()
	if err := e.secrets.DeleteSecret(ctx, ref); err != nil {
		e.logger.Warn("Approval checkpoint could not be deleted",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// ResumeFromApproval resumes the run behind a decided approval. tenantID is the
// tenant of the stored approval record: callers read it from the record, never from
// the request. It claims the approval (compare-and-set with a lease) so two nodes
// cannot both resume it, rebuilds the execution from the checkpoint under the same
// ExecutionID, and runs the steps after the gate in the background. The run's
// context derives from the engine, not from ctx, so it outlives the caller's
// request; workflow.Timeout is not re-armed. A rejected approval fails the run,
// unless the gate step says on_failure: continue.
//
// It returns business.ErrApprovalAlreadyClaimed when another claim is live and
// business.ErrApprovalNotDecided while the approval is pending or expired.
func (e *Engine) ResumeFromApproval(ctx context.Context, tenantID, approvalID string) (*WorkflowExecution, error) {
	if e.approvalStore == nil || e.secrets == nil {
		return nil, fmt.Errorf("approval store is not configured")
	}
	if e.baseCtx.Err() != nil {
		return nil, fmt.Errorf("engine is shut down")
	}
	rec, err := e.approvalStore.GetApproval(ctx, tenantID, approvalID)
	if err != nil {
		return nil, err
	}

	// A claim by this node's own in-flight resume is not a stale claim.
	flightKey := tenantID + "/" + approvalID
	e.mutex.Lock()
	if _, busy := e.resuming[flightKey]; busy {
		e.mutex.Unlock()
		return nil, business.ErrApprovalAlreadyClaimed
	}
	e.resuming[flightKey] = struct{}{}
	e.mutex.Unlock()
	release := func() {
		e.mutex.Lock()
		delete(e.resuming, flightKey)
		e.mutex.Unlock()
	}

	if err := e.approvalStore.ClaimResume(ctx, tenantID, approvalID, e.nodeID, time.Now(), e.approvalLease); err != nil {
		release()
		return nil, err
	}

	cp, err := e.loadCheckpoint(ctx, rec)
	if err != nil {
		defer release()
		e.failUnrestorable(rec, err)
		return nil, fmt.Errorf("checkpoint cannot be restored: %w", err)
	}

	runCtx, cancel := context.WithCancel(e.baseCtx)
	runCtx = context.WithValue(runCtx, ctxkeys.TenantID, rec.TenantID)
	runCtx = withComposedWorkflowBudget(runCtx)

	// Tenant comes from the approval record. Checkpointed variables never decide it.
	execution := &WorkflowExecution{
		ID:           rec.ExecutionID,
		WorkflowName: cp.Workflow.Name,
		TenantID:     rec.TenantID,
		Status:       StatusPending,
		StartTime:    cp.StartTime,
		StepResults:  cp.StepResults,
		Variables:    cp.Variables,
		Context:      runCtx,
		Cancel:       cancel,
		Done:         make(chan struct{}),
	}
	if execution.StepResults == nil {
		execution.StepResults = make(map[string]StepResult)
	}
	if execution.Variables == nil {
		execution.Variables = make(map[string]any)
	}
	execution.SetCurrentStep(cp.GateStepID)

	workflow := cp.Workflow
	AssignStepIDs(workflow.Steps)
	gate := workflow.Steps[cp.GateIndex]
	tail := workflow.Steps[cp.GateIndex+1:]

	gateResult := execution.StepResults[cp.GateStepID]
	end := time.Now()
	gateResult.EndTime = &end
	if gateResult.Output == nil {
		gateResult.Output = make(map[string]any)
	}
	gateResult.Output["decided_by"] = rec.DecidedBy
	gateResult.Output["justification"] = rec.Justification

	var failure error
	if rec.Status == business.ApprovalStatusApproved {
		gateResult.Status = StatusCompleted
		gateResult.Output["approved"] = true
	} else {
		reason := fmt.Sprintf("approval rejected by %s", rec.DecidedBy)
		if rec.Justification != "" {
			reason += ": " + rec.Justification
		}
		gateResult.Status = StatusFailed
		gateResult.Error = reason
		gateResult.Output["approved"] = false
		if gate.OnFailure != ActionContinue {
			failure = errors.New(reason)
		}
	}
	execution.StepResults[cp.GateStepID] = gateResult

	e.mutex.Lock()
	e.executions[execution.ID] = execution
	e.mutex.Unlock()
	e.persistExecution(execution)

	if failure != nil {
		execution.SetStatus(StatusFailed)
		e.failExecution(execution, failure)
		close(execution.Done)
		cancel()
		e.finishResume(rec, release, true)
		return execution, nil
	}

	e.background.Add(1)
	go func() {
		defer e.background.Done()
		e.runWorkflowSteps(execution, workflow, tail, func() {
			// A run cut short by engine shutdown keeps its claim so the lease
			// lapses and another engine finishes it; anything else is done.
			e.finishResume(rec, release, e.baseCtx.Err() == nil)
		})
	}()
	return execution, nil
}

// finishResume releases the in-flight marker and, when the run finished, ends the
// approval's claim cycle and drops the checkpoint.
func (e *Engine) finishResume(rec *business.WorkflowApproval, release func(), finished bool) {
	defer release()
	if !finished {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), approvalStoreTimeout)
	defer cancel()
	if err := e.approvalStore.MarkResumed(ctx, rec.TenantID, rec.ApprovalID, time.Now()); err != nil {
		e.logger.Warn("Approval could not be marked resumed",
			"approval_id", logging.SanitizeLogValue(rec.ApprovalID),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	e.deleteCheckpoint(rec.CheckpointRef)
}

func (e *Engine) loadCheckpoint(ctx context.Context, rec *business.WorkflowApproval) (*approvalCheckpoint, error) {
	if rec.CheckpointRef == "" {
		return nil, fmt.Errorf("approval has no checkpoint reference")
	}
	secret, err := e.secrets.GetSecret(ctx, rec.CheckpointRef)
	if err != nil {
		return nil, fmt.Errorf("checkpoint unavailable: %w", err)
	}
	var cp approvalCheckpoint
	if err := json.Unmarshal([]byte(secret.Value), &cp); err != nil {
		return nil, fmt.Errorf("checkpoint unreadable: %w", err)
	}
	if cp.Version != approvalCheckpointVersion {
		return nil, fmt.Errorf("checkpoint version %d is not supported", cp.Version)
	}
	if cp.GateIndex < 0 || cp.GateIndex >= len(cp.Workflow.Steps) {
		return nil, fmt.Errorf("checkpoint gate index is out of range")
	}
	return &cp, nil
}

// failUnrestorable records the run as failed, with the reason, in the executions
// list, and ends the approval's claim cycle so recovery does not retry it forever.
func (e *Engine) failUnrestorable(rec *business.WorkflowApproval, cause error) {
	e.failRunOfApproval(rec, "approval checkpoint could not be restored: "+cause.Error())
	ctx, cancel := context.WithTimeout(context.Background(), approvalStoreTimeout)
	defer cancel()
	if err := e.approvalStore.MarkResumed(ctx, rec.TenantID, rec.ApprovalID, time.Now()); err != nil {
		e.logger.Warn("Approval could not be marked resumed",
			"approval_id", logging.SanitizeLogValue(rec.ApprovalID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// failRunOfApproval fails the run behind rec with reason. It updates the execution
// this node holds, or, after a restart when it holds none, records a failed
// execution from the approval record so the run stays visible.
func (e *Engine) failRunOfApproval(rec *business.WorkflowApproval, reason string) {
	e.mutex.Lock()
	execution, exists := e.executions[rec.ExecutionID]
	e.mutex.Unlock()

	if !exists {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		execution = &WorkflowExecution{
			ID:           rec.ExecutionID,
			WorkflowName: rec.WorkflowName,
			TenantID:     rec.TenantID,
			StartTime:    rec.RequestedAt,
			StepResults:  make(map[string]StepResult),
			Variables:    make(map[string]any),
			Context:      ctx,
			Cancel:       func() {},
			Done:         make(chan struct{}),
		}
		close(execution.Done)
		execution.SetCurrentStep(rec.StepID)
		e.mutex.Lock()
		e.executions[execution.ID] = execution
		e.mutex.Unlock()
		e.persistExecution(execution)
	} else if execution.GetStatus() != StatusAwaitingApproval && execution.GetStatus() != StatusPending {
		return
	}
	e.failExecution(execution, errors.New(reason))
}

// RecoverApprovals expires approvals past their deadline and fails their runs, and
// resumes decided approvals nobody is resuming. Every node runs it at start and
// periodically; the store's compare-and-set decides which node acts on each approval.
func (e *Engine) RecoverApprovals(ctx context.Context) error {
	if e.approvalStore == nil {
		return nil
	}
	now := time.Now()
	var errs []error

	expired, err := e.approvalStore.ExpireDue(ctx, now)
	if err != nil {
		errs = append(errs, fmt.Errorf("expire due approvals: %w", err))
	}
	for _, rec := range expired {
		e.failRunOfApproval(rec, "approval timed out before a decision was made")
		e.deleteCheckpoint(rec.CheckpointRef)
	}

	unresumed, err := e.approvalStore.ListUnresumed(ctx, now, e.approvalLease)
	if err != nil {
		errs = append(errs, fmt.Errorf("list unresumed approvals: %w", err))
	}
	for _, rec := range unresumed {
		_, err := e.ResumeFromApproval(ctx, rec.TenantID, rec.ApprovalID)
		if err != nil && !errors.Is(err, business.ErrApprovalAlreadyClaimed) {
			e.logger.Warn("Approval could not be resumed",
				"approval_id", logging.SanitizeLogValue(rec.ApprovalID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
	return errors.Join(errs...)
}

// StartApprovalRecovery runs RecoverApprovals once now and then every interval
// until the engine is shut down or ctx ends.
func (e *Engine) StartApprovalRecovery(ctx context.Context, interval time.Duration) {
	if e.approvalStore == nil || interval <= 0 {
		return
	}
	sweep := func() {
		if err := e.RecoverApprovals(ctx); err != nil {
			e.logger.Warn("Approval recovery sweep failed",
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
	sweep()
	e.background.Add(1)
	go func() {
		defer e.background.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.baseCtx.Done():
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
}

// Shutdown stops the approval sweep and cancels runs resumed from approvals. Their
// claims stay in the store, so another engine finishes them once the lease lapses.
func (e *Engine) Shutdown() {
	e.baseCancel()
	e.background.Wait()
}
