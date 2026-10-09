// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DefaultExecutionRetention is how many terminal executions per tenant the engine
// keeps in the durable store; older ones are pruned after each terminal write.
const DefaultExecutionRetention = 1000

// executionStoreTimeout bounds each execution-store call so a slow store never
// stalls a run for long.
const executionStoreTimeout = 10 * time.Second

// ErrExecutionNotFound is returned when no execution with the id exists for the tenant,
// on this node or in the durable store.
var ErrExecutionNotFound = errors.New("execution not found")

// WithExecutionStore gives the engine the durable store execution history is written
// through to, which makes it readable from every controller node and across restarts.
// Without one, executions are node-local and lost on restart.
func WithExecutionStore(store business.WorkflowExecutionStore) EngineOption {
	return func(e *Engine) { e.executionStore = store }
}

// WithExecutionRetention sets how many terminal executions per tenant stay in the
// durable store (default DefaultExecutionRetention). A non-positive n is ignored.
func WithExecutionRetention(n int) EngineOption {
	return func(e *Engine) {
		if n > 0 {
			e.executionRetention = n
		}
	}
}

// executionPayload is the engine-owned JSON held in WorkflowExecutionRecord.Payload.
//
// Variables are deliberately absent: they carry values resolved at run time, which
// can be secrets (the approval checkpoint holding them goes to the secrets provider
// for that reason). For the same reason the variable snapshots that errors and trace
// entries attach are dropped by scrubExecutionPayload.
type executionPayload struct {
	CurrentStep    string                `json:"current_step,omitempty"`
	StepResults    map[string]StepResult `json:"step_results,omitempty"`
	ExecutionTrace []ExecutionStep       `json:"execution_trace,omitempty"`
	Error          string                `json:"error,omitempty"`
	ErrorDetails   *WorkflowError        `json:"error_details,omitempty"`
}

// scrubErrorDetails returns a copy of err without variable state or stack frames,
// recursively through child errors.
func scrubErrorDetails(err *WorkflowError) *WorkflowError {
	if err == nil {
		return nil
	}
	c := *err
	c.VariableState = nil
	c.StackTrace = nil
	if len(err.ChildErrors) > 0 {
		c.ChildErrors = make([]*WorkflowError, len(err.ChildErrors))
		for i, child := range err.ChildErrors {
			c.ChildErrors[i] = scrubErrorDetails(child)
		}
	}
	return &c
}

func scrubStepResult(r StepResult) StepResult {
	r.ErrorDetails = scrubErrorDetails(r.ErrorDetails)
	if len(r.RetryAttempts) > 0 {
		attempts := make([]RetryAttempt, len(r.RetryAttempts))
		for i, a := range r.RetryAttempts {
			a.Error = scrubErrorDetails(a.Error)
			attempts[i] = a
		}
		r.RetryAttempts = attempts
	}
	return r
}

// buildExecutionRecord snapshots execution through its thread-safe getters.
func buildExecutionRecord(execution *WorkflowExecution) (*business.WorkflowExecutionRecord, error) {
	results := execution.GetStepResults()
	for k, r := range results {
		results[k] = scrubStepResult(r)
	}
	trace := execution.GetExecutionTrace()
	for i := range trace {
		trace[i].Variables = nil
	}
	payload, err := json.Marshal(executionPayload{
		CurrentStep:    execution.GetCurrentStep(),
		StepResults:    results,
		ExecutionTrace: trace,
		Error:          execution.GetError(),
		ErrorDetails:   scrubErrorDetails(execution.GetErrorDetails()),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal execution payload: %w", err)
	}
	rec := &business.WorkflowExecutionRecord{
		TenantID:     execution.TenantID,
		ExecutionID:  execution.ID,
		WorkflowName: execution.WorkflowName,
		Status:       string(execution.GetStatus()),
		StartTime:    execution.StartTime.UTC(),
		Payload:      payload,
	}
	if end := execution.GetEndTime(); end != nil {
		rec.EndTime = end.UTC()
	}
	return rec, nil
}

// executionFromRecord rebuilds a read-only WorkflowExecution. It has no Context,
// Cancel or Done: a record from the store has no live owner on this node.
func executionFromRecord(rec *business.WorkflowExecutionRecord) (*WorkflowExecution, error) {
	var p executionPayload
	if len(rec.Payload) > 0 {
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			return nil, fmt.Errorf("unreadable execution payload: %w", err)
		}
	}
	ex := &WorkflowExecution{
		ID:             rec.ExecutionID,
		WorkflowName:   rec.WorkflowName,
		TenantID:       rec.TenantID,
		Status:         ExecutionStatus(rec.Status),
		StartTime:      rec.StartTime,
		CurrentStep:    p.CurrentStep,
		StepResults:    p.StepResults,
		Variables:      make(map[string]interface{}),
		ExecutionTrace: p.ExecutionTrace,
		Error:          p.Error,
		ErrorDetails:   p.ErrorDetails,
	}
	if ex.StepResults == nil {
		ex.StepResults = make(map[string]StepResult)
	}
	if !rec.EndTime.IsZero() {
		end := rec.EndTime
		ex.EndTime = &end
	}
	return ex, nil
}

// persistExecution writes execution's current state through to the durable store, and
// prunes the tenant's history when the execution is terminal. A store failure is
// logged and otherwise ignored: persistence never fails or blocks the run. Snapshot
// and write are serialized per execution so an older snapshot cannot land after a
// newer one.
func (e *Engine) persistExecution(execution *WorkflowExecution) {
	if e.executionStore == nil || execution == nil {
		return
	}
	execution.persistMu.Lock()
	defer execution.persistMu.Unlock()

	rec, err := buildExecutionRecord(execution)
	if err != nil {
		e.logExecutionStoreFailure("snapshot", execution.ID, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), executionStoreTimeout)
	defer cancel()
	if err := e.executionStore.Save(ctx, rec); err != nil {
		e.logExecutionStoreFailure("save", execution.ID, err)
		return
	}
	if business.IsTerminalWorkflowExecutionStatus(rec.Status) {
		if _, err := e.executionStore.Prune(ctx, rec.TenantID, e.executionRetention); err != nil {
			e.logExecutionStoreFailure("prune", execution.ID, err)
		}
	}
}

func (e *Engine) logExecutionStoreFailure(op, executionID string, err error) {
	e.logger.Warn("Workflow execution store write failed",
		"operation", op,
		"execution_id", logging.SanitizeLogValue(executionID),
		"error", logging.SanitizeLogValue(err.Error()))
}

// recordStepResult records a step's result and writes the execution through.
func (e *Engine) recordStepResult(execution *WorkflowExecution, key string, result StepResult) {
	execution.SetStepResult(key, result)
	e.persistExecution(execution)
}

// GetExecution returns a copy of the execution for (tenantID, executionID). A run this
// node owns answers from its live in-memory state; any other answers from the durable
// store, so a run is readable from every node and after a restart. An execution that
// belongs to another tenant is reported as not found.
func (e *Engine) GetExecution(ctx context.Context, tenantID, executionID string) (*WorkflowExecution, error) {
	e.mutex.RLock()
	execution, exists := e.executions[executionID]
	e.mutex.RUnlock()

	if exists && execution.TenantID == tenantID {
		return copyExecution(execution), nil
	}
	if e.executionStore == nil {
		return nil, fmt.Errorf("%w: %s", ErrExecutionNotFound, executionID)
	}
	rec, err := e.executionStore.Get(ctx, tenantID, executionID)
	if errors.Is(err, business.ErrWorkflowExecutionNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrExecutionNotFound, executionID)
	}
	if err != nil {
		return nil, fmt.Errorf("read execution: %w", err)
	}
	return executionFromRecord(rec)
}

// ListExecutions returns tenantID's executions, newest first: the durable history
// plus any run this node owns, the live state winning for a run in both.
func (e *Engine) ListExecutions(ctx context.Context, tenantID string) ([]*WorkflowExecution, error) {
	byID := make(map[string]*WorkflowExecution)
	if e.executionStore != nil {
		recs, err := e.executionStore.List(ctx, tenantID, "", 0)
		if err != nil {
			return nil, fmt.Errorf("list executions: %w", err)
		}
		for _, rec := range recs {
			ex, err := executionFromRecord(rec)
			if err != nil {
				e.logExecutionStoreFailure("decode", rec.ExecutionID, err)
				continue
			}
			byID[ex.ID] = ex
		}
	}

	e.mutex.RLock()
	for id, execution := range e.executions {
		if execution.TenantID == tenantID {
			byID[id] = copyExecution(execution)
		}
	}
	e.mutex.RUnlock()

	executions := make([]*WorkflowExecution, 0, len(byID))
	for _, ex := range byID {
		executions = append(executions, ex)
	}
	sort.Slice(executions, func(a, b int) bool {
		if !executions[a].StartTime.Equal(executions[b].StartTime) {
			return executions[a].StartTime.After(executions[b].StartTime)
		}
		return executions[a].ID > executions[b].ID
	})
	return executions, nil
}

// copyExecution returns a copy of execution built from its thread-safe getters.
func copyExecution(execution *WorkflowExecution) *WorkflowExecution {
	c := &WorkflowExecution{
		ID:             execution.ID,
		WorkflowName:   execution.WorkflowName,
		TenantID:       execution.TenantID,
		Status:         execution.GetStatus(),
		StartTime:      execution.StartTime,
		EndTime:        execution.GetEndTime(),
		CurrentStep:    execution.GetCurrentStep(),
		StepResults:    execution.GetStepResults(),
		Variables:      execution.GetVariables(),
		ExecutionTrace: execution.GetExecutionTrace(),
		Error:          execution.GetError(),
		ErrorDetails:   execution.GetErrorDetails(),
		Context:        execution.Context,
		Cancel:         execution.Cancel,
	}
	if c.EndTime != nil {
		end := *c.EndTime
		c.EndTime = &end
	}
	return c
}
