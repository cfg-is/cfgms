// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// sharedRunStore adapts a business.ScriptRunStore — the cluster-shared run
// store (Issue #4528) — to RunStore, so every controller node reads and
// completes the same runs.
type sharedRunStore struct {
	store business.ScriptRunStore
}

// NewSharedRunStore returns a RunStore backed by the storage provider's
// ScriptRunStore.
func NewSharedRunStore(store business.ScriptRunStore) RunStore {
	return &sharedRunStore{store: store}
}

func toBusinessRun(r *RunRecord) (*business.ScriptRun, error) {
	filter, err := json.Marshal(r.Filter)
	if err != nil {
		return nil, fmt.Errorf("run store: marshal filter: %w", err)
	}
	return &business.ScriptRun{
		RunID: r.RunID, TenantID: r.TenantID, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		Status: string(r.Status), FilterJSON: filter, ScriptRef: r.ScriptRef,
		InlineContent: r.InlineContent, Shell: string(r.Shell),
		JobCount: r.JobCount, CompletedJobs: r.CompletedJobs, FailedJobs: r.FailedJobs,
		Kind: r.Kind, ActionJSON: r.ActionJSON,
	}, nil
}

func fromBusinessRun(b *business.ScriptRun) *RunRecord {
	r := &RunRecord{
		RunID: b.RunID, TenantID: b.TenantID, CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt,
		Status: RunStatus(b.Status), ScriptRef: b.ScriptRef, InlineContent: b.InlineContent,
		Shell: scriptmodule.ShellType(b.Shell), JobCount: b.JobCount,
		CompletedJobs: b.CompletedJobs, FailedJobs: b.FailedJobs,
		Kind: b.Kind, ActionJSON: b.ActionJSON,
	}
	if len(b.FilterJSON) > 0 {
		_ = json.Unmarshal(b.FilterJSON, &r.Filter)
	}
	return r
}

func fromBusinessJob(b *business.ScriptRunJob) *JobRecord {
	return &JobRecord{
		JobID: b.JobID, RunID: b.RunID, DeviceID: b.DeviceID, ExecutionID: b.ExecutionID,
		Status: JobStatus(b.Status), CreatedAt: b.CreatedAt, CompletedAt: b.CompletedAt,
		Output: b.Output, Stderr: b.Stderr, ExitCode: b.ExitCode,
		ResultCode: b.ResultCode, DispatchedAt: b.DispatchedAt,
	}
}

func toBusinessJob(j *JobRecord) *business.ScriptRunJob {
	return &business.ScriptRunJob{
		JobID: j.JobID, RunID: j.RunID, DeviceID: j.DeviceID, ExecutionID: j.ExecutionID,
		Status: string(j.Status), CreatedAt: j.CreatedAt, CompletedAt: j.CompletedAt,
		Output: j.Output, Stderr: j.Stderr, ExitCode: j.ExitCode,
		ResultCode: j.ResultCode, DispatchedAt: j.DispatchedAt,
	}
}

// completedAtFor mirrors RunStoreSQL: a terminal status stamps completed_at now.
func completedAtFor(status JobStatus) *time.Time {
	if !status.IsTerminal() {
		return nil
	}
	t := time.Now().UTC()
	return &t
}

func (s *sharedRunStore) CreateRun(r *RunRecord) error {
	b, err := toBusinessRun(r)
	if err != nil {
		return err
	}
	return s.store.CreateRun(context.Background(), b)
}

func (s *sharedRunStore) CreateJob(j *JobRecord) error {
	return s.store.CreateJob(context.Background(), toBusinessJob(j))
}

func (s *sharedRunStore) GetRun(runID string) (*RunRecord, error) {
	b, err := s.store.GetRun(context.Background(), runID)
	if errors.Is(err, business.ErrScriptRunNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return fromBusinessRun(b), nil
}

func (s *sharedRunStore) ListRuns(tenantID string, limit, offset int) ([]*RunRecord, error) {
	bs, err := s.store.ListRuns(context.Background(), tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	runs := make([]*RunRecord, 0, len(bs))
	for _, b := range bs {
		runs = append(runs, fromBusinessRun(b))
	}
	return runs, nil
}

func (s *sharedRunStore) ListRunJobs(runID string) ([]*JobRecord, error) {
	bs, err := s.store.ListRunJobs(context.Background(), runID)
	if err != nil {
		return nil, err
	}
	jobs := make([]*JobRecord, 0, len(bs))
	for _, b := range bs {
		jobs = append(jobs, fromBusinessJob(b))
	}
	return jobs, nil
}

func (s *sharedRunStore) UpdateJobStatus(jobID string, status JobStatus, executionID string) error {
	return s.store.UpdateJobStatus(context.Background(), jobID, string(status), executionID, completedAtFor(status))
}

func (s *sharedRunStore) UpdateJobResult(jobID string, status JobStatus, executionID, output, stderr string, exitCode int) error {
	return s.store.UpdateJobResult(context.Background(), jobID, string(status), executionID, output, stderr, exitCode, completedAtFor(status))
}

func (s *sharedRunStore) UpdateJobResultCode(jobID, code string) error {
	return s.store.UpdateJobResultCode(context.Background(), jobID, code)
}

func (s *sharedRunStore) MarkJobDispatched(jobID string, at time.Time) (bool, error) {
	return s.store.MarkJobDispatched(context.Background(), jobID, at)
}

func (s *sharedRunStore) ListStaleActionJobs(pendingBefore, dispatchedBefore time.Time) ([]*JobRecord, error) {
	bs, err := s.store.ListStaleActionJobs(context.Background(), pendingBefore, dispatchedBefore)
	if err != nil {
		return nil, err
	}
	jobs := make([]*JobRecord, 0, len(bs))
	for _, b := range bs {
		jobs = append(jobs, fromBusinessJob(b))
	}
	return jobs, nil
}

func (s *sharedRunStore) ExpireJobIfStatus(jobID string, fromStatus JobStatus, resultCode string, at time.Time) (bool, error) {
	return s.store.ExpireJobIfStatus(context.Background(), jobID, string(fromStatus), resultCode, at)
}

func (s *sharedRunStore) UpdateRunStatus(runID string, status RunStatus) error {
	return s.store.UpdateRunStatus(context.Background(), runID, string(status))
}

func (s *sharedRunStore) UpdateRunCounts(runID string, completedJobs, failedJobs int) error {
	return s.store.UpdateRunCounts(context.Background(), runID, completedJobs, failedJobs)
}

func (s *sharedRunStore) CreateExecutionGrant(deviceID, tenantID, executionID string, scope []string, ttl time.Duration) error {
	now := time.Now().UTC()
	return s.store.CreateExecutionGrant(context.Background(), &business.ExecutionGrant{
		DeviceID: deviceID, TenantID: tenantID, ExecutionID: executionID, Scope: scope,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	})
}

func (s *sharedRunStore) LookupGrant(deviceID, executionID string) (*ExecutionGrant, error) {
	g, err := s.store.LookupGrant(context.Background(), deviceID, executionID)
	switch {
	case errors.Is(err, business.ErrExecutionGrantNotFound):
		return nil, ErrGrantNotFound
	case errors.Is(err, business.ErrExecutionGrantConsumed):
		return nil, ErrGrantConsumed
	case err != nil:
		return nil, err
	}
	return &ExecutionGrant{
		DeviceID: g.DeviceID, TenantID: g.TenantID, ExecutionID: g.ExecutionID, Scope: g.Scope,
		CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt, Consumed: g.Consumed,
	}, nil
}

func (s *sharedRunStore) ConsumeGrant(executionID string) error {
	return s.store.ConsumeGrant(context.Background(), executionID)
}

// sharedQueueStore adapts a business.ExecutionQueueStore — the cluster-shared
// execution queue (Issue #4528) — to the script module's QueueStore. The full
// QueueEntry travels as the row payload; the store's State/DispatchedAt/
// CompletedAt columns are authoritative on read.
type sharedQueueStore struct {
	store business.ExecutionQueueStore
}

// NewSharedQueueStore returns a scriptmodule.QueueStore backed by the storage
// provider's ExecutionQueueStore.
func NewSharedQueueStore(store business.ExecutionQueueStore) scriptmodule.QueueStore {
	return &sharedQueueStore{store: store}
}

func (s *sharedQueueStore) decode(b *business.ExecutionQueueEntry) (*scriptmodule.QueueEntry, error) {
	e := &scriptmodule.QueueEntry{}
	if err := json.Unmarshal(b.Payload, e); err != nil {
		return nil, fmt.Errorf("execution queue: decode entry %s: %w", b.ExecutionID, err)
	}
	e.ExecutionID = b.ExecutionID
	e.DeviceID = b.DeviceID
	e.State = scriptmodule.QueueState(b.State)
	e.DispatchedAt = b.DispatchedAt
	e.CompletedAt = b.CompletedAt
	return e, nil
}

func (s *sharedQueueStore) decodeAll(bs []*business.ExecutionQueueEntry) ([]*scriptmodule.QueueEntry, error) {
	out := make([]*scriptmodule.QueueEntry, 0, len(bs))
	for _, b := range bs {
		e, err := s.decode(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *sharedQueueStore) Enqueue(entry *scriptmodule.QueueEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("execution queue: encode entry: %w", err)
	}
	err = s.store.Enqueue(context.Background(), &business.ExecutionQueueEntry{
		ExecutionID: entry.ExecutionID, DeviceID: entry.DeviceID, ParamHash: entry.ParamHash,
		State: string(entry.State), QueuedAt: entry.QueuedAt, ExpiresAt: entry.ExpiresAt,
		DispatchedAt: entry.DispatchedAt, CompletedAt: entry.CompletedAt, Payload: payload,
	})
	if errors.Is(err, business.ErrDuplicateQueuedExecution) {
		return scriptmodule.ErrDuplicateExecution
	}
	return err
}

func (s *sharedQueueStore) Dequeue(deviceID string) ([]*scriptmodule.QueueEntry, error) {
	bs, err := s.store.Dequeue(context.Background(), deviceID, time.Now())
	if err != nil {
		return nil, err
	}
	return s.decodeAll(bs)
}

func (s *sharedQueueStore) AcknowledgeCompletion(executionID, deviceID string, state scriptmodule.QueueState, _ *scriptmodule.ExecutionResult) error {
	return s.store.AcknowledgeCompletion(context.Background(), executionID, deviceID, string(state), time.Now())
}

func (s *sharedQueueStore) Cancel(deviceID, executionID string) error {
	return s.store.Cancel(context.Background(), deviceID, executionID)
}

func (s *sharedQueueStore) RequeueStale(dispatchTimeout time.Duration) (int, error) {
	return s.store.RequeueStale(context.Background(), time.Now().Add(-dispatchTimeout))
}

func (s *sharedQueueStore) CleanupExpired() (int, error) {
	return s.store.CleanupExpired(context.Background(), time.Now())
}

func (s *sharedQueueStore) List(deviceID string) ([]*scriptmodule.QueueEntry, error) {
	bs, err := s.store.List(context.Background(), deviceID)
	if err != nil {
		return nil, err
	}
	return s.decodeAll(bs)
}

func (s *sharedQueueStore) GetStats() (scriptmodule.QueueStoreStats, error) {
	b, err := s.store.GetStats(context.Background())
	if err != nil {
		return scriptmodule.QueueStoreStats{}, err
	}
	return scriptmodule.QueueStoreStats{
		TotalEntries:      b.TotalEntries,
		QueuedCount:       b.CountsByState[business.ExecutionQueueStateQueued],
		DispatchedCount:   b.CountsByState[business.ExecutionQueueStateDispatched],
		CompletedCount:    b.CountsByState[business.ExecutionQueueStateCompleted],
		FailedCount:       b.CountsByState[business.ExecutionQueueStateFailed],
		ExpiredCount:      b.CountsByState[business.ExecutionQueueStateExpired],
		CancelledCount:    b.CountsByState[business.ExecutionQueueStateCancelled],
		DeviceQueueDepths: b.DeviceQueueDepths,
	}, nil
}
