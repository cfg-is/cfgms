// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package memory provides in-memory storage implementations for development and testing.
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// BatchJobStore is a thread-safe in-memory implementation of business.BatchJobStore.
// Used in tests and development environments where durable batch-job persistence
// is not required. All mutations deep-copy the stored record to prevent aliasing.
type BatchJobStore struct {
	mu   sync.RWMutex
	jobs map[string]*batchjob.BatchJob
}

// NewBatchJobStore returns an initialised in-memory BatchJobStore.
func NewBatchJobStore() *BatchJobStore {
	return &BatchJobStore{jobs: make(map[string]*batchjob.BatchJob)}
}

// CreateBatchJob inserts a new batch job. Returns an error if a record with
// the same ID already exists.
func (s *BatchJobStore) CreateBatchJob(_ context.Context, job *batchjob.BatchJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[job.ID]; exists {
		return fmt.Errorf("batch job %q already exists", job.ID)
	}
	s.jobs[job.ID] = deepCopyJob(job)
	return nil
}

// UpdateBatchJobStatus sets the top-level status and updates UpdatedAt.
func (s *BatchJobStore) UpdateBatchJobStatus(_ context.Context, id string, status batchjob.BatchJobStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return business.ErrBatchJobNotFound
	}
	j.Status = status
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// UpdateBatchTargets replaces the resolved target steward IDs for the job.
func (s *BatchJobStore) UpdateBatchTargets(_ context.Context, id string, targets []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return business.ErrBatchJobNotFound
	}
	j.Targets = append([]string(nil), targets...)
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// UpdateBatchStep upserts the step identified by step.Index within the job.
// A matching index is replaced in-place; an unrecognised index appends a new step.
func (s *BatchJobStore) UpdateBatchStep(_ context.Context, jobID string, step batchjob.BatchStep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		return business.ErrBatchJobNotFound
	}
	cp := copyStep(step)
	for i := range j.Steps {
		if j.Steps[i].Index == step.Index {
			j.Steps[i] = cp
			j.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	j.Steps = append(j.Steps, cp)
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// GetBatchJob retrieves a deep copy of the batch job identified by id.
func (s *BatchJobStore) GetBatchJob(_ context.Context, id string) (*batchjob.BatchJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, business.ErrBatchJobNotFound
	}
	return deepCopyJob(j), nil
}

// ListBatchJobsByTenant returns deep copies of all jobs belonging to tenantID.
func (s *BatchJobStore) ListBatchJobsByTenant(_ context.Context, tenantID string) ([]*batchjob.BatchJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*batchjob.BatchJob
	for _, j := range s.jobs {
		if j.TenantID == tenantID {
			out = append(out, deepCopyJob(j))
		}
	}
	return out, nil
}

func (s *BatchJobStore) HealthCheck(_ context.Context) error { return nil }
func (s *BatchJobStore) Initialize(_ context.Context) error  { return nil }
func (s *BatchJobStore) Close() error                        { return nil }

var _ business.BatchJobStore = (*BatchJobStore)(nil)

// deepCopyJob returns a fully independent copy of job, preventing aliasing
// between the store's internal state and caller-held pointers.
func deepCopyJob(j *batchjob.BatchJob) *batchjob.BatchJob {
	cp := *j
	cp.Targets = append([]string(nil), j.Targets...)
	cp.Steps = make([]batchjob.BatchStep, len(j.Steps))
	for i, s := range j.Steps {
		cp.Steps[i] = copyStep(s)
	}
	return &cp
}

// copyStep returns an independent copy of a BatchStep.
func copyStep(s batchjob.BatchStep) batchjob.BatchStep {
	cp := s
	cp.StewardIDs = append([]string(nil), s.StewardIDs...)
	cp.FailedIDs = append([]string(nil), s.FailedIDs...)
	if s.StartedAt != nil {
		t := *s.StartedAt
		cp.StartedAt = &t
	}
	if s.CompletedAt != nil {
		t := *s.CompletedAt
		cp.CompletedAt = &t
	}
	return cp
}
