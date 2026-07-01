// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemBatchJobStore is a minimal in-memory BatchJobStore for contract testing only.
type inMemBatchJobStore struct {
	mu   sync.RWMutex
	jobs map[string]*batchjob.BatchJob
}

func newInMemBatchJobStore() business.BatchJobStore {
	return &inMemBatchJobStore{jobs: make(map[string]*batchjob.BatchJob)}
}

func (s *inMemBatchJobStore) CreateBatchJob(_ context.Context, job *batchjob.BatchJob) error {
	if job == nil {
		return errBatchJobTestNilRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[job.ID]; exists {
		return errBatchJobTestDuplicateID
	}
	cp := deepCopyBatchJob(job)
	s.jobs[job.ID] = cp
	return nil
}

func (s *inMemBatchJobStore) UpdateBatchJobStatus(_ context.Context, id string, status batchjob.BatchJobStatus) error {
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

func (s *inMemBatchJobStore) UpdateBatchStep(_ context.Context, jobID string, step batchjob.BatchStep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		return business.ErrBatchJobNotFound
	}
	for i := range j.Steps {
		if j.Steps[i].Index == step.Index {
			j.Steps[i] = copyBatchStep(step)
			j.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	j.Steps = append(j.Steps, copyBatchStep(step))
	j.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *inMemBatchJobStore) GetBatchJob(_ context.Context, id string) (*batchjob.BatchJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, business.ErrBatchJobNotFound
	}
	return deepCopyBatchJob(j), nil
}

func (s *inMemBatchJobStore) ListBatchJobsByTenant(_ context.Context, tenantID string) ([]*batchjob.BatchJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*batchjob.BatchJob
	for _, j := range s.jobs {
		if j.TenantID == tenantID {
			out = append(out, deepCopyBatchJob(j))
		}
	}
	return out, nil
}

func (s *inMemBatchJobStore) HealthCheck(_ context.Context) error { return nil }
func (s *inMemBatchJobStore) Initialize(_ context.Context) error  { return nil }
func (s *inMemBatchJobStore) Close() error                        { return nil }

var _ business.BatchJobStore = (*inMemBatchJobStore)(nil)

// deep copy helpers
func deepCopyBatchJob(j *batchjob.BatchJob) *batchjob.BatchJob {
	cp := *j
	cp.Targets = append([]string(nil), j.Targets...)
	cp.Steps = make([]batchjob.BatchStep, len(j.Steps))
	for i, s := range j.Steps {
		cp.Steps[i] = copyBatchStep(s)
	}
	return &cp
}

func copyBatchStep(s batchjob.BatchStep) batchjob.BatchStep {
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

var (
	errBatchJobTestNilRecord   = errBatchJobTestStr("nil job record")
	errBatchJobTestDuplicateID = errBatchJobTestStr("duplicate batch job ID")
)

type errBatchJobTestStr string

func (e errBatchJobTestStr) Error() string { return string(e) }

// --- Contract tests ---

func newTestBatchJob(id, tenantID string) *batchjob.BatchJob {
	now := time.Now().UTC()
	return &batchjob.BatchJob{
		ID:       id,
		TenantID: tenantID,
		Selector: "tag:prod",
		Config: batchjob.BatchJobConfig{
			BatchSize:         5,
			PreviousConfigRef: "cfg-v1",
		},
		Targets:     []string{"s-1", "s-2", "s-3"},
		Status:      batchjob.BatchJobStatusPending,
		Steps:       []batchjob.BatchStep{{Index: 0, StewardIDs: []string{"s-1"}, Status: batchjob.BatchStepStatusPending}},
		CreatedAt:   now,
		UpdatedAt:   now,
		InitiatedBy: "operator@example.com",
	}
}

func TestBatchJobStore_Contract(t *testing.T) {
	store := newInMemBatchJobStore()
	ctx := context.Background()

	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get round-trip", func(t *testing.T) {
		job := newTestBatchJob("job-1", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		got, err := store.GetBatchJob(ctx, "job-1")
		require.NoError(t, err)
		assert.Equal(t, "job-1", got.ID)
		assert.Equal(t, "tenant-1", got.TenantID)
		assert.Equal(t, batchjob.BatchJobStatusPending, got.Status)
		assert.Equal(t, "tag:prod", got.Selector)
		assert.Equal(t, 5, got.Config.BatchSize)
		assert.Equal(t, "cfg-v1", got.Config.PreviousConfigRef)
		assert.Equal(t, []string{"s-1", "s-2", "s-3"}, got.Targets)
		assert.Equal(t, "operator@example.com", got.InitiatedBy)
		assert.Len(t, got.Steps, 1)
	})

	t.Run("duplicate ID returns error", func(t *testing.T) {
		job := newTestBatchJob("job-dup", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))
		err := store.CreateBatchJob(ctx, job)
		require.Error(t, err)
	})

	t.Run("get not found returns ErrBatchJobNotFound", func(t *testing.T) {
		_, err := store.GetBatchJob(ctx, "no-such-id")
		assert.ErrorIs(t, err, business.ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchJobStatus reflects in Get", func(t *testing.T) {
		job := newTestBatchJob("job-status", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		require.NoError(t, store.UpdateBatchJobStatus(ctx, "job-status", batchjob.BatchJobStatusRunning))
		got, err := store.GetBatchJob(ctx, "job-status")
		require.NoError(t, err)
		assert.Equal(t, batchjob.BatchJobStatusRunning, got.Status)

		require.NoError(t, store.UpdateBatchJobStatus(ctx, "job-status", batchjob.BatchJobStatusCompleted))
		got, err = store.GetBatchJob(ctx, "job-status")
		require.NoError(t, err)
		assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
	})

	t.Run("UpdateBatchJobStatus not found", func(t *testing.T) {
		err := store.UpdateBatchJobStatus(ctx, "ghost", batchjob.BatchJobStatusFailed)
		assert.ErrorIs(t, err, business.ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchStep round-trips step fields", func(t *testing.T) {
		job := newTestBatchJob("job-step", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		now := time.Now().UTC()
		step := batchjob.BatchStep{
			Index:         0,
			StewardIDs:    []string{"s-1"},
			Status:        batchjob.BatchStepStatusRunning,
			StartedAt:     &now,
			FailedIDs:     []string{"s-1"},
			RollbackJobID: "rj-001",
		}
		require.NoError(t, store.UpdateBatchStep(ctx, "job-step", step))

		got, err := store.GetBatchJob(ctx, "job-step")
		require.NoError(t, err)
		require.Len(t, got.Steps, 1)
		s := got.Steps[0]
		assert.Equal(t, 0, s.Index)
		assert.Equal(t, batchjob.BatchStepStatusRunning, s.Status)
		assert.Equal(t, []string{"s-1"}, s.FailedIDs)
		assert.Equal(t, "rj-001", s.RollbackJobID)
		require.NotNil(t, s.StartedAt)
	})

	t.Run("UpdateBatchStep not found", func(t *testing.T) {
		step := batchjob.BatchStep{Index: 0, Status: batchjob.BatchStepStatusFailed}
		err := store.UpdateBatchStep(ctx, "ghost-job", step)
		assert.ErrorIs(t, err, business.ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchStep appends step with new index", func(t *testing.T) {
		job := newTestBatchJob("job-step-append", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		newStep := batchjob.BatchStep{
			Index:      1,
			StewardIDs: []string{"s-2"},
			Status:     batchjob.BatchStepStatusPending,
		}
		require.NoError(t, store.UpdateBatchStep(ctx, "job-step-append", newStep))

		got, err := store.GetBatchJob(ctx, "job-step-append")
		require.NoError(t, err)
		assert.Len(t, got.Steps, 2, "new index must be appended, not replace existing")
	})

	t.Run("ListBatchJobsByTenant scopes by tenant", func(t *testing.T) {
		require.NoError(t, store.CreateBatchJob(ctx, newTestBatchJob("job-ta-1", "tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newTestBatchJob("job-ta-2", "tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newTestBatchJob("job-tb-1", "tenant-B")))

		listA, err := store.ListBatchJobsByTenant(ctx, "tenant-A")
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		listB, err := store.ListBatchJobsByTenant(ctx, "tenant-B")
		require.NoError(t, err)
		assert.Len(t, listB, 1)
		assert.Equal(t, "job-tb-1", listB[0].ID)

		listNone, err := store.ListBatchJobsByTenant(ctx, "tenant-unknown")
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	require.NoError(t, store.Close())
}

func TestErrBatchJobNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrBatchJobNotFound)
	assert.Equal(t, "batch job not found", business.ErrBatchJobNotFound.Error())
}
