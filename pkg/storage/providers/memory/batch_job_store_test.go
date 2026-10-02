// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

func newMemTestBatchJob(id, tenantID string) *batchjob.BatchJob {
	now := time.Now().UTC()
	return &batchjob.BatchJob{
		ID:       id,
		TenantID: tenantID,
		Selector: "tag:staging",
		Config: batchjob.BatchJobConfig{
			BatchSize:         3,
			PreviousConfigRef: "cfg-v2",
		},
		Targets:     []string{"s-a", "s-b"},
		Status:      batchjob.BatchJobStatusPending,
		Steps:       []batchjob.BatchStep{{Index: 0, StewardIDs: []string{"s-a"}, Status: batchjob.BatchStepStatusPending}},
		CreatedAt:   now,
		UpdatedAt:   now,
		InitiatedBy: "admin@example.com",
	}
}

func TestBatchJobStore_Memory_InitializeAndHealthCheck(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))
	require.NoError(t, store.Close())
}

func TestBatchJobStore_Memory_CreateAndGet(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	job := newMemTestBatchJob("job-mem-1", "tenant-1")
	require.NoError(t, store.CreateBatchJob(ctx, job))

	got, err := store.GetBatchJob(ctx, "job-mem-1")
	require.NoError(t, err)
	assert.Equal(t, "job-mem-1", got.ID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, batchjob.BatchJobStatusPending, got.Status)
	assert.Equal(t, "tag:staging", got.Selector)
	assert.Equal(t, 3, got.Config.BatchSize)
	assert.Equal(t, "cfg-v2", got.Config.PreviousConfigRef)
	assert.Equal(t, []string{"s-a", "s-b"}, got.Targets)
	assert.Equal(t, "admin@example.com", got.InitiatedBy)
}

func TestBatchJobStore_Memory_CreateDuplicateIDReturnsError(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	job := newMemTestBatchJob("job-dup", "tenant-1")
	require.NoError(t, store.CreateBatchJob(ctx, job))
	err := store.CreateBatchJob(ctx, job)
	require.Error(t, err)
}

func TestBatchJobStore_Memory_GetNotFound(t *testing.T) {
	store := memory.NewBatchJobStore()
	_, err := store.GetBatchJob(context.Background(), "no-such-id")
	assert.ErrorIs(t, err, business.ErrBatchJobNotFound)
}

func TestBatchJobStore_Memory_UpdateBatchJobStatus(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("job-s", "tenant-1")))

	require.NoError(t, store.UpdateBatchJobStatus(ctx, "job-s", batchjob.BatchJobStatusRunning))
	got, err := store.GetBatchJob(ctx, "job-s")
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusRunning, got.Status)

	require.NoError(t, store.UpdateBatchJobStatus(ctx, "job-s", batchjob.BatchJobStatusPaused))
	got, err = store.GetBatchJob(ctx, "job-s")
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusPaused, got.Status)
}

func TestBatchJobStore_Memory_UpdateBatchJobStatusNotFound(t *testing.T) {
	store := memory.NewBatchJobStore()
	err := store.UpdateBatchJobStatus(context.Background(), "ghost", batchjob.BatchJobStatusFailed)
	assert.ErrorIs(t, err, business.ErrBatchJobNotFound)
}

func TestBatchJobStore_Memory_UpdateBatchStep(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("job-step", "tenant-1")))

	now := time.Now().UTC()
	completed := now.Add(30 * time.Second)
	step := batchjob.BatchStep{
		Index:         0,
		StewardIDs:    []string{"s-a"},
		Status:        batchjob.BatchStepStatusCompleted,
		StartedAt:     &now,
		CompletedAt:   &completed,
		FailedIDs:     []string{},
		RollbackJobID: "",
	}
	require.NoError(t, store.UpdateBatchStep(ctx, "job-step", step))

	got, err := store.GetBatchJob(ctx, "job-step")
	require.NoError(t, err)
	require.Len(t, got.Steps, 1)
	s := got.Steps[0]
	assert.Equal(t, 0, s.Index)
	assert.Equal(t, batchjob.BatchStepStatusCompleted, s.Status)
	require.NotNil(t, s.StartedAt)
	require.NotNil(t, s.CompletedAt)
}

func TestBatchJobStore_Memory_UpdateBatchStepNotFound(t *testing.T) {
	store := memory.NewBatchJobStore()
	step := batchjob.BatchStep{Index: 0}
	err := store.UpdateBatchStep(context.Background(), "ghost-job", step)
	assert.ErrorIs(t, err, business.ErrBatchJobNotFound)
}

func TestBatchJobStore_Memory_ListBatchJobsByTenant(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("j-a1", "tenant-A")))
	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("j-a2", "tenant-A")))
	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("j-b1", "tenant-B")))

	listA, err := store.ListBatchJobsByTenant(ctx, "tenant-A")
	require.NoError(t, err)
	assert.Len(t, listA, 2)

	listB, err := store.ListBatchJobsByTenant(ctx, "tenant-B")
	require.NoError(t, err)
	assert.Len(t, listB, 1)
	assert.Equal(t, "j-b1", listB[0].ID)

	listNone, err := store.ListBatchJobsByTenant(ctx, "tenant-unknown")
	require.NoError(t, err)
	assert.Empty(t, listNone)
}

func TestBatchJobStore_Memory_ConcurrencySafe(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	const workers = 20
	errs := make(chan error, workers*4)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		go func(n int) {
			defer wg.Done()
			id := "concurrent-job-" + string(rune('a'+n))
			tenantID := "tenant-" + string(rune('a'+n%3))
			job := newMemTestBatchJob(id, tenantID)
			if err := store.CreateBatchJob(ctx, job); err != nil {
				errs <- err
				return
			}
			if _, err := store.GetBatchJob(ctx, id); err != nil {
				errs <- err
			}
			if err := store.UpdateBatchJobStatus(ctx, id, batchjob.BatchJobStatusRunning); err != nil {
				errs <- err
			}
			if _, err := store.ListBatchJobsByTenant(ctx, tenantID); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}

func TestBatchJobStore_Memory_CreateIsolatesFromMutation(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	job := newMemTestBatchJob("job-alias", "tenant-1")
	require.NoError(t, store.CreateBatchJob(ctx, job))

	// Mutating original after create must not affect stored copy.
	job.Status = batchjob.BatchJobStatusFailed
	job.Targets = append(job.Targets, "s-mutated")
	job.Steps[0].StewardIDs = append(job.Steps[0].StewardIDs, "s-injected")

	got, err := store.GetBatchJob(ctx, "job-alias")
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusPending, got.Status)
	assert.Len(t, got.Targets, 2)
	require.Len(t, got.Steps, 1)
	assert.Len(t, got.Steps[0].StewardIDs, 1, "step StewardIDs must be deep-copied on create")
}

func TestBatchJobStore_Memory_GetIsolatesFromMutation(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("job-get-alias", "tenant-1")))

	got, err := store.GetBatchJob(ctx, "job-get-alias")
	require.NoError(t, err)

	// Mutating returned copy must not affect stored value.
	got.Status = batchjob.BatchJobStatusFailed
	got.Targets = append(got.Targets, "s-extra")
	got.Steps[0].StewardIDs = append(got.Steps[0].StewardIDs, "s-injected")

	got2, err := store.GetBatchJob(ctx, "job-get-alias")
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusPending, got2.Status)
	assert.Len(t, got2.Targets, 2)
	require.Len(t, got2.Steps, 1)
	assert.Len(t, got2.Steps[0].StewardIDs, 1, "step StewardIDs must be deep-copied on get")
}

func TestBatchJobStore_Memory_UpdateBatchStepAppendNewIndex(t *testing.T) {
	store := memory.NewBatchJobStore()
	ctx := context.Background()

	require.NoError(t, store.CreateBatchJob(ctx, newMemTestBatchJob("job-append", "tenant-1")))

	// Append a step with an index not present in the original fixture.
	newStep := batchjob.BatchStep{
		Index:      1,
		StewardIDs: []string{"s-b"},
		Status:     batchjob.BatchStepStatusPending,
	}
	require.NoError(t, store.UpdateBatchStep(ctx, "job-append", newStep))

	got, err := store.GetBatchJob(ctx, "job-append")
	require.NoError(t, err)
	assert.Len(t, got.Steps, 2, "new index must be appended, not replace existing")

	// The original step (index 0) is unchanged.
	assert.Equal(t, 0, got.Steps[0].Index)
	// The new step (index 1) is present.
	found := false
	for _, s := range got.Steps {
		if s.Index == 1 {
			found = true
			assert.Equal(t, batchjob.BatchStepStatusPending, s.Status)
			assert.Equal(t, []string{"s-b"}, s.StewardIDs)
		}
	}
	assert.True(t, found, "appended step with index 1 must be present")
}
