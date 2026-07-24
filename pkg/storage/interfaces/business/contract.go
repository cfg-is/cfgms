// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

func newContractBatchJob(id, tenantID string) *batchjob.BatchJob {
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

// BatchJobStoreContract runs the full BatchJobStore contract test suite against store.
// Call from provider-specific test files to validate a new BatchJobStore implementation:
//
//	func TestMySQLiteBatchJobStore_Contract(t *testing.T) {
//	    store := openStore(t)
//	    business.BatchJobStoreContract(t, store)
//	}
func BatchJobStoreContract(t *testing.T, store BatchJobStore) {
	t.Helper()
	ctx := context.Background()

	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get round-trip", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-1", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		got, err := store.GetBatchJob(ctx, "ctr-job-1")
		require.NoError(t, err)
		assert.Equal(t, "ctr-job-1", got.ID)
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
		job := newContractBatchJob("ctr-job-dup", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))
		err := store.CreateBatchJob(ctx, job)
		require.Error(t, err)
	})

	t.Run("get not found returns ErrBatchJobNotFound", func(t *testing.T) {
		_, err := store.GetBatchJob(ctx, "ctr-no-such-id")
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchJobStatus reflects in Get", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-status", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		require.NoError(t, store.UpdateBatchJobStatus(ctx, "ctr-job-status", batchjob.BatchJobStatusRunning))
		got, err := store.GetBatchJob(ctx, "ctr-job-status")
		require.NoError(t, err)
		assert.Equal(t, batchjob.BatchJobStatusRunning, got.Status)

		require.NoError(t, store.UpdateBatchJobStatus(ctx, "ctr-job-status", batchjob.BatchJobStatusCompleted))
		got, err = store.GetBatchJob(ctx, "ctr-job-status")
		require.NoError(t, err)
		assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
	})

	t.Run("UpdateBatchJobStatus not found", func(t *testing.T) {
		err := store.UpdateBatchJobStatus(ctx, "ctr-ghost", batchjob.BatchJobStatusFailed)
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchTargets reflects in Get", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-targets", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		newTargets := []string{"s-10", "s-11", "s-12"}
		require.NoError(t, store.UpdateBatchTargets(ctx, "ctr-job-targets", newTargets))

		got, err := store.GetBatchJob(ctx, "ctr-job-targets")
		require.NoError(t, err)
		assert.Equal(t, newTargets, got.Targets)
	})

	t.Run("UpdateBatchTargets not found", func(t *testing.T) {
		err := store.UpdateBatchTargets(ctx, "ctr-ghost-targets", []string{"s-1"})
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchStep round-trips step fields", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-step", "tenant-1")
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
		require.NoError(t, store.UpdateBatchStep(ctx, "ctr-job-step", step))

		got, err := store.GetBatchJob(ctx, "ctr-job-step")
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
		err := store.UpdateBatchStep(ctx, "ctr-ghost-step", step)
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchStep appends step with new index", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-step-append", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		newStep := batchjob.BatchStep{
			Index:      1,
			StewardIDs: []string{"s-2"},
			Status:     batchjob.BatchStepStatusPending,
		}
		require.NoError(t, store.UpdateBatchStep(ctx, "ctr-job-step-append", newStep))

		got, err := store.GetBatchJob(ctx, "ctr-job-step-append")
		require.NoError(t, err)
		assert.Len(t, got.Steps, 2, "new index must be appended, not replace existing")
	})

	t.Run("ListBatchJobsByTenant scopes by tenant", func(t *testing.T) {
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-job-ta-1", "ctr-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-job-ta-2", "ctr-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-job-tb-1", "ctr-tenant-B")))

		listA, err := store.ListBatchJobsByTenant(ctx, "ctr-tenant-A")
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		listB, err := store.ListBatchJobsByTenant(ctx, "ctr-tenant-B")
		require.NoError(t, err)
		assert.Len(t, listB, 1)
		assert.Equal(t, "ctr-job-tb-1", listB[0].ID)

		listNone, err := store.ListBatchJobsByTenant(ctx, "ctr-tenant-unknown")
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	t.Run("ListBatchJobs scopes by tenant and paginates", func(t *testing.T) {
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-list-ta-1", "ctr-list-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-list-ta-2", "ctr-list-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-list-tb-1", "ctr-list-tenant-B")))

		// Tenant-scoped: only tenant-A's jobs.
		listA, err := store.ListBatchJobs(ctx, "ctr-list-tenant-A", 50, 0)
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		// Tenant-scoped with limit=1: pagination works.
		listA1, err := store.ListBatchJobs(ctx, "ctr-list-tenant-A", 1, 0)
		require.NoError(t, err)
		assert.Len(t, listA1, 1)

		// Global (empty tenant): returns all jobs including both tenants.
		listAll, err := store.ListBatchJobs(ctx, "", 500, 0)
		require.NoError(t, err)
		// At least the 3 we just inserted (other test cases may have inserted more).
		assert.GreaterOrEqual(t, len(listAll), 3)

		// Unknown tenant returns empty slice, not nil.
		listNone, err := store.ListBatchJobs(ctx, "ctr-list-tenant-unknown", 50, 0)
		require.NoError(t, err)
		assert.NotNil(t, listNone)
		assert.Empty(t, listNone)
	})

	require.NoError(t, store.Close())
}
