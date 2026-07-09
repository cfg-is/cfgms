// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func openTestSQLiteStore(t *testing.T) *batchjob.SQLiteBatchJobStore {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "batch_jobs.db")
	store, err := batchjob.NewSQLiteBatchJobStoreFromDSN(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestSQLiteBatchJobStore_Contract validates that SQLiteBatchJobStore satisfies the
// full BatchJobStore interface contract defined in pkg/storage/interfaces/business.
// Run with -race to verify concurrent-access safety.
func TestSQLiteBatchJobStore_Contract(t *testing.T) {
	store := openTestSQLiteStore(t)
	// business.BatchJobStoreContract calls Initialize and Close internally.
	business.BatchJobStoreContract(t, store)
}

// TestSQLiteBatchJobStore_ReopenPersists verifies that data written in one
// SQLiteBatchJobStore instance is visible after reopening the same file.
func TestSQLiteBatchJobStore_ReopenPersists(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "batch_jobs.db")

	// First connection: create and populate a job.
	{
		store, err := batchjob.NewSQLiteBatchJobStoreFromDSN(dsn)
		require.NoError(t, err)
		ctx := t.Context()
		require.NoError(t, store.Initialize(ctx))
		job := &batchjob.BatchJob{
			ID:       "persist-job-1",
			TenantID: "t-1",
			Selector: "all",
			Config:   batchjob.BatchJobConfig{BatchSize: 2},
			Targets:  []string{"s-1"},
			Status:   batchjob.BatchJobStatusPending,
		}
		require.NoError(t, store.CreateBatchJob(ctx, job))
		require.NoError(t, store.Close())
	}

	// Second connection: data must still be there.
	{
		store, err := batchjob.NewSQLiteBatchJobStoreFromDSN(dsn)
		require.NoError(t, err)
		ctx := t.Context()
		require.NoError(t, store.Initialize(ctx))
		got, err := store.GetBatchJob(ctx, "persist-job-1")
		require.NoError(t, err)
		require.Equal(t, batchjob.BatchJobStatusPending, got.Status)
		require.Equal(t, []string{"s-1"}, got.Targets)
		require.NoError(t, store.Close())
	}
}
