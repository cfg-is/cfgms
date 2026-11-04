// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// openSQLiteStoreAt opens the SQLite file at path the way a caller must before
// handing the connection to NewSQLiteBatchJobStore.
func openSQLiteStoreAt(t *testing.T, path string) *batchjob.SQLiteBatchJobStore {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec("PRAGMA busy_timeout = 5000")
	if err != nil {
		_ = db.Close()
	}
	require.NoError(t, err)
	return batchjob.NewSQLiteBatchJobStore(db)
}

func openTestSQLiteStore(t *testing.T) *batchjob.SQLiteBatchJobStore {
	t.Helper()
	store := openSQLiteStoreAt(t, filepath.Join(t.TempDir(), "batch_jobs.db"))
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
		store := openSQLiteStoreAt(t, dsn)
		ctx := t.Context()
		require.NoError(t, store.Initialize(ctx))
		job := &business.BatchJob{
			ID:       "persist-job-1",
			TenantID: "t-1",
			Selector: "all",
			Config:   business.BatchJobConfig{BatchSize: 2},
			Targets:  []string{"s-1"},
			Status:   business.BatchJobStatusPending,
		}
		require.NoError(t, store.CreateBatchJob(ctx, job))
		require.NoError(t, store.Close())
	}

	// Second connection: data must still be there.
	{
		store := openSQLiteStoreAt(t, dsn)
		ctx := t.Context()
		require.NoError(t, store.Initialize(ctx))
		got, err := store.GetBatchJob(ctx, "persist-job-1")
		require.NoError(t, err)
		require.Equal(t, business.BatchJobStatusPending, got.Status)
		require.Equal(t, []string{"s-1"}, got.Targets)
		require.NoError(t, store.Close())
	}
}
