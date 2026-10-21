// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestWorkflowExecutionStoreAt builds the store through the provider factory so
// the tests also cover config parsing and path resolution.
func newTestWorkflowExecutionStoreAt(t *testing.T, path string) business.WorkflowExecutionStore {
	t.Helper()
	store, err := NewSQLiteProvider(path).CreateWorkflowExecutionStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.(*SQLiteWorkflowExecutionStore).Close() })
	return store
}

func TestSQLiteWorkflowExecutionStore_Contract(t *testing.T) {
	business.WorkflowExecutionStoreContract(t, newTestWorkflowExecutionStoreAt(t, filepath.Join(t.TempDir(), "cfgms.db")))
}

// TestSQLiteWorkflowExecutionStore_SurvivesRestart proves records are durable: a
// second store opened on the same file reads what the first one wrote.
func TestSQLiteWorkflowExecutionStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Millisecond)

	first, err := NewSQLiteProvider(path).CreateWorkflowExecutionStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	require.NoError(t, first.Save(ctx, &business.WorkflowExecutionRecord{
		TenantID: "t1", ExecutionID: "e1", WorkflowName: "wf", Status: "completed",
		StartTime: start, EndTime: start.Add(time.Second), Payload: []byte(`{"ok":true}`),
	}))
	require.NoError(t, first.(*SQLiteWorkflowExecutionStore).Close())

	second := newTestWorkflowExecutionStoreAt(t, path)
	got, err := second.Get(ctx, "t1", "e1")
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	assert.JSONEq(t, `{"ok":true}`, string(got.Payload))
}

// openNoBusyTimeoutHandle opens a second handle on path with no busy_timeout, so
// lock contention surfaces as SQLITE_BUSY immediately — the failure the Go-level
// retry must absorb.
func openNoBusyTimeoutHandle(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(0)")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestSQLiteWorkflowExecutionStore_SaveRetriesWhenWriteLockHeld holds the write lock
// from another connection and proves Save waits it out rather than returning BUSY.
// Reverting the retryOnBusy wrapper makes this fail with "database is locked".
func TestSQLiteWorkflowExecutionStore_SaveRetriesWhenWriteLockHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	newTestWorkflowExecutionStoreAt(t, path) // creates the schema
	store := &SQLiteWorkflowExecutionStore{db: openNoBusyTimeoutHandle(t, path)}

	ctx := context.Background()
	holder := openNoBusyTimeoutHandle(t, path)
	conn, err := holder.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE")
	require.NoError(t, err)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = conn.ExecContext(ctx, "COMMIT")
	}()

	rec := &business.WorkflowExecutionRecord{TenantID: "t1", ExecutionID: "e1", WorkflowName: "wf", Status: "running", StartTime: time.Now().UTC()}
	require.NoError(t, store.Save(ctx, rec))
	got, err := store.Get(ctx, "t1", "e1")
	require.NoError(t, err)
	assert.Equal(t, "running", got.Status)
}

// TestSQLiteWorkflowExecutionStore_OverlappingSaves issues concurrent saves and
// prunes from separate production handles on one file and asserts none fails (the
// forced-BUSY case is covered by the lock-held test above).
func TestSQLiteWorkflowExecutionStore_OverlappingSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	stores := []*SQLiteWorkflowExecutionStore{
		newTestWorkflowExecutionStoreAt(t, path).(*SQLiteWorkflowExecutionStore),
		newTestWorkflowExecutionStoreAt(t, path).(*SQLiteWorkflowExecutionStore),
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := stores[i%2]
			for j := 0; j < 5; j++ {
				rec := &business.WorkflowExecutionRecord{TenantID: "t1", ExecutionID: fmt.Sprintf("e-%d-%d", i, j),
					WorkflowName: "wf", Status: "completed", StartTime: time.Now().UTC()}
				if err := s.Save(ctx, rec); err != nil {
					errs <- err
				}
				if _, err := s.Prune(ctx, "t1", 50); err != nil {
					errs <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}
