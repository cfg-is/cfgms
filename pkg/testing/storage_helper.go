// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package testing provides testing utilities for CFGMS components
package testing

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing — OSS composite (flatfile + SQLite)
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// testStorageSeq produces unique in-memory SQLite database names across all tests.
var testStorageSeq int64

// SetupTestStorage creates an OSS composite storage manager for testing.
// Uses flatfile (config/audit/steward) and a named in-memory SQLite (business data).
//
// Named in-memory SQLite avoids file I/O entirely. On Windows CI, WAL mode's
// FlushFileBuffers call blocks for minutes under load — switching to in-memory
// eliminates that syscall while preserving per-call isolation (distinct names).
func SetupTestStorage(t *testing.T) *interfaces.StorageManager {
	t.Helper()

	flatfileRoot := t.TempDir()
	seq := atomic.AddInt64(&testStorageSeq, 1)
	sqlitePath := fmt.Sprintf("file:cfgms-test-%d?mode=memory&cache=shared", seq)

	storageManager, err := interfaces.CreateOSSStorageManager(flatfileRoot, sqlitePath)
	if err != nil {
		t.Fatalf("Failed to create test storage: %v", err)
	}

	t.Cleanup(func() {
		// Close releases the in-memory SQLite database. This also prevents the
		// named in-memory DB from persisting beyond the test's lifetime.
		if err := storageManager.Close(); err != nil {
			t.Logf("SetupTestStorage cleanup: storage close error: %v", err)
		}
	})

	return storageManager
}

// SetupTestRBACManager creates an RBAC manager with git storage for testing.
//
// A FlushAudit cleanup is registered so pending async audit writes land before
// SetupTestStorage closes the storage manager and t.TempDir removes the flatfile
// directory. Without this flush, the cleanup races with audit writes and fails
// with "directory not empty" on Linux or held-handle errors on Windows.
func SetupTestRBACManager(t *testing.T) *rbac.Manager {
	storageManager := SetupTestStorage(t)

	manager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)

	ctx := context.Background()
	if err := manager.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize test RBAC manager: %v", err)
	}

	t.Cleanup(func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.FlushAudit(flushCtx); err != nil {
			t.Logf("SetupTestRBACManager cleanup: FlushAudit error: %v", err)
		}
	})

	return manager
}

// SetupTestAuditManager creates an audit manager with git storage for testing.
// The manager's background drain goroutine is stopped automatically on test
// cleanup so pending entries reach the store and the goroutine does not leak
// between tests (Issue #764).
func SetupTestAuditManager(t *testing.T) *audit.Manager {
	t.Helper()
	storageManager := SetupTestStorage(t)
	m, err := audit.NewManager(storageManager.GetAuditStore(), "test")
	if err != nil {
		t.Fatalf("Failed to initialize test audit manager: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
	})
	return m
}
