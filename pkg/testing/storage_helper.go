// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package testing provides testing utilities for CFGMS components
package testing

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing — OSS composite (flatfile + SQLite)
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// SetupTestStorage creates an OSS composite storage manager for testing.
// Uses flatfile (config/audit/steward) and SQLite (business data) providers backed
// by temporary directories — each call produces fully isolated storage.
//
// The returned manager is registered with t.Cleanup to close all SQLite handles
// before t.TempDir cleanup runs. This is required on Windows, where RemoveAll
// fails if any database file is still held open.
func SetupTestStorage(t *testing.T) *interfaces.StorageManager {
	t.Helper()

	flatfileRoot := t.TempDir()
	sqlitePath := t.TempDir() + "/cfgms.db"

	storageManager, err := interfaces.CreateOSSStorageManager(flatfileRoot, sqlitePath)
	if err != nil {
		t.Fatalf("Failed to create test storage: %v", err)
	}

	t.Cleanup(func() {
		if err := storageManager.Close(); err != nil {
			t.Logf("SetupTestStorage cleanup: storage close error: %v", err)
		}
	})

	return storageManager
}

// SetupTestRBACManager creates an RBAC manager with git storage for testing
func SetupTestRBACManager(t *testing.T) *rbac.Manager {
	storageManager := SetupTestStorage(t)

	manager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)

	// Initialize with default permissions and roles
	ctx := context.Background()

	if err := manager.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize test RBAC manager: %v", err)
	}

	return manager
}

// SetupTestAuditManager creates an audit manager with git storage for testing
func SetupTestAuditManager(t *testing.T) *audit.Manager {
	t.Helper()
	storageManager := SetupTestStorage(t)
	m, err := audit.NewManager(storageManager.GetAuditStore(), "test")
	if err != nil {
		t.Fatalf("Failed to initialize test audit manager: %v", err)
	}
	return m
}
