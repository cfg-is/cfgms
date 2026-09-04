// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Module-approval-store wiring tests (ADR-031 Decision 1, Issue #3886). These cover
// CreateClusterStorageManager's ModuleApprovalStoreCreator branch and the
// StorageManager accessors it writes through — the glue that makes module bundle
// approval status cluster-visible in a clustered controller. Mirrors
// cert_store_wiring_test.go's shape for CertRevocationStoreCreator/SigningCursorStoreCreator
// (Issue #3852).
//
// They live in the external interfaces_test package because the real store
// implementation ships in pkg/storage/providers/database, which imports
// pkg/storage/interfaces — an in-package test importing it would be an import cycle.
package interfaces_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestDatabaseProvider_SatisfiesModuleApprovalStoreCreator pins the type assertion
// CreateClusterStorageManager makes, on the value it actually makes it on: the
// provider the registry hands back for "database". The failed-assertion failure mode
// is silent — the store is never created and a clustered controller falls back to
// ModuleCache's node-local file store with no error anywhere.
func TestDatabaseProvider_SatisfiesModuleApprovalStoreCreator(t *testing.T) {
	provider, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err, "the database provider must be registered (blank-imported in providers_test.go)")

	_, ok := provider.(interfaces.ModuleApprovalStoreCreator)
	assert.True(t, ok,
		"the database provider must satisfy ModuleApprovalStoreCreator — CreateClusterStorageManager wires the cluster-visible module approval store through exactly this assertion")
}

// TestOSSStorageManager_ModuleApprovalStoreUnwiredAndSettable covers the other side of
// the wiring contract, without a database: a provider that does not implement the
// creator extension leaves the accessor nil, which is the signal the server-startup
// wiring reads to leave ModuleCache on its file-backed default (single-node
// deployments see no behavioural change). The Set/Get accessors then round-trip a
// real store, since those setters are the only path by which the created store
// reaches the manager.
func TestOSSStorageManager_ModuleApprovalStoreUnwiredAndSettable(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "oss-module-approval.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Nil(t, sm.GetModuleApprovalStore(),
		"the OSS tier's providers implement no ModuleApprovalStoreCreator, so the accessor must stay nil and callers must fall back to the file-backed store")

	// Round-trip through the setter with a real implementation (pkg/testing's
	// in-process reference store — no mock framework).
	store := pkgtesting.SetupTestModuleApprovalStore()
	sm.SetModuleApprovalStore(store)

	assert.Same(t, store, sm.GetModuleApprovalStore(),
		"GetModuleApprovalStore must return the store SetModuleApprovalStore was handed")
}

// TestCreateClusterStorageManager_ModuleApprovalStore verifies the cluster tier — the
// tier a real multi-node deployment runs on — wires a working, cluster-visible
// approval store through CreateClusterStorageManager itself rather than through a
// hand-constructed store.
//
// Two independently created StorageManagers over the same DSN stand in for two
// controller nodes: a status written through node A's wired store is observed, and
// CAS-protected, through node B's wired store with no restart and no shared
// in-process state. Skipped when PostgreSQL is not reachable.
func TestCreateClusterStorageManager_ModuleApprovalStore(t *testing.T) {
	dsn := skipIfNoPostgres(t)

	nodeA, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	storeA := nodeA.GetModuleApprovalStore()
	require.NotNil(t, storeA,
		"GetModuleApprovalStore must be wired — the database provider supplies it, and a nil here silently drops a clustered controller back to node-local approval status")

	nodeB, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	storeB := nodeB.GetModuleApprovalStore()
	require.NotNil(t, storeB)

	ctx := context.Background()
	addr := fmt.Sprintf("wiring-test/module/1.0.0/%d", time.Now().UnixNano())
	t.Cleanup(func() { deleteModuleApprovalRow(t, dsn, addr) })

	effective, err := storeA.PutApprovalStatusIfAbsent(ctx, addr, business.ModuleApprovalPending)
	require.NoError(t, err)
	require.Equal(t, business.ModuleApprovalPending, effective)

	statusFromB, found, err := storeB.GetApprovalStatus(ctx, addr)
	require.NoError(t, err)
	require.True(t, found, "a status written through one wired store must be observed through another node's wired store")
	assert.Equal(t, business.ModuleApprovalPending, statusFromB)

	ok, err := storeB.CompareAndSetApprovalStatus(ctx, addr, business.ModuleApprovalPending, business.ModuleApprovalApproved)
	require.NoError(t, err)
	assert.True(t, ok, "node B's CAS must win against the status node A wrote")

	statusFromA, found, err := storeA.GetApprovalStatus(ctx, addr)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalApproved, statusFromA,
		"node A must observe the transition node B performed, with no restart")

	// A second CAS from the now-stale "pending" expectation must be refused — the
	// serialization that keeps approval decisions from diverging across nodes.
	ok, err = storeA.CompareAndSetApprovalStatus(ctx, addr, business.ModuleApprovalPending, business.ModuleApprovalRejected)
	require.NoError(t, err)
	assert.False(t, ok, "a stale CAS must be refused rather than overwrite the already-decided status")
}

// deleteModuleApprovalRow removes a test address from the shared cluster database so
// repeated runs against a persistent test Postgres start clean.
func deleteModuleApprovalRow(t *testing.T, dsn, addr string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Logf("cleanup: open postgres: %v", err)
		return
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DELETE FROM cfgms_module_approvals WHERE address = $1`, addr); err != nil {
		t.Logf("cleanup: delete module approval row: %v", err)
	}
}
