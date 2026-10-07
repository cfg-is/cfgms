// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Cert-store wiring tests (ADR-031 Decision 1, Issue #3852). These cover
// CreateClusterStorageManager's CertRevocationStoreCreator/SigningCursorStoreCreator
// branches and the StorageManager accessors they write through — the glue that makes
// revocation and signing-cursor state cluster-visible in a clustered controller.
// pkg/cert's own tests construct the Postgres-backed stores directly and inject them
// via cert.ManagerConfig, so without these tests a regression in this wiring (the type
// assertion silently ceasing to match, or the created store never being set) would
// leave every node quietly back on the node-local file store with all cert-level tests
// still green.
//
// They live in the external interfaces_test package because the real store
// implementations ship in pkg/storage/providers/*, which import
// pkg/storage/interfaces — an in-package test importing them would be an import cycle.
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

	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TestDatabaseProvider_SatisfiesCertStoreCreators pins the type assertions
// CreateClusterStorageManager makes, on the value it actually makes them on: the
// provider the registry hands back for "database". Both wiring branches are
// `provider.(Creator)` checks, and a failed assertion is silent — the store is never
// created and a clustered controller falls back to node-local revocation with no
// error anywhere.
//
// The database provider carries its own compile-time assertions (plugin.go), which
// catch a renamed or re-signatured method. This test covers what those cannot: that
// the registry entry for "database" is that same type, so the runtime assertion in
// the wiring path still matches. It needs no database.
func TestDatabaseProvider_SatisfiesCertStoreCreators(t *testing.T) {
	provider, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err, "the database provider must be registered (blank-imported in providers_test.go)")

	_, revOK := provider.(interfaces.CertRevocationStoreCreator)
	assert.True(t, revOK,
		"the database provider must satisfy CertRevocationStoreCreator — CreateClusterStorageManager wires the cluster-visible revocation store through exactly this assertion")

	_, curOK := provider.(interfaces.SigningCursorStoreCreator)
	assert.True(t, curOK,
		"the database provider must satisfy SigningCursorStoreCreator — CreateClusterStorageManager wires the cluster-visible signing cursor through exactly this assertion")
}

// TestOSSStorageManager_CertStoresUnwiredAndSettable covers the other side of the
// wiring contract, without a database: a provider that does not implement the creator
// extensions leaves both accessors nil, which is the signal
// initialization.wireClusterCertStores reads to leave cert.NewManager on its
// file-backed default (AC2: a single-node deployment sees no behavioural change).
// The Set*/Get* accessors then round-trip a real store, since those setters are the
// only path by which the created stores reach the manager.
func TestOSSStorageManager_CertStoresUnwiredAndSettable(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "oss-cert-stores.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Nil(t, sm.GetCertRevocationStore(),
		"the OSS tier's providers implement no CertRevocationStoreCreator, so the accessor must stay nil and callers must fall back to the file-backed store")
	assert.Nil(t, sm.GetSigningCursorStore(),
		"the OSS tier's providers implement no SigningCursorStoreCreator, so the accessor must stay nil and callers must fall back to the file-backed store")

	// Round-trip through the setters with real implementations (pkg/cert's own
	// file-backed stores — no mock framework).
	revStore, err := cert.NewFileRevocationStore(t.TempDir())
	require.NoError(t, err)
	cursorStore, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)

	sm.SetCertRevocationStore(revStore)
	sm.SetSigningCursorStore(cursorStore)

	assert.Same(t, revStore, sm.GetCertRevocationStore(),
		"GetCertRevocationStore must return the store SetCertRevocationStore was handed")
	assert.Same(t, cursorStore, sm.GetSigningCursorStore(),
		"GetSigningCursorStore must return the store SetSigningCursorStore was handed")
}

// TestCreateClusterStorageManager_CertRevocationStore verifies the cluster tier — the
// tier a real multi-node deployment runs on — wires a working, cluster-visible
// revocation store through CreateClusterStorageManager itself rather than through a
// hand-constructed store.
//
// Two independently created StorageManagers over the same DSN stand in for two
// controller nodes: a revocation written through node A's wired store is observed
// through node B's wired store with no restart and no shared in-process state. Skipped
// when PostgreSQL is not reachable.
func TestCreateClusterStorageManager_CertRevocationStore(t *testing.T) {
	dsn := skipIfNoPostgres(t)

	nodeA, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	storeA := nodeA.GetCertRevocationStore()
	require.NotNil(t, storeA,
		"GetCertRevocationStore must be wired — the database provider supplies it, and a nil here silently drops a clustered controller back to node-local revocation")

	nodeB, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	storeB := nodeB.GetCertRevocationStore()
	require.NotNil(t, storeB)

	ctx := context.Background()
	serial := fmt.Sprintf("wiring-revocation-%d", time.Now().UnixNano())
	t.Cleanup(func() { deleteRevocationRow(t, dsn, serial) })

	revokedBefore, err := storeB.IsRevoked(ctx, serial)
	require.NoError(t, err)
	require.False(t, revokedBefore, "sanity: the serial must start out unrevoked")

	require.NoError(t, storeA.Revoke(ctx, certinterfaces.RevocationEntry{
		Serial:    serial,
		RevokedAt: time.Now().UTC(),
		Reason:    "cluster wiring test",
	}))

	revokedAfter, err := storeB.IsRevoked(ctx, serial)
	require.NoError(t, err)
	assert.True(t, revokedAfter,
		"a revocation written through one wired store must be observed through another node's wired store — this is the cluster visibility the wiring exists to provide")
}

// TestCreateClusterStorageManager_SigningCursorStore verifies the cluster tier wires a
// working, cluster-visible signing-cursor store, and that the wired store is the
// serializing one: a second node's wired store observes the first node's transition
// and its own non-forced transition is refused while the overlap window is open.
// Skipped when PostgreSQL is not reachable.
func TestCreateClusterStorageManager_SigningCursorStore(t *testing.T) {
	dsn := skipIfNoPostgres(t)

	nodeA, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	storeA := nodeA.GetSigningCursorStore()
	require.NotNil(t, storeA,
		"GetSigningCursorStore must be wired — the database provider supplies it, and a nil here silently drops a clustered controller back to a node-local cursor file")

	nodeB, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	storeB := nodeB.GetSigningCursorStore()
	require.NotNil(t, storeB)

	// The cursor table holds exactly one row for the whole cluster, so start from a
	// known-empty state rather than whatever an earlier test left behind.
	truncateSigningCursor(t, dsn)
	t.Cleanup(func() { truncateSigningCursor(t, dsn) })

	ctx := context.Background()

	// First rotation on node A. Nothing is in progress before a cursor exists, so
	// this establishes the cursor with no rotating serial.
	first, err := storeA.TransitionCursor(ctx, "wiring-cursor-serial-1", 7, false)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, "wiring-cursor-serial-1", first.CurrentSerial)
	assert.Empty(t, first.RotatingSerial, "the first rotation has no prior signer to demote")

	observed, err := storeB.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, observed,
		"a cursor written through one wired store must be readable through another node's wired store")
	assert.Equal(t, "wiring-cursor-serial-1", observed.CurrentSerial)

	// Second rotation, issued from the other node: it must build on node A's cursor
	// rather than starting a parallel one, demoting node A's serial into the overlap
	// window.
	second, err := storeB.TransitionCursor(ctx, "wiring-cursor-serial-2", 7, false)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, "wiring-cursor-serial-2", second.CurrentSerial)
	assert.Equal(t, "wiring-cursor-serial-1", second.RotatingSerial,
		"the second node must demote the first node's serial — proof both nodes share one cursor rather than each holding its own")

	fromA, err := storeA.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, fromA)
	assert.Equal(t, "wiring-cursor-serial-2", fromA.CurrentSerial,
		"node A must observe the rotation node B performed, with no restart")

	// With an overlap window now open, a third non-forced rotation from either node
	// is refused — the serialization that keeps cursors from diverging.
	_, err = storeA.TransitionCursor(ctx, "wiring-cursor-serial-3", 7, false)
	assert.ErrorIs(t, err, certinterfaces.ErrSigningRotationInProgress,
		"the wired store must serialize rotations across nodes — a non-forced transition during another node's overlap window must be refused, not allowed to diverge")
}

// deleteRevocationRow removes a test serial from the shared cluster database so
// repeated runs against a persistent test Postgres start clean.
func deleteRevocationRow(t *testing.T, dsn, serial string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Logf("cleanup: open postgres: %v", err)
		return
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DELETE FROM cfgms_cert_revocations WHERE serial = $1`, serial); err != nil {
		t.Logf("cleanup: delete revocation row: %v", err)
	}
}

// truncateSigningCursor clears the single-row signing cursor table. The store keys
// every cursor to one fixed row id, so tests must not inherit a prior run's rotation.
func truncateSigningCursor(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`DELETE FROM cfgms_signing_cursor`)
	require.NoError(t, err)
}
