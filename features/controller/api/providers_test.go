// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api test-only provider registrations.
// The blank import triggers init() to register the filesystem blob provider so that
// handlers_installer_test.go can use blob.CreateBlobStoreFromConfig("filesystem", ...).
// newTestAPIBatchJobStore is defined here so that the concrete memory-provider import
// is confined to the allowlisted */providers_test.go path (see scripts/check-providers.sh).
package api

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem blob provider for installer tests
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
	"github.com/cfgis/cfgms/pkg/testutil"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// newTestAPIBatchJobStore returns a memory-backed BatchJobStore for handler tests.
func newTestAPIBatchJobStore() batchjob.BatchJobStore {
	return memory.NewBatchJobStore()
}

// newTestStewardDurableStore returns a real flat-file StewardStore rooted at a
// t.TempDir() (no external infrastructure required) along with its backing root
// directory. Tests that need to induce a genuine durable-store write failure use
// the returned root to toggle directory permissions. The concrete flatfile import
// is confined to this allowlisted */providers_test.go path (see scripts/check-providers.sh).
func newTestStewardDurableStore(t *testing.T) (business.StewardStore, string) {
	t.Helper()
	root := t.TempDir()
	st, err := flatfile.NewFlatFileStewardStore(root)
	require.NoError(t, err, "creating flat-file steward store")
	return st, root
}

// newTestFlatFileAlertStore returns a real flat-file AlertStore rooted at t.TempDir().
// The concrete flatfile import is confined to this allowlisted */providers_test.go path.
func newTestFlatFileAlertStore(t *testing.T) business.AlertStore {
	t.Helper()
	st, err := flatfile.NewFlatFileAlertStore(t.TempDir())
	require.NoError(t, err, "creating flat-file alert store")
	return st
}

// newTestNonceStorePair returns two independent business.NonceStore instances
// rooted at the same directory — simulating two controller nodes sharing one
// durable nonce store (Issue #3755, ADR-031 Decision 1: any-node service). The
// concrete flatfile import is confined to this allowlisted */providers_test.go path.
func newTestNonceStorePair(t *testing.T) (business.NonceStore, business.NonceStore) {
	t.Helper()
	root := t.TempDir()
	nodeA, err := flatfile.NewFlatFileNonceStore(root)
	require.NoError(t, err, "creating flat-file nonce store for node A")
	nodeB, err := flatfile.NewFlatFileNonceStore(root)
	require.NoError(t, err, "creating flat-file nonce store for node B")
	return nodeA, nodeB
}

// newTestFlatFileLeaseStore returns a real flat-file business.LeaseStore rooted at
// t.TempDir(), for tests that wire ha.Manager.SetLeaseStore against a real (not
// mocked) S3 database lease (pkg/lease, ADR-031 Decision 5, Issue #3760). The
// concrete flatfile import is confined to this allowlisted */providers_test.go path.
func newTestFlatFileLeaseStore(t *testing.T) business.LeaseStore {
	t.Helper()
	st, err := flatfile.NewFlatFileLeaseStore(t.TempDir())
	require.NoError(t, err, "creating flat-file lease store")
	return st
}

// alertStoreProviders returns a map of provider-name → AlertStore for table-driven
// handler tests that must exercise every working provider against real components.
// The flat-file store always participates (t.TempDir(), no external dependency); the
// PostgreSQL store participates only when a test database is reachable, in which case
// tryNewDatabaseAlertStore returns a real store and otherwise nil.
func alertStoreProviders(t *testing.T) map[string]business.AlertStore {
	t.Helper()
	stores := map[string]business.AlertStore{
		"flatfile": newTestFlatFileAlertStore(t),
	}
	if st := tryNewDatabaseAlertStore(t); st != nil {
		stores["database"] = st
	}
	return stores
}

// testDatabaseDSN builds the PostgreSQL DSN used by the handler tests that run against
// a real test database, from the standard CFGMS test-database environment variables.
func testDatabaseDSN() string {
	host := os.Getenv("CFGMS_TEST_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("CFGMS_TEST_DB_PORT")
	if port == "" {
		port = "5432"
	}
	return fmt.Sprintf("host=%s port=%s dbname=cfgms_test user=cfgms_test password=%s sslmode=disable",
		host, port, testutil.GetTestDBPassword())
}

// tryNewDatabaseAlertStore returns a real PostgreSQL-backed AlertStore, or nil when
// the test database is not reachable. It never skips: callers keep running against
// the providers that are available. The concrete database import is confined to this
// allowlisted */providers_test.go path (see scripts/check-providers.sh).
func tryNewDatabaseAlertStore(t *testing.T) business.AlertStore {
	t.Helper()
	dsn := testDatabaseDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil
	}
	if pingErr := db.Ping(); pingErr != nil {
		_ = db.Close()
		return nil
	}
	_ = db.Close()
	st, err := database.NewDatabaseAlertStore(dsn, map[string]interface{}{})
	if err != nil {
		return nil
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// tryNewDatabasePendingRegistrationStore returns a real PostgreSQL-backed
// PendingRegistrationStore obtained through DatabaseProvider.CreatePendingRegistrationStore
// — the exact constructor a cluster-mode controller calls via CreateClusterStorageManager
// (Issue #3401) — or nil when the test database is not reachable. It never skips: callers
// keep running against the providers that are available. The concrete database import is
// confined to this allowlisted */providers_test.go path (see scripts/check-providers.sh).
func tryNewDatabasePendingRegistrationStore(t *testing.T) business.PendingRegistrationStore {
	t.Helper()
	dsn := testDatabaseDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil
	}
	if pingErr := db.Ping(); pingErr != nil {
		_ = db.Close()
		return nil
	}
	_ = db.Close()

	// Postgres is reachable, so the provider has no excuse to decline. Failing here rather
	// than returning nil is deliberate: if CreatePendingRegistrationStore regresses to
	// ErrNotSupported (Issue #3401), the caller must fail, not skip.
	provider := &database.DatabaseProvider{}
	st, err := provider.CreatePendingRegistrationStore(map[string]interface{}{"dsn": dsn})
	require.NoError(t, err, "DatabaseProvider.CreatePendingRegistrationStore must return a working store against a reachable test database, never ErrNotSupported (Issue #3401)")
	require.NotNil(t, st, "DatabaseProvider.CreatePendingRegistrationStore must return a non-nil store")
	if closer, ok := st.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	return st
}
