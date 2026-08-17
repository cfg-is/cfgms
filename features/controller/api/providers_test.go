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

// testAlertStoreDSN builds the PostgreSQL DSN used by the alert-store handler tests
// from the standard CFGMS test-database environment variables.
func testAlertStoreDSN() string {
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
	dsn := testAlertStoreDSN()
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
