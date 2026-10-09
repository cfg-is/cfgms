// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package run test-only provider registration. The blank import registers the
// PostgreSQL storage provider so the cluster-shared store tests can build their
// stores the way the controller does in cluster mode, through
// interfaces.CreateClusterStorageManager. Confined to this allowlisted
// */providers_test.go path (see scripts/check-providers.sh).
package run

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database" // registers the "database" provider
	"github.com/cfgis/cfgms/pkg/testutil"
)

// newTestClusterStorage returns a cluster-mode StorageManager over the test
// PostgreSQL database, or skips when it is unavailable
// (fails instead when CFGMS_TEST_INTEGRATION=1).
func newTestClusterStorage(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping PostgreSQL-backed test in short mode")
	}
	port := os.Getenv("CFGMS_TEST_DB_PORT")
	if port == "" {
		port = "5432"
	}
	dsn := fmt.Sprintf("host=localhost port=%s dbname=cfgms_test user=cfgms_test password=%s sslmode=disable",
		port, testutil.GetTestDBPassword())
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		if os.Getenv("CFGMS_TEST_INTEGRATION") == "1" {
			t.Fatalf("PostgreSQL test database not reachable with CFGMS_TEST_INTEGRATION=1: %v", err)
		}
		t.Skip("PostgreSQL test database not reachable:", err)
	}
	_ = db.Close()

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	sm, err := interfaces.CreateClusterStorageManager(dsn, hex.EncodeToString(key), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	require.NotNil(t, sm.GetScriptRunStore(), "cluster storage must provide a shared script run store")
	require.NotNil(t, sm.GetExecutionQueueStore(), "cluster storage must provide a shared execution queue store")
	return sm
}
