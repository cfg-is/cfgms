// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Cluster-store construction helpers for cluster_store_test.go (Issue #3852,
// AC4-AC6). Split into their own providers_test.go file, rather than
// importing pkg/storage/providers/database directly from
// cluster_store_test.go, so this is the only file in the package matching
// scripts/check-providers.sh's */providers_test.go storage-provider-import
// allowlist entry.
package cert_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
)

// newClusterManager builds a cert.Manager backed by its own FileStore (a
// fresh temp dir — simulating a node with no knowledge of any other node's
// locally-issued certificates) but a RevocationStore/SigningCursorStore
// backed by db, simulating one controller node in a cluster deployment.
func newClusterManager(t *testing.T, db *sql.DB) *cert.Manager {
	t.Helper()
	revStore, err := database.NewDatabaseCertRevocationStore(db, clusterTestConfig())
	require.NoError(t, err)
	curStore, err := database.NewDatabaseSigningCursorStore(db, clusterTestConfig())
	require.NoError(t, err)

	m, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
		RevocationStore:    revStore,
		SigningCursorStore: curStore,
	})
	require.NoError(t, err)
	return m
}

func dropClusterTables(t *testing.T, db *sql.DB) {
	t.Helper()
	require.NoError(t, database.NewDatabaseSchemas().DropAllTables(context.Background(), db))
}
