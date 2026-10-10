// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

// PostgreSQL-backed cluster stores for the signing identity scenarios (Issue
// #4798). This file carries the pkg/storage/providers/database import (see the
// */providers_test.go allowlist in scripts/check-providers.sh). The tests skip
// when no test database is reachable (CFGMS_TEST_DB_*), like
// pkg/cert/cluster_store_test.go.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/providers/database"
)

func clusterDBConfig() map[string]interface{} {
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return map[string]interface{}{
		"host": "localhost", "port": port, "database": "cfgms_test",
		"username": "cfgms_test", "password": os.Getenv("CFGMS_TEST_DB_PASSWORD"), "sslmode": "disable",
	}
}

// pgClusterStores returns cursor, acknowledgement and revocation stores backed by
// one PostgreSQL database, or skips the test when none is reachable.
func pgClusterStores(t *testing.T) clusterStores {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping database tests in short mode")
	}
	cfg := clusterDBConfig()
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], cfg["username"], cfg["password"], cfg["sslmode"])
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("PostgreSQL test database not available: " + err.Error())
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skip("PostgreSQL test database not reachable: " + err.Error())
	}
	t.Cleanup(func() { _ = db.Close() })

	drop := func() { require.NoError(t, database.NewDatabaseSchemas().DropAllTables(context.Background(), db)) }
	drop()
	t.Cleanup(drop)

	cursor, err := database.NewDatabaseSigningCursorStore(db, cfg)
	require.NoError(t, err)
	acks, err := database.NewDatabaseSigningTrustAckStore(db, cfg)
	require.NoError(t, err)
	rev, err := database.NewDatabaseCertRevocationStore(db, cfg)
	require.NoError(t, err)
	return clusterStores{cursor: cursor, acks: acks, revocation: rev}
}
