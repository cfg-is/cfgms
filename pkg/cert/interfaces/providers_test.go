// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Registers the Postgres-backed RevocationStore/SigningCursorStore case for
// the contract test in contract_test.go (Issue #3852, AC7). Split into its
// own providers_test.go file, rather than importing
// pkg/storage/providers/database directly from contract_test.go, so this is
// the only file in the package matching scripts/check-providers.sh's
// */providers_test.go storage-provider-import allowlist entry.
package interfaces_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
)

func init() {
	registeredProviderCases = append(registeredProviderCases, storeProviderCase{
		name: "database",
		newStores: func(t *testing.T) (certinterfaces.RevocationStore, certinterfaces.SigningCursorStore, string) {
			db, skip := testPostgresDB(t)
			if skip != "" {
				return nil, nil, skip
			}
			rev, err := database.NewDatabaseCertRevocationStore(db, testPostgresConfig())
			require.NoError(t, err)
			cur, err := database.NewDatabaseSigningCursorStore(db, testPostgresConfig())
			require.NoError(t, err)
			return rev, cur, ""
		},
	})
}

// testPostgresConfig mirrors pkg/storage/providers/database's own test
// configuration convention (host/port/credentials via CFGMS_TEST_DB_* env vars).
func testPostgresConfig() map[string]interface{} {
	password := os.Getenv("CFGMS_TEST_DB_PASSWORD")
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return map[string]interface{}{
		"host": "localhost", "port": port, "database": "cfgms_test",
		"username": "cfgms_test", "password": password, "sslmode": "disable",
	}
}

// testPostgresDB opens a connection to the test database, returning a skip
// reason when it is not reachable rather than failing the test — matching
// pkg/storage/providers/database/plugin_test.go's getTestDB convention.
//
// It also drops and recreates every table before returning, matching that
// package's setupTestDatabase and pkg/cert's own dropClusterTables. Without
// this, the contract test's "database" case inherits whatever state the last
// test to touch cfgms_test left behind: this package, pkg/cert, and
// pkg/storage/providers/database all share one Postgres schema when run in
// the same CI job (Issue #3852 AC7 wiring), and pkg/cert's cluster tests seed
// a real signing-cursor row without ever cleaning it up — so this contract
// test's "no rotation has occurred yet" assumption fails whenever pkg/cert's
// package runs first, which alphabetical package ordering guarantees for
// `go test ./pkg/cert/...`.
func testPostgresDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	if testing.Short() {
		return nil, "skipping database tests in short mode"
	}
	cfg := testPostgresConfig()
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], cfg["username"], cfg["password"], cfg["sslmode"])
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, "PostgreSQL test database not available: " + err.Error()
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, "PostgreSQL test database not reachable: " + err.Error()
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.NewDatabaseSchemas().DropAllTables(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, "failed to reset test database state: " + err.Error()
	}
	return db, ""
}
