// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test — provider contract-suite wiring.
//
// This file runs each real EntityGraphProvider implementation through the shared
// RunEntityGraphContractTests harness (see contract_test.go). It is deliberately
// named providers_test.go so the check-providers.sh architecture script permits
// the direct sqlite/database provider imports (the */providers_test.go
// exception); every other file in this package imports only the interface.
package interfaces_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/database"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/stretchr/testify/require"
)

// TestSQLiteEntityGraphProvider_ContractSuite runs the shared contract suite
// against a real, file-backed SQLite provider. A fresh database per subtest
// keeps each acceptance criterion isolated; file-backed (not :memory:) exercises
// the real WAL path that RebuildProjections depends on.
func TestSQLiteEntityGraphProvider_ContractSuite(t *testing.T) {
	RunEntityGraphContractTests(t, func(t *testing.T) interfaces.EntityGraphProvider {
		p, err := sqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Close() })
		return p
	})
}

// TestDatabaseEntityGraphProvider_ContractSuite runs the shared contract suite
// against a real PostgreSQL provider. It is skipped in -short mode and when no
// test Postgres is reachable. Subtests share one database; the suite's ACs are
// tenant- and subject-scoped (stable subjects upsert, tenant cuts isolate
// reads), so they stay correct without per-subtest teardown.
func TestDatabaseEntityGraphProvider_ContractSuite(t *testing.T) {
	dsn := skipIfNoTestPostgres(t)
	RunEntityGraphContractTests(t, func(t *testing.T) interfaces.EntityGraphProvider {
		p, err := database.NewDatabaseEntityGraphProvider(dsn)
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Close() })
		return p
	})
}

// testPostgresDSN builds a Postgres DSN from the standard CFGMS test environment
// variables, matching the storage database provider tests.
func testPostgresDSN() string {
	pw := testutil.GetTestDBPassword()
	port := 5432
	if p := os.Getenv("CFGMS_TEST_DB_PORT"); p != "" {
		if pi, err := strconv.Atoi(p); err == nil {
			port = pi
		}
	}
	dbName := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_NAME"); v != "" {
		dbName = v
	}
	dbUser := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_USER"); v != "" {
		dbUser = v
	}
	return fmt.Sprintf("host=localhost port=%d dbname=%s user=%s password=%s sslmode=disable",
		port, dbName, dbUser, pw)
}

// skipIfNoTestPostgres skips the calling test when running with -short or when
// the test Postgres instance is not reachable, returning the DSN otherwise. The
// "postgres" driver is registered transitively via the database provider import.
func skipIfNoTestPostgres(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres entity-graph contract suite in short mode")
	}
	dsn := testPostgresDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("Postgres not available:", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skip("Postgres not reachable:", err)
	}
	return dsn
}
