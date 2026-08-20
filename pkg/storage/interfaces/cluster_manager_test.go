// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces_test

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// buildClusterTestDSN returns a test Postgres DSN using the same env vars as the
// database provider tests (CFGMS_TEST_DB_PORT, CFGMS_TEST_DB_USER, CFGMS_TEST_DB_NAME).
func buildClusterTestDSN() string {
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

// skipIfNoPostgres skips the test if Postgres is not reachable and returns the DSN.
func skipIfNoPostgres(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in short mode")
	}
	dsn := buildClusterTestDSN()
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

// TestCreateClusterStorageManager_RequiresDSN verifies the function rejects an empty DSN
// before touching the database provider.
func TestCreateClusterStorageManager_RequiresDSN(t *testing.T) {
	_, err := interfaces.CreateClusterStorageManager("", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres_dsn")
}

// TestCreateClusterStorageManager_DatabaseProvider verifies that CreateClusterStorageManager
// returns a StorageManager backed by the database provider. GetStewardStore() must be
// the database-provider impl (not flatfile/SQLite). This is the REQUIRED test for
// Issue #2119 acceptance criteria.
func TestCreateClusterStorageManager_DatabaseProvider(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), nil)
	require.NoError(t, err)
	require.NotNil(t, sm)
	defer func() { _ = sm.Close() }()

	assert.Equal(t, "database", sm.GetProviderName(),
		"cluster storage manager must use the database provider, not flatfile or SQLite")
	assert.NotNil(t, sm.GetStewardStore(),
		"database-backed steward store must be non-nil")
	assert.NotNil(t, sm.GetAuditStore(),
		"database-backed audit store must be non-nil")
	assert.NotNil(t, sm.GetRBACStore(),
		"database-backed RBAC store must be non-nil")
	assert.NotNil(t, sm.GetClientTenantStore(),
		"database-backed client tenant store must be non-nil")
	// Issue #3401: CreatePendingRegistrationStore returned ErrNotSupported, leaving this
	// store nil and every cluster-mode registration endpoint answering 503.
	assert.NotNil(t, sm.GetPendingRegistrationStore(),
		"database-backed pending registration store must be non-nil — a nil store makes every cluster-mode registration endpoint return 503")
}

// TestCreateClusterStorageManager_WithS3Config verifies that s3Config is accepted
// (including nil) without error — blob store creation is the caller's responsibility.
func TestCreateClusterStorageManager_WithS3Config(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	s3Cfg := map[string]interface{}{
		"bucket": "cfgms-test-installers",
		"region": "us-east-1",
	}
	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), s3Cfg)
	require.NoError(t, err)
	require.NotNil(t, sm)
	defer func() { _ = sm.Close() }()

	assert.Equal(t, "database", sm.GetProviderName())
}

// testSessionHMACKey returns the session HMAC key used by cluster storage tests.
// CFGMS_TEST_SESSION_HMAC_KEY lets CI inject a real key; a fixed test-only key is
// used for local development, matching the pattern in pkg/testing/storage/fixtures.go.
func testSessionHMACKey() string {
	if key := os.Getenv("CFGMS_TEST_SESSION_HMAC_KEY"); key != "" {
		return key
	}
	return "test-hmac-key-for-cluster-manager-tests-only"
}
