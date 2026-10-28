// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config_test

// Real storage-provider constructors for the atomic-update tests. They live in
// providers_test.go because that is the one test-file name the provider-import
// check (scripts/check-providers.sh) allows to import pkg/storage/providers/*.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/testutil"
)

func newFlatfile(t *testing.T) cfgconfig.ConfigStore {
	t.Helper()
	s, err := flatfile.NewFlatFileConfigStore(t.TempDir())
	require.NoError(t, err)
	return s
}

// newDatabase builds a real PostgreSQL-backed store; it skips when the test
// database is unavailable (merge-queue Postgres test, repository convention).
func newDatabase(t *testing.T) cfgconfig.ConfigStore {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	port := 5432
	if p, err := strconv.Atoi(os.Getenv("CFGMS_TEST_DB_PORT")); err == nil {
		port = p
	}
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	cfg := map[string]interface{}{
		"host": "localhost", "port": port, "database": "cfgms_test",
		"username": "cfgms_test", "password": testutil.GetTestDBPassword(),
		"sslmode": "disable", "session_hmac_key": hex.EncodeToString(key),
	}
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		cfg["host"], port, cfg["database"], cfg["username"], cfg["password"])
	probe, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("PostgreSQL test database not available:", err)
	}
	if err := probe.Ping(); err != nil {
		_ = probe.Close()
		t.Skip("PostgreSQL test database not reachable:", err)
	}
	_ = probe.Close()

	p := &database.DatabaseProvider{}
	t.Cleanup(func() { _ = p.Close() })
	s, err := p.CreateConfigStore(cfg)
	require.NoError(t, err)
	return s
}

// newFlatfileAt builds a flatfile config store rooted at root.
func newFlatfileAt(root string) (cfgconfig.ConfigStore, error) {
	return flatfile.NewFlatFileConfigStore(root)
}

// newSQLiteConfigStore asks the SQLite provider for a config store at path.
func newSQLiteConfigStore(path string) (cfgconfig.ConfigStore, error) {
	return (&sqlite.SQLiteProvider{}).CreateConfigStore(map[string]interface{}{"path": path})
}
