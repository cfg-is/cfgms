// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Contract test for RevocationStore and SigningCursorStore (Issue #3852, AC7).
// Runs the same semantics against every implementation: pkg/cert's file-backed
// store (single-node, always exercised) and the Postgres-backed store
// (pkg/storage/providers/database; skipped when no test database is reachable,
// matching the convention pkg/storage/providers/database's own tests use).
package interfaces_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
)

// storeProviderCase names one implementation pair to run the shared contract
// against. newStores returns fresh, isolated stores or an empty skip reason.
type storeProviderCase struct {
	name      string
	newStores func(t *testing.T) (certinterfaces.RevocationStore, certinterfaces.SigningCursorStore, string /* skip reason */)
}

func storeProviderCases() []storeProviderCase {
	return []storeProviderCase{
		{
			name: "file",
			newStores: func(t *testing.T) (certinterfaces.RevocationStore, certinterfaces.SigningCursorStore, string) {
				dir := t.TempDir()
				rev, err := cert.NewFileRevocationStore(dir)
				require.NoError(t, err)
				cur, err := cert.NewFileSigningCursorStore(dir)
				require.NoError(t, err)
				return rev, cur, ""
			},
		},
		{
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
		},
	}
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
	return db, ""
}

func TestRevocationStore_Contract(t *testing.T) {
	for _, tc := range storeProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			revStore, _, skip := tc.newStores(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()

			revoked, err := revStore.IsRevoked(ctx, "serial-1")
			require.NoError(t, err)
			assert.False(t, revoked, "an unrevoked serial must report false")

			first := time.Now().UTC().Truncate(time.Second)
			require.NoError(t, revStore.Revoke(ctx, certinterfaces.RevocationEntry{
				Serial: "serial-1", RevokedAt: first, Reason: "compromised",
			}))

			revoked, err = revStore.IsRevoked(ctx, "serial-1")
			require.NoError(t, err)
			assert.True(t, revoked)

			// Repeated revoke of the same serial is a no-op: original RevokedAt wins.
			require.NoError(t, revStore.Revoke(ctx, certinterfaces.RevocationEntry{
				Serial: "serial-1", RevokedAt: first.Add(time.Hour), Reason: "attacker-supplied",
			}))
			entries, err := revStore.ListRevoked(ctx)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.True(t, first.Equal(entries[0].RevokedAt), "original RevokedAt must be preserved on double-revoke")

			revoked, err = revStore.IsRevoked(ctx, "serial-never-revoked")
			require.NoError(t, err)
			assert.False(t, revoked)
		})
	}
}

func TestSigningCursorStore_Contract(t *testing.T) {
	for _, tc := range storeProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, curStore, skip := tc.newStores(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()

			cursor, err := curStore.LoadCursor(ctx)
			require.NoError(t, err)
			assert.Nil(t, cursor, "no rotation has occurred yet")

			cursor, err = curStore.TransitionCursor(ctx, "serial-v1", 30, false)
			require.NoError(t, err)
			require.NotNil(t, cursor)
			assert.Equal(t, "serial-v1", cursor.CurrentSerial)
			assert.Empty(t, cursor.RotatingSerial)

			cursor, err = curStore.TransitionCursor(ctx, "serial-v2", 30, false)
			require.NoError(t, err)
			assert.Equal(t, "serial-v2", cursor.CurrentSerial)
			assert.Equal(t, "serial-v1", cursor.RotatingSerial)

			// A third transition within the 30-day overlap window must be rejected.
			_, err = curStore.TransitionCursor(ctx, "serial-v3", 30, false)
			require.Error(t, err)
			assert.True(t, errors.Is(err, certinterfaces.ErrSigningRotationInProgress))

			loaded, err := curStore.LoadCursor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "serial-v2", loaded.CurrentSerial, "cursor must be unchanged after a rejected transition")

			// force bypasses the in-progress guard.
			cursor, err = curStore.TransitionCursor(ctx, "serial-v3", 7, true)
			require.NoError(t, err)
			assert.Equal(t, "serial-v3", cursor.CurrentSerial)
			assert.Equal(t, "serial-v2", cursor.RotatingSerial)
		})
	}
}
