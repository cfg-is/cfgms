// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage provides tests for the PostgreSQL-backed DNA storage backend.

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// buildDNATestDSN constructs a PostgreSQL DSN for DNA backend tests using the
// same environment variables as the rest of the integration test suite.
func buildDNATestDSN() string {
	password := testutil.GetTestDBPassword()
	host := "localhost"
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		host, port, "cfgms_test", "cfgms_test", password)
}

// skipIfDatabaseUnavailable skips the test when PostgreSQL is unreachable or
// when running in short mode.
func skipIfDatabaseUnavailable(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping DNA database backend tests in short mode")
	}

	dsn := buildDNATestDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("PostgreSQL test database not available:", err)
	}
	defer db.Close() //nolint:errcheck

	if err := db.Ping(); err != nil {
		t.Skip("PostgreSQL test database not reachable:", err)
	}
}

// dropDNATables removes DNA-related tables so each test starts with a clean schema.
func dropDNATables(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	for _, table := range []string{"dna_references", "storage_stats", "dna_history", "device_tenant"} {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE")
		require.NoError(t, err, "failed to drop %s", table)
	}
}

// TestDatabaseBackend_TwoManagersShareState is the REQUIRED test for Issue #2118:
// two Manager instances backed by the same PostgreSQL connection string
// independently store and retrieve the same DNA records, proving no node-local
// dependency exists in cluster mode.
func TestDatabaseBackend_TwoManagersShareState(t *testing.T) {
	skipIfDatabaseUnavailable(t)

	dsn := buildDNATestDSN()
	dropDNATables(t, dsn)

	logger := logging.NewNoopLogger()

	makeCfg := func() *Config {
		cfg := DefaultConfig()
		cfg.Backend = BackendDatabase
		cfg.DatabaseURL = dsn
		cfg.EnableDeduplication = false
		return cfg
	}

	// Open first manager — simulates controller node A.
	mgr1, err := NewManager(makeCfg(), logger)
	require.NoError(t, err, "failed to create manager 1")
	defer mgr1.Close() //nolint:errcheck

	// Open second manager with the same connection string — simulates controller node B.
	mgr2, err := NewManager(makeCfg(), logger)
	require.NoError(t, err, "failed to create manager 2")
	defer mgr2.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("NodeA_StoresDNA_NodeB_Retrieves", func(t *testing.T) {
		deviceID := "shared-device-001"
		dna := attachTestFragment(t, &commonpb.DNA{
			Id:              deviceID,
			LastUpdated:     timestamppb.New(time.Now()),
			ConfigHash:      "hash-abc",
			LastSyncTime:    timestamppb.New(time.Now()),
			AttributeCount:  4,
			SyncFingerprint: "fp-001",
		}, map[string]string{
			"os":           "linux",
			"architecture": "amd64",
			"hostname":     "node-a-host",
			"version":      "1.2.3",
		})

		// Node A stores the DNA record.
		require.NoError(t, mgr1.Store(ctx, deviceID, dna, nil))

		// Node B retrieves it directly from the shared store (not from its own
		// in-memory index, which is empty for mgr2).
		record, err := mgr2.GetLatestByDeviceID(ctx, deviceID)
		require.NoError(t, err, "node B must retrieve record stored by node A")

		assert.Equal(t, deviceID, record.DeviceID)
		require.NotNil(t, record.DNA)
		recordAttrs := dnaAttrs(record.DNA)
		assert.Equal(t, "linux", recordAttrs["os"])
		assert.Equal(t, "amd64", recordAttrs["architecture"])
		assert.Equal(t, "node-a-host", recordAttrs["hostname"])
	})

	t.Run("ListAllDeviceIDs_CrossNode", func(t *testing.T) {
		devices := []string{"fleet-device-101", "fleet-device-102", "fleet-device-103"}
		for _, id := range devices {
			dna := attachTestFragment(t, &commonpb.DNA{
				Id:              id,
				LastUpdated:     timestamppb.New(time.Now()),
				AttributeCount:  2,
				SyncFingerprint: "fp-" + id,
			}, map[string]string{"os": "linux", "hostname": id})
			require.NoError(t, mgr1.Store(ctx, id, dna, nil), "node A failed to store %s", id)
		}

		// Node B lists all device IDs — must see records written by node A.
		ids, err := mgr2.ListAllDeviceIDs(ctx)
		require.NoError(t, err)

		idSet := make(map[string]bool, len(ids))
		for _, id := range ids {
			idSet[id] = true
		}
		for _, expected := range devices {
			assert.True(t, idSet[expected], "node B missing device %s stored by node A", expected)
		}
	})

	t.Run("Ping_DatabaseBackend", func(t *testing.T) {
		require.NoError(t, mgr1.Ping(ctx))
		require.NoError(t, mgr2.Ping(ctx))
	})

	t.Run("StoreWithTenantAndStatus", func(t *testing.T) {
		deviceID := "tenant-device-001"
		dna := attachTestFragment(t, &commonpb.DNA{
			Id:              deviceID,
			LastUpdated:     timestamppb.New(time.Now()),
			AttributeCount:  3,
			SyncFingerprint: "fp-tenant-001",
		}, map[string]string{
			"os":           "windows",
			"architecture": "amd64",
			"hostname":     "win-host-01",
		})
		opts := &StoreOptions{TenantID: "tenant-alpha", Status: "online"}
		require.NoError(t, mgr1.Store(ctx, deviceID, dna, opts))

		// Node B retrieves the record and verifies tenant/status fields.
		record, err := mgr2.GetLatestByDeviceID(ctx, deviceID)
		require.NoError(t, err)
		assert.Equal(t, "tenant-alpha", record.TenantID)
		assert.Equal(t, "online", record.Status)
	})
}

// TestDatabaseBackend_StoreAndRetrieve is a unit test for the single-node
// DatabaseBackend verifying that Store and GetLatestByDeviceID round-trip
// correctly using the same Manager instance.
func TestDatabaseBackend_StoreAndRetrieve(t *testing.T) {
	skipIfDatabaseUnavailable(t)

	dsn := buildDNATestDSN()
	dropDNATables(t, dsn)

	cfg := DefaultConfig()
	cfg.Backend = BackendDatabase
	cfg.DatabaseURL = dsn
	cfg.EnableDeduplication = false

	mgr, err := NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	defer mgr.Close() //nolint:errcheck

	ctx := context.Background()
	deviceID := "db-test-device"
	dna := attachTestFragment(t, &commonpb.DNA{
		Id:              deviceID,
		LastUpdated:     timestamppb.New(time.Now()),
		AttributeCount:  3,
		SyncFingerprint: "fp-db",
	}, map[string]string{
		"os":           "darwin",
		"architecture": "arm64",
		"hostname":     "mac-host",
	})

	require.NoError(t, mgr.Store(ctx, deviceID, dna, nil))

	record, err := mgr.GetLatestByDeviceID(ctx, deviceID)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, deviceID, record.DeviceID)
	require.NotNil(t, record.DNA)
	recordAttrs := dnaAttrs(record.DNA)
	assert.Equal(t, "darwin", recordAttrs["os"])
	assert.Equal(t, "arm64", recordAttrs["architecture"])
}

// TestDatabaseBackend_QueryFleet verifies that QueryFleet against the Postgres
// backend filters records correctly by OS, status, and tenant.
func TestDatabaseBackend_QueryFleet(t *testing.T) {
	skipIfDatabaseUnavailable(t)

	dsn := buildDNATestDSN()
	dropDNATables(t, dsn)

	cfg := DefaultConfig()
	cfg.Backend = BackendDatabase
	cfg.DatabaseURL = dsn
	cfg.EnableDeduplication = false

	mgr, err := NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	defer mgr.Close() //nolint:errcheck

	ctx := context.Background()

	// Seed records with varied attributes.
	seed := []struct {
		id     string
		attrs  map[string]string
		tenant string
		status string
	}{
		{"dev-linux-1", map[string]string{"os": "linux", "architecture": "amd64", "hostname": "h1"}, "t1", "online"},
		{"dev-linux-2", map[string]string{"os": "linux", "architecture": "arm64", "hostname": "h2"}, "t1", "offline"},
		{"dev-windows-1", map[string]string{"os": "windows", "architecture": "amd64", "hostname": "h3"}, "t2", "online"},
	}
	for _, s := range seed {
		dna := attachTestFragment(t, &commonpb.DNA{Id: s.id, SyncFingerprint: "fp-" + s.id}, s.attrs)
		require.NoError(t, mgr.Store(ctx, s.id, dna, &StoreOptions{TenantID: s.tenant, Status: s.status}))
	}

	t.Run("FilterByOS", func(t *testing.T) {
		result, err := mgr.QueryFleet(ctx, &FleetFilter{OS: "linux"})
		require.NoError(t, err)
		assert.Equal(t, int64(2), result.TotalCount)
		for _, r := range result.Records {
			assert.Equal(t, "linux", r.OS)
		}
	})

	t.Run("FilterByStatus", func(t *testing.T) {
		result, err := mgr.QueryFleet(ctx, &FleetFilter{Status: "online"})
		require.NoError(t, err)
		assert.Equal(t, int64(2), result.TotalCount)
	})

	t.Run("FilterByTenant", func(t *testing.T) {
		result, err := mgr.QueryFleet(ctx, &FleetFilter{TenantID: "t2"})
		require.NoError(t, err)
		assert.Equal(t, int64(1), result.TotalCount)
		assert.Equal(t, "dev-windows-1", result.Records[0].DeviceID)
	})
}

// TestDatabaseBackend_DeviceTenant exercises the PostgreSQL implementations of
// setDeviceTenant, getDeviceTenant and listDeviceTenants through the Manager
// (Issue #3324). It also pins the schema requirement: initializeSchema must
// create device_tenant, otherwise every query here fails with "relation does not
// exist" and, in production, LoadFromStorage aborts the whole registry warm-load.
func TestDatabaseBackend_DeviceTenant(t *testing.T) {
	skipIfDatabaseUnavailable(t)

	dsn := buildDNATestDSN()
	dropDNATables(t, dsn)

	makeCfg := func() *Config {
		cfg := DefaultConfig()
		cfg.Backend = BackendDatabase
		cfg.DatabaseURL = dsn
		cfg.EnableDeduplication = false
		return cfg
	}

	mgr, err := NewManager(makeCfg(), logging.NewNoopLogger())
	require.NoError(t, err)
	defer mgr.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("UnknownDeviceNotFound", func(t *testing.T) {
		tid, found, err := mgr.GetDeviceTenant(ctx, "dt-unknown")
		require.NoError(t, err, "a missing mapping is not an error")
		assert.False(t, found)
		assert.Empty(t, tid)
	})

	t.Run("SetThenGet", func(t *testing.T) {
		require.NoError(t, mgr.SetDeviceTenant(ctx, "dt-dev-1", "tenant-alpha"))

		tid, found, err := mgr.GetDeviceTenant(ctx, "dt-dev-1")
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, "tenant-alpha", tid)
	})

	t.Run("UpsertOverwritesTenantOnMove", func(t *testing.T) {
		require.NoError(t, mgr.SetDeviceTenant(ctx, "dt-dev-move", "tenant-src"))
		require.NoError(t, mgr.SetDeviceTenant(ctx, "dt-dev-move", "tenant-dst"))

		tid, found, err := mgr.GetDeviceTenant(ctx, "dt-dev-move")
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, "tenant-dst", tid,
			"ON CONFLICT upsert must replace the tenant; a stale mapping reverts moved devices")
	})

	t.Run("ListDeviceTenants", func(t *testing.T) {
		require.NoError(t, mgr.SetDeviceTenant(ctx, "dt-dev-2", "tenant-beta"))

		all, err := mgr.ListDeviceTenants(ctx)
		require.NoError(t, err)
		assert.Equal(t, "tenant-alpha", all["dt-dev-1"])
		assert.Equal(t, "tenant-beta", all["dt-dev-2"])
		assert.Equal(t, "tenant-dst", all["dt-dev-move"])
		assert.NotContains(t, all, "dt-unknown")
	})

	t.Run("SharedAcrossManagers", func(t *testing.T) {
		// Cluster mode: a second controller node reading the same database must
		// see the mapping written by the first, with no node-local state.
		mgr2, err := NewManager(makeCfg(), logging.NewNoopLogger())
		require.NoError(t, err)
		defer mgr2.Close() //nolint:errcheck

		require.NoError(t, mgr.SetDeviceTenant(ctx, "dt-shared", "tenant-shared"))

		tid, found, err := mgr2.GetDeviceTenant(ctx, "dt-shared")
		require.NoError(t, err)
		require.True(t, found, "node B must see the mapping written by node A")
		assert.Equal(t, "tenant-shared", tid)

		all, err := mgr2.ListDeviceTenants(ctx)
		require.NoError(t, err)
		assert.Equal(t, "tenant-shared", all["dt-shared"])
	})
}

// clearDNAEnv unsets every env var buildDNAConnString and NewDatabaseBackend's
// CFGMS_DNA_DATABASE_URL lookup consult, plus their _FILE companions, and
// restores the original values via t.Cleanup — so these tests can't leak
// state into (or pick up state from) the surrounding environment.
func clearDNAEnv(t *testing.T) {
	t.Helper()
	names := []string{
		"CFGMS_DNA_DATABASE_URL", "CFGMS_DNA_DATABASE_URL_FILE",
		"CFGMS_DNA_DB_PASSWORD", "CFGMS_DNA_DB_PASSWORD_FILE",
		"CFGMS_DNA_DB_HOST", "CFGMS_DNA_DB_PORT", "CFGMS_DNA_DB_NAME", "CFGMS_DNA_DB_USER",
	}
	for _, name := range names {
		orig, existed := os.LookupEnv(name)
		require.NoError(t, os.Unsetenv(name))
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, orig)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

// TestBuildDNAConnString_PasswordFromFile is a required test (DNA URL/password
// _FILE indirection): CFGMS_DNA_DB_PASSWORD_FILE delivers the password when
// CFGMS_DNA_DB_PASSWORD itself is unset — the same sealed-credential delivery
// (ADR-030) already used for CFGMS_STORAGE_DB_PASSWORD, extended here so the
// DNA backend's password never has to enter a systemd unit's plaintext
// Environment= directive.
func TestBuildDNAConnString_PasswordFromFile(t *testing.T) {
	clearDNAEnv(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "dna-db-password")
	require.NoError(t, os.WriteFile(path, []byte("s3cr3t-from-file\n"), 0o600))

	require.NoError(t, os.Setenv("CFGMS_DNA_DB_PASSWORD_FILE", path))

	dsn, err := buildDNAConnString()
	require.NoError(t, err)
	assert.Contains(t, dsn, "s3cr3t-from-file", "password must be read from the file, with the trailing newline stripped")
	assert.NotContains(t, dsn, "\n", "a trailing newline in the file must not leak into the DSN")
}

// TestBuildDNAConnString_DirectValueWinsOverFile is a required test: an
// operator override via the direct env var takes precedence over a
// file-delivered value, matching resolveEnvValue's documented precedence.
func TestBuildDNAConnString_DirectValueWinsOverFile(t *testing.T) {
	clearDNAEnv(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "dna-db-password")
	require.NoError(t, os.WriteFile(path, []byte("from-file"), 0o600))

	require.NoError(t, os.Setenv("CFGMS_DNA_DB_PASSWORD_FILE", path))
	require.NoError(t, os.Setenv("CFGMS_DNA_DB_PASSWORD", "from-direct-var"))

	dsn, err := buildDNAConnString()
	require.NoError(t, err)
	assert.Contains(t, dsn, "from-direct-var")
	assert.NotContains(t, dsn, "from-file")
}

// TestBuildDNAConnString_MissingPasswordAndFile_Errors is a required test:
// absent both CFGMS_DNA_DB_PASSWORD and CFGMS_DNA_DB_PASSWORD_FILE, the
// backend still fails closed with a clear error — the _FILE addition must not
// weaken the existing "credential required" guarantee.
func TestBuildDNAConnString_MissingPasswordAndFile_Errors(t *testing.T) {
	clearDNAEnv(t)

	_, err := buildDNAConnString()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_DNA_DB_PASSWORD")
}

// TestNewDatabaseBackend_DatabaseURLFromFile is a required test: when
// CFGMS_DNA_DATABASE_URL itself is unset, NewDatabaseBackend resolves it from
// CFGMS_DNA_DATABASE_URL_FILE — the full-connection-string equivalent of the
// individual-var _FILE support above. Uses a real DB connection (skipped when
// unavailable) so the resolved value is proven to actually work end to end,
// not just string-matched.
func TestNewDatabaseBackend_DatabaseURLFromFile(t *testing.T) {
	skipIfDatabaseUnavailable(t)
	clearDNAEnv(t)

	dsn := buildDNATestDSN()
	dropDNATables(t, dsn)

	dir := t.TempDir()
	path := filepath.Join(dir, "dna-database-url")
	require.NoError(t, os.WriteFile(path, []byte(dsn), 0o600))
	require.NoError(t, os.Setenv("CFGMS_DNA_DATABASE_URL_FILE", path))

	backend, err := NewDatabaseBackend(DefaultConfig(), logging.NewNoopLogger())
	require.NoError(t, err, "NewDatabaseBackend must resolve the DSN from CFGMS_DNA_DATABASE_URL_FILE")
	defer backend.Close() //nolint:errcheck
}
