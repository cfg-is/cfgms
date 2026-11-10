// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	upgradeProbeRole     = "cfgms_upgrade_probe"
	upgradeProbePassword = "cfgms_upgrade_probe_pw" // #nosec G101 -- throwaway role in a disposable test database
)

// upgradeTestRecord returns an UpgradeRecord with every mandatory field set.
func upgradeTestRecord(id, stewardID, tenantID string) *business.UpgradeRecord {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.UpgradeRecord{
		ID:        id,
		StewardID: stewardID,
		TenantID:  tenantID,
		Version:   "v2.0.0",
		Platform:  "linux",
		Arch:      "amd64",
		SHA256:    "deadbeefdeadbeefdeadbeefdeadbeef",
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "operator@example.com",
			TenantID:   tenantID,
			AuthMethod: "mtls",
		},
		Publisher:       "cfgms",
		SignatureDigest: "sha256:cafebabe",
		BundleSignature: []byte{0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04},
		CreatedAt:       now,
		OperationNonce:  []byte{0xde, 0xad, 0xbe, 0xef},
		DispatchedAt:    now,
	}
}

// TestUpgradeStore_Contract runs the shared UpgradeStore contract (Issue #5977)
// against PostgreSQL.
func TestUpgradeStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseUpgradeStore(db, getTestConfig())
	require.NoError(t, err)
	business.UpgradeStoreContract(t, store)
}

// TestUpgradeStore_ContractUnderRLS runs the same contract as a non-superuser
// role. Superusers bypass row-level security even under FORCE, so only a
// non-superuser connection proves that the by-ID read, the listings and the
// tenant-scoped writes work under the policies the cluster actually runs with
// (migration 010, Issue #3478).
func TestUpgradeStore_ContractUnderRLS(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	_, err := NewDatabaseUpgradeStore(db, getTestConfig())
	require.NoError(t, err)

	probe := provisionUpgradeProbe(t, db)
	// The probe cannot own the table, so it cannot run the schema DDL: build the
	// store directly on the probe pool, as a controller connected as a
	// non-superuser service role would after the schema exists.
	business.UpgradeStoreContract(t, &DatabaseUpgradeStore{db: probe})
}

// TestUpgradeStore_PersistsAcrossReopen writes an upgrade, drops the store and
// opens a new one on the same database (a controller restart), then reads the
// record back with its status, signature provenance and completion time.
func TestUpgradeStore_PersistsAcrossReopen(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	first, err := NewDatabaseUpgradeStore(db, getTestConfig())
	require.NoError(t, err)
	rec := upgradeTestRecord("upg-reopen", "steward-reopen", "tenant-reopen")
	require.NoError(t, first.CreateUpgrade(ctx, rec))
	require.NoError(t, first.UpdateUpgradeStatus(ctx, "upg-reopen", business.UpgradeStatusFailed, "checksum mismatch"))
	require.NoError(t, first.Close())

	second, err := NewDatabaseUpgradeStore(db, getTestConfig())
	require.NoError(t, err)
	got, err := second.GetUpgrade(ctx, "upg-reopen")
	require.NoError(t, err)
	assert.Equal(t, business.UpgradeStatusFailed, got.Status)
	assert.Equal(t, "checksum mismatch", got.ErrorMessage)
	assert.Equal(t, rec.BundleSignature, got.BundleSignature)
	assert.Equal(t, rec.Publisher, got.Publisher)
	require.NotNil(t, got.CompletedAt)

	list, err := second.ListUpgradesBySteward(ctx, "steward-reopen")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "upg-reopen", list[0].ID)
}

// TestUpgradeStore_TwoNodesShareRecords proves the cluster property the store
// exists for: two nodes, each with its own connection pool and store handle on
// one database, see each other's records and status updates.
func TestUpgradeStore_TwoNodesShareRecords(t *testing.T) {
	dbA := setupTestDatabase(t)
	t.Cleanup(func() { _ = dbA.Close() })
	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	ctx := context.Background()

	nodeA, err := NewDatabaseUpgradeStore(dbA, getTestConfig())
	require.NoError(t, err)
	nodeB, err := NewDatabaseUpgradeStore(dbB, getTestConfig())
	require.NoError(t, err)

	require.NoError(t, nodeA.CreateUpgrade(ctx, upgradeTestRecord("upg-shared", "steward-shared", "tenant-shared")))

	got, err := nodeB.GetUpgrade(ctx, "upg-shared")
	require.NoError(t, err, "a record created on one node must be readable on another")
	assert.Equal(t, "steward-shared", got.StewardID)

	require.NoError(t, nodeB.UpdateUpgradeStatus(ctx, "upg-shared", business.UpgradeStatusRolledBack, "operator rollback"))
	got, err = nodeA.GetUpgrade(ctx, "upg-shared")
	require.NoError(t, err)
	assert.Equal(t, business.UpgradeStatusRolledBack, got.Status, "a status update on one node must be visible on another")
}

// TestUpgradeStore_CreateErrors covers the refusals that keep the audit trail
// intact: a nil record, a missing signature and a duplicate ID.
func TestUpgradeStore_CreateErrors(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	store, err := NewDatabaseUpgradeStore(db, getTestConfig())
	require.NoError(t, err)

	require.Error(t, store.CreateUpgrade(ctx, nil))

	unsigned := upgradeTestRecord("upg-unsigned", "steward-e", "tenant-e")
	unsigned.BundleSignature = nil
	require.Error(t, store.CreateUpgrade(ctx, unsigned))

	rec := upgradeTestRecord("upg-dup", "steward-e", "tenant-e")
	require.NoError(t, store.CreateUpgrade(ctx, rec))
	err = store.CreateUpgrade(ctx, rec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestUpgradeStore_AbsentNonceRoundTrips proves a record without an operation
// nonce is stored and read back without one.
func TestUpgradeStore_AbsentNonceRoundTrips(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	store, err := NewDatabaseUpgradeStore(db, getTestConfig())
	require.NoError(t, err)

	rec := upgradeTestRecord("upg-nononce", "steward-n", "tenant-n")
	rec.OperationNonce = nil
	require.NoError(t, store.CreateUpgrade(ctx, rec))
	got, err := store.GetUpgrade(ctx, "upg-nononce")
	require.NoError(t, err)
	assert.Empty(t, got.OperationNonce)
}

// TestUpgradeStore_SchemaIdempotent proves the table creation can run on every
// startup of every node.
func TestUpgradeStore_SchemaIdempotent(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreateUpgradeRecordsTable(ctx, db))
	require.NoError(t, schemas.CreateUpgradeRecordsTable(ctx, db))

	var reg *string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass('cfgms_upgrade_records')::text`).Scan(&reg))
	require.NotNil(t, reg, "cfgms_upgrade_records must exist")
}

// TestDatabaseProvider_CreateUpgradeStore proves the provider creator returns a
// working store on the shared pool.
func TestDatabaseProvider_CreateUpgradeStore(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	store, err := provider.CreateUpgradeStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)
	ctx := context.Background()
	require.NoError(t, store.CreateUpgrade(ctx, upgradeTestRecord("upg-provider", "steward-p", "tenant-p")))
	got, err := store.GetUpgrade(ctx, "upg-provider")
	require.NoError(t, err)
	assert.Equal(t, "steward-p", got.StewardID)
}

// TestDatabaseProvider_CreateUpgradeStore_BadConfig proves a configuration the
// provider cannot connect with is reported, not turned into a nil store.
func TestDatabaseProvider_CreateUpgradeStore_BadConfig(t *testing.T) {
	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	store, err := provider.CreateUpgradeStore(map[string]interface{}{})
	require.Error(t, err)
	assert.Nil(t, store)
}

// provisionUpgradeProbe creates a non-superuser role with only the table
// privileges the store needs and returns a pool connected as that role.
//
//duplication:justified pkg/storage/providers/database/rollout_store_test.go -- same non-superuser probe-role provisioning as provisionRolloutProbe; the role name and table differ
func provisionUpgradeProbe(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	ctx := context.Background()

	var schemaName string
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT n.nspname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relname = 'cfgms_upgrade_records'
		ORDER BY array_position(current_schemas(false), n.nspname)
		LIMIT 1`).Scan(&schemaName), "must resolve the schema cfgms_upgrade_records lives in")
	schemaIdent := pq.QuoteIdentifier(schemaName)

	_, _ = db.ExecContext(ctx, fmt.Sprintf(`DROP OWNED BY %s`, upgradeProbeRole))
	for _, stmt := range []string{
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, upgradeProbeRole),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, upgradeProbeRole, upgradeProbePassword),
		fmt.Sprintf(`ALTER ROLE %s SET search_path = %s, public`, upgradeProbeRole, schemaIdent),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA %s TO %s`, schemaIdent, upgradeProbeRole),
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE ON cfgms_upgrade_records TO %s`, upgradeProbeRole),
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Skipf("cannot provision a non-superuser probe role (needs CREATEROLE): %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP OWNED BY %s`, upgradeProbeRole))
		_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, upgradeProbeRole))
	})

	cfg := getTestConfig()
	probe, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], upgradeProbeRole, upgradeProbePassword, cfg["sslmode"]))
	require.NoError(t, err)
	t.Cleanup(func() { _ = probe.Close() })
	require.NoError(t, probe.Ping())
	return probe
}
