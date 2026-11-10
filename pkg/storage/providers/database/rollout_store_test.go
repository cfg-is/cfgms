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
	rolloutProbeRole     = "cfgms_rollout_probe"
	rolloutProbePassword = "cfgms_rollout_probe_pw" // #nosec G101 -- throwaway role in a disposable test database
)

// TestRolloutStore_Contract runs the shared RolloutStore contract (Issue #5976)
// against PostgreSQL.
func TestRolloutStore_Contract(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseRolloutStore(db, getTestConfig())
	require.NoError(t, err)
	business.RolloutStoreContract(t, store)
}

// TestRolloutStore_ContractUnderRLS runs the same contract as a non-superuser
// role. Superusers bypass row-level security even under FORCE, so only a
// non-superuser connection proves that the by-ID read, the cross-tenant
// ListInProgressRollouts and the tenant-scoped writes work under the policies
// the cluster actually runs with (migration 010, Issue #3478).
func TestRolloutStore_ContractUnderRLS(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	_, err := NewDatabaseRolloutStore(db, getTestConfig())
	require.NoError(t, err)

	probe := provisionRolloutProbe(t, db)
	// The probe cannot own the table, so it cannot run the schema DDL: build the
	// store directly on the probe pool, as a controller connected as a
	// non-superuser service role would after the schema exists.
	business.RolloutStoreContract(t, &DatabaseRolloutStore{db: probe})
}

// TestRolloutStore_PersistsAcrossReopen writes a rollout, drops the store and
// opens a new one on the same database (a controller restart), then reads the
// record back with status, ring progress, halt metadata and deferred stewards.
func TestRolloutStore_PersistsAcrossReopen(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	first, err := NewDatabaseRolloutStore(db, getTestConfig())
	require.NoError(t, err)
	started := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, first.CreateRollout(ctx, &business.RolloutRecord{
		ID: "rollout-reopen", TenantID: "tenant-reopen", InitiatedBy: "admin-1", TargetVersion: "v3.1.0",
		CurrentRing: "canary", RingsTotal: 3, Status: business.RolloutStatusInProgress,
		StartedAt: started, OwnerNodeID: "node-a",
	}))
	require.NoError(t, first.UpdateRolloutProgress(ctx, "rollout-reopen", business.RolloutStatusInProgress, "early", 1, nil, ""))
	require.NoError(t, first.AppendDeferredStewards(ctx, "rollout-reopen", []string{"s-1", "s-2"}))
	halted := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, first.UpdateRolloutProgress(ctx, "rollout-reopen", business.RolloutStatusHalted, "early", 1, &halted, "advancing node stopped"))
	require.NoError(t, first.Close())

	second, err := NewDatabaseRolloutStore(db, getTestConfig())
	require.NoError(t, err)
	got, err := second.GetRollout(ctx, "rollout-reopen")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusHalted, got.Status)
	assert.Equal(t, "early", got.CurrentRing)
	assert.Equal(t, 1, got.RingsCompleted)
	assert.Equal(t, 3, got.RingsTotal)
	assert.Equal(t, "advancing node stopped", got.Error)
	require.NotNil(t, got.HaltedAt)
	assert.True(t, halted.Equal(*got.HaltedAt))
	assert.Equal(t, []string{"s-1", "s-2"}, got.DeferredStewards)
	assert.Equal(t, "node-a", got.OwnerNodeID)
	assert.True(t, started.Equal(got.StartedAt))

	list, err := second.ListRolloutsByTenant(ctx, "tenant-reopen")
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

// TestRolloutStore_SchemaIdempotent proves the table creation can run on every
// startup of every node.
func TestRolloutStore_SchemaIdempotent(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreateRolloutRecordsTable(ctx, db))
	require.NoError(t, schemas.CreateRolloutRecordsTable(ctx, db))

	var reg *string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass('cfgms_rollout_records')::text`).Scan(&reg))
	require.NotNil(t, reg, "cfgms_rollout_records must exist")
}

// TestRolloutStore_ConcurrentAppendsKeepEveryID proves two appenders (two nodes)
// do not overwrite each other's deferred stewards.
func TestRolloutStore_ConcurrentAppendsKeepEveryID(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	store, err := NewDatabaseRolloutStore(db, getTestConfig())
	require.NoError(t, err)
	require.NoError(t, store.CreateRollout(ctx, &business.RolloutRecord{
		ID: "rollout-concurrent", TenantID: "tenant-c", Status: business.RolloutStatusInProgress, StartedAt: time.Now().UTC(),
	}))

	const n = 12
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			errs <- store.AppendDeferredStewards(ctx, "rollout-concurrent", []string{fmt.Sprintf("s-%d", i)})
		}(i)
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
	got, err := store.GetRollout(ctx, "rollout-concurrent")
	require.NoError(t, err)
	assert.Len(t, got.DeferredStewards, n)
}

// provisionRolloutProbe creates a non-superuser role with only the table
// privileges the store needs and returns a pool connected as that role.
func provisionRolloutProbe(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	ctx := context.Background()

	var schemaName string
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT n.nspname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relname = 'cfgms_rollout_records'
		ORDER BY array_position(current_schemas(false), n.nspname)
		LIMIT 1`).Scan(&schemaName), "must resolve the schema cfgms_rollout_records lives in")
	schemaIdent := pq.QuoteIdentifier(schemaName)

	_, _ = db.ExecContext(ctx, fmt.Sprintf(`DROP OWNED BY %s`, rolloutProbeRole))
	for _, stmt := range []string{
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rolloutProbeRole),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, rolloutProbeRole, rolloutProbePassword),
		fmt.Sprintf(`ALTER ROLE %s SET search_path = %s, public`, rolloutProbeRole, schemaIdent),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA %s TO %s`, schemaIdent, rolloutProbeRole),
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE ON cfgms_rollout_records TO %s`, rolloutProbeRole),
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Skipf("cannot provision a non-superuser probe role (needs CREATEROLE): %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP OWNED BY %s`, rolloutProbeRole))
		_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rolloutProbeRole))
	})

	cfg := getTestConfig()
	probe, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], rolloutProbeRole, rolloutProbePassword, cfg["sslmode"]))
	require.NoError(t, err)
	t.Cleanup(func() { _ = probe.Close() })
	require.NoError(t, probe.Ping())
	return probe
}
