// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// versionRow is the full content of the single cfgms_schema_version row.
type versionRow struct {
	version, minNode, contractApplied int
	recentRequired                    sql.NullInt64
	recentAt                          sql.NullTime
}

func readVersionRow(t *testing.T, db *sql.DB) versionRow {
	t.Helper()
	var r versionRow
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT version, min_node_version, contract_applied, recent_gate_required, recent_gate_at
		FROM cfgms_schema_version WHERE id = 1`).
		Scan(&r.version, &r.minNode, &r.contractApplied, &r.recentRequired, &r.recentAt))
	return r
}

func countVersionRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `SELECT count(*) FROM cfgms_schema_version`).Scan(&n))
	return n
}

// prepareVersionRow makes sure the version row exists, snapshots it and restores the
// snapshot in t.Cleanup: keep-schema mode does not truncate cfgms_schema_version, so a
// test that edits the row must put it back for the tests that follow.
func prepareVersionRow(t *testing.T, db *sql.DB) {
	t.Helper()
	require.NoError(t, checkSchemaVersion(context.Background(), db, currentSchemaRange()))
	orig := readVersionRow(t, db)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `
			UPDATE cfgms_schema_version SET version = $1, min_node_version = $2, contract_applied = $3,
				recent_gate_required = $4, recent_gate_at = $5 WHERE id = 1`,
			orig.version, orig.minNode, orig.contractApplied, orig.recentRequired, orig.recentAt)
		assert.NoError(t, err, "restoring cfgms_schema_version")
	})
}

func setVersionRow(t *testing.T, db *sql.DB, version, minNode int) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		UPDATE cfgms_schema_version SET version = $1, min_node_version = $2,
			recent_gate_required = NULL, recent_gate_at = NULL WHERE id = 1`, version, minNode)
	require.NoError(t, err)
}

func cachedPoolCount(p *DatabaseProvider) int {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	return len(p.pools)
}

func newGateProvider(t *testing.T, r schemaRange) *DatabaseProvider {
	t.Helper()
	p := &DatabaseProvider{schemaRange: r}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestSchemaVersion_Constants(t *testing.T) {
	assert.GreaterOrEqual(t, SchemaVersion, 1)
	assert.LessOrEqual(t, MinToleratedSchemaVersion, SchemaVersion, "a node must tolerate its own version")
	assert.Equal(t, schemaRange{SchemaVersion: SchemaVersion, MinTolerated: MinToleratedSchemaVersion}, currentSchemaRange())
}

func TestSchemaVersion_FreshDatabaseRecordsCurrent(t *testing.T) {
	skipInKeepSchemaMode(t, "needs an empty database; keep mode preserves another revision's cfgms_schema_version")
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := newGateProvider(t, schemaRange{})
	_, err := provider.CreateConfigStore(getTestConfig())
	require.NoError(t, err)

	assert.Equal(t, 1, countVersionRows(t, db))
	assert.Equal(t, SchemaVersion, readVersionRow(t, db).version)
}

func TestSchemaVersion_LegacyDatabaseWithoutRecordIsAccepted(t *testing.T) {
	skipInKeepSchemaMode(t, "needs a database without a version record")
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	// A database created by an earlier revision: store tables exist, no version table.
	require.NoError(t, NewDatabaseSchemas().CreateAllTables(context.Background(), db))
	var regclass sql.NullString
	require.NoError(t, db.QueryRow(`SELECT to_regclass('cfgms_schema_version')::text`).Scan(&regclass))
	require.False(t, regclass.Valid, "precondition: no version table")

	provider := newGateProvider(t, schemaRange{})
	_, err := provider.CreateConfigStore(getTestConfig())
	require.NoError(t, err)

	assert.Equal(t, 1, countVersionRows(t, db))
	assert.Equal(t, SchemaVersion, readVersionRow(t, db).version)
}

func TestSchemaVersion_RefusesRecordedVersionBelowTolerated(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 2, 0)

	provider := newGateProvider(t, schemaRange{SchemaVersion: 5, MinTolerated: 3})
	config := getTestConfig()
	_, err := provider.CreateConfigStore(config)
	require.Error(t, err)

	assert.ErrorIs(t, err, ErrSchemaVersionOutOfRange)
	assert.NotErrorIs(t, err, business.ErrNotSupported)
	assert.Contains(t, err.Error(), "recorded schema version is 2")
	assert.Contains(t, err.Error(), "tolerates 3 through 5")
	assert.Contains(t, err.Error(), "upgrade")
	assert.NotContains(t, err.Error(), fmt.Sprint(config["password"]), "error must not carry credentials")
	assert.Zero(t, cachedPoolCount(provider), "a refused pool must not be cached")
	assert.Equal(t, 2, readVersionRow(t, db).version, "a refusal must not change the row")
}

func TestSchemaVersion_RefusesWhenContractFloorAboveNode(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 4, 4)

	provider := newGateProvider(t, schemaRange{SchemaVersion: 2, MinTolerated: 0})
	_, err := provider.CreateConfigStore(getTestConfig())
	require.Error(t, err)

	assert.ErrorIs(t, err, ErrSchemaVersionOutOfRange)
	assert.NotErrorIs(t, err, business.ErrNotSupported)
	assert.Contains(t, err.Error(), "schema version 4 or later")
	assert.Contains(t, err.Error(), "controller is at 2")
	assert.Zero(t, cachedPoolCount(provider))
}

func TestSchemaVersion_NeverLowersRecordedVersion(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 7, 0)

	provider := newGateProvider(t, schemaRange{SchemaVersion: 2, MinTolerated: 0})
	_, err := provider.sharedPool(getTestConfig())
	require.NoError(t, err)

	assert.Equal(t, 7, readVersionRow(t, db).version, "an older-range node must not lower the recorded version")
}

func TestSchemaVersion_RaisesRecordedVersion(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 1, 0)

	provider := newGateProvider(t, schemaRange{SchemaVersion: 3, MinTolerated: 1})
	_, err := provider.sharedPool(getTestConfig())
	require.NoError(t, err)

	assert.Equal(t, 3, readVersionRow(t, db).version)
}

func TestSchemaVersion_ConcurrentFirstStartConverges(t *testing.T) {
	skipInKeepSchemaMode(t, "needs an empty database to race the first start")
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	// Separate providers so the provider-wide pool mutex does not serialise the gates.
	const nodes = 8
	providers := make([]*DatabaseProvider, nodes)
	errs := make([]error, nodes)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range providers {
		providers[i] = newGateProvider(t, schemaRange{})
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = providers[i].sharedPool(getTestConfig())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "node %d", i)
	}
	assert.Equal(t, 1, countVersionRows(t, db))
	assert.Equal(t, SchemaVersion, readVersionRow(t, db).version)
}

func TestSchemaVersion_GateRecordsRecentGatePass(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 0, 0)

	pass := func(r schemaRange) {
		t.Helper()
		p := newGateProvider(t, r)
		_, err := p.sharedPool(getTestConfig())
		require.NoError(t, err)
	}

	pass(schemaRange{SchemaVersion: 3})
	row := readVersionRow(t, db)
	assert.Equal(t, int64(3), row.recentRequired.Int64)
	require.True(t, row.recentAt.Valid)
	assert.WithinDuration(t, time.Now(), row.recentAt.Time, time.Minute)

	// A lower pass within the window lowers the recorded requirement; a higher one does not raise it.
	pass(schemaRange{SchemaVersion: 2})
	assert.Equal(t, int64(2), readVersionRow(t, db).recentRequired.Int64)
	pass(schemaRange{SchemaVersion: 5})
	assert.Equal(t, int64(2), readVersionRow(t, db).recentRequired.Int64)

	// Once the earlier pass is stale it no longer constrains the requirement.
	_, err := db.Exec(`UPDATE cfgms_schema_version SET recent_gate_at = now() - ($1::double precision * interval '1 second') WHERE id = 1`,
		(business.NodeRegistryStaleAfter + time.Minute).Seconds())
	require.NoError(t, err)
	pass(schemaRange{SchemaVersion: 4})
	row = readVersionRow(t, db)
	assert.Equal(t, int64(4), row.recentRequired.Int64)
	assert.WithinDuration(t, time.Now(), row.recentAt.Time, time.Minute)
}

func TestSchemaVersion_RefusedNodeDoesNotRecordRecentGate(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 2, 0)

	provider := newGateProvider(t, schemaRange{SchemaVersion: 5, MinTolerated: 3})
	_, err := provider.sharedPool(getTestConfig())
	require.ErrorIs(t, err, ErrSchemaVersionOutOfRange)

	row := readVersionRow(t, db)
	assert.False(t, row.recentRequired.Valid, "a refused node must not record recent_gate_required")
	assert.False(t, row.recentAt.Valid, "a refused node must not record recent_gate_at")
}

func TestSchemaVersion_RefusalLeavesNoCachedPool(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	prepareVersionRow(t, db)
	setVersionRow(t, db, 2, 0)

	provider := newGateProvider(t, schemaRange{SchemaVersion: 5, MinTolerated: 3})
	config := getTestConfig()

	_, err := provider.CreateConfigStore(config)
	require.ErrorIs(t, err, ErrSchemaVersionOutOfRange)
	assert.Zero(t, cachedPoolCount(provider))

	// Repair the row: a retry must re-run the gate and succeed.
	setVersionRow(t, db, 3, 0)
	store, err := provider.CreateConfigStore(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	assert.Equal(t, 1, cachedPoolCount(provider))
	assert.Equal(t, 5, readVersionRow(t, db).version)
}

func TestSchemaVersion_DropAllTablesRemovesVersionTable(t *testing.T) {
	skipInKeepSchemaMode(t, "DropAllTables is destructive and keep mode preserves cfgms_schema_version")
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, checkSchemaVersion(context.Background(), db, currentSchemaRange()))
	exists := func() bool {
		var regclass sql.NullString
		require.NoError(t, db.QueryRow(`SELECT to_regclass('cfgms_schema_version')::text`).Scan(&regclass))
		return regclass.Valid
	}
	require.True(t, exists(), "precondition: table exists")

	require.NoError(t, NewDatabaseSchemas().DropAllTables(context.Background(), db))
	assert.False(t, exists(), "DropAllTables must remove cfgms_schema_version")
}

func TestSchemaVersion_ErrorSentinelIsNotNotSupported(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", ErrSchemaVersionOutOfRange)
	assert.True(t, errors.Is(err, ErrSchemaVersionOutOfRange))
	assert.False(t, errors.Is(ErrSchemaVersionOutOfRange, business.ErrNotSupported))
}
