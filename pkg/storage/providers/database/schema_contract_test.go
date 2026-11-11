// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The contract-step tests run against a real Postgres. The production step list is
// empty and SchemaVersion is 1, so no step is valid against the production constants:
// the tests inject a schemaRange with a higher ceiling and their own step lists. Every
// step drops a column of a scratch table the test creates, never a production table.

// contractTestRange is the range the tests apply steps under: a node at schema version 5.
var contractTestRange = schemaRange{SchemaVersion: 5, MinTolerated: 0}

const (
	scratchTable    = "cfgms_contract_scratch"
	scratchLogTable = "cfgms_contract_scratch_log"
)

// freshTestDB opens a connection of its own. Cleanups use it because the db handle a
// test closes with a defer is already closed when t.Cleanup functions run.
func freshTestDB(t *testing.T) *sql.DB {
	t.Helper()
	cfg := getTestConfig()
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], cfg["username"], cfg["password"], cfg["sslmode"])
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	return db
}

// execFresh runs statements on a fresh connection; used from t.Cleanup.
func execFresh(t *testing.T, statements ...string) {
	t.Helper()
	db := freshTestDB(t)
	defer func() { _ = db.Close() }()
	for _, s := range statements {
		_, err := db.ExecContext(context.Background(), s)
		assert.NoError(t, err, "cleanup statement %q", s)
	}
}

// contractEnv prepares a database for a contract-step test: the version row is
// snapshotted (and restored in t.Cleanup) and reset to the given recorded version with
// no floor, no applied step and no recent gate pass; a scratch table exists; and, when
// withRegistry is set, an empty node registry exists.
func contractEnv(t *testing.T, recordedVersion int, withRegistry bool) *sql.DB {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	prepareVersionRow(t, db)

	_, err := db.Exec(`
		UPDATE cfgms_schema_version SET version = $1, min_node_version = 0, contract_applied = 0,
			recent_gate_required = NULL, recent_gate_at = NULL WHERE id = 1`, recordedVersion)
	require.NoError(t, err)

	for _, s := range []string{
		`DROP TABLE IF EXISTS ` + scratchTable + `, ` + scratchLogTable,
		`CREATE TABLE ` + scratchTable + ` (id INTEGER, col_a TEXT, col_b TEXT)`,
		`CREATE TABLE ` + scratchLogTable + ` (n INTEGER)`,
	} {
		_, err := db.Exec(s)
		require.NoError(t, err)
	}
	t.Cleanup(func() { execFresh(t, `DROP TABLE IF EXISTS `+scratchTable+`, `+scratchLogTable) })

	if withRegistry {
		require.NoError(t, NewDatabaseSchemas().CreateNodeRegistryTable(context.Background(), db))
		_, err := db.Exec(`DELETE FROM cfgms_node_registry`)
		require.NoError(t, err)
		t.Cleanup(func() { execFresh(t, `DELETE FROM cfgms_node_registry`) })
	}
	return db
}

// insertNode adds a registry row whose liveness timestamp is age in the past on the
// database clock.
func insertNode(t *testing.T, db *sql.DB, id string, schemaRequired int, age time.Duration) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO cfgms_node_registry (node_id, address, version, schema_required, updated_at)
		VALUES ($1, 'addr', 'test', $2, now() - ($3::double precision * interval '1 second'))`,
		id, schemaRequired, age.Seconds())
	require.NoError(t, err)
}

func scratchHasColumn(t *testing.T, db *sql.DB, column string) bool {
	t.Helper()
	var exists bool
	require.NoError(t, db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		               WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`,
		scratchTable, column).Scan(&exists))
	return exists
}

func scratchLogCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+scratchLogTable).Scan(&n))
	return n
}

// dropColumnStep drops a scratch column and logs that it ran. The drop has no IF
// EXISTS, so running the step twice fails, and the log row counts how often it ran.
func dropColumnStep(version, unusedSince int, column string) ContractStep {
	return ContractStep{
		Version:     version,
		UnusedSince: unusedSince,
		Description: "drop scratch column " + column,
		Statements: []string{
			`ALTER TABLE ` + scratchTable + ` DROP COLUMN ` + column,
			fmt.Sprintf(`INSERT INTO %s (n) VALUES (%d)`, scratchLogTable, version),
		},
	}
}

func apply(t *testing.T, db *sql.DB, steps ...ContractStep) error {
	t.Helper()
	return ApplyContractSteps(context.Background(), db, contractTestRange, steps)
}

func requireUnchanged(t *testing.T, db *sql.DB, wantMinNode, wantApplied int) {
	t.Helper()
	row := readVersionRow(t, db)
	assert.Equal(t, wantMinNode, row.minNode, "min_node_version")
	assert.Equal(t, wantApplied, row.contractApplied, "contract_applied")
}

func TestApplyContractSteps_ProductionListIsEmptyNoOp(t *testing.T) {
	assert.Empty(t, contractSteps, "no real contract step ships in this story")

	// A nil database proves that no step means no database access.
	require.NoError(t, ApplyContractSteps(context.Background(), nil, currentSchemaRange(), contractSteps))
}

func TestApplyContractSteps_InvalidStepRejected(t *testing.T) {
	cases := []struct {
		name  string
		steps []ContractStep
	}{
		{"unused-since equals version", []ContractStep{{Version: 3, UnusedSince: 3}}},
		{"unused-since above version", []ContractStep{{Version: 3, UnusedSince: 4}}},
		{"unused-since zero", []ContractStep{{Version: 3, UnusedSince: 0}}},
		{"unused-since negative", []ContractStep{{Version: 3, UnusedSince: -1}}},
		{"version above the node schema version", []ContractStep{{Version: 6, UnusedSince: 2}}},
		{"duplicate version", []ContractStep{{Version: 3, UnusedSince: 2}, {Version: 3, UnusedSince: 1}}},
		{"valid step before an invalid one", []ContractStep{{Version: 3, UnusedSince: 2}, {Version: 4, UnusedSince: 4}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A nil database: validation must fail before the database is touched.
			err := ApplyContractSteps(context.Background(), nil, contractTestRange, tc.steps)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidContractStep)
			assert.NotErrorIs(t, err, ErrContractStepBlocked)
		})
	}

	t.Run("production constants admit no step", func(t *testing.T) {
		err := ApplyContractSteps(context.Background(), nil, currentSchemaRange(), []ContractStep{{Version: 2, UnusedSince: 1}})
		assert.ErrorIs(t, err, ErrInvalidContractStep, "SchemaVersion is %d, so version 2 is above it", SchemaVersion)
	})
}

func TestApplyContractSteps_InvalidStepAppliesNothing(t *testing.T) {
	db := contractEnv(t, 5, true)

	err := apply(t, db, dropColumnStep(3, 2, "col_a"), dropColumnStep(4, 4, "col_b"))
	require.ErrorIs(t, err, ErrInvalidContractStep)

	assert.True(t, scratchHasColumn(t, db, "col_a"), "the valid step must not run when the list is invalid")
	requireUnchanged(t, db, 0, 0)
}

func TestApplyContractSteps_BlockedByLiveOlderNode(t *testing.T) {
	db := contractEnv(t, 5, true)
	insertNode(t, db, "node-old", 1, 0)

	err := apply(t, db, dropColumnStep(3, 2, "col_a"))
	require.Error(t, err)

	assert.ErrorIs(t, err, ErrContractStepBlocked)
	assert.Contains(t, err.Error(), `"node-old"`, "the error names the blocking node")
	assert.Contains(t, err.Error(), "schema version 1", "the error names the blocking node's version")
	assert.Contains(t, err.Error(), "step version 3")
	assert.True(t, scratchHasColumn(t, db, "col_a"), "a blocked step must not run its statements")
	assert.Zero(t, scratchLogCount(t, db))
	requireUnchanged(t, db, 0, 0)
}

func TestApplyContractSteps_NMinusOneAtMarkerDoesNotBlockAndKeepsRollback(t *testing.T) {
	db := contractEnv(t, 3, true)
	// The previous revision of a normal roll: exactly at the marker.
	insertNode(t, db, "node-n-minus-1", 2, 0)

	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	assert.False(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 2, 3)

	// The node at the marker is not refused by the schema-version gate after the step...
	atMarker := newGateProvider(t, schemaRange{SchemaVersion: 2, MinTolerated: 0})
	_, err := atMarker.sharedPool(getTestConfig())
	require.NoError(t, err, "rollback by one version must still start")

	// ...and one below the marker is.
	below := newGateProvider(t, schemaRange{SchemaVersion: 1, MinTolerated: 0})
	_, err = below.sharedPool(getTestConfig())
	require.ErrorIs(t, err, ErrSchemaVersionOutOfRange)
}

func TestApplyContractSteps_GatePassedButNotYetRegisteredBlocks(t *testing.T) {
	db := contractEnv(t, 3, true)

	// A node at schema version 1 passes the gate; it has no registry row yet.
	require.NoError(t, checkSchemaVersion(context.Background(), db, schemaRange{SchemaVersion: 1}))
	row := readVersionRow(t, db)
	require.True(t, row.recentRequired.Valid)
	require.Equal(t, int64(1), row.recentRequired.Int64)

	err := apply(t, db, dropColumnStep(3, 2, "col_a"))
	require.ErrorIs(t, err, ErrContractStepBlocked)
	assert.Contains(t, err.Error(), "passed the schema-version gate at schema version 1")
	assert.True(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 0, 0)
}

func TestApplyContractSteps_GatePassAtMarkerOrStaleDoesNotBlock(t *testing.T) {
	db := contractEnv(t, 3, true)

	// A gate pass at the marker does not block.
	require.NoError(t, checkSchemaVersion(context.Background(), db, schemaRange{SchemaVersion: 2}))
	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	requireUnchanged(t, db, 2, 3)

	// A gate pass below a later step's marker blocks while recent, and not once stale.
	_, err := db.Exec(`UPDATE cfgms_schema_version SET recent_gate_required = 2, recent_gate_at = now() WHERE id = 1`)
	require.NoError(t, err)
	require.ErrorIs(t, apply(t, db, dropColumnStep(4, 3, "col_b")), ErrContractStepBlocked)

	_, err = db.Exec(`UPDATE cfgms_schema_version SET recent_gate_at = now() - ($1::double precision * interval '1 second') WHERE id = 1`,
		(business.NodeRegistryStaleAfter + time.Minute).Seconds())
	require.NoError(t, err)
	require.NoError(t, apply(t, db, dropColumnStep(4, 3, "col_b")))
	requireUnchanged(t, db, 3, 4)
}

func TestApplyContractSteps_StaleNodeDoesNotBlock(t *testing.T) {
	db := contractEnv(t, 5, true)
	insertNode(t, db, "node-gone", 1, business.NodeRegistryStaleAfter+time.Minute)

	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	assert.False(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_LegacyZeroRowBlocks(t *testing.T) {
	db := contractEnv(t, 5, true)
	// A node that predates the column never wrote it: the row keeps the default 0.
	_, err := db.Exec(`INSERT INTO cfgms_node_registry (node_id, address) VALUES ('node-legacy', 'addr')`)
	require.NoError(t, err)

	err = apply(t, db, dropColumnStep(3, 2, "col_a"))
	require.ErrorIs(t, err, ErrContractStepBlocked)
	assert.Contains(t, err.Error(), `"node-legacy"`)
	assert.Contains(t, err.Error(), "schema version 0")
	assert.True(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 0, 0)
}

func TestApplyContractSteps_RegistryWithoutSchemaColumnBlocks(t *testing.T) {
	skipInKeepSchemaMode(t, "drops registry columns, which keep mode must preserve for the other revision")
	db := contractEnv(t, 5, true)

	// The registry as an older revision created it, before schema_required existed. The
	// cleanup (registered after the registry's own, so it runs first) re-adds the columns.
	t.Cleanup(func() {
		fresh := freshTestDB(t)
		defer func() { _ = fresh.Close() }()
		assert.NoError(t, NewDatabaseSchemas().CreateNodeRegistryTable(context.Background(), fresh))
	})
	_, err := db.Exec(`ALTER TABLE cfgms_node_registry DROP COLUMN schema_required, DROP COLUMN schema_min_tolerated`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO cfgms_node_registry (node_id, address) VALUES ('node-ancient', 'addr')`)
	require.NoError(t, err)

	// A live row blocks, and the missing column is not an error.
	err = apply(t, db, dropColumnStep(3, 2, "col_a"))
	require.ErrorIs(t, err, ErrContractStepBlocked)
	assert.Contains(t, err.Error(), `"node-ancient"`)
	assert.True(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 0, 0)

	// Once the row is stale nothing blocks, and still no undefined-column error.
	_, err = db.Exec(`UPDATE cfgms_node_registry SET updated_at = now() - ($1::double precision * interval '1 second')`,
		(business.NodeRegistryStaleAfter + time.Minute).Seconds())
	require.NoError(t, err)
	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_MissingRegistryTableMeansNoNodes(t *testing.T) {
	skipInKeepSchemaMode(t, "drops the node registry table, which keep mode must preserve for the other revision")
	db := contractEnv(t, 5, false)
	_, err := db.Exec(`DROP TABLE IF EXISTS cfgms_node_registry`)
	require.NoError(t, err)

	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	assert.False(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_AppliesOnceAndRaisesFloor(t *testing.T) {
	db := contractEnv(t, 5, true)
	step := dropColumnStep(3, 2, "col_a")

	require.NoError(t, apply(t, db, step))
	assert.False(t, scratchHasColumn(t, db, "col_a"))
	assert.Equal(t, 1, scratchLogCount(t, db))
	row := readVersionRow(t, db)
	assert.GreaterOrEqual(t, row.minNode, step.UnusedSince)
	assert.Equal(t, step.Version, row.contractApplied)

	// A second call is a no-op: re-running the drop would fail.
	require.NoError(t, apply(t, db, step))
	assert.Equal(t, 1, scratchLogCount(t, db))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_NeverLowersFloor(t *testing.T) {
	db := contractEnv(t, 5, true)
	_, err := db.Exec(`UPDATE cfgms_schema_version SET min_node_version = 4 WHERE id = 1`)
	require.NoError(t, err)

	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	requireUnchanged(t, db, 4, 3)
}

func TestApplyContractSteps_LaterStepWithSmallerMarkerStillApplies(t *testing.T) {
	db := contractEnv(t, 5, true)
	first := dropColumnStep(3, 2, "col_a")
	later := dropColumnStep(4, 1, "col_b") // smaller marker than the floor the first step raised

	require.NoError(t, apply(t, db, first))
	requireUnchanged(t, db, 2, 3)

	// The floor (2) is above the later step's marker (1), yet the step has not run:
	// contract_applied, not the floor, says what was applied.
	require.NoError(t, apply(t, db, first, later))
	assert.False(t, scratchHasColumn(t, db, "col_b"))
	assert.Equal(t, 2, scratchLogCount(t, db), "each step ran exactly once")
	requireUnchanged(t, db, 2, 4)

	require.NoError(t, apply(t, db, first, later))
	assert.Equal(t, 2, scratchLogCount(t, db))
}

func TestApplyContractSteps_AppliesInAscendingVersionOrder(t *testing.T) {
	db := contractEnv(t, 5, true)

	// Listed out of order: version 4 must not run before version 3.
	require.NoError(t, apply(t, db, dropColumnStep(4, 2, "col_b"), dropColumnStep(3, 2, "col_a")))

	// ctid order is insertion order for a table that is only ever appended to.
	rows, err := db.Query(`SELECT n FROM ` + scratchLogTable + ` ORDER BY ctid`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var ran []int
	for rows.Next() {
		var n int
		require.NoError(t, rows.Scan(&n))
		ran = append(ran, n)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []int{3, 4}, ran)
	requireUnchanged(t, db, 2, 4)
}

func TestApplyContractSteps_BlockedStepStopsLaterSteps(t *testing.T) {
	db := contractEnv(t, 5, true)
	insertNode(t, db, "node-old", 2, 0)

	// The first step (marker 2) applies; the second (marker 3) is blocked by the node at 2.
	err := apply(t, db, dropColumnStep(3, 2, "col_a"), dropColumnStep(4, 3, "col_b"))
	require.ErrorIs(t, err, ErrContractStepBlocked)
	assert.Contains(t, err.Error(), "step version 4")

	assert.False(t, scratchHasColumn(t, db, "col_a"), "the unblocked step before it stays applied")
	assert.True(t, scratchHasColumn(t, db, "col_b"))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_ConcurrentCallsApplyOnce(t *testing.T) {
	db := contractEnv(t, 5, true)
	step := dropColumnStep(3, 2, "col_a")

	const nodes = 8
	errs := make([]error, nodes)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = ApplyContractSteps(context.Background(), db, contractTestRange, []ContractStep{step})
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "call %d", i)
	}
	assert.Equal(t, 1, scratchLogCount(t, db), "the step ran exactly once")
	assert.False(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_FloorRefusesOlderNodeAtStartup(t *testing.T) {
	db := contractEnv(t, 5, true)
	require.NoError(t, apply(t, db, dropColumnStep(4, 3, "col_a")))
	requireUnchanged(t, db, 3, 4)

	// Through sharedPool: a node whose SchemaVersion is below the marker is refused.
	older := newGateProvider(t, schemaRange{SchemaVersion: 2, MinTolerated: 0})
	config := getTestConfig()
	_, err := older.sharedPool(config)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSchemaVersionOutOfRange)
	assert.Contains(t, err.Error(), "schema version 3 or later")
	assert.Zero(t, cachedPoolCount(older), "a refused pool must not be cached")

	// A node at the marker, and a newer one, start.
	for _, version := range []int{3, 5} {
		p := newGateProvider(t, schemaRange{SchemaVersion: version, MinTolerated: 0})
		_, err := p.sharedPool(config)
		require.NoError(t, err, "node at schema version %d", version)
	}
}

func TestApplyContractSteps_FailedStatementRollsBack(t *testing.T) {
	db := contractEnv(t, 5, true)
	step := dropColumnStep(3, 2, "col_a")
	step.Statements = append(step.Statements, `ALTER TABLE cfgms_contract_table_that_does_not_exist DROP COLUMN x`)

	err := apply(t, db, step)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrContractStepBlocked, "a statement failure is not a block")
	assert.Contains(t, err.Error(), "statement 3")

	assert.True(t, scratchHasColumn(t, db, "col_a"), "the earlier drop must roll back")
	assert.Zero(t, scratchLogCount(t, db))
	requireUnchanged(t, db, 0, 0)
}

func TestApplyContractSteps_LockTimeoutFailsFast(t *testing.T) {
	db := contractEnv(t, 5, true)

	// Another transaction holds the version row.
	holder, err := db.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = holder.Exec(`SELECT 1 FROM cfgms_schema_version WHERE id = 1 FOR UPDATE`)
	require.NoError(t, err)

	began := time.Now()
	err = apply(t, db, dropColumnStep(3, 2, "col_a"))
	elapsed := time.Since(began)
	require.NoError(t, holder.Rollback())

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrContractStepBlocked)
	assert.Contains(t, err.Error(), "lock timeout")
	assert.Less(t, elapsed, 20*time.Second, "the step must fail at lock_timeout, not queue behind the holder")
	assert.True(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 0, 0)

	// The next start retries and succeeds.
	require.NoError(t, apply(t, db, dropColumnStep(3, 2, "col_a")))
	requireUnchanged(t, db, 2, 3)
}

// withContractSteps swaps the production step list for the test and restores it.
func withContractSteps(t *testing.T, steps []ContractStep) {
	t.Helper()
	orig := contractSteps
	contractSteps = steps
	t.Cleanup(func() { contractSteps = orig })
}

func TestApplyContractSteps_SharedPoolStartsWhenStepIsBlocked(t *testing.T) {
	db := contractEnv(t, 5, true)
	insertNode(t, db, "node-old", 1, 0)
	withContractSteps(t, []ContractStep{dropColumnStep(3, 2, "col_a")})

	// A rolling deploy: the older node is still live, so the step waits and the new node starts.
	p := newGateProvider(t, contractTestRange)
	_, err := p.sharedPool(getTestConfig())
	require.NoError(t, err)
	assert.Equal(t, 1, cachedPoolCount(p))
	assert.True(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 0, 0)
}

func TestApplyContractSteps_SharedPoolAppliesStepAtStartup(t *testing.T) {
	db := contractEnv(t, 5, true)
	withContractSteps(t, []ContractStep{dropColumnStep(3, 2, "col_a")})

	p := newGateProvider(t, contractTestRange)
	_, err := p.sharedPool(getTestConfig())
	require.NoError(t, err)

	assert.False(t, scratchHasColumn(t, db, "col_a"))
	requireUnchanged(t, db, 2, 3)
}

func TestApplyContractSteps_SharedPoolRefusesStartOnStatementError(t *testing.T) {
	db := contractEnv(t, 5, true)
	step := dropColumnStep(3, 2, "col_a")
	step.Statements = []string{`ALTER TABLE cfgms_contract_table_that_does_not_exist DROP COLUMN x`}
	withContractSteps(t, []ContractStep{step})

	p := newGateProvider(t, contractTestRange)
	_, err := p.sharedPool(getTestConfig())
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrContractStepBlocked)
	assert.Zero(t, cachedPoolCount(p), "a failed pool must not be cached")
	requireUnchanged(t, db, 0, 0)
}
