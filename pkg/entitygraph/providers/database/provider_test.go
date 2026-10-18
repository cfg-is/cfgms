// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// provider_test.go contains database-provider integration tests that require a
// live PostgreSQL connection. These mirror the SQLite provider_test.go tests and
// verify the same invariants on the Postgres backend.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/stretchr/testify/require"
)

// skipIfNoPostgres skips the calling test when running with -short or when the
// test Postgres instance is not reachable, returning the DSN otherwise.
func skipIfNoPostgres(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres integration test in short mode")
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

func newTestDBProvider(t *testing.T, dsn string) *DatabaseEntityGraphProvider {
	t.Helper()
	p, err := NewDatabaseEntityGraphProvider(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func dbObs(subject, source string, kind types.ObservationKind, at time.Time, payload map[string]interface{}) types.Observation {
	return types.Observation{
		Source:     source,
		ObservedAt: at,
		RecordedAt: at,
		Subject:    subject,
		Kind:       kind,
		Confidence: types.ConfidenceHigh,
		Payload:    payload,
	}
}

func dbMustEID(t *testing.T, s string) types.EID {
	t.Helper()
	eid, err := types.ParseEID(s)
	require.NoError(t, err)
	return eid
}

// TestRebuildProjections_Database verifies the corruption-recovery path on the
// PostgreSQL provider: delete both projection tables, confirm reads fail, call
// RebuildProjections, confirm reads recover with correct values. Mirrors
// sqlite/provider_test.go:TestRebuildProjections.
func TestRebuildProjections_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	p := newTestDBProvider(t, dsn)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := dbMustEID(t, "host:db-rebuild")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:file",
		Observations: []types.Observation{
			dbObs(eid.String(), "enforcing-module:file", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host", "hostname": "db-rb01", "owning_tenant": "root/msp-rebuild",
			}),
		},
	}))

	// Corrupt the projections; the log remains the source of truth.
	_, err := p.db.ExecContext(ctx, `DELETE FROM eg_entity_current WHERE subject = $1`, eid.String())
	require.NoError(t, err)
	_, err = p.db.ExecContext(ctx, `DELETE FROM eg_entity_index WHERE subject = $1`, eid.String())
	require.NoError(t, err)

	_, err = p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.Error(t, err, "entity must not be found after corruption")

	require.NoError(t, p.RebuildProjections(ctx))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.Equal(t, "db-rb01", view.Entity.Attributes["hostname"])
}

// TestUpdateDriftLifecycleMissingRecord_Database exercises the
// sql.ErrNoRows -> errNotFound branch on the PostgreSQL provider: a valid
// transition ("acknowledge") passes transitionLifecycleStatus but the subject
// has no row in eg_drift_projection, so the projection lookup must surface
// errNotFound. Mirrors sqlite/provider_test.go:TestUpdateDriftLifecycleMissingRecord.
func TestUpdateDriftLifecycleMissingRecord_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	p := newTestDBProvider(t, dsn)
	err := p.UpdateDriftLifecycle(context.Background(), interfaces.DriftLifecycleUpdate{
		EID:        dbMustEID(t, "host:db-no-drift"),
		Transition: "acknowledge",
		Actor:      "operator:alice",
	})
	require.ErrorIs(t, err, errNotFound)
}

// TestContentHashDedup_Database verifies that a bit-identical re-observation
// from the same source appends no new log row on the PostgreSQL provider.
// Mirrors sqlite/provider_test.go:TestContentHashDedup. AC 2 requires this
// row-count assertion on both providers.
func TestContentHashDedup_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	p := newTestDBProvider(t, dsn)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := dbMustEID(t, "host:db-dedup")
	payload := map[string]interface{}{"entity_kind": "host", "hostname": "db-h1", "owning_tenant": "root/dedup-db"}

	batch := interfaces.ObservationBatch{
		Source: "observer:scan",
		Observations: []types.Observation{
			dbObs(eid.String(), "observer:scan", types.ObservationKindState, now, payload),
		},
	}
	require.NoError(t, p.ReportObservations(ctx, batch))
	require.NoError(t, p.ReportObservations(ctx, batch)) // identical — must not append

	var count int
	require.NoError(t, p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM eg_observation_log WHERE subject = $1`, eid.String()).Scan(&count))
	require.Equal(t, 1, count, "bit-identical re-observation must not append a log row")
}

// TestCollapseAsOfWalkBudget covers the as-of group walk time budget (Issue #5170):
// an expired budget is ErrCollapseGroupTooLarge, the default budget succeeds, and
// a canceled caller gets its own context error.
func TestCollapseAsOfWalkBudget(t *testing.T) {
	p := newTestDBProvider(t, skipIfNoPostgres(t))
	ctx := context.Background()
	now := time.Now().UTC()

	a, b := "host:budget-a", "host:budget-b"
	for _, e := range []string{a, b} {
		require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
			Source: "observer:scan",
			Observations: []types.Observation{
				dbObs(e, "observer:scan", types.ObservationKindState, now, map[string]interface{}{
					"entity_kind": "host", "owning_tenant": "root",
				}),
			},
		}))
	}
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "operator:test",
		Observations: []types.Observation{
			dbObs("same-as|"+a+"|"+b, "operator:test", types.ObservationKindState, now, map[string]interface{}{}),
		},
	}))

	asOf := now.Add(time.Second)
	opts := interfaces.GetEntityOpts{CollapseGroup: true, AsOf: &asOf, TenantFilter: "root"}
	eid := dbMustEID(t, a)

	t.Run("default budget succeeds", func(t *testing.T) {
		_, err := p.GetEntity(ctx, eid, opts)
		require.NoError(t, err)
	})

	t.Run("expired budget is too large", func(t *testing.T) {
		orig := collapseAsOfWalkBudget
		collapseAsOfWalkBudget = time.Nanosecond
		t.Cleanup(func() { collapseAsOfWalkBudget = orig })
		_, err := p.GetEntity(ctx, eid, opts)
		require.ErrorIs(t, err, interfaces.ErrCollapseGroupTooLarge)
	})

	t.Run("canceled caller is not mapped", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := p.GetEntity(canceled, eid, opts)
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, interfaces.ErrCollapseGroupTooLarge)
	})
}
