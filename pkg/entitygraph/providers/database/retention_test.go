// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/stretchr/testify/require"
)

// TestRunRetentionGC_AdvisoryLockPinnedToConnection verifies Issue #4074 (1):
// the pg_try_advisory_lock guard must be acquired, held, and released on one
// pinned connection. pg_try_advisory_lock is session-scoped, so if the acquire
// statement returns its connection to the pool before the sweep finishes,
// SetMaxIdleConns(0) closes that connection synchronously, ending the Postgres
// session and releasing the lock early — a second raw connection would then be
// able to take the lock while RunRetentionGC is still running.
func TestRunRetentionGC_AdvisoryLockPinnedToConnection(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	p := newTestDBProvider(t, dsn)
	p.db.SetMaxIdleConns(0)

	ctx := context.Background()

	probeDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probeDB.Close() })

	probeConn, err := probeDB.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probeConn.Close() })

	var gcErr error
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		gcErr = p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30})
	}()

	deadline := time.Now().Add(10 * time.Second)
	sawLockHeldDuringGC := false

loop:
	for {
		select {
		case <-gcDone:
			break loop
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for RunRetentionGC to finish")
		}

		var acquired bool
		require.NoError(t, probeConn.QueryRowContext(ctx,
			`SELECT pg_try_advisory_lock($1)`, gcAdvisoryLockKey).Scan(&acquired))
		if !acquired {
			sawLockHeldDuringGC = true
			continue
		}

		// We took the lock — only acceptable if RunRetentionGC had already
		// returned by the time the acquire committed.
		select {
		case <-gcDone:
			_, _ = probeConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
			break loop
		default:
			_, _ = probeConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
			t.Fatal("a second connection acquired the advisory lock while RunRetentionGC was still running — the lock is not connection-pinned")
		}
	}

	<-gcDone
	require.NoError(t, gcErr)
	require.True(t, sawLockHeldDuringGC,
		"test never observed the lock held by RunRetentionGC; strengthen the workload or timing before trusting this test")

	// The lock must be free now that RunRetentionGC has returned.
	var acquiredAfter bool
	require.NoError(t, probeConn.QueryRowContext(ctx,
		`SELECT pg_try_advisory_lock($1)`, gcAdvisoryLockKey).Scan(&acquiredAfter))
	require.True(t, acquiredAfter, "advisory lock must be free after RunRetentionGC returns")
	_, err = probeConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
	require.NoError(t, err)
}

const dbRetentionSrc = "enforcing-module:retention-scope"

func dbDeclareScope(t *testing.T, p *DatabaseEntityGraphProvider, anchor, peer types.EID, at time.Time) types.ClaimScopePattern {
	t.Helper()
	ent := func(e types.EID) types.Observation {
		return dbObs(e.String(), dbRetentionSrc, types.ObservationKindState, at, map[string]interface{}{
			"entity_kind": "host", "owning_tenant": "root/ret",
		})
	}
	pattern := types.ClaimScopePattern{Edge: &types.EdgeScopePattern{
		EdgeType: "same-as", AnchorEID: anchor, Direction: types.TraversalOutbound,
	}}
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source: dbRetentionSrc,
		Observations: []types.Observation{
			ent(anchor), ent(peer),
			dbObs("same-as|"+anchor.String()+"|"+peer.String(), dbRetentionSrc, types.ObservationKindState, at, map[string]interface{}{}),
		},
		ClaimScopes: []types.ClaimScope{{Source: dbRetentionSrc, AsOf: at, Pattern: pattern}},
	}))
	return pattern
}

func dbScopeRows(t *testing.T, p *DatabaseEntityGraphProvider, pattern types.ClaimScopePattern) int {
	t.Helper()
	var n int
	require.NoError(t, p.db.QueryRow(
		`SELECT COUNT(*) FROM eg_claim_scope_prior WHERE source = $1 AND claim_scope_key = $2`,
		dbRetentionSrc, dbPatternKey(pattern)).Scan(&n))
	return n
}

func dbRetract(t *testing.T, p *DatabaseEntityGraphProvider, e types.EID, at time.Time) {
	t.Helper()
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source:       dbRetentionSrc,
		Observations: []types.Observation{dbObs(e.String(), dbRetentionSrc, types.ObservationKindAbsence, at, map[string]interface{}{})},
	}))
}

func TestRunRetentionGC_SweepsAbandonedEdgeScope(t *testing.T) {
	p := newTestDBProvider(t, skipIfNoPostgres(t))
	old := time.Now().UTC().AddDate(0, 0, -200)

	dead, _ := types.ParseEID("host:retgc-auth/dead")
	live, _ := types.ParseEID("host:retgc-auth/live")
	p1, _ := types.ParseEID("host:retgc-auth/p1")
	p2, _ := types.ParseEID("host:retgc-auth/p2")

	deadScope := dbDeclareScope(t, p, dead, p1, old)
	liveScope := dbDeclareScope(t, p, live, p2, time.Now().UTC())
	dbRetract(t, p, dead, old.Add(time.Hour))

	require.NoError(t, p.RunRetentionGC(context.Background(), interfaces.RetentionPolicy{HistoryDays: 30}))

	require.Equal(t, 0, dbScopeRows(t, p, deadScope), "abandoned scope must be removed")
	require.Equal(t, 1, dbScopeRows(t, p, liveScope), "live scope must remain")
}

func TestRunRetentionGC_KeepsScopeInsideTombstoneWindow(t *testing.T) {
	p := newTestDBProvider(t, skipIfNoPostgres(t))
	now := time.Now().UTC()

	anchor, _ := types.ParseEID("host:retgc-auth/window")
	peer, _ := types.ParseEID("host:retgc-auth/wpeer")
	scope := dbDeclareScope(t, p, anchor, peer, now.Add(-time.Hour))
	dbRetract(t, p, anchor, now)

	require.NoError(t, p.RunRetentionGC(context.Background(), interfaces.RetentionPolicy{HistoryDays: 30}))

	require.Equal(t, 1, dbScopeRows(t, p, scope), "retracted anchor inside tombstone window keeps its scope")
}
