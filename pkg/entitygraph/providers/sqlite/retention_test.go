// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

const retentionSrc = "enforcing-module:retention-scope"

func retentionEntityObs(eid string, at time.Time) types.Observation {
	return obs(eid, retentionSrc, types.ObservationKindState, at, map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/ret",
	})
}

// declareSameAsScope reports anchor, peer, the anchor→peer edge and an edge scope
// anchored at anchor.
func declareSameAsScope(t *testing.T, p *SQLiteEntityGraphProvider, anchor, peer types.EID, at time.Time) {
	t.Helper()
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source: retentionSrc,
		Observations: []types.Observation{
			retentionEntityObs(anchor.String(), at),
			retentionEntityObs(peer.String(), at),
			obs("same-as|"+anchor.String()+"|"+peer.String(), retentionSrc, types.ObservationKindState, at, map[string]interface{}{}),
		},
		ClaimScopes: []types.ClaimScope{{
			Source: retentionSrc,
			AsOf:   at,
			Pattern: types.ClaimScopePattern{Edge: &types.EdgeScopePattern{
				EdgeType: "same-as", AnchorEID: anchor, Direction: types.TraversalOutbound,
			}},
		}},
	}))
}

func retractEntity(t *testing.T, p *SQLiteEntityGraphProvider, eid types.EID, at time.Time) {
	t.Helper()
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source:       retentionSrc,
		Observations: []types.Observation{obs(eid.String(), retentionSrc, types.ObservationKindAbsence, at, map[string]interface{}{})},
	}))
}

func scopeKeyFor(anchor types.EID) string {
	return claimScopeKey(retentionSrc, types.ClaimScopePattern{Edge: &types.EdgeScopePattern{
		EdgeType: "same-as", AnchorEID: anchor, Direction: types.TraversalOutbound,
	}})
}

func scopeRowCount(t *testing.T, p *SQLiteEntityGraphProvider, key string) int {
	t.Helper()
	var n int
	require.NoError(t, p.db.QueryRow(`SELECT COUNT(*) FROM eg_claim_scope_prior WHERE scope_key = ?`, key).Scan(&n))
	return n
}

func TestRunRetentionGC_SweepsAbandonedEdgeScope(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -200)
	now := time.Now().UTC()

	dead := mustEID(t, "host:ret-auth/dead")
	live := mustEID(t, "host:ret-auth/live")
	declareSameAsScope(t, p, dead, mustEID(t, "host:ret-auth/p1"), old)
	declareSameAsScope(t, p, live, mustEID(t, "host:ret-auth/p2"), now)
	require.Equal(t, 1, scopeRowCount(t, p, scopeKeyFor(dead)))

	retractEntity(t, p, dead, old.Add(time.Hour))
	require.NoError(t, p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30}))

	assert.Equal(t, 0, scopeRowCount(t, p, scopeKeyFor(dead)), "abandoned scope must be removed")
	assert.Equal(t, 1, scopeRowCount(t, p, scopeKeyFor(live)), "live scope must remain")
}

func TestRunRetentionGC_KeepsScopeInsideTombstoneWindow(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()

	anchor := mustEID(t, "host:ret-auth/window")
	peer := mustEID(t, "host:ret-auth/wpeer")
	declareSameAsScope(t, p, anchor, peer, now.Add(-time.Hour))
	retractEntity(t, p, anchor, now)

	require.NoError(t, p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30}))

	assert.Equal(t, 1, scopeRowCount(t, p, scopeKeyFor(anchor)), "retracted anchor inside tombstone window keeps its scope")
	var n int
	require.NoError(t, p.db.QueryRow(`SELECT COUNT(*) FROM eg_observation_log WHERE subject LIKE 'same-as|%'`).Scan(&n))
	assert.Positive(t, n, "edge log rows must be retained")
}

func TestRunRetentionGC_AbandonedScopeSweepIsAtomic(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	keyA := scopeKeyFor(mustEID(t, "host:ret-auth/ghost-a"))
	keyB := scopeKeyFor(mustEID(t, "host:ret-auth/ghost-b"))
	for _, k := range []string{keyA, keyB} {
		_, err := p.db.Exec(`INSERT INTO eg_claim_scope_prior (scope_key, source, as_of, subjects) VALUES (?, ?, '', '[]')`, k, retentionSrc)
		require.NoError(t, err)
	}
	// An unparseable key must be skipped, never deleted.
	_, err := p.db.Exec(`INSERT INTO eg_claim_scope_prior (scope_key, source, as_of, subjects) VALUES (?, ?, '', '[]')`,
		retentionSrc+"\x1fedge\x1fbroken", retentionSrc)
	require.NoError(t, err)

	_, err = p.db.Exec(`CREATE TRIGGER inject_fail BEFORE DELETE ON eg_claim_scope_prior
		WHEN OLD.scope_key = '` + keyB + `' BEGIN SELECT RAISE(ABORT, 'injected'); END`)
	require.NoError(t, err)

	err = p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retention gc:")
	assert.Equal(t, 1, scopeRowCount(t, p, keyA), "first delete must roll back")
	assert.Equal(t, 1, scopeRowCount(t, p, keyB))

	_, err = p.db.Exec(`DROP TRIGGER inject_fail`)
	require.NoError(t, err)
	require.NoError(t, p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30}))
	assert.Equal(t, 0, scopeRowCount(t, p, keyA))
	assert.Equal(t, 0, scopeRowCount(t, p, keyB))
	var n int
	require.NoError(t, p.db.QueryRow(`SELECT COUNT(*) FROM eg_claim_scope_prior`).Scan(&n))
	assert.Equal(t, 1, n, "unparseable key stays in place")
}

func TestRunRetentionGC_KeepsScopeWhoseAnchorHasEdgeRows(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()

	anchor := mustEID(t, "host:ret-auth/fragment")
	peer := mustEID(t, "host:ret-auth/fpeer")
	declareSameAsScope(t, p, anchor, peer, now)

	// Strip every entity-level row of the anchor, leaving only edge rows.
	for _, q := range []string{
		`DELETE FROM eg_entity_index WHERE subject = ?`,
		`DELETE FROM eg_entity_current WHERE subject = ?`,
		`DELETE FROM eg_observation_log WHERE subject = ?`,
	} {
		_, err := p.db.Exec(q, anchor.String())
		require.NoError(t, err)
	}

	require.NoError(t, p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30}))

	assert.Equal(t, 1, scopeRowCount(t, p, scopeKeyFor(anchor)))
	edges, err := p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &anchor, Source: retentionSrc})
	require.NoError(t, err)
	assert.Len(t, edges, 1)
}
