// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// newTestProvider returns a file-backed provider in a temp dir. File-backed
// (not :memory:) so RebuildProjections and multi-statement flows exercise the
// real WAL path.
func newTestProvider(t *testing.T) *SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func mustEID(t *testing.T, s string) types.EID {
	t.Helper()
	eid, err := types.ParseEID(s)
	require.NoError(t, err)
	return eid
}

func obs(subject, source string, kind types.ObservationKind, at time.Time, payload map[string]interface{}) types.Observation {
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

func TestReportAndGetEntity(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:abc123")

	err := p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:file",
		Observations: []types.Observation{
			obs(eid.String(), "enforcing-module:file", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root/msp-a/client-1",
				"hostname":      "web01",
				"cpu_count":     float64(8),
			}),
		},
	})
	require.NoError(t, err)

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.Equal(t, "host", view.Entity.Kind)
	require.Equal(t, "root/msp-a/client-1", view.Entity.OwningTenant)
	require.Equal(t, "web01", view.Entity.Attributes["hostname"])
	require.Equal(t, float64(8), view.Entity.Attributes["cpu_count"])
	require.Len(t, view.Sources, 1)
}

func TestGetEntityNotFound(t *testing.T) {
	p := newTestProvider(t)
	_, err := p.GetEntity(context.Background(), mustEID(t, "host:nope"), interfaces.GetEntityOpts{})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestContentHashDedup(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:dedup")
	payload := map[string]interface{}{"entity_kind": "host", "hostname": "h1"}

	batch := interfaces.ObservationBatch{
		Source:       "observer:scan",
		Observations: []types.Observation{obs(eid.String(), "observer:scan", types.ObservationKindState, now, payload)},
	}
	require.NoError(t, p.ReportObservations(ctx, batch))
	require.NoError(t, p.ReportObservations(ctx, batch)) // identical → no new log row

	var count int
	require.NoError(t, p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM eg_observation_log WHERE subject = ?`, eid.String()).Scan(&count))
	require.Equal(t, 1, count, "bit-identical re-observation must not append a log row")
}

func TestPrecedenceMerge(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:prec")

	// Observer says color=blue; enforcing module says color=red. Enforcing wins.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "observer:scan",
		Observations: []types.Observation{
			obs(eid.String(), "observer:scan", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host", "color": "blue", "only_observer": "x",
			}),
		},
	}))
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:paint",
		Observations: []types.Observation{
			obs(eid.String(), "enforcing-module:paint", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host", "color": "red",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.Equal(t, "red", view.Entity.Attributes["color"], "enforcing module overrides observer")
	require.Equal(t, "x", view.Entity.Attributes["only_observer"], "lower-precedence-only keys survive")
}

func TestTenantFilter(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:tenant")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "observer:scan",
		Observations: []types.Observation{
			obs(eid.String(), "observer:scan", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root/msp-a/client-1",
			}),
		},
	}))

	_, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/msp-a"})
	require.NoError(t, err, "matching tenant subtree is visible")

	_, err = p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/msp-b"})
	require.ErrorIs(t, err, ErrNotFound, "other tenant subtree is invisible")

	// Prefix-collision guard: "root/msp-a" must not match "root/msp-a-other" or "root/msp-ab".
	eid2 := mustEID(t, "host:prefix-tenant")
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "observer:scan",
		Observations: []types.Observation{
			obs(eid2.String(), "observer:scan", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root/msp-ab",
			}),
		},
	}))
	_, err = p.GetEntity(ctx, eid2, interfaces.GetEntityOpts{TenantFilter: "root/msp-a"})
	require.ErrorIs(t, err, ErrNotFound, "sibling tenant sharing a name prefix must not be visible")
}

func TestQueryEntitiesPaging(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, name := range []string{"a", "b", "c"} {
		eid := mustEID(t, "host:"+name)
		require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
			Source: "observer:scan",
			Observations: []types.Observation{
				obs(eid.String(), "observer:scan", types.ObservationKindState, now, map[string]interface{}{
					"entity_kind": "host", "owning_tenant": "root/t",
				}),
			},
		}))
	}

	page1, err := p.QueryEntities(ctx, interfaces.EntityFilter{Kind: "host"}, interfaces.PageToken{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, page1.Entities, 2)
	require.NotEmpty(t, page1.NextToken)

	page2, err := p.QueryEntities(ctx, interfaces.EntityFilter{Kind: "host"}, interfaces.PageToken{PageSize: 2, Token: page1.NextToken})
	require.NoError(t, err)
	require.Len(t, page2.Entities, 1)
	require.Empty(t, page2.NextToken)
}

func TestResolveIdentity(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:ident")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "observer:scan",
		Observations: []types.Observation{
			obs(eid.String(), "observer:scan", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host",
				"machine_sid": "S-1-5-21-XYZ",
				"mac_addrs":   []interface{}{"00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"},
			}),
		},
	}))

	got, err := p.ResolveIdentity(ctx, interfaces.IdentityClaims{MachineSID: "S-1-5-21-XYZ"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, eid.String(), got[0].String())

	got, err = p.ResolveIdentity(ctx, interfaces.IdentityClaims{MACAddrs: []string{"aa:bb:cc:dd:ee:ff"}})
	require.NoError(t, err)
	require.Len(t, got, 1)

	// Empty claims → empty result, not an error.
	got, err = p.ResolveIdentity(ctx, interfaces.IdentityClaims{})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestRebuildProjections(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:rebuild")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:file",
		Observations: []types.Observation{
			obs(eid.String(), "enforcing-module:file", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host", "hostname": "rb01",
			}),
		},
	}))

	// Corrupt the projections; the log remains the source of truth.
	_, err := p.db.ExecContext(ctx, `DELETE FROM eg_entity_current`)
	require.NoError(t, err)
	_, err = p.db.ExecContext(ctx, `DELETE FROM eg_entity_index`)
	require.NoError(t, err)

	_, err = p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, p.RebuildProjections(ctx))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.Equal(t, "rb01", view.Entity.Attributes["hostname"])
}

func TestGetDesiredStateNotFound(t *testing.T) {
	p := newTestProvider(t)
	ds, err := p.GetDesiredState(context.Background(), mustEID(t, "host:x"))
	require.NoError(t, err)
	require.Nil(t, ds)
}

func TestUpdateDriftLifecycleInvalidTransition(t *testing.T) {
	p := newTestProvider(t)
	err := p.UpdateDriftLifecycle(context.Background(), interfaces.DriftLifecycleUpdate{
		EID:        mustEID(t, "host:x"),
		Transition: "fly",
	})
	require.Error(t, err)
}

// TestUpdateDriftLifecycleMissingRecord exercises the sql.ErrNoRows -> ErrNotFound
// branch: a valid transition ("acknowledge") passes transitionLifecycleStatus but
// the subject has no row in eg_drift_projection, so the projection lookup must
// surface ErrNotFound rather than an opaque error.
func TestUpdateDriftLifecycleMissingRecord(t *testing.T) {
	p := newTestProvider(t)
	err := p.UpdateDriftLifecycle(context.Background(), interfaces.DriftLifecycleUpdate{
		EID:        mustEID(t, "host:no-drift"),
		Transition: "acknowledge",
		Actor:      "operator:alice",
	})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetEdgesEmpty(t *testing.T) {
	// GetEdges on an empty provider returns empty slice, not ErrNotImplemented.
	p := newTestProvider(t)
	edges, err := p.GetEdges(context.Background(), interfaces.EdgeFilter{})
	require.NoError(t, err)
	require.Empty(t, edges)
}

func TestSubjectKind(t *testing.T) {
	require.Equal(t, "entity", subjectKind("host:abc"))
	require.Equal(t, "edge", subjectKind("contains|host:a|host:b"))
}

func TestParseEdgeSubject(t *testing.T) {
	edgeType, from, to, err := parseEdgeSubject("contains|host:a|host:b")
	require.NoError(t, err)
	require.Equal(t, "contains", edgeType)
	require.Equal(t, "host:a", from)
	require.Equal(t, "host:b", to)

	// to_subject may include a local_id with slashes.
	edgeType, from, to, err = parseEdgeSubject("runs-on|cluster:cl1|host:cl1/vm1")
	require.NoError(t, err)
	require.Equal(t, "runs-on", edgeType)
	require.Equal(t, "cluster:cl1", from)
	require.Equal(t, "host:cl1/vm1", to)

	_, _, _, err = parseEdgeSubject("bad")
	require.Error(t, err, "missing components must error")

	_, _, _, err = parseEdgeSubject("two|parts")
	require.Error(t, err)
}

func TestSourceClassPrecedence(t *testing.T) {
	require.Equal(t, types.SourceClassEnforcingModule, resolveSourceClass("enforcing-module:hyperv"))
	require.Equal(t, types.SourceClassObserver, resolveSourceClass("mystery:thing"))
	require.Less(t, sourceClassRank(types.SourceClassEnforcingModule), sourceClassRank(types.SourceClassObserver))
}

func TestProviderSatisfiesInterface(t *testing.T) {
	var _ interfaces.EntityGraphProvider = (*SQLiteEntityGraphProvider)(nil)
	require.NotEqual(t, "", (&SQLiteEntityGraphProvider{}).Name())
}

func TestDedupErrorPathIsClean(t *testing.T) {
	// Guard: an empty batch is a no-op, not an error.
	p := newTestProvider(t)
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{}))
	// ErrNotFound is a valid non-nil sentinel; confirm it is not accidentally nil.
	require.NotNil(t, ErrNotFound, "ErrNotFound must be a non-nil sentinel error")
}

func TestEscapeLIKE(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"host:abc", "host:abc"},
		{"host:server%01", `host:server\%01`},
		{"host:server_01", `host:server\_01`},
		{`host:back\slash`, `host:back\\slash`},
		{`100%_done`, `100\%\_done`},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, escapeLIKE(tc.in), "input: %q", tc.in)
	}
}

// TestLIKEWildcardInEID_CollapseAsOf verifies that an EID containing SQL LIKE
// metacharacters (%, _) does not produce spurious group members during temporal BFS.
// Without LIKE escaping, pattern 'same-as|host:server%01|%' (where % is a wildcard)
// would match 'same-as|host:server01|host:wildcard-peer', wrongly including those
// entities in the group for host:server%01.
func TestLIKEWildcardInEID_CollapseAsOf(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// decoy: host:server01 — an EID that an unescaped LIKE pattern for host:server%01
	// would spuriously match (% wildcard matches empty string, so server%01 matches server01).
	decoy := "host:server01"
	peer := "host:wildcard-peer"
	subject := "host:server%01"

	for _, e := range []string{decoy, peer, subject} {
		require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
			Source: "observer:scan",
			Observations: []types.Observation{
				obs(e, "observer:scan", types.ObservationKindState, now, map[string]interface{}{
					"entity_kind": "host", "owning_tenant": "root",
				}),
			},
		}))
	}

	// Create a same-as edge between decoy and peer — NOT involving the test subject.
	edgeSubject := "same-as|" + decoy + "|" + peer
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "operator:test",
		Observations: []types.Observation{
			obs(edgeSubject, "operator:test", types.ObservationKindState, now, map[string]interface{}{}),
		},
	}))

	testEID := mustEID(t, subject)
	members, err := p.resolveGroupMembersAsOf(ctx, testEID, now.Add(time.Second))
	require.NoError(t, err)
	// The subject has no same-as edges; only itself should be returned.
	require.Len(t, members, 1, "subject with %% in EID must not match decoy's edges via unescaped LIKE")
	require.Equal(t, subject, members[0].String())
}

// TestLIKEWildcardInEID_Timeline verifies that GetTimeline does not include
// same-as-change events from edges unrelated to the queried subject when the
// subject EID contains SQL LIKE metacharacters.
func TestLIKEWildcardInEID_Timeline(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	now := time.Now().UTC()

	decoy := "host:server01"
	peer := "host:wildcard-peer2"
	subject := "host:server%01"

	for _, e := range []string{decoy, peer, subject} {
		require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
			Source: "observer:scan",
			Observations: []types.Observation{
				obs(e, "observer:scan", types.ObservationKindState, now, map[string]interface{}{
					"entity_kind": "host", "owning_tenant": "root",
				}),
			},
		}))
	}

	// Same-as edge between decoy and peer — not involving subject.
	edgeSubject := "same-as|" + decoy + "|" + peer
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "operator:test",
		Observations: []types.Observation{
			obs(edgeSubject, "operator:test", types.ObservationKindState, now, map[string]interface{}{}),
		},
	}))

	testEID := mustEID(t, subject)
	events, err := p.GetTimeline(ctx, []interfaces.EIDRef{testEID}, interfaces.TimeRange{
		From: now.Add(-time.Second),
		To:   now.Add(time.Minute),
	})
	require.NoError(t, err)

	// Only state-change events for subject itself should be present — no spurious
	// same-as-change events from the decoy's edge.
	for _, ev := range events {
		require.NotEqual(t, "same-as-change", ev.Kind,
			"no same-as-change events expected for a subject with no same-as edges")
	}
}
