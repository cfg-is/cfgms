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

func TestUnimplementedReturnsErrNotImplemented(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	eid := mustEID(t, "host:x")

	_, err := p.GetDesiredState(ctx, eid)
	require.ErrorIs(t, err, interfaces.ErrNotImplemented)
	err = p.UpdateDriftLifecycle(ctx, interfaces.DriftLifecycleUpdate{})
	require.ErrorIs(t, err, interfaces.ErrNotImplemented)
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
