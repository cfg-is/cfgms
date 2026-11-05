// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// --- Characterization tests: collapse, drift and temporal (Issue #5799) ---
// These pin the observable behaviour of the provider through its methods so the
// dialect-independent code can move to egcommon without a behaviour change.

func reportState(t *testing.T, p *SQLiteEntityGraphProvider, subject, source string, at time.Time, payload map[string]interface{}) {
	t.Helper()
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source:       source,
		Observations: []types.Observation{obs(subject, source, types.ObservationKindState, at, payload)},
	}))
}

func TestCharacterizeResolveCollapseGroup(t *testing.T) {
	for _, asOf := range []bool{false, true} {
		name := "current"
		if asOf {
			name = "as-of"
		}
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t)
			ctx := context.Background()
			now := time.Now().UTC().Add(-time.Minute)

			reportState(t, p, "host:a", "observer:one", now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root", "color": "red", "size": "big",
			})
			reportState(t, p, "host:b", "operator-assertion:two", now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root", "color": "blue",
			})
			reportState(t, p, "host:c", "observer:three", now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "other", "color": "green",
			})
			reportEdge(t, p, "same-as", "host:a", "host:b")
			reportEdge(t, p, "same-as", "host:b", "host:c")

			var at *time.Time
			if asOf {
				later := time.Now().UTC().Add(time.Minute)
				at = &later
			}

			view, err := p.resolveCollapseGroup(ctx, mustEID(t, "host:a"), at, interfaces.TenantCut{})
			require.NoError(t, err)
			require.NotNil(t, view)
			require.Len(t, view.Members, 3)
			require.Equal(t, "host:a", view.Members[0].String())
			require.Equal(t, "host:c", view.Members[2].String())
			require.Equal(t, "big", view.Merged["size"])
			require.NotEmpty(t, view.Conflicts["color"], "losing sources are retained as conflicts")
			for i := 1; i < len(view.Conflicts["color"]); i++ {
				require.LessOrEqual(t, view.Conflicts["color"][i-1].Source, view.Conflicts["color"][i].Source)
			}

			// The cut removes host:c, and its out-of-cut edge no longer links the group.
			cut := interfaces.NewTenantCut("root", nil)
			view, err = p.resolveCollapseGroup(ctx, mustEID(t, "host:a"), at, cut)
			require.NoError(t, err)
			require.NotNil(t, view)
			require.Len(t, view.Members, 2)

			// An entity without same-as edges has no group.
			reportState(t, p, "host:solo", "observer:one", now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root",
			})
			view, err = p.resolveCollapseGroup(ctx, mustEID(t, "host:solo"), at, interfaces.TenantCut{})
			require.NoError(t, err)
			require.Nil(t, view)
		})
	}
}

func TestCharacterizeGetDesiredState(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	eid := mustEID(t, "host:d1")

	got, err := p.GetDesiredState(ctx, eid)
	require.NoError(t, err)
	require.Nil(t, got)

	at := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:cfg",
		Observations: []types.Observation{obs("host:d1", "enforcing-module:cfg", types.ObservationKindDesiredState, at,
			map[string]interface{}{"config_revision": "rev-1", "mode": "strict"})},
	}))
	got, err = p.GetDesiredState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "rev-1", got.ConfigRevision)
	require.Equal(t, map[string]interface{}{"mode": "strict"}, got.State)
}

func TestCharacterizeDriftListAndLifecycle(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute)

	for _, s := range []string{"host:x1", "host:x2"} {
		reportState(t, p, s, "observer:one", at, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root"})
		require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
			Source: "steward:drift",
			Observations: []types.Observation{obs(s, "steward:drift", types.ObservationKindDriftDiff, at, map[string]interface{}{
				"config_revision": "rev-9",
				"fields": []interface{}{
					map[string]interface{}{"attribute": "mode", "desired": "a", "actual": "b", "matching": false},
				},
			})},
		}))
	}

	state, err := p.GetDriftState(ctx, mustEID(t, "host:x1"))
	require.NoError(t, err)
	require.Equal(t, "detected", state.LifecycleStatus)
	require.Equal(t, "rev-9", state.ConfigRevision)
	require.Equal(t, []interfaces.DriftField{{Attribute: "mode", Desired: "a", Actual: "b"}}, state.Fields)

	require.NoError(t, p.UpdateDriftLifecycle(ctx, interfaces.DriftLifecycleUpdate{
		EID: mustEID(t, "host:x1"), Transition: "acknowledge", Actor: "op", At: at.Add(time.Second),
	}))

	list, err := p.ListDrifted(ctx, interfaces.DriftFilter{})
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, "host:x1", list[0].EID.String())
	require.Equal(t, "acknowledged", list[0].LifecycleStatus)

	list, err = p.ListDrifted(ctx, interfaces.DriftFilter{LifecycleStatus: "detected", Kind: "host", TenantFilter: "root", TenantSubtreeIDs: []string{"root"}})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "host:x2", list[0].EID.String())

	list, err = p.ListDrifted(ctx, interfaces.DriftFilter{After: "host:x1", Limit: 1})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "host:x2", list[0].EID.String())

	err = p.UpdateDriftLifecycle(ctx, interfaces.DriftLifecycleUpdate{EID: mustEID(t, "host:x1"), Transition: "bogus", Actor: "op"})
	require.EqualError(t, err, `entitygraph/sqlite: unknown lifecycle transition "bogus"`)
}

func TestCharacterizeDiffAttributeChanges(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour)
	t1 := t0.Add(10 * time.Minute)
	t2 := t0.Add(20 * time.Minute)

	reportState(t, p, "host:t", "observer:one", t0, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root", "keep": "same", "chg": "old", "gone": "x"})
	reportState(t, p, "host:t", "observer:one", t2, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root", "keep": "same", "chg": "new", "added": "y"})

	diff, err := p.Diff(ctx, mustEID(t, "host:t"), interfaces.TimeRange{From: t1, To: t2.Add(time.Second)})
	require.NoError(t, err)
	var names []string
	for _, c := range diff.Changes {
		names = append(names, c.Attribute)
	}
	require.Equal(t, []string{"added", "chg", "gone"}, names)
	require.Equal(t, "old", diff.Changes[1].Before)
	require.Equal(t, "new", diff.Changes[1].After)
	require.Nil(t, diff.Changes[0].Before)
	require.Nil(t, diff.Changes[2].After)
}
