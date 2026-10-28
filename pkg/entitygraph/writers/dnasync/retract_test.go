// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dnasync_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func entityVisible(t *testing.T, p interfaces.EntityGraphProvider, eid types.EID) bool {
	t.Helper()
	view, err := p.GetEntity(context.Background(), eid, interfaces.GetEntityOpts{})
	return err == nil && view != nil
}

func TestRetractFragments_HostScopedRetracted(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	a := makeHostFrag("file:/etc/a", "enforcing-module:file")
	b := makeHostFrag("file:/etc/b", "enforcing-module:file")
	require.NoError(t, w.WriteFragmentsPartial(ctx, "steward-r", []*commonpb.Fragment{a, b}, nil, types.DefaultTaxonomy()))

	require.NoError(t, w.RetractFragments(ctx, "steward-r", []string{"file:/etc/a"}, types.DefaultTaxonomy()))

	require.False(t, entityVisible(t, p, mustParseEID(t, "host:steward-r/file:/etc/a")), "retracted id must be gone")
	require.True(t, entityVisible(t, p, mustParseEID(t, "host:steward-r/file:/etc/b")), "unlisted id must be untouched")
}

func TestRetractFragments_OtherSourceObservationSurvives(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	frag := &commonpb.Fragment{
		FragmentId:     "cluster:shared",
		CanonicalBytes: makeTestCanonBytes(map[string]string{"resource_owner": "tenant-a"}),
	}
	require.NoError(t, w.WriteFragmentsPartial(ctx, "steward-1", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))
	require.NoError(t, w.WriteFragmentsPartial(ctx, "steward-2", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	require.NoError(t, w.RetractFragments(ctx, "steward-1", []string{"cluster:shared"}, types.DefaultTaxonomy()))

	eid := mustParseEID(t, "cluster:shared")
	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, view, "entity must remain visible from the other source")

	// Retracting the second source removes the entity entirely.
	require.NoError(t, w.RetractFragments(ctx, "steward-2", []string{"cluster:shared"}, types.DefaultTaxonomy()))
	require.False(t, entityVisible(t, p, eid))
}

func TestRetractFragments_UnknownIDIsNoOp(t *testing.T) {
	p := newTestProvider(t)
	w := newTestWriter(t, p)
	ctx := context.Background()

	kept := makeHostFrag("file:/etc/kept", "enforcing-module:file")
	require.NoError(t, w.WriteFragmentsPartial(ctx, "steward-u", []*commonpb.Fragment{kept}, nil, types.DefaultTaxonomy()))

	require.NoError(t, w.RetractFragments(ctx, "steward-u", []string{"file:/never/reported"}, types.DefaultTaxonomy()))
	require.NoError(t, w.RetractFragments(ctx, "steward-u", nil, types.DefaultTaxonomy()))

	require.True(t, entityVisible(t, p, mustParseEID(t, "host:steward-u/file:/etc/kept")))
}
