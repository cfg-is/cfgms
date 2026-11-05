// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func testEdge(t *testing.T, from, to string) *types.Edge {
	t.Helper()
	f, err := types.ParseEID(from)
	require.NoError(t, err)
	to2, err := types.ParseEID(to)
	require.NoError(t, err)
	return &types.Edge{Type: "link", From: f, To: to2}
}

func TestPeerSubject(t *testing.T) {
	e := testEdge(t, "host:a", "host:b")
	require.Equal(t, "host:b", PeerSubject(e, []string{"host:a"}, types.TraversalOutbound))
	require.Equal(t, "host:a", PeerSubject(e, []string{"host:b"}, types.TraversalInbound))
	require.Equal(t, "host:b", PeerSubject(e, []string{"host:a"}, types.TraversalBoth))
	require.Equal(t, "host:a", PeerSubject(e, []string{"host:b"}, types.TraversalBoth))
	require.Equal(t, "", PeerSubject(e, []string{"host:a", "host:b"}, types.TraversalBoth), "both ends in frontier has no peer")
	require.Equal(t, "", PeerSubject(e, []string{"host:z"}, types.TraversalBoth), "neither end in frontier has no peer")
}

func TestGetNeighborhood_DepthTooLargeUsesDialectPrefix(t *testing.T) {
	root, err := types.ParseEID("host:a")
	require.NoError(t, err)
	hop := func(context.Context, []string, int) ([]*types.Edge, error) {
		t.Fatal("hop must not run when depth is rejected")
		return nil, nil
	}
	for _, prefix := range []string{"entitygraph/sqlite", "entitygraph/database"} {
		_, err := GetNeighborhood(context.Background(), nil, Dialect{Prefix: prefix}, root, types.TraversalBoth, NeighborhoodMaxDepth+1, hop)
		require.EqualError(t, err, prefix+": depth 4 exceeds maximum 3")
	}
}
