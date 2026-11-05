// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func TestResolveWatchCursor_InvalidCursor(t *testing.T) {
	// A non-numeric cursor is rejected before any DB access, so a nil *sql.DB is
	// safe here and keeps the test a pure error-path check.
	for _, bad := range []string{"abc", "12x", "3.14", "-", "0x10", " 5"} {
		_, err := ResolveWatchCursor(context.Background(), nil, bad)
		require.Error(t, err, "cursor %q must be rejected", bad)
		require.Contains(t, err.Error(), "must be a decimal integer")
	}
}

func TestResolveWatchCursor_ValidDecimal(t *testing.T) {
	seq, err := ResolveWatchCursor(context.Background(), nil, "42")
	require.NoError(t, err)
	require.Equal(t, int64(42), seq)
}

func TestStartWatch_InvalidCursorUsesDialectPrefix(t *testing.T) {
	for _, prefix := range []string{"entitygraph/sqlite", "entitygraph/database"} {
		_, err := StartWatch(context.Background(), nil, Dialect{Prefix: prefix}, interfaces.WatchFilter{}, "abc", nil)
		require.EqualError(t, err, prefix+`: watch: invalid cursor "abc": must be a decimal integer`)
	}
}

func TestBuildWatchEvent_OKFalseBranches(t *testing.T) {
	// Edge subject that does not split into exactly three parts.
	_, ok := BuildWatchEvent("two|parts", "observation", "", 1)
	require.False(t, ok, "malformed edge subject (wrong part count) must not yield an event")

	// Well-formed edge subject but the from-EID is not a parseable EID.
	_, ok = BuildWatchEvent("contains|nocolon|host:b", "observation", "", 2)
	require.False(t, ok, "edge with non-parseable from-EID must not yield an event")

	// Non-edge subject that is not a parseable EID.
	_, ok = BuildWatchEvent("nocolon-subject", "observation", "", 3)
	require.False(t, ok, "non-edge subject that is not a valid EID must not yield an event")
}

func TestBuildWatchEvent_OKTrue(t *testing.T) {
	ev, ok := BuildWatchEvent("host:abc", string(types.ObservationKindDriftDiff), "", 7)
	require.True(t, ok)
	require.Equal(t, "drift-updated", ev.EventKind)
	require.Equal(t, int64(7), ev.Version)

	ev, ok = BuildWatchEvent("host:abc", "observation", "2026-01-02T03:04:05Z", 9)
	require.True(t, ok)
	require.Equal(t, "entity-updated", ev.EventKind)
	require.Equal(t, 2026, ev.At.Year())

	ev, ok = BuildWatchEvent("contains|host:a|host:b", "observation", "", 8)
	require.True(t, ok)
	require.Equal(t, "edge-updated", ev.EventKind)
	require.Equal(t, "host:a", ev.Subject.String())
}

func TestWatchFilterMatches(t *testing.T) {
	host, ok := BuildWatchEvent("host:a", "observation", "", 1)
	require.True(t, ok)
	edge, ok := BuildWatchEvent("contains|host:a|host:b", "observation", "", 2)
	require.True(t, ok)
	eidA, err := types.ParseEID("host:a")
	require.NoError(t, err)
	eidB, err := types.ParseEID("host:b")
	require.NoError(t, err)

	require.True(t, WatchFilterMatches(host, "", interfaces.WatchFilter{}))

	// Kinds
	require.True(t, WatchFilterMatches(host, "", interfaces.WatchFilter{Kinds: []string{"entity-updated"}}))
	require.False(t, WatchFilterMatches(host, "", interfaces.WatchFilter{Kinds: []string{"edge-updated"}}))

	// Tenant: owner or listed subtree passes, others and empty owner fail; edges skip it.
	f := interfaces.WatchFilter{TenantFilter: "msp-a", TenantSubtreeIDs: []string{"client-1"}}
	require.True(t, WatchFilterMatches(host, "msp-a", f))
	require.True(t, WatchFilterMatches(host, "client-1", f))
	require.False(t, WatchFilterMatches(host, "msp-b", f))
	require.False(t, WatchFilterMatches(host, "", f))
	require.True(t, WatchFilterMatches(edge, "", f))

	// EIDs
	require.True(t, WatchFilterMatches(host, "", interfaces.WatchFilter{EIDs: []interfaces.EIDRef{eidA}}))
	require.False(t, WatchFilterMatches(host, "", interfaces.WatchFilter{EIDs: []interfaces.EIDRef{eidB}}))
}
