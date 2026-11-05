// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

func TestEscapeLIKE(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"host:server%01", `host:server\%01`},
		{"host:server_01", `host:server\_01`},
		{`host:back\slash`, `host:back\\slash`},
		{`100%_done`, `100\%\_done`},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, EscapeLIKE(tc.in), "input: %q", tc.in)
	}
}

func TestTenantSubtreeCond(t *testing.T) {
	cut := interfaces.NewTenantCut("root", []string{"root/a"})
	var args []interface{}
	n := 3
	got := TenantSubtreeCond("i.owning_tenant", cut, func() string {
		ph := "$" + string(rune('0'+n))
		n++
		return ph
	}, &args)
	require.Equal(t, "i.owning_tenant IN ($3, $4)", got)
	require.Len(t, args, 2)
	require.Equal(t, 5, n)

	args = nil
	got = TenantSubtreeCond("c", cut, func() string { return "?" }, &args)
	require.Equal(t, "c IN (?, ?)", got)
	require.ElementsMatch(t, []interface{}{"root", "root/a"}, args)
}

func TestGroupWalk(t *testing.T) {
	w := NewGroupWalk("host:a")
	require.Equal(t, []string{"host:a"}, w.Queue)
	require.NoError(t, w.Add("host:b"))
	require.NoError(t, w.Add("host:b"), "a repeated peer is not re-queued")
	require.Equal(t, []string{"host:a", "host:b"}, w.Queue)

	full := NewGroupWalk("host:0")
	for i := 1; i < interfaces.MaxCollapseGroupMembers; i++ {
		require.NoError(t, full.Add("host:"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	require.Len(t, full.Visited, interfaces.MaxCollapseGroupMembers)
	require.ErrorIs(t, full.Add("host:over"), interfaces.ErrCollapseGroupTooLarge)
}

func TestSortedGroupMembersSkipsUnparseable(t *testing.T) {
	got := SortedGroupMembers(map[string]struct{}{"host:b": {}, "host:a": {}, "not an eid": {}})
	require.Len(t, got, 2)
	require.Equal(t, "host:a", got[0].String())
	require.Equal(t, "host:b", got[1].String())
}

func TestBuildConflicts(t *testing.T) {
	type entry struct {
		source  string
		payload map[string]interface{}
	}
	view := func(e entry) (string, map[string]interface{}) { return e.source, e.payload }
	entries := []entry{
		{"z", map[string]interface{}{"color": "red", "same": 1}},
		{"a", map[string]interface{}{"color": "blue", "same": 1, "unmerged": true}},
	}
	merged := map[string]interface{}{"color": "green", "same": 1}
	got := BuildConflicts(entries, view, merged)
	require.Len(t, got, 1)
	require.Equal(t, "a", got["color"][0].Source)
	require.Equal(t, "z", got["color"][1].Source)

	require.Nil(t, BuildConflicts(entries, view, map[string]interface{}{"same": 1}))
}

func openMemory(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestScanAsOfMembers(t *testing.T) {
	db := openMemory(t)
	d := Dialect{Prefix: "entitygraph/test"}
	rows, err := db.QueryContext(context.Background(), `SELECT 'host:a' UNION ALL SELECT 'host:b'`)
	require.NoError(t, err)
	got, err := ScanAsOfMembers(rows, d)
	_ = rows.Close()
	require.NoError(t, err)
	require.Len(t, got, 2)

	rows, err = db.QueryContext(context.Background(), `SELECT NULL`)
	require.NoError(t, err)
	_, err = ScanAsOfMembers(rows, d)
	_ = rows.Close()
	require.ErrorContains(t, err, "entitygraph/test: scan group as-of member")

	rows, err = db.QueryContext(context.Background(), `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n LIMIT ?) SELECT 'host:' || i FROM n`, interfaces.MaxCollapseGroupMembers+1)
	require.NoError(t, err)
	_, err = ScanAsOfMembers(rows, d)
	_ = rows.Close()
	require.ErrorIs(t, err, interfaces.ErrCollapseGroupTooLarge)
}

func TestScanMemberSources(t *testing.T) {
	db := openMemory(t)
	d := Dialect{Prefix: "entitygraph/test"}
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `SELECT 'observer:s', 'observer', '2026-01-02T03:04:05Z', 'h1', '{"k":"v"}'
		UNION ALL SELECT 'observer:t', 'observer', 'bad-time', 'h2', ''`)
	require.NoError(t, err)
	got, err := ScanMemberSources(rows, d)
	_ = rows.Close()
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "v", got[0].Payload["k"])
	require.Equal(t, 2026, got[0].ObservedAt.Year())
	require.True(t, got[1].ObservedAt.IsZero(), "an unparseable time decodes to the zero time")
	require.Nil(t, got[1].Payload)

	rows, err = db.QueryContext(ctx, `SELECT 's', 'c', 't', 'h', '{not json'`)
	require.NoError(t, err)
	_, err = ScanMemberSources(rows, d)
	_ = rows.Close()
	require.ErrorContains(t, err, "entitygraph/test: decode member payload")

	rows, err = db.QueryContext(ctx, `SELECT 's'`)
	require.NoError(t, err)
	_, err = ScanMemberSources(rows, d)
	_ = rows.Close()
	require.ErrorContains(t, err, "entitygraph/test: scan member source")
}
