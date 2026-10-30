// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

func opCount(evs []ChangeEvent, op string) int {
	n := 0
	for _, e := range evs {
		if e.Op == op {
			n++
		}
	}
	return n
}

func TestMembership_MemberAddedAndRemoved_LoggedWithFields(t *testing.T) {
	f := newFixture(t)
	// First observation of the group is baseline; the change below is not.
	f.batch(t, "steward-7", authA, []Fragment{userFrag("u-base", "g1")}, nil)

	f.clock.set(f.clock.now().Add(time.Hour))
	recorded := f.clock.now()
	supplied := recorded.Add(-10 * time.Minute)
	frag := userFrag("u-new", "g1")
	frag.ObservedAt = supplied
	f.batch(t, "steward-7", authA, []Fragment{frag}, nil)

	evs := f.changes(t, "tenant-a", authA, "g1", false)
	if len(evs) != 1 {
		t.Fatalf("got %d non-baseline events, want 1: %+v", len(evs), evs)
	}
	e := evs[0]
	want := ChangeEvent{
		Tenant: "tenant-a", GroupEID: "directory:a.example/group:g1", GroupID: "g1",
		MemberEID: "directory:a.example/user:u-new", MemberID: "u-new", MemberType: MemberTypeUser,
		Op: OpAdded, ObservedAt: supplied, RecordedAt: recorded, Source: authA, ReportedBy: "steward-7",
	}
	if e != want {
		t.Fatalf("added event = %+v\nwant %+v", e, want)
	}

	f.clock.set(recorded.Add(time.Hour))
	f.batch(t, "steward-7", authA, []Fragment{userFrag("u-new")}, nil) // left g1
	evs = f.changes(t, "tenant-a", authA, "g1", false)
	if len(evs) != 2 || evs[1].Op != OpRemoved || evs[1].MemberID != "u-new" || evs[1].ReportedBy != "steward-7" {
		t.Fatalf("removal not logged: %+v", evs)
	}
	if got := f.groupsOf(t, "tenant-a", authA, "u-new", 10); len(got) != 0 {
		t.Fatalf("u-new still in groups %v", got)
	}
	if ms := f.members(t, "tenant-a", authA, "g1", 10); len(ms) != 1 || ms[0].ID != "u-base" {
		t.Fatalf("members after leave = %+v", ms)
	}
}

func TestMembership_UnchangedBatchLogsNothing(t *testing.T) {
	f := newFixture(t)
	ups := []Fragment{userFrag("u1", "g1", "g2"), userFrag("u2", "g1")}
	first := f.batch(t, "s", authA, ups, nil)
	if first.Added != 3 {
		t.Fatalf("first batch Added = %d, want 3", first.Added)
	}
	before := len(f.changes(t, "tenant-a", authA, "g1", true))
	again := f.batch(t, "s", authA, ups, nil)
	if again.Added != 0 || again.Removed != 0 {
		t.Fatalf("unchanged batch result = %+v", again)
	}
	if after := len(f.changes(t, "tenant-a", authA, "g1", true)); after != before {
		t.Fatalf("unchanged batch grew the log from %d to %d events", before, after)
	}
}

func TestMembership_BaselineExcludedByDefault(t *testing.T) {
	f := newFixture(t)
	f.batch(t, "s", authA, []Fragment{userFrag("u1", "g1"), userFrag("u2", "g1")}, nil)
	if n := len(f.changes(t, "tenant-a", authA, "g1", false)); n != 0 {
		t.Fatalf("default ListChanges returned %d baseline events", n)
	}
	all := f.changes(t, "tenant-a", authA, "g1", true)
	if len(all) != 2 {
		t.Fatalf("IncludeBaseline returned %d events, want 2", len(all))
	}
	for _, e := range all {
		if !e.Baseline || e.Op != OpAdded {
			t.Fatalf("first-observation event = %+v, want baseline added", e)
		}
	}
	f.batch(t, "s", authA, []Fragment{userFrag("u3", "g1")}, nil)
	if n := len(f.changes(t, "tenant-a", authA, "g1", false)); n != 1 {
		t.Fatalf("post-baseline change not listed by default, got %d", n)
	}
}

func TestMembership_UserFragmentRemoved_LogsRemovalForEveryGroup(t *testing.T) {
	f := newFixture(t)
	f.batch(t, "s", authA, []Fragment{userFrag("u1", "g1", "g2", "g3"), userFrag("u2", "g1")}, nil)
	res := f.batch(t, "s", authA, nil, []RemovedFragment{{Kind: egtypes.KindDirectoryUser, ObjectID: "u1"}})
	if res.Removed != 3 {
		t.Fatalf("Removed = %d, want 3", res.Removed)
	}
	for _, g := range []string{"g1", "g2", "g3"} {
		evs := f.changes(t, "tenant-a", authA, g, true)
		var removed []string
		for _, e := range evs {
			if e.Op == OpRemoved {
				removed = append(removed, e.MemberID)
			}
		}
		if len(removed) != 1 || removed[0] != "u1" {
			t.Fatalf("group %s removals = %v, want [u1]", g, removed)
		}
	}
	if got := f.groupsOf(t, "tenant-a", authA, "u1", 10); len(got) != 0 {
		t.Fatalf("removed user still in %v", got)
	}
	if ms := f.members(t, "tenant-a", authA, "g1", 10); len(ms) != 1 || ms[0].ID != "u2" {
		t.Fatalf("g1 members = %+v, want only u2", ms)
	}
}

func TestMembership_GroupFragmentRemoved_LogsRemovalForEveryMember(t *testing.T) {
	f := newFixture(t)
	ups := []Fragment{groupFrag("g-child", []string{"g-parent"})}
	for i := 0; i < 20; i++ {
		ups = append(ups, userFrag(oid("u", i), "g-parent"))
	}
	f.batch(t, "s", authA, ups, nil)
	if n := len(f.members(t, "tenant-a", authA, "g-parent", 7)); n != 21 {
		t.Fatalf("g-parent has %d members, want 21 (20 users and a nested group)", n)
	}
	res := f.batch(t, "s", authA, nil, []RemovedFragment{{Kind: egtypes.KindDirectoryGroup, ObjectID: "g-parent"}})
	if res.Removed != 21 {
		t.Fatalf("Removed = %d, want 21", res.Removed)
	}
	evs := f.changes(t, "tenant-a", authA, "g-parent", true)
	if got := opCount(evs, OpRemoved); got != 21 {
		t.Fatalf("%d removed events, want 21", got)
	}
	if n := len(f.members(t, "tenant-a", authA, "g-parent", 10)); n != 0 {
		t.Fatalf("removed group still lists %d members", n)
	}
	for idx := 0; idx < membershipShards; idx++ {
		if _, err := f.store.GetConfig(context.Background(), shardKey("tenant-a", authA, "g-parent", idx)); err == nil {
			t.Fatalf("shard %d of the removed group still exists", idx)
		}
	}
	if got := f.groupsOf(t, "tenant-a", authA, "u-000003", 10); len(got) != 0 {
		t.Fatalf("member index still lists %v after group removal", got)
	}
}

func TestMembership_MemberOfEntryWithAuthorityPrefix_Rejected(t *testing.T) {
	f := newFixture(t)
	res := f.batch(t, "s", authA, []Fragment{userFrag("u1",
		"good-guid",
		"directory:b.example/group:evil",
		"b.example/group-x",
		"has:colon",
		"has/slash",
		"ctrl\x01char",
		"",
	)}, nil)
	if res.RejectedEntries != 6 {
		t.Fatalf("RejectedEntries = %d, want 6", res.RejectedEntries)
	}
	if got := f.groupsOf(t, "tenant-a", authA, "u1", 10); len(got) != 1 || got[0] != "good-guid" {
		t.Fatalf("groups = %v, want only the valid entry", got)
	}
	if f.warns.find(WarningRejectedEntries) == nil {
		t.Fatal("no warning for rejected entries")
	}
	// An entry carrying an authority prefix never reaches another authority's keys.
	if ms := f.members(t, "tenant-b", authB, "group:evil", 10); len(ms) != 0 {
		t.Fatalf("prefixed entry created membership in another authority: %+v", ms)
	}
}

func TestMembership_RemovalAfterStewardMove_WritesOwningTenantOnly(t *testing.T) {
	f := newFixture(t)
	f.batch(t, "steward-1", authA, []Fragment{userFrag("u1", "g1")}, nil)
	// The steward now reports for a domain owned by another tenant, and a removal
	// arrives in a batch carrying no upserts.
	res := f.batch(t, "steward-1", authB, nil, []RemovedFragment{{Kind: egtypes.KindDirectoryUser, ObjectID: "u1"}})
	if res.Removed != 1 {
		t.Fatalf("Removed = %d, want 1", res.Removed)
	}
	if got := f.groupsOf(t, "tenant-a", authA, "u1", 10); len(got) != 0 {
		t.Fatalf("owning tenant still lists %v", got)
	}
	evs := f.changes(t, "tenant-a", authA, "g1", true)
	if len(evs) != 2 || evs[1].Op != OpRemoved || evs[1].Tenant != "tenant-a" {
		t.Fatalf("removal not logged in the owning tenant: %+v", evs)
	}
	other, err := f.store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("removal wrote %d entries into the peer's current tenant", len(other))
	}
}

func TestMembership_PeerLastKnownDomain_UsedForRemovals(t *testing.T) {
	f := newFixture(t)
	f.batch(t, "steward-1", authA, []Fragment{userFrag("u1", "g1")}, nil)
	var pv peerValue
	if ok, err := getValue(context.Background(), f.store, peerKey("steward-1"), &pv); err != nil || !ok {
		t.Fatalf("peer entry missing: ok=%v err=%v", ok, err)
	}
	if pv.Authority != authA || pv.PeerID != "steward-1" {
		t.Fatalf("peer entry = %+v", pv)
	}
	// No authority supplied with the removal: the stored one is used.
	res := f.batch(t, "steward-1", "", nil, []RemovedFragment{{Kind: egtypes.KindDirectoryUser, ObjectID: "u1"}})
	if res.Removed != 1 {
		t.Fatalf("Removed = %d, want 1", res.Removed)
	}
	// A peer with no stored authority and none supplied cannot remove anything.
	res = f.batch(t, "steward-unknown", "", nil, []RemovedFragment{{Kind: egtypes.KindDirectoryUser, ObjectID: "u1"}})
	if res.SkippedRemovals != 1 || res.Removed != 0 {
		t.Fatalf("removal without a known authority: %+v", res)
	}
}

func TestMembership_StewardSuppliedFutureOrPastTimeIsClamped(t *testing.T) {
	f := newFixture(t)
	now := f.clock.now()
	cases := []struct {
		id       string
		supplied time.Time
		want     time.Time
	}{
		{"u-future", now.Add(72 * time.Hour), now},
		{"u-ancient", now.Add(-30 * 24 * time.Hour), now.Add(-DefaultMaxBackdate)},
		{"u-recent", now.Add(-time.Hour), now.Add(-time.Hour)},
		{"u-zero", time.Time{}, now},
	}
	for _, c := range cases {
		fr := userFrag(c.id, "g1")
		fr.ObservedAt = c.supplied
		f.batch(t, "s", authA, []Fragment{fr}, nil)
	}
	got := map[string]ChangeEvent{}
	for _, e := range f.changes(t, "tenant-a", authA, "g1", true) {
		got[e.MemberID] = e
	}
	for _, c := range cases {
		e := got[c.id]
		if !e.ObservedAt.Equal(c.want) {
			t.Errorf("%s observed_at = %v, want %v", c.id, e.ObservedAt, c.want)
		}
		if !e.RecordedAt.Equal(now) {
			t.Errorf("%s recorded_at = %v, want %v", c.id, e.RecordedAt, now)
		}
		if e.ObservedAt.After(e.RecordedAt) {
			t.Errorf("%s observed_at is after recorded_at", c.id)
		}
	}
}

func TestMembership_LargeChangeBatchEmitsWarningAndLogsEverything(t *testing.T) {
	f := newFixture(t, WithLargeBatchThreshold(100))
	const users = 150
	ups := make([]Fragment, 0, users)
	for i := 0; i < users; i++ {
		ups = append(ups, userFrag(oid("u", i), "g1", "g2"))
	}
	res := f.batch(t, "steward-9", authA, ups, nil)
	if res.Added != 2*users {
		t.Fatalf("Added = %d, want %d: nothing may be dropped", res.Added, 2*users)
	}
	for _, g := range []string{"g1", "g2"} {
		if n := len(f.changes(t, "tenant-a", authA, g, true)); n != users {
			t.Fatalf("group %s logged %d events, want %d", g, n, users)
		}
	}
	w := f.warns.find(WarningLargeBatch)
	if w == nil {
		t.Fatalf("no large-batch warning; got %v", f.warns.kinds())
	}
	if w.Tenant != "tenant-a" || w.Peer != "steward-9" || w.Counts["changes"] != 2*users {
		t.Fatalf("warning = %+v", *w)
	}
	// A batch under the threshold stays quiet.
	quiet := newFixture(t, WithLargeBatchThreshold(100))
	quiet.batch(t, "s", authA, []Fragment{userFrag("u1", "g1")}, nil)
	if quiet.warns.find(WarningLargeBatch) != nil {
		t.Fatal("small batch emitted a large-batch warning")
	}
}

func TestMembership_TruncatedObjectIsFlaggedAndWarned(t *testing.T) {
	f := newFixture(t)
	f.batch(t, "s", authA, []Fragment{userFrag("u1", "g1", "g2")}, nil)
	trunc := Fragment{Kind: egtypes.KindDirectoryUser, ObjectID: "u1",
		Attributes: map[string]any{"member_of": []string{"g1"}, "member_of_truncated": true}}
	res := f.batch(t, "s", authA, []Fragment{trunc}, nil)
	if res.TruncatedObjects != 1 {
		t.Fatalf("TruncatedObjects = %d, want 1", res.TruncatedObjects)
	}
	if f.warns.find(WarningTruncatedObject) == nil {
		t.Fatalf("no truncation warning; got %v", f.warns.kinds())
	}
	page, err := f.m.ListGroupsOf(context.Background(), "tenant-a", authA, "u1", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated {
		t.Fatal("truncated flag not recorded")
	}
	// A truncated list cannot prove g2 was left, so g2 is kept, not silently cut.
	if len(page.GroupIDs) != 2 || res.Removed != 0 {
		t.Fatalf("groups = %v removed = %d; truncated source must not remove memberships", page.GroupIDs, res.Removed)
	}
}

func TestMembership_GroupIDsWithColonAndDot_StoreAndListOnFlatfile(t *testing.T) {
	f := newFixtureOn(t, newFlatStore(t))
	const group = "CN=Domain.Admins:v1.0"
	const m365Group = "grp:team.alpha"
	f.batch(t, "s", authA, []Fragment{userFrag("u1", "g1"), {Kind: egtypes.KindDirectoryGroup, ObjectID: group,
		Attributes: map[string]any{"other_members": []GroupMember{{ID: "comp.1", Type: "computer", DisplayName: "PC:1"}}}}}, nil)
	ms := f.members(t, "tenant-a", authA, group, 10)
	if len(ms) != 1 || ms[0].ID != "comp.1" {
		t.Fatalf("members of %q = %+v", group, ms)
	}
	if _, err := f.m.ApplyGroup(context.Background(), "tenant-m", "m365:abc.def", m365Group,
		[]GroupMember{{ID: "u.1", Type: "user"}}, time.Time{}); err != nil {
		t.Fatalf("ApplyGroup: %v", err)
	}
	if ms := f.members(t, "tenant-m", "m365:abc.def", m365Group, 10); len(ms) != 1 {
		t.Fatalf("m365 members = %+v", ms)
	}
	if got := f.groupsOf(t, "tenant-m", "m365:abc.def", "u.1", 10); len(got) != 1 || got[0] != m365Group {
		t.Fatalf("groups of u.1 = %v", got)
	}
	if n := len(f.changes(t, "tenant-a", authA, group, true)); n != 1 {
		t.Fatalf("change log for %q has %d events, want 1", group, n)
	}
}

func TestMembership_ConcurrentBatchesDoNotLoseUpdates(t *testing.T) {
	f := newFixtureOn(t, newFlatStore(t))
	const workers, rounds, perBatch = 2, 6, 40
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				ups := make([]Fragment, 0, perBatch)
				for i := 0; i < perBatch; i++ {
					ups = append(ups, userFrag(fmt.Sprintf("w%d-r%d-u%d", w, r, i), "shared-group"))
				}
				if _, err := f.m.ApplyBatch(context.Background(), fmt.Sprintf("steward-%d", w), authA, ups, nil); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent ApplyBatch: %v", err)
	}
	const want = workers * rounds * perBatch
	if n := len(f.members(t, "tenant-a", authA, "shared-group", 50)); n != want {
		t.Fatalf("shared-group has %d members, want %d: updates were lost", n, want)
	}
	if n := len(f.changes(t, "tenant-a", authA, "shared-group", true)); n != want {
		t.Fatalf("change log has %d events, want %d", n, want)
	}
}

func TestMembershipLog_SequenceAllocationIsMonotonicUnderConcurrency(t *testing.T) {
	f := newFixtureOn(t, newMemStore())
	const workers, perWorker = 8, 330
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			evs := make([]ChangeEvent, perWorker)
			for i := range evs {
				evs[i] = ChangeEvent{Tenant: "tenant-a", GroupID: "g", MemberID: fmt.Sprintf("w%d-%d", w, i), Op: OpAdded}
			}
			errs <- f.m.appendEvents(context.Background(), "tenant-a", authA, "g", evs)
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("appendEvents: %v", err)
		}
	}
	h := groupHash(authA, "g")
	var sv seqValue
	if ok, err := getValue(context.Background(), f.store, seqKey("tenant-a", h), &sv); err != nil || !ok {
		t.Fatalf("counter: ok=%v err=%v", ok, err)
	}
	total, seen := 0, map[string]bool{}
	for seq := uint64(1); seq <= sv.Current; seq++ {
		var lv logValue
		ok, err := getValue(context.Background(), f.store, logKey("tenant-a", h, seq), &lv)
		if err != nil || !ok {
			t.Fatalf("sequence %d is missing (counter at %d): the sequence must be contiguous", seq, sv.Current)
		}
		if len(lv.Events) > logEntryCapacity {
			t.Fatalf("entry %d holds %d events, capacity %d", seq, len(lv.Events), logEntryCapacity)
		}
		if seq < sv.Current && len(lv.Events) != logEntryCapacity {
			t.Fatalf("entry %d was left before it was full (%d events)", seq, len(lv.Events))
		}
		for _, e := range lv.Events {
			if seen[e.MemberID] {
				t.Fatalf("event %s recorded twice", e.MemberID)
			}
			seen[e.MemberID] = true
		}
		total += len(lv.Events)
	}
	if total != workers*perWorker {
		t.Fatalf("log holds %d events, want %d", total, workers*perWorker)
	}
	if want := uint64((workers*perWorker + logEntryCapacity - 1) / logEntryCapacity); sv.Current != want {
		t.Fatalf("counter = %d, want %d", sv.Current, want)
	}
}

func TestMembership_ApplyGroup_M365SetDiffLogsAddsAndRemoves(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const auth, tenant, group = "m365:11111111-2222-3333-4444-555555555555", "tenant-m", "grp-1"
	t0 := f.clock.now()
	first, err := f.m.ApplyGroup(ctx, tenant, auth, group, []GroupMember{
		{ID: "u1", Type: "user", DisplayName: "One"}, {ID: "u2", Type: "user"}, {ID: "u3", Type: "user"}}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Added != 3 || first.Baseline != 3 {
		t.Fatalf("first sync = %+v, want 3 baseline adds", first)
	}
	f.clock.set(t0.Add(time.Hour))
	second, err := f.m.ApplyGroup(ctx, tenant, auth, group, []GroupMember{
		{ID: "u2", Type: "user"}, {ID: "u3", Type: "user"}, {ID: "u4", Type: "user"}}, f.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	if second.Added != 1 || second.Removed != 1 || second.Baseline != 0 {
		t.Fatalf("second sync = %+v, want 1 add and 1 remove", second)
	}
	evs := f.changes(t, tenant, auth, group, false)
	if len(evs) != 2 {
		t.Fatalf("non-baseline events = %+v", evs)
	}
	ops := map[string]string{}
	for _, e := range evs {
		ops[e.MemberID] = e.Op
		if e.Source != auth || e.ReportedBy != "" || e.Tenant != tenant {
			t.Fatalf("event fields = %+v", e)
		}
	}
	if ops["u1"] != OpRemoved || ops["u4"] != OpAdded {
		t.Fatalf("ops = %v", ops)
	}
	if ms := f.members(t, tenant, auth, group, 10); len(ms) != 3 {
		t.Fatalf("members = %+v", ms)
	}
	if got := f.groupsOf(t, tenant, auth, "u1", 10); len(got) != 0 {
		t.Fatalf("u1 still indexed in %v", got)
	}
	// An identical sync logs nothing.
	third, err := f.m.ApplyGroup(ctx, tenant, auth, group, []GroupMember{
		{ID: "u2", Type: "user"}, {ID: "u3", Type: "user"}, {ID: "u4", Type: "user"}}, f.clock.now())
	if err != nil || third.Added != 0 || third.Removed != 0 {
		t.Fatalf("identical sync = %+v err=%v", third, err)
	}
}

func TestMembership_NonUserGroupMembers_StoredAndLoggedWithTypeIDName(t *testing.T) {
	f := newFixture(t)
	// AD: other_members on a group fragment.
	others := []GroupMember{
		{ID: "c-1", Type: "computer", DisplayName: "WS-01"},
		{ID: "k-1", Type: "contact", DisplayName: "Pat Contact"},
		{ID: "fsp-1", Type: "foreign_security_principal", DisplayName: "S-1-5-21"},
		{ID: "x-1", Type: "something-new", DisplayName: "Mystery"},
		{ID: "bad:id", Type: "computer"},                  // not a bare id: rejected
		{ID: "u-sneaky", Type: "user", DisplayName: "no"}, // users come from user fragments
	}
	res := f.batch(t, "s", authA, []Fragment{groupFrag("g1", nil, others...)}, nil)
	if res.RejectedEntries != 2 {
		t.Fatalf("RejectedEntries = %d, want 2", res.RejectedEntries)
	}
	want := map[string]Member{
		"c-1":   {ID: "c-1", Type: MemberTypeComputer, DisplayName: "WS-01"},
		"k-1":   {ID: "k-1", Type: MemberTypeContact, DisplayName: "Pat Contact"},
		"fsp-1": {ID: "fsp-1", Type: MemberTypeForeignSecurityPrincipal, DisplayName: "S-1-5-21"},
		"x-1":   {ID: "x-1", Type: MemberTypeOther, DisplayName: "Mystery"},
	}
	ms := f.members(t, "tenant-a", authA, "g1", 10)
	if len(ms) != len(want) {
		t.Fatalf("members = %+v", ms)
	}
	for _, m := range ms {
		if want[m.ID] != m {
			t.Fatalf("member %+v, want %+v", m, want[m.ID])
		}
	}
	evs := f.changes(t, "tenant-a", authA, "g1", true)
	if len(evs) != 4 {
		t.Fatalf("events = %+v", evs)
	}
	for _, e := range evs {
		w := want[e.MemberID]
		if e.MemberType != w.Type || e.MemberName != w.DisplayName || e.Op != OpAdded ||
			e.MemberEID != objectEID(authA, w.Type, w.ID) {
			t.Fatalf("event = %+v, want type %s name %q", e, w.Type, w.DisplayName)
		}
	}
	if got := f.groupsOf(t, "tenant-a", authA, "c-1", 10); len(got) != 1 || got[0] != "g1" {
		t.Fatalf("groups of computer = %v", got)
	}
	// Dropping a member from other_members logs a removal.
	f.batch(t, "s", authA, []Fragment{groupFrag("g1", nil, others[0])}, nil)
	if n := opCount(f.changes(t, "tenant-a", authA, "g1", true), OpRemoved); n != 3 {
		t.Fatalf("%d removals, want 3", n)
	}

	// M365: ApplyGroup takes the same member kinds.
	const auth, tenant = "m365:aaaa", "tenant-m"
	if _, err := f.m.ApplyGroup(context.Background(), tenant, auth, "grp", []GroupMember{
		{ID: "dev-1", Type: "device", DisplayName: "Laptop"},
		{ID: "sp-1", Type: "service_principal", DisplayName: "Backup App"},
		{ID: "u-1", Type: "user", DisplayName: "Ada"},
	}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got := map[string]ChangeEvent{}
	for _, e := range f.changes(t, tenant, auth, "grp", true) {
		got[e.MemberID] = e
	}
	if got["dev-1"].MemberType != MemberTypeDevice || got["dev-1"].MemberName != "Laptop" ||
		got["sp-1"].MemberType != MemberTypeServicePrincipal || got["sp-1"].MemberName != "Backup App" ||
		got["u-1"].MemberType != MemberTypeUser {
		t.Fatalf("m365 events = %+v", got)
	}
}

func TestMembership_ClusterModeWithNonAtomicStore_FailsClosed(t *testing.T) {
	store := newFlatStore(t) // the flatfile provider is not a ConditionalConfigStore
	f := newFixtureOn(t, store)
	cfgconfig.SetClusterConfigured(true)
	t.Cleanup(func() { cfgconfig.SetClusterConfigured(false) })

	if _, err := f.m.ApplyBatch(context.Background(), "s", authA, []Fragment{userFrag("u1", "g1")}, nil); err != ErrNotClusterAtomic {
		t.Fatalf("ApplyBatch error = %v, want ErrNotClusterAtomic", err)
	}
	if _, err := f.m.ApplyGroup(context.Background(), "tenant-m", "m365:x", "g", []GroupMember{{ID: "u1", Type: "user"}}, time.Time{}); err != ErrNotClusterAtomic {
		t.Fatalf("ApplyGroup error = %v, want ErrNotClusterAtomic", err)
	}
	entries, err := store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed-closed write left %d entries", len(entries))
	}

	// The same cluster with a conditional store proceeds.
	g := newFixtureOn(t, newMemStore())
	if _, err := g.m.ApplyBatch(context.Background(), "s", authA, []Fragment{userFrag("u1", "g1")}, nil); err != nil {
		t.Fatalf("conditional store in cluster mode: %v", err)
	}
}

func TestMembership_UnknownDomainOwner_WritesNothing(t *testing.T) {
	f := newFixture(t)
	_, err := f.m.ApplyBatch(context.Background(), "s", "directory:unregistered.example", []Fragment{userFrag("u1", "g1")}, nil)
	if err != ErrUnknownDomainOwner {
		t.Fatalf("error = %v, want ErrUnknownDomainOwner", err)
	}
	entries, _ := f.store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{})
	if len(entries) != 0 {
		t.Fatalf("%d entries written for an unowned authority", len(entries))
	}
}
