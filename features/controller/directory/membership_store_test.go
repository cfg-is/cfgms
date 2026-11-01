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

// testOwners is a static domain registry: domain -> owning tenant.
type testOwners struct {
	mu sync.Mutex
	m  map[string]string
}

func (o *testOwners) Owner(_ context.Context, domain string) (string, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	t, ok := o.m[domain]
	return t, ok, nil
}

func (o *testOwners) set(domain, tenant string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[domain] = tenant
}

// testClock is a settable time source.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

const (
	authA = "directory:a.example"
	authB = "directory:b.example"
)

type fixture struct {
	m      *Membership
	store  cfgconfig.ConfigStore
	owners *testOwners
	clock  *testClock
	warns  *warnLog
}

type warnLog struct {
	mu sync.Mutex
	ws []Warning
}

func (w *warnLog) add(_ context.Context, x Warning) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ws = append(w.ws, x)
}

func (w *warnLog) kinds() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, x := range w.ws {
		out = append(out, x.Kind)
	}
	return out
}

func (w *warnLog) find(kind string) *Warning {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.ws {
		if w.ws[i].Kind == kind {
			return &w.ws[i]
		}
	}
	return nil
}

func newFixtureOn(t *testing.T, store cfgconfig.ConfigStore, opts ...Option) *fixture {
	t.Helper()
	f := &fixture{
		store:  store,
		owners: &testOwners{m: map[string]string{"a.example": "tenant-a", "b.example": "tenant-b"}},
		clock:  &testClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		warns:  &warnLog{},
	}
	all := append([]Option{WithClock(f.clock.now), WithWarningEmitter(f.warns.add)}, opts...)
	m, err := NewMembership(store, f.owners, all...)
	if err != nil {
		t.Fatalf("NewMembership: %v", err)
	}
	f.m = m
	return f
}

func newFixture(t *testing.T, opts ...Option) *fixture {
	t.Helper()
	return newFixtureOn(t, newFlatStore(t), opts...)
}

// memConfigStore is a real in-memory ConditionalConfigStore used where a test needs
// the store's semantics at a scale an fsync-per-write file store cannot reach under
// -race. It implements the operations the membership code uses.
type memConfigStore struct {
	cfgconfig.ConfigStore // unused operations panic on the nil interface
	mu                    sync.Mutex
	entries               map[string]*cfgconfig.ConfigEntry
}

func newMemStore() *memConfigStore {
	return &memConfigStore{entries: map[string]*cfgconfig.ConfigEntry{}}
}

func clonedEntry(e *cfgconfig.ConfigEntry) *cfgconfig.ConfigEntry {
	c := *e
	k := *e.Key
	c.Key = &k
	c.Data = append([]byte(nil), e.Data...)
	c.Tags = append([]string(nil), e.Tags...)
	return &c
}

func (s *memConfigStore) StoreConfig(_ context.Context, e *cfgconfig.ConfigEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := clonedEntry(e)
	if old, ok := s.entries[e.Key.String()]; ok {
		c.Version = old.Version + 1
	} else {
		c.Version = 1
	}
	s.entries[e.Key.String()] = c
	return nil
}

func (s *memConfigStore) GetConfig(_ context.Context, k *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k.String()]
	if !ok {
		return nil, cfgconfig.ErrConfigNotFound
	}
	return clonedEntry(e), nil
}

func (s *memConfigStore) DeleteConfig(_ context.Context, k *cfgconfig.ConfigKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[k.String()]; !ok {
		return cfgconfig.ErrConfigNotFound
	}
	delete(s.entries, k.String())
	return nil
}

func (s *memConfigStore) CompareAndSwapConfig(_ context.Context, e *cfgconfig.ConfigEntry, expected int64) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur int64
	if old, ok := s.entries[e.Key.String()]; ok {
		cur = old.Version
	}
	if cur != expected {
		return cur, false, nil
	}
	c := clonedEntry(e)
	c.Version = cur + 1
	s.entries[e.Key.String()] = c
	return c.Version, true, nil
}

func (s *memConfigStore) ListConfigs(_ context.Context, f *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*cfgconfig.ConfigEntry
	for _, e := range s.entries {
		if f.TenantID != "" && e.Key.TenantID != f.TenantID {
			continue
		}
		if f.Namespace != "" && e.Key.Namespace != f.Namespace {
			continue
		}
		okTags := true
		for _, want := range f.Tags {
			found := false
			for _, tag := range e.Tags {
				found = found || tag == want
			}
			okTags = okTags && found
		}
		if okTags {
			out = append(out, clonedEntry(e))
		}
	}
	return out, nil
}

func oid(prefix string, i int) string { return fmt.Sprintf("%s-%06d", prefix, i) }

func userFrag(id string, groups ...string) Fragment {
	return Fragment{Kind: egtypes.KindDirectoryUser, ObjectID: id, Attributes: map[string]any{"member_of": groups}}
}

func groupFrag(id string, parents []string, others ...GroupMember) Fragment {
	attrs := map[string]any{"member_of": parents}
	if others != nil {
		attrs["other_members"] = others
	}
	return Fragment{Kind: egtypes.KindDirectoryGroup, ObjectID: id, Attributes: attrs}
}

func (f *fixture) batch(t *testing.T, peer, authority string, ups []Fragment, rem []RemovedFragment) ApplyResult {
	t.Helper()
	res, err := f.m.ApplyBatch(context.Background(), peer, authority, ups, rem)
	if err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}
	return res
}

func (f *fixture) members(t *testing.T, tenant, authority, group string, pageSize int) []Member {
	t.Helper()
	var out []Member
	cur := ""
	for {
		p, err := f.m.ListMembers(context.Background(), tenant, authority, group, cur, pageSize)
		if err != nil {
			t.Fatalf("ListMembers: %v", err)
		}
		out = append(out, p.Members...)
		if p.NextCursor == "" {
			return out
		}
		cur = p.NextCursor
	}
}

func (f *fixture) groupsOf(t *testing.T, tenant, authority, member string, pageSize int) []string {
	t.Helper()
	var out []string
	cur := ""
	for {
		p, err := f.m.ListGroupsOf(context.Background(), tenant, authority, member, cur, pageSize)
		if err != nil {
			t.Fatalf("ListGroupsOf: %v", err)
		}
		out = append(out, p.GroupIDs...)
		if p.NextCursor == "" {
			return out
		}
		cur = p.NextCursor
	}
}

func (f *fixture) changes(t *testing.T, tenant, authority, group string, baseline bool) []ChangeEvent {
	t.Helper()
	var out []ChangeEvent
	cur := ""
	for {
		p, err := f.m.ListChanges(context.Background(), tenant, ChangeQuery{Authority: authority, GroupID: group, IncludeBaseline: baseline, Cursor: cur, Limit: 250})
		if err != nil {
			t.Fatalf("ListChanges: %v", err)
		}
		out = append(out, p.Events...)
		if p.NextCursor == "" {
			return out
		}
		cur = p.NextCursor
	}
}

func TestMembership_UserIn300Groups_AllRecordedAndListed(t *testing.T) {
	f := newFixture(t)
	groups := make([]string, 300)
	for i := range groups {
		groups[i] = oid("grp", i)
	}
	res := f.batch(t, "steward-1", authA, []Fragment{userFrag("user-1", groups...)}, nil)
	if res.Added != 300 {
		t.Fatalf("Added = %d, want 300", res.Added)
	}
	got := f.groupsOf(t, "tenant-a", authA, "user-1", 64)
	if len(got) != 300 {
		t.Fatalf("ListGroupsOf returned %d groups, want 300", len(got))
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Fatalf("group %s listed twice", g)
		}
		seen[g] = true
	}
	for _, g := range groups {
		if !seen[g] {
			t.Fatalf("group %s missing from ListGroupsOf", g)
		}
		ms := f.members(t, "tenant-a", authA, g, 10)
		if len(ms) != 1 || ms[0].ID != "user-1" || ms[0].Type != MemberTypeUser {
			t.Fatalf("group %s members = %+v", g, ms)
		}
	}
}

func TestMembership_GroupWith60000Members_AllRecordedAndPaged(t *testing.T) {
	// The in-memory conditional store keeps this at full scale under -race; the
	// file-backed path is exercised at scale by the first-sync test below.
	f := newFixtureOn(t, newMemStore())
	const total, batchSize = 60000, 2000
	for start := 0; start < total; start += batchSize {
		ups := make([]Fragment, 0, batchSize)
		for i := start; i < start+batchSize; i++ {
			ups = append(ups, userFrag(oid("u", i), "big-group"))
		}
		f.batch(t, "steward-1", authA, ups, nil)
	}
	members := f.members(t, "tenant-a", authA, "big-group", 1000)
	if len(members) != total {
		t.Fatalf("ListMembers returned %d members, want %d", len(members), total)
	}
	seen := make(map[string]struct{}, total)
	for _, mb := range members {
		if _, dup := seen[mb.ID]; dup {
			t.Fatalf("member %s returned twice across pages", mb.ID)
		}
		seen[mb.ID] = struct{}{}
	}
	for i := 0; i < total; i++ {
		if _, ok := seen[oid("u", i)]; !ok {
			t.Fatalf("member %s missing", oid("u", i))
		}
	}
	if ev := f.changes(t, "tenant-a", authA, "big-group", true); len(ev) != total {
		t.Fatalf("change log holds %d events, want %d", len(ev), total)
	}
}

func TestMembership_FirstSyncOf50000Users_InBatchesOf2000_CompletesOnFileBackedStore(t *testing.T) {
	f := newFixture(t)
	total, batchSize := 50000, 2000
	if testing.Short() {
		// The file-backed store fsyncs every entry. `make test` runs -short under
		// -race with a 10m hang detector, which the full 50,000 users (about 50,000
		// fsynced index entries) can exceed on a slow disk. -short therefore syncs
		// two batches; a plain `go test` runs the full first sync.
		total = 2 * batchSize
	}
	deadline := time.Now().Add(9 * time.Minute) // generous CI bound, not a performance claim
	for start := 0; start < total; start += batchSize {
		ups := make([]Fragment, 0, batchSize)
		for i := start; i < start+batchSize; i++ {
			ups = append(ups, userFrag(oid("u", i), oid("dept", i%5), "all-staff"))
		}
		f.batch(t, "steward-1", authA, ups, nil)
		if time.Now().After(deadline) {
			t.Fatalf("first sync did not finish within the CI bound at user %d", start+batchSize)
		}
	}
	if n := len(f.members(t, "tenant-a", authA, "all-staff", 1000)); n != total {
		t.Fatalf("all-staff has %d members, want %d", n, total)
	}
	// The shard count is fixed, so a batch writes at most 64 shards per group
	// however many members it carries.
	entries, err := f.store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant-a", Namespace: NamespaceMembership})
	if err != nil {
		t.Fatal(err)
	}
	if want := 6 * membershipShards; len(entries) > want { // 5 dept groups + all-staff
		t.Fatalf("%d shard entries, want at most %d (6 groups x 64 shards)", len(entries), want)
	}
}

func TestMembership_CursorBoundToTenantAndSubject(t *testing.T) {
	f := newFixture(t)
	f.owners.set("c.example", "tenant-c")
	ups := []Fragment{userFrag("u1", "g"), userFrag("u2", "g"), userFrag("u3", "g")}
	f.batch(t, "s", authA, ups, nil)
	p, err := f.m.ListMembers(context.Background(), "tenant-a", authA, "g", "", 1)
	if err != nil || p.NextCursor == "" {
		t.Fatalf("first page: %v cursor=%q", err, p.NextCursor)
	}
	if _, err := f.m.ListMembers(context.Background(), "tenant-b", authA, "g", p.NextCursor, 1); err != ErrInvalidCursor {
		t.Fatalf("cross-tenant cursor error = %v, want ErrInvalidCursor", err)
	}
	if _, err := f.m.ListMembers(context.Background(), "tenant-a", authA, "other-group", p.NextCursor, 1); err != ErrInvalidCursor {
		t.Fatalf("cross-subject cursor error = %v, want ErrInvalidCursor", err)
	}
	if _, err := f.m.ListMembers(context.Background(), "tenant-a", authA, "g", "not-a-cursor!", 1); err != ErrInvalidCursor {
		t.Fatalf("garbage cursor error = %v, want ErrInvalidCursor", err)
	}
	if _, err := f.m.ListGroupsOf(context.Background(), "tenant-a", authA, "u1", p.NextCursor, 1); err != ErrInvalidCursor {
		t.Fatalf("members cursor used for groups = %v, want ErrInvalidCursor", err)
	}
}

func TestMembership_TwoTenantsIsolated(t *testing.T) {
	f := newFixture(t)
	// The same ids reported for two different tenants' domains.
	f.batch(t, "steward-a", authA, []Fragment{userFrag("u1", "g1")}, nil)
	f.batch(t, "steward-b", authB, []Fragment{userFrag("u1", "g1"), userFrag("u2", "g1")}, nil)

	if n := len(f.members(t, "tenant-a", authA, "g1", 10)); n != 1 {
		t.Fatalf("tenant-a sees %d members, want 1", n)
	}
	if n := len(f.members(t, "tenant-b", authB, "g1", 10)); n != 2 {
		t.Fatalf("tenant-b sees %d members, want 2", n)
	}
	// A tenant cannot read the other's state by naming the other's authority.
	if n := len(f.members(t, "tenant-a", authB, "g1", 10)); n != 0 {
		t.Fatalf("tenant-a read %d members of tenant-b's authority", n)
	}
	if n := len(f.groupsOf(t, "tenant-b", authA, "u1", 10)); n != 0 {
		t.Fatalf("tenant-b read %d groups of tenant-a's authority", n)
	}
	if n := len(f.changes(t, "tenant-a", authB, "g1", true)); n != 0 {
		t.Fatalf("tenant-a read %d change events of tenant-b", n)
	}
	for _, ev := range f.changes(t, "tenant-b", authB, "g1", true) {
		if ev.Tenant != "tenant-b" {
			t.Fatalf("tenant-b log holds an event of tenant %q", ev.Tenant)
		}
	}
}
