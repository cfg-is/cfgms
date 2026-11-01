// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/lease"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// listRecorder wraps a real store and records every ListConfigs filter.
type listRecorder struct {
	cfgconfig.ConfigStore
	mu      sync.Mutex
	filters []cfgconfig.ConfigFilter
}

func (r *listRecorder) ListConfigs(ctx context.Context, f *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	r.mu.Lock()
	r.filters = append(r.filters, *f)
	r.mu.Unlock()
	return r.ConfigStore.ListConfigs(ctx, f)
}

// AtomicLockRoot forwards the wrapped store's lock directory so AtomicUpdate keeps
// its per-key file lock.
func (r *listRecorder) AtomicLockRoot() string {
	return r.ConfigStore.(cfgconfig.AtomicLockDirProvider).AtomicLockRoot()
}

func (r *listRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.filters = nil
}

type staticPeers map[string]bool

func (p staticPeers) PeerRegistered(_ context.Context, id string) (bool, error) { return p[id], nil }

// seedOldAndNew writes one group's events in an old month and another's 500 days
// later, leaving the clock at the later time.
func seedOldAndNew(t *testing.T, f *fixture) (oldAt, newAt time.Time) {
	t.Helper()
	oldAt = time.Date(2025, 1, 15, 9, 0, 0, 0, time.UTC)
	f.clock.set(oldAt)
	f.batch(t, "steward-old", authA, []Fragment{userFrag("u-old", "g-old")}, nil)
	newAt = oldAt.Add(500 * 24 * time.Hour)
	f.clock.set(newAt)
	f.batch(t, "steward-new", authA, []Fragment{userFrag("u-new", "g-new")}, nil)
	return oldAt, newAt
}

func TestMembershipRetention_ListsOnlyOldMonthBuckets(t *testing.T) {
	rec := &listRecorder{ConfigStore: newFlatStore(t)}
	f := newFixtureOn(t, rec)
	_, newAt := seedOldAndNew(t, f)
	rec.reset()

	if _, err := f.m.SweepRetention(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	cutoffMonth := newAt.Add(-DefaultRetention).UTC().Format(monthLayout)
	if len(rec.filters) != defaultSweepLookbackMonths+1 {
		t.Fatalf("sweep issued %d listings, want %d month buckets", len(rec.filters), defaultSweepLookbackMonths+1)
	}
	for _, fl := range rec.filters {
		if fl.Namespace != NamespaceMembershipLog || len(fl.Tags) != 1 {
			t.Fatalf("sweep listed %+v: every listing must be one month-bucket tag of the log namespace", fl)
		}
		month := fl.Tags[0]
		if len(month) != len("m:2006-01") || month[:2] != "m:" || month[2:] > cutoffMonth {
			t.Fatalf("sweep listed bucket %q, newer than the cutoff month %s", month, cutoffMonth)
		}
	}
}

func TestMembershipLog_RetentionSweepDeletesOldEntriesOnly(t *testing.T) {
	f := newFixture(t)
	_, newAt := seedOldAndNew(t, f)
	ctx := context.Background()

	res, err := f.m.SweepRetention(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.EntriesDeleted != 1 || res.CountersDeleted != 1 {
		t.Fatalf("sweep = %+v, want 1 entry and 1 counter deleted", res)
	}
	if n := len(f.changes(t, "tenant-a", authA, "g-old", true)); n != 0 {
		t.Fatalf("old group still has %d log events", n)
	}
	if n := len(f.changes(t, "tenant-a", authA, "g-new", true)); n != 1 {
		t.Fatalf("recent group has %d log events, want 1", n)
	}
	if ok, _ := f.m.groupObserved(ctx, "tenant-a", authA, "g-old"); ok {
		t.Fatal("counter of a group with no log entries was kept")
	}
	if ok, _ := f.m.groupObserved(ctx, "tenant-a", authA, "g-new"); !ok {
		t.Fatal("counter of a group with log entries was deleted")
	}
	// Retention never touches membership state.
	if ms := f.members(t, "tenant-a", authA, "g-old", 10); len(ms) != 1 {
		t.Fatalf("retention removed membership state: %+v", ms)
	}

	// An entry in an old month bucket that was appended to recently is kept.
	f.clock.set(newAt)
	f.batch(t, "steward-new", authA, []Fragment{userFrag("u-new2", "g-old")}, nil)
	f.clock.set(newAt.Add(DefaultRetention + 24*time.Hour))
	res, err = f.m.SweepRetention(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.EntriesDeleted != 2 {
		t.Fatalf("second sweep = %+v, want both remaining entries aged out", res)
	}
}

func TestMembershipLog_RetentionKeepsRecentlyAppendedEntry(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	f.clock.set(start)
	f.batch(t, "s", authA, []Fragment{userFrag("u1", "g1")}, nil)
	// 380 days later (inside retention) the same entry is appended to; the entry's
	// bucket month is now older than the cutoff month but its newest event is not.
	f.clock.set(start.Add(380 * 24 * time.Hour))
	f.batch(t, "s", authA, []Fragment{userFrag("u2", "g1")}, nil)
	f.clock.set(start.Add(430 * 24 * time.Hour))
	res, err := f.m.SweepRetention(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.EntriesDeleted != 0 {
		t.Fatalf("sweep deleted %d entries holding events younger than the retention period", res.EntriesDeleted)
	}
	if n := len(f.changes(t, "tenant-a", authA, "g1", true)); n != 2 {
		t.Fatalf("log has %d events, want 2", n)
	}
}

func TestMembershipRetention_DeletesDeregisteredPeerEntries(t *testing.T) {
	f := newFixture(t)
	f.batch(t, "steward-live", authA, []Fragment{userFrag("u1", "g1")}, nil)
	f.batch(t, "steward-gone", authA, []Fragment{userFrag("u2", "g1")}, nil)
	res, err := f.m.SweepRetention(context.Background(), staticPeers{"steward-live": true})
	if err != nil {
		t.Fatal(err)
	}
	if res.PeersDeleted != 1 {
		t.Fatalf("PeersDeleted = %d, want 1", res.PeersDeleted)
	}
	var pv peerValue
	if ok, _ := getValue(context.Background(), f.store, peerKey("steward-gone"), &pv); ok {
		t.Fatal("deregistered peer entry kept")
	}
	if ok, _ := getValue(context.Background(), f.store, peerKey("steward-live"), &pv); !ok {
		t.Fatal("registered peer entry deleted")
	}
}

func TestMembershipRetention_RunsUnderSingletonJob(t *testing.T) {
	f := newFixture(t)
	seedOldAndNew(t, f)
	job, err := lease.NewSingletonJob(nil, "directory-membership-retention", "node-1", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !f.m.RunRetention(context.Background(), job, nil) {
		t.Fatal("job did not run")
	}
	if n := len(f.changes(t, "tenant-a", authA, "g-old", true)); n != 0 {
		t.Fatalf("sweep under the singleton job left %d old events", n)
	}
}
