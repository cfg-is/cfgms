// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// countingConfigStore wraps a real config store and counts entries written.
type countingConfigStore struct {
	cfgconfig.ConfigStore
	writes atomic.Int64
}

func (c *countingConfigStore) StoreConfig(ctx context.Context, e *cfgconfig.ConfigEntry) error {
	c.writes.Add(1)
	return c.ConfigStore.StoreConfig(ctx, e)
}

func (c *countingConfigStore) StoreConfigBatch(ctx context.Context, es []*cfgconfig.ConfigEntry) error {
	c.writes.Add(int64(len(es)))
	return c.ConfigStore.StoreConfigBatch(ctx, es)
}

func newFlatfileConfigStore(t *testing.T, root string) cfgconfig.ConfigStore {
	t.Helper()
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	cs, err := p.CreateConfigStore(map[string]interface{}{"root": root})
	require.NoError(t, err)
	return cs
}

func bulkFrags(prefix string, n int) []*commonpb.Fragment {
	out := make([]*commonpb.Fragment, n)
	for i := range out {
		out[i] = &commonpb.Fragment{
			FragmentId:     fmt.Sprintf("%s:%d", prefix, i),
			CanonicalBytes: []byte(fmt.Sprintf("bytes-%s-%d", prefix, i)),
		}
	}
	return out
}

func newBulkStore(t *testing.T) (*BulkManifestStore, *countingConfigStore) {
	t.Helper()
	cs := &countingConfigStore{ConfigStore: newFlatfileConfigStore(t, t.TempDir())}
	s, err := NewBulkManifestStore(cs)
	require.NoError(t, err)
	return s, cs
}

func TestBulkStore_RoundTripAcrossRestart(t *testing.T) {
	root := t.TempDir()
	s1, err := NewBulkManifestStore(newFlatfileConfigStore(t, root))
	require.NoError(t, err)

	frags := bulkFrags("file", 5000)
	require.NoError(t, s1.ApplyDelta("steward-1", frags))
	want, err := s1.CurrentManifest("steward-1")
	require.NoError(t, err)
	require.Len(t, want, 5000)
	wantRoots, err := s1.BucketRoots("steward-1")
	require.NoError(t, err)

	// A fresh store over a fresh config store on the same root is a restart.
	s2, err := NewBulkManifestStore(newFlatfileConfigStore(t, root))
	require.NoError(t, err)
	got, err := s2.CurrentManifest("steward-1")
	require.NoError(t, err)
	require.Len(t, got, 5000)
	for i := range want {
		assert.Equal(t, want[i].GetFragmentId(), got[i].GetFragmentId())
		assert.Equal(t, want[i].GetFragmentHash(), got[i].GetFragmentHash())
	}

	gotRoots, err := s2.BucketRoots("steward-1")
	require.NoError(t, err)
	require.Len(t, gotRoots, stewarddna.BucketCount)
	for i := range wantRoots {
		assert.True(t, bytes.Equal(wantRoots[i], gotRoots[i]), "bucket %d root changed across restart", i)
	}
	assert.Equal(t, stewarddna.BulkRoot(got), stewarddna.BulkRoot(want))
	assert.Equal(t, stewarddna.BucketRoots(got), gotRoots, "persisted roots must equal roots recomputed from the manifest")
}

func TestBulkStore_DerivesHashFromBytes(t *testing.T) {
	s, _ := newBulkStore(t)
	f := &commonpb.Fragment{
		FragmentId:     "file:/etc/x",
		CanonicalBytes: []byte("real-bytes"),
		FragmentHash:   "deadbeef-asserted-by-steward",
	}
	require.NoError(t, s.ApplyDelta("steward-1", []*commonpb.Fragment{f}))
	m, err := s.CurrentManifest("steward-1")
	require.NoError(t, err)
	require.Len(t, m, 1)
	assert.Equal(t, stewarddna.FragmentHash([]byte("real-bytes")), m[0].GetFragmentHash())
}

func TestBulkStore_TwoStewardsIsolated(t *testing.T) {
	s, _ := newBulkStore(t)
	require.NoError(t, s.ApplyDelta("steward-a", bulkFrags("x", 50)))
	require.NoError(t, s.ApplyDelta("steward-b", bulkFrags("y", 30)))

	a, err := s.CurrentManifest("steward-a")
	require.NoError(t, err)
	b, err := s.CurrentManifest("steward-b")
	require.NoError(t, err)
	assert.Len(t, a, 50)
	assert.Len(t, b, 30)

	require.NoError(t, s.RemoveFragments("steward-a", []string{"x:0", "y:0"}))
	a, _ = s.CurrentManifest("steward-a")
	b, _ = s.CurrentManifest("steward-b")
	assert.Len(t, a, 49)
	assert.Len(t, b, 30, "removal on one steward must not touch another")

	none, err := s.CurrentManifest("steward-c")
	require.NoError(t, err)
	assert.Nil(t, none)
}

func TestBulkStore_RejectsOverCapWithoutPartialWrite(t *testing.T) {
	s, cs := newBulkStore(t)
	require.NoError(t, s.ApplyDelta("steward-1", bulkFrags("seed", 10)))

	// Fill the in-memory count to just under the cap without writing 250k shards.
	s.mu.Lock()
	s.counts["steward-1"] = MaxBulkFragmentsPerSteward - 5
	s.mu.Unlock()

	before := cs.writes.Load()
	err := s.ApplyDelta("steward-1", bulkFrags("over", 6))
	require.Error(t, err)
	assert.Equal(t, before, cs.writes.Load(), "a rejected delta must not write")

	m, _ := s.CurrentManifest("steward-1")
	assert.Len(t, m, 10, "stored manifest must be unchanged")

	// Replacing existing ids adds nothing, so it fits even at the cap; so do 5 new ones.
	require.NoError(t, s.ApplyDelta("steward-1", bulkFrags("seed", 10)))
	require.NoError(t, s.ApplyDelta("steward-1", bulkFrags("fits", 5)))
}

func TestBulkStore_DeltaRewritesOnlyTouchedBuckets(t *testing.T) {
	s, cs := newBulkStore(t)
	require.NoError(t, s.ApplyDelta("steward-1", bulkFrags("file", 2000)))

	before := cs.writes.Load()
	f := &commonpb.Fragment{FragmentId: "file:0", CanonicalBytes: []byte("changed")}
	require.NoError(t, s.ApplyDelta("steward-1", []*commonpb.Fragment{f}))
	assert.Equal(t, int64(1), cs.writes.Load()-before, "one fragment touches exactly one bucket")

	roots1, err := s.BucketRoots("steward-1")
	require.NoError(t, err)
	require.NoError(t, s.ApplyDelta("steward-1", []*commonpb.Fragment{{FragmentId: "file:0", CanonicalBytes: []byte("changed-again")}}))
	roots2, err := s.BucketRoots("steward-1")
	require.NoError(t, err)
	changed := 0
	for i := range roots1 {
		if !bytes.Equal(roots1[i], roots2[i]) {
			changed++
			assert.Equal(t, stewarddna.BucketOf("file:0"), i)
		}
	}
	assert.Equal(t, 1, changed)
}

func TestBulkStore_RemoveFragments(t *testing.T) {
	s, _ := newBulkStore(t)
	require.NoError(t, s.ApplyDelta("steward-1", bulkFrags("f", 1)))
	require.NoError(t, s.RemoveFragments("steward-1", []string{"f:0", "never-stored"}))
	m, err := s.CurrentManifest("steward-1")
	require.NoError(t, err)
	assert.Empty(t, m)
	roots, err := s.BucketRoots("steward-1")
	require.NoError(t, err)
	for _, r := range roots {
		assert.Equal(t, stewarddna.EmptyBucketRoot(), r)
	}
}

func TestNewBulkManifestStore_NilConfigStore(t *testing.T) {
	_, err := NewBulkManifestStore(nil)
	require.Error(t, err)
}
