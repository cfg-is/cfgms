// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

func TestBucketOf_StableAndUniform(t *testing.T) {
	seen := make(map[int]bool)
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("user:%d", i)
		b := BucketOf(id)
		require.GreaterOrEqual(t, b, 0)
		require.Less(t, b, BucketCount)
		assert.Equal(t, b, BucketOf(id), "BucketOf must be stable")
		seen[b] = true
	}
	assert.Len(t, seen, 256, "10,000 ids must reach all 256 buckets")
}

func TestBucketRoots_ChangeOnlyInTouchedBucket(t *testing.T) {
	var manifest []*commonpb.ManifestEntry
	for i := 0; i < 2000; i++ {
		manifest = append(manifest, &commonpb.ManifestEntry{
			FragmentId: fmt.Sprintf("user:%d", i), FragmentHash: fmt.Sprintf("h%d", i),
		})
	}
	before := BucketRoots(manifest)
	require.Len(t, before, 256)
	rootBefore := BulkRoot(manifest)

	touched := BucketOf(manifest[7].FragmentId)
	manifest[7] = &commonpb.ManifestEntry{FragmentId: manifest[7].FragmentId, FragmentHash: "changed"}
	after := BucketRoots(manifest)
	for i := range before {
		if i == touched {
			assert.False(t, bytes.Equal(before[i], after[i]), "touched bucket must change")
		} else {
			assert.True(t, bytes.Equal(before[i], after[i]), "bucket %d must not change", i)
		}
	}
	assert.NotEqual(t, rootBefore, BulkRoot(manifest))
}

func TestBucketRoots_EmptyAndOrderIndependent(t *testing.T) {
	roots := BucketRoots(nil)
	require.Len(t, roots, 256)
	for _, r := range roots {
		assert.Equal(t, EmptyBucketRoot(), r)
	}
	assert.Equal(t, "", BulkRoot(nil))

	a := &commonpb.ManifestEntry{FragmentId: "a", FragmentHash: "1"}
	b := &commonpb.ManifestEntry{FragmentId: "b", FragmentHash: "2"}
	assert.Equal(t, BulkRoot([]*commonpb.ManifestEntry{a, b}), BulkRoot([]*commonpb.ManifestEntry{b, a}))
	assert.NotEmpty(t, BulkRoot([]*commonpb.ManifestEntry{a}))
}
