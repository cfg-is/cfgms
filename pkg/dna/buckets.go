// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"crypto/sha256"
	"encoding/hex"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// BucketCount is the number of buckets the bulk lane partitions fragments into.
// One bucket manifest stays around 200 entries per 50,000 objects.
const BucketCount = 256

// emptyBucketRootHex is the root of a bucket with no entries: the SHA-256 of the
// empty byte stream, which is what AggregateRoot yields for an empty manifest.
const emptyBucketRootHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// EmptyBucketRoot returns a copy of the fixed root of an empty bucket.
func EmptyBucketRoot() []byte {
	b, _ := hex.DecodeString(emptyBucketRootHex)
	return b
}

// BucketOf returns the bulk-lane bucket of a fragment ID: the first byte of the
// SHA-256 of the ID.
func BucketOf(id string) int {
	sum := sha256.Sum256([]byte(id))
	return int(sum[0])
}

// BucketRoots returns exactly BucketCount roots, one per bucket. A bucket's root
// is AggregateRoot over the manifest entries that fall in it, so it changes only
// when an entry in that bucket changes. Empty buckets carry EmptyBucketRoot.
func BucketRoots(manifest []*commonpb.ManifestEntry) [][]byte {
	buckets := make([][]*commonpb.ManifestEntry, BucketCount)
	for _, e := range manifest {
		if e == nil {
			continue
		}
		b := BucketOf(e.GetFragmentId())
		buckets[b] = append(buckets[b], e)
	}
	roots := make([][]byte, BucketCount)
	for i, entries := range buckets {
		if len(entries) == 0 {
			roots[i] = EmptyBucketRoot()
			continue
		}
		hexRoot, err := AggregateRoot(entries)
		if err != nil {
			// Only reachable for IDs over 4 GiB; treat the bucket as unhashable
			// rather than silently equal to an empty one.
			roots[i] = nil
			continue
		}
		roots[i], _ = hex.DecodeString(hexRoot)
	}
	return roots
}

// BulkRoot returns the aggregate root over the 256 bucket roots, as lowercase
// hex. It returns "" for an empty manifest, which is how a steward with no bulk
// fragments reports "absent" on the heartbeat.
func BulkRoot(manifest []*commonpb.ManifestEntry) string {
	if len(manifest) == 0 {
		return ""
	}
	h := sha256.New()
	for _, r := range BucketRoots(manifest) {
		_, _ = h.Write(r)
	}
	return hex.EncodeToString(h.Sum(nil))
}
