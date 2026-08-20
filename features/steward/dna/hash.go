// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// FragmentHash returns the SHA-256 of canonicalBytes as a lowercase hex string.
//
// Full 32-byte digest — no truncation, no alternate digest size (ADR-017 §6,
// SE threat #3).
func FragmentHash(canonicalBytes []byte) string {
	sum := sha256.Sum256(canonicalBytes)
	return fmt.Sprintf("%x", sum[:])
}

// AggregateRootHexLen is the length of a SHA-256 digest rendered as lowercase
// hex — the only encoding AggregateRoot and FragmentHash produce (ADR-017 §6).
const AggregateRootHexLen = 64

// IsValidAggregateRoot reports whether s is a well-formed aggregate root:
// exactly AggregateRootHexLen lowercase hexadecimal characters.
//
// An aggregate root arrives from a steward as an arbitrary, unbounded string
// (common.proto DNA.aggregate_root). Every controller-side consumer that treats
// it as an identity — log field, map key, content-address, filesystem path
// component — must validate it here first; a root that is not the exact shape
// AggregateRoot produces is attacker-supplied data, not a digest.
func IsValidAggregateRoot(s string) bool {
	if len(s) != AggregateRootHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// AggregateRoot computes the Merkle-style aggregate root over the manifest.
//
// The manifest is sorted by fragment_id (byte-wise, not locale-aware) before
// hashing so the result is independent of input order (ADR-017 §6, SE threat #3).
//
// Injection-proof encoding: each (fragment_id, fragment_hash) pair is written
// as two length-prefixed fields (uint32 BE length + bytes) so that differently-
// split strings cannot produce the same byte stream.  Naive concatenation
// ("ab"+"c" vs "a"+"bc") is explicitly closed by the length prefix.
func AggregateRoot(manifest []*commonpb.ManifestEntry) (string, error) {
	sorted := make([]*commonpb.ManifestEntry, len(manifest))
	copy(sorted, manifest)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].GetFragmentId() < sorted[j].GetFragmentId()
	})

	h := sha256.New()
	var lenBuf [4]byte
	for _, entry := range sorted {
		idBytes := []byte(entry.GetFragmentId())
		if len(idBytes) > math.MaxUint32 {
			return "", fmt.Errorf("fragment ID exceeds uint32 length")
		}
		// #nosec G115 -- fragment ID length is explicitly bounded above.
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(idBytes)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(idBytes)

		hashBytes := []byte(entry.GetFragmentHash())
		if len(hashBytes) > math.MaxUint32 {
			return "", fmt.Errorf("fragment hash exceeds uint32 length")
		}
		// #nosec G115 -- fragment hash length is explicitly bounded above.
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hashBytes)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(hashBytes)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
