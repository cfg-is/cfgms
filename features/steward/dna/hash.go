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
