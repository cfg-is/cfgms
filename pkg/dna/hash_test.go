// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// --- FragmentHash tests ---

func TestFragmentHash_KnownVector(t *testing.T) {
	// SHA-256 of empty input is the well-known constant.
	got := FragmentHash([]byte{})
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", got)
}

func TestFragmentHash_FullDigest(t *testing.T) {
	// Full SHA-256 hex is 64 lowercase hex characters — no truncation.
	hash := FragmentHash([]byte("some canonical bytes"))
	assert.Len(t, hash, 64, "FragmentHash must return full 32-byte SHA-256 hex (64 chars)")
	for _, c := range hash {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"FragmentHash must be lowercase hex, got char: %c", c)
	}
}

func TestFragmentHash_Deterministic(t *testing.T) {
	b := []byte("canonical fragment state")
	assert.Equal(t, FragmentHash(b), FragmentHash(b), "same bytes must produce same hash")
}

func TestFragmentHash_DifferentInputs(t *testing.T) {
	assert.NotEqual(t, FragmentHash([]byte("a")), FragmentHash([]byte("b")))
}

// --- AggregateRoot tests ---

func TestAggregateRoot_Empty(t *testing.T) {
	root, err := AggregateRoot(nil)
	require.NoError(t, err)
	// SHA-256 of zero bytes written to the hasher.
	assert.Len(t, root, 64)
}

func TestAggregateRoot_Deterministic(t *testing.T) {
	entries := []*commonpb.ManifestEntry{
		{FragmentId: "file:/etc/hosts", FragmentHash: "aabbcc"},
		{FragmentId: "service:sshd", FragmentHash: "112233"},
	}
	r1, err := AggregateRoot(entries)
	require.NoError(t, err)
	r2, err := AggregateRoot(entries)
	require.NoError(t, err)
	assert.Equal(t, r1, r2)
}

func TestAggregateRoot_OrderIndependent(t *testing.T) {
	// Reordering input must not change the root — AggregateRoot sorts internally.
	a := []*commonpb.ManifestEntry{
		{FragmentId: "aaa", FragmentHash: "111"},
		{FragmentId: "bbb", FragmentHash: "222"},
		{FragmentId: "ccc", FragmentHash: "333"},
	}
	b := []*commonpb.ManifestEntry{
		{FragmentId: "ccc", FragmentHash: "333"},
		{FragmentId: "aaa", FragmentHash: "111"},
		{FragmentId: "bbb", FragmentHash: "222"},
	}
	ra, err := AggregateRoot(a)
	require.NoError(t, err)
	rb, err := AggregateRoot(b)
	require.NoError(t, err)
	assert.Equal(t, ra, rb, "AggregateRoot must be order-independent")
}

func TestAggregateRoot_DifferentHashesSameIDs(t *testing.T) {
	a := []*commonpb.ManifestEntry{{FragmentId: "x", FragmentHash: "000"}}
	b := []*commonpb.ManifestEntry{{FragmentId: "x", FragmentHash: "fff"}}
	ra, err := AggregateRoot(a)
	require.NoError(t, err)
	rb, err := AggregateRoot(b)
	require.NoError(t, err)
	assert.NotEqual(t, ra, rb, "different fragment hashes must produce different aggregate roots")
}

// TestAggregateRoot_InjectionProof is the REQUIRED SECURITY TEST (AC).
//
// Proves that the manifest-entry encoding is injection-proof at this second
// concatenation site (SE threat #3).  Two manifests with differently-split
// strings that would collide under naive id+hash concatenation must produce
// different roots because each field is length-prefixed.
//
// Example collision under naive concatenation:
//
//	entry A: id="ab", hash="c"   → "ab" + "c"  = "abc"
//	entry B: id="a",  hash="bc"  → "a"  + "bc" = "abc"
//
// Length-prefix encoding distinguishes them:
//
//	A: [0,0,0,2]"ab" [0,0,0,1]"c"
//	B: [0,0,0,1]"a"  [0,0,0,2]"bc"
func TestAggregateRoot_InjectionProof(t *testing.T) {
	manifestA := []*commonpb.ManifestEntry{
		{FragmentId: "ab", FragmentHash: "c"},
	}
	manifestB := []*commonpb.ManifestEntry{
		{FragmentId: "a", FragmentHash: "bc"},
	}
	ra, err := AggregateRoot(manifestA)
	require.NoError(t, err)
	rb, err := AggregateRoot(manifestB)
	require.NoError(t, err)
	assert.NotEqual(t, ra, rb,
		"AggregateRoot must be injection-proof: id='ab',hash='c' must differ from id='a',hash='bc'")
}

func TestAggregateRoot_FullDigest(t *testing.T) {
	entries := []*commonpb.ManifestEntry{{FragmentId: "f", FragmentHash: "h"}}
	root, err := AggregateRoot(entries)
	require.NoError(t, err)
	assert.Len(t, root, 64, "AggregateRoot must return full 32-byte SHA-256 hex (64 chars — no truncation)")
}
