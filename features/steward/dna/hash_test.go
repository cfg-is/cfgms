// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeHash_NilAttributes(t *testing.T) {
	hash := ComputeHash(nil)
	assert.Equal(t, "", hash, "nil attributes should produce empty hash")
}

func TestComputeHash_EmptyAttributes(t *testing.T) {
	hash := ComputeHash(map[string]string{})
	assert.Equal(t, "", hash, "empty attributes should produce empty hash")
}

func TestComputeHash_Deterministic(t *testing.T) {
	attrs := map[string]string{
		"os":       "linux",
		"arch":     "amd64",
		"hostname": "test-host",
	}
	hash1 := ComputeHash(attrs)
	hash2 := ComputeHash(attrs)
	assert.NotEmpty(t, hash1, "non-empty attributes should produce non-empty hash")
	assert.Equal(t, hash1, hash2, "same attributes should always produce the same hash")
}

func TestComputeHash_OrderIndependent(t *testing.T) {
	attrs1 := map[string]string{"alpha": "1", "beta": "2", "gamma": "3"}
	attrs2 := map[string]string{"gamma": "3", "alpha": "1", "beta": "2"}
	assert.Equal(t, ComputeHash(attrs1), ComputeHash(attrs2),
		"attribute order must not affect the hash (deterministic over map iteration order)")
}

func TestComputeHash_ChangedValue(t *testing.T) {
	attrs1 := map[string]string{"os": "linux", "version": "1.0"}
	attrs2 := map[string]string{"os": "linux", "version": "2.0"}
	hash1 := ComputeHash(attrs1)
	hash2 := ComputeHash(attrs2)
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2, "different attribute values must produce different hashes")
}

func TestComputeHash_ChangedKey(t *testing.T) {
	attrs1 := map[string]string{"key_a": "value"}
	attrs2 := map[string]string{"key_b": "value"}
	assert.NotEqual(t, ComputeHash(attrs1), ComputeHash(attrs2),
		"different attribute keys must produce different hashes")
}

func TestComputeHash_AdditionalAttribute(t *testing.T) {
	attrs1 := map[string]string{"os": "linux"}
	attrs2 := map[string]string{"os": "linux", "arch": "amd64"}
	assert.NotEqual(t, ComputeHash(attrs1), ComputeHash(attrs2),
		"adding an attribute must change the hash")
}

func TestComputeHash_EmptyValueSentinelDistinctFromAbsent(t *testing.T) {
	// computeDelta emits empty-string sentinels for deleted keys so the controller
	// can detect the removal via hash comparison.  Verify that a map with key "b"
	// set to "" produces a different hash than a map where "b" is simply absent.
	withSentinel := map[string]string{"a": "1", "b": ""}
	withoutKey := map[string]string{"a": "1"}
	assert.NotEqual(t, ComputeHash(withSentinel), ComputeHash(withoutKey),
		"empty-string sentinel value must produce a different hash than an absent key")
}

func TestComputeHash_ProducesHexString(t *testing.T) {
	attrs := map[string]string{"k": "v"}
	hash := ComputeHash(attrs)
	assert.NotEmpty(t, hash)
	for _, c := range hash {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"hash must be a lowercase hex string, got char: %c", c)
	}
}
