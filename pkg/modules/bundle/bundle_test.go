// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

func makeTestMetadata() *modules.ModuleMetadata {
	return &modules.ModuleMetadata{
		Name:      "test-module",
		Version:   "1.0.0",
		Publisher: "cfgms",
	}
}

func TestBundle_ContentAddress(t *testing.T) {
	b := &bundle.Bundle{
		Manifest: makeTestMetadata(),
		Binaries: map[string]string{
			"linux-amd64":   "binaries/test-module-linux-amd64",
			"linux-arm64":   "binaries/test-module-linux-arm64",
			"windows-amd64": "binaries/test-module-windows-amd64",
		},
		ContentHash: "somehash",
	}

	ca := b.ContentAddress()
	assert.Equal(t, "cfgms", ca.Publisher)
	assert.Equal(t, "test-module", ca.Name)
	assert.Equal(t, "1.0.0", ca.Version)
	assert.Equal(t, "somehash", ca.ContentHash)
}

// TestBundle_RoundTrip verifies that a bundle can be serialized to YAML and
// deserialized back with ContentHash unchanged.
func TestBundle_RoundTrip(t *testing.T) {
	meta := makeTestMetadata()
	binContent := map[string][]byte{
		"linux-amd64": []byte("fake-binary-linux-amd64-content"),
		"linux-arm64": []byte("fake-binary-linux-arm64-content"),
	}

	// Compute hash from binary content and manifest
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	hash, err := bundle.ComputeContentHash(binContent, manifestBytes)
	require.NoError(t, err)

	// Build a bundle with paths (not inline content)
	b := &bundle.Bundle{
		Manifest: meta,
		Binaries: map[string]string{
			"linux-amd64": "path/to/linux-amd64",
			"linux-arm64": "path/to/linux-arm64",
		},
		ContentHash: hash,
	}

	// Serialize
	data, err := yaml.Marshal(b)
	require.NoError(t, err)

	// Deserialize
	var b2 bundle.Bundle
	err = yaml.Unmarshal(data, &b2)
	require.NoError(t, err)

	assert.Equal(t, b.ContentHash, b2.ContentHash)
	assert.Equal(t, b.Manifest.Name, b2.Manifest.Name)
	assert.Equal(t, b.Manifest.Version, b2.Manifest.Version)
	assert.Equal(t, b.Manifest.Publisher, b2.Manifest.Publisher)
	assert.Equal(t, b.Binaries["linux-amd64"], b2.Binaries["linux-amd64"])
}

// TestBundle_HashDeterminism verifies that identical binary content always
// produces the same content hash regardless of map iteration order.
func TestBundle_HashDeterminism(t *testing.T) {
	meta := makeTestMetadata()
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	binContent := map[string][]byte{
		"linux-amd64":   []byte("binary-content-amd64"),
		"linux-arm64":   []byte("binary-content-arm64"),
		"windows-amd64": []byte("binary-content-windows"),
	}

	// Compute the hash multiple times; all results must be identical.
	hash1, err := bundle.ComputeContentHash(binContent, manifestBytes)
	require.NoError(t, err)

	hash2, err := bundle.ComputeContentHash(binContent, manifestBytes)
	require.NoError(t, err)

	hash3, err := bundle.ComputeContentHash(binContent, manifestBytes)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2)
	assert.Equal(t, hash2, hash3)

	// Verify the hash is a valid base64 string (non-empty)
	decoded, err := base64.StdEncoding.DecodeString(hash1)
	require.NoError(t, err)
	assert.Len(t, decoded, 32) // SHA-256 is 32 bytes
}

// TestBundle_TamperedContentProducesDifferentHash verifies that modifying binary
// content changes the hash.
func TestBundle_TamperedContentProducesDifferentHash(t *testing.T) {
	meta := makeTestMetadata()
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	original := map[string][]byte{
		"linux-amd64": []byte("original-binary-content"),
	}
	tampered := map[string][]byte{
		"linux-amd64": []byte("TAMPERED-binary-content"),
	}

	hashOriginal, err := bundle.ComputeContentHash(original, manifestBytes)
	require.NoError(t, err)

	hashTampered, err := bundle.ComputeContentHash(tampered, manifestBytes)
	require.NoError(t, err)

	assert.NotEqual(t, hashOriginal, hashTampered)
}

func TestComputeContentHashFromDigests_BoundaryShift(t *testing.T) {
	d := func(b byte) [32]byte {
		var x [32]byte
		for i := range x {
			x[i] = b
		}
		return x
	}
	manifest := []byte("name: m\n")

	base, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"linux-amd64": d(1), "linux-arm64": d(2)}, manifest)
	require.NoError(t, err)

	t.Run("key/digest boundary", func(t *testing.T) {
		// Digest whose first byte equals a would-be key byte differs from base.
		dg := d(1)
		dg[0] = 'x'
		h, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"linux-amd64": dg, "linux-arm64": d(2)}, manifest)
		require.NoError(t, err)
		assert.NotEqual(t, base, h)
	})

	t.Run("digest/next-key boundary", func(t *testing.T) {
		// Same digest bytes assigned to the other key.
		h, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"linux-amd64": d(2), "linux-arm64": d(1)}, manifest)
		require.NoError(t, err)
		assert.NotEqual(t, base, h)
	})

	t.Run("last-digest/manifest boundary", func(t *testing.T) {
		// Moving a leading manifest byte into the digest position must not collide.
		dg := d(2)
		shifted := append([]byte(nil), manifest[1:]...)
		dg2 := dg
		dg2[31] = manifest[0]
		h1, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"linux-amd64": d(1), "linux-arm64": dg2}, shifted)
		require.NoError(t, err)
		assert.NotEqual(t, base, h1)

		h2, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"linux-amd64": d(1), "linux-arm64": d(2)}, append(manifest, 0))
		require.NoError(t, err)
		assert.NotEqual(t, base, h2)
	})
}

func TestComputeContentHashFromDigests_RefusesBadKeys(t *testing.T) {
	var z [32]byte
	for _, key := range []string{"plan9-mips", "", "linux", "Linux-amd64", "linux-amd64 "} {
		_, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{key: z}, []byte("m"))
		assert.Error(t, err, "key %q", key)
	}
	assert.True(t, bundle.ValidPlatformKey("windows-arm64"))
	assert.False(t, bundle.ValidPlatformKey("freebsd-amd64"))
}

func TestComputeContentHashFromDigests_OrderIndependent(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2
	want, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"linux-amd64": a, "darwin-arm64": b, "windows-amd64": a}, []byte("m"))
	require.NoError(t, err)
	for i := 0; i < 20; i++ {
		got, err := bundle.ComputeContentHashFromDigests(map[string][32]byte{"windows-amd64": a, "darwin-arm64": b, "linux-amd64": a}, []byte("m"))
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}

func TestComputeContentHash_EqualsFromDigests(t *testing.T) {
	bins := map[string][]byte{"linux-amd64": []byte("one"), "darwin-arm64": []byte("two")}
	manifest := []byte("name: m\n")
	digests := map[string][32]byte{}
	for k, v := range bins {
		digests[k] = sha256.Sum256(v)
	}
	want, err := bundle.ComputeContentHashFromDigests(digests, manifest)
	require.NoError(t, err)
	got, err := bundle.ComputeContentHash(bins, manifest)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	t.Run("changing one binary changes hash", func(t *testing.T) {
		changed := map[string][]byte{"linux-amd64": []byte("one"), "darwin-arm64": []byte("twp")}
		h, err := bundle.ComputeContentHash(changed, manifest)
		require.NoError(t, err)
		assert.NotEqual(t, got, h)
	})
	t.Run("changing manifest changes hash", func(t *testing.T) {
		h, err := bundle.ComputeContentHash(bins, []byte("name: n\n"))
		require.NoError(t, err)
		assert.NotEqual(t, got, h)
	})
}
