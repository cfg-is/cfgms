// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle_test

import (
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
