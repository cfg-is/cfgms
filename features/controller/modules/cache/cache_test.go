// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cache_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

func makeTestBundle(publisher, name, version, hash string) *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: &modules.ModuleMetadata{
			Name:      name,
			Version:   version,
			Publisher: publisher,
			Executors: []string{"steward"},
		},
		Binaries:    map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures:  []bundle.BundleSignature{{Publisher: publisher, Algorithm: "ed25519", Signature: make([]byte, 64)}},
		ContentHash: hash,
	}
}

func makeTestCache(t *testing.T) *cache.ModuleCache {
	t.Helper()
	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	return c
}

// [REQUIRED TEST] Put then Get round-trip returns identical bundle.
func TestModuleCache_PutGet_RoundTrip(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "hyperv", "0.2.1", "abc123hash")

	require.NoError(t, c.Put(b))

	got, err := c.Get(b.ContentAddress())
	require.NoError(t, err)

	assert.Equal(t, b.Manifest.Name, got.Manifest.Name)
	assert.Equal(t, b.Manifest.Version, got.Manifest.Version)
	assert.Equal(t, b.Manifest.Publisher, got.Manifest.Publisher)
	assert.Equal(t, b.ContentHash, got.ContentHash)
	assert.Equal(t, b.Binaries, got.Binaries)
	require.Len(t, got.Signatures, 1)
	assert.Equal(t, b.Signatures[0].Publisher, got.Signatures[0].Publisher)
	assert.Equal(t, b.Signatures[0].Algorithm, got.Signatures[0].Algorithm)
}

// [REQUIRED TEST] Put of identical bundle (same content hash) is idempotent (no error, no duplicate).
func TestModuleCache_Put_Idempotent(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "hyperv", "0.2.1", "abc123hash")

	require.NoError(t, c.Put(b))
	// Second Put with same bundle must succeed without error.
	require.NoError(t, c.Put(b))

	entries, err := c.List()
	require.NoError(t, err)
	assert.Len(t, entries, 1, "idempotent Put must not create duplicate entries")
}

// TestModuleCache_Put_ConflictDifferentHash ensures ErrContentAddressConflict is returned
// when a different hash exists at the same (publisher/name/version).
func TestModuleCache_Put_ConflictDifferentHash(t *testing.T) {
	c := makeTestCache(t)
	b1 := makeTestBundle("cfgms", "hyperv", "0.2.1", "hash-original")
	b2 := makeTestBundle("cfgms", "hyperv", "0.2.1", "hash-different")

	require.NoError(t, c.Put(b1))
	err := c.Put(b2)
	assert.ErrorIs(t, err, cache.ErrContentAddressConflict)
}

// TestModuleCache_Get_NotFound returns ErrBundleNotFound for unknown addresses.
func TestModuleCache_Get_NotFound(t *testing.T) {
	c := makeTestCache(t)
	addr := bundle.ContentAddress{
		Publisher:   "cfgms",
		Name:        "missing",
		Version:     "1.0.0",
		ContentHash: "nohash",
	}
	_, err := c.Get(addr)
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// TestModuleCache_List returns all stored entries with correct approval status.
func TestModuleCache_List(t *testing.T) {
	c := makeTestCache(t)

	b1 := makeTestBundle("cfgms", "hyperv", "0.2.1", "hash1")
	b2 := makeTestBundle("cfgms", "file", "1.0.0", "hash2")
	require.NoError(t, c.Put(b1))
	require.NoError(t, c.Put(b2))

	entries, err := c.List()
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	for _, e := range entries {
		assert.Equal(t, cache.ApprovalStatusPending, e.Status, "new entries must start as pending")
	}
}

// TestModuleCache_List_EmptyCache returns nil/empty for an empty cache.
func TestModuleCache_List_EmptyCache(t *testing.T) {
	c := makeTestCache(t)
	entries, err := c.List()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestModuleCache_List_RootIsNotDirectory returns a wrapped error if the cache
// root path exists but is a regular file. Behaviour must be identical across
// Linux/macOS/Windows — Windows' os.ReadDir on a regular file produces a
// different error shape than Linux's, so List must Stat the root explicitly.
func TestModuleCache_List_RootIsNotDirectory(t *testing.T) {
	parent := t.TempDir()
	rootAsFile := parent + string(os.PathSeparator) + "module-cache"
	require.NoError(t, os.WriteFile(rootAsFile, []byte("not-a-dir"), 0640))

	// Construct a cache pointing at the file. We use the fact that cache.New
	// calls MkdirAll which would fail here — so we go via Put/Get/List through
	// a freshly-created cache whose rootDir we then sabotage.
	c, err := cache.New(parent + string(os.PathSeparator) + "real-root")
	require.NoError(t, err)
	require.NoError(t, c.Put(makeTestBundle("cfgms", "firewall", "1.0.0", "hash1")))

	// Now sabotage the real-root path by replacing it with a regular file.
	realRoot := parent + string(os.PathSeparator) + "real-root"
	require.NoError(t, os.RemoveAll(realRoot))
	require.NoError(t, os.WriteFile(realRoot, []byte("not-a-dir"), 0640))

	_, listErr := c.List()
	require.Error(t, listErr)
	assert.Contains(t, listErr.Error(), "cache root is not a directory")
}

// TestModuleCache_SetGetApprovalStatus round-trips status updates.
func TestModuleCache_SetGetApprovalStatus(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "hyperv", "0.2.1", "abc123hash")
	require.NoError(t, c.Put(b))
	addr := b.ContentAddress()

	// Initial status is pending.
	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusPending, status)

	// Approve it.
	require.NoError(t, c.SetApprovalStatus(addr, cache.ApprovalStatusApproved))
	status, err = c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)

	// Reject it.
	require.NoError(t, c.SetApprovalStatus(addr, cache.ApprovalStatusRejected))
	status, err = c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, status)
}

// TestModuleCache_SetApprovalStatus_NotFound returns ErrBundleNotFound for missing bundles.
func TestModuleCache_SetApprovalStatus_NotFound(t *testing.T) {
	c := makeTestCache(t)
	addr := bundle.ContentAddress{Publisher: "cfgms", Name: "missing", Version: "1.0.0", ContentHash: "nohash"}
	err := c.SetApprovalStatus(addr, cache.ApprovalStatusApproved)
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// TestModuleCache_InvalidPathComponents rejects path traversal in both Get and Put.
func TestModuleCache_InvalidPathComponents(t *testing.T) {
	type testCase struct {
		publisher   string
		name        string
		version     string
		contentHash string
	}

	cases := []testCase{
		{publisher: "../evil", name: "mod", version: "1.0.0", contentHash: "hash"},
		{publisher: "cfgms", name: "../evil", version: "1.0.0", contentHash: "hash"},
		{publisher: "cfgms", name: "mod", version: "../evil", contentHash: "hash"},
		{publisher: "", name: "mod", version: "1.0.0", contentHash: "hash"},
	}
	// Note: ContentHash with ".." is rejected; "/" and "\" in hash cause Rename failure
	// on some platforms but are validated via the dot-sequence check.
	dotCases := []testCase{
		{publisher: "cfgms", name: "mod", version: "1.0.0", contentHash: "../evil"},
	}

	c := makeTestCache(t)

	for _, tc := range append(cases, dotCases...) {
		addr := bundle.ContentAddress{
			Publisher:   tc.publisher,
			Name:        tc.name,
			Version:     tc.version,
			ContentHash: tc.contentHash,
		}

		// Both Get and Put must reject path traversal.
		_, getErr := c.Get(addr)
		assert.Error(t, getErr, "Get must reject addr %+v", addr)

		b := &bundle.Bundle{
			Manifest: &modules.ModuleMetadata{
				Name:      tc.name,
				Version:   tc.version,
				Publisher: tc.publisher,
				Executors: []string{"steward"},
			},
			ContentHash: tc.contentHash,
		}
		putErr := c.Put(b)
		assert.Error(t, putErr, "Put must reject addr %+v", addr)
	}
}

// TestModuleCache_List_ShowsApprovedStatus verifies List reflects updated status.
func TestModuleCache_List_ShowsApprovedStatus(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "hyperv", "0.2.1", "hash1")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, cache.ApprovalStatusApproved, entries[0].Status)
}

// TestModuleCache_PutManifestContentPreserved verifies manifest YAML roundtrip preserves fields.
func TestModuleCache_PutManifestContentPreserved(t *testing.T) {
	c := makeTestCache(t)
	meta := &modules.ModuleMetadata{
		Name:        "hyperv",
		Version:     "0.2.1",
		Publisher:   "cfgms",
		Description: "Hyper-V module",
		Executors:   []string{"steward"},
	}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	hash, err := bundle.ComputeContentHash(map[string][]byte{"linux-amd64": []byte("bin")}, manifestBytes)
	require.NoError(t, err)

	b := &bundle.Bundle{
		Manifest:    meta,
		Binaries:    map[string]string{"linux-amd64": "binaries/linux-amd64"},
		ContentHash: hash,
	}
	require.NoError(t, c.Put(b))

	got, err := c.Get(b.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, "Hyper-V module", got.Manifest.Description)
	assert.Equal(t, hash, got.ContentHash)
}
