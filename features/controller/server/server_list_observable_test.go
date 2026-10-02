// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// Tests for moduleManifestAdapter.ListObservableManifests, which gates which
// approved module bundles are eligible for Tier-2 observe dispatch (Issue #3563,
// ADR-024 Amendment 2).
package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	modulecache "github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// makeListObservableCacheAt creates a real ModuleCache rooted at the given path
// and returns it. Callers that need to manipulate the root on disk (error-path
// tests) use this variant so they know the exact root directory.
func makeListObservableCacheAt(t *testing.T, root string) *modulecache.ModuleCache {
	t.Helper()
	c, err := modulecache.New(root)
	require.NoError(t, err)
	return c
}

// makeListObservableCache creates a real ModuleCache in a temp directory.
func makeListObservableCache(t *testing.T) *modulecache.ModuleCache {
	t.Helper()
	return makeListObservableCacheAt(t, filepath.Join(t.TempDir(), "module-cache"))
}

// makeListObservableBundle builds a minimal bundle with the given manifest and a
// stable content hash derived from the name. Signatures carry a zero-filled
// Ed25519 signature which is sufficient for cache storage tests (signature
// verification is not exercised here).
func makeListObservableBundle(manifest *modules.ModuleMetadata, contentHash string) *bundle.Bundle {
	return &bundle.Bundle{
		Manifest:    manifest,
		Binaries:    map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures:  []bundle.BundleSignature{{Publisher: manifest.Publisher, Algorithm: "ed25519", Signature: make([]byte, 64)}},
		ContentHash: contentHash,
	}
}

// putApproved adds a bundle to the cache and sets its approval status to Approved.
func putApproved(t *testing.T, c *modulecache.ModuleCache, b *bundle.Bundle) {
	t.Helper()
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), modulecache.ApprovalStatusApproved))
}

// putPending adds a bundle to the cache and leaves it in the default Pending state.
func putPending(t *testing.T, c *modulecache.ModuleCache, b *bundle.Bundle) {
	t.Helper()
	require.NoError(t, c.Put(b))
	// Default status is Pending — no SetApprovalStatus call needed.
}

// ---------------------------------------------------------------------------
// ListObservableManifests tests
// ---------------------------------------------------------------------------

// TestListObservableManifests_AlwaysPull_Approved verifies that a manifest with
// AlwaysPull true and empty ObserveWhen is included when its bundle is Approved.
// This is the primary positive AC for Issue #3563.
func TestListObservableManifests_AlwaysPull_Approved(t *testing.T) {
	c := makeListObservableCache(t)
	manifest := &modules.ModuleMetadata{
		Name:       "osquery",
		Version:    "0.1.0",
		Publisher:  "cfgms",
		Executors:  []string{"steward"},
		Kind:       "steward",
		AlwaysPull: true,
	}
	b := makeListObservableBundle(manifest, "hash-osq-001")
	putApproved(t, c, b)

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "osquery", got[0].Name)
	assert.True(t, got[0].AlwaysPull)
}

// [REQUIRED TEST] TestListObservableManifests_AlwaysPull_NotApproved verifies that
// a manifest with AlwaysPull true and empty ObserveWhen does NOT appear when its
// bundle is not Approved (Pending status). This is the required negative test:
// a positive-only test would pass under both the correct fix and the
// unsafe bypass-shaped mistake, so it does not substitute for this one.
func TestListObservableManifests_AlwaysPull_NotApproved(t *testing.T) {
	c := makeListObservableCache(t)
	manifest := &modules.ModuleMetadata{
		Name:       "osquery",
		Version:    "0.1.0",
		Publisher:  "cfgms",
		Executors:  []string{"steward"},
		Kind:       "steward",
		AlwaysPull: true,
	}
	b := makeListObservableBundle(manifest, "hash-osq-002")
	putPending(t, c, b) // Deliberately NOT approved.

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.NoError(t, err)
	assert.Empty(t, got, "unapproved AlwaysPull bundle must not appear in ListObservableManifests")
}

// TestListObservableManifests_ObserveWhen_Approved verifies that the existing
// observe_when-only path (hyperv) is unaffected by the AlwaysPull change.
// This is the required regression test (AC: "existing observe_when-only modules
// are unaffected").
func TestListObservableManifests_ObserveWhen_Approved(t *testing.T) {
	c := makeListObservableCache(t)
	manifest := &modules.ModuleMetadata{
		Name:      "hyperv",
		Version:   "0.1.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
		Kind:      "steward",
		ObserveWhen: []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		},
	}
	b := makeListObservableBundle(manifest, "hash-hyperv-001")
	putApproved(t, c, b)

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "hyperv", got[0].Name)
}

// TestListObservableManifests_NoObserveNoAlwaysPull_Excluded verifies that a
// manifest with neither observe_when nor always_pull is never returned, preserving
// the existing default-off semantics (ADR-024 §2).
func TestListObservableManifests_NoObserveNoAlwaysPull_Excluded(t *testing.T) {
	c := makeListObservableCache(t)
	manifest := &modules.ModuleMetadata{
		Name:      "plain-module",
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
		Kind:      "steward",
	}
	b := makeListObservableBundle(manifest, "hash-plain-001")
	putApproved(t, c, b)

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.NoError(t, err)
	assert.Empty(t, got, "a manifest with no observe_when and always_pull=false must be excluded")
}

// TestListObservableManifests_MixedApprovalStatuses verifies that approval
// filtering and the AlwaysPull/ObserveWhen gate compose correctly: only
// manifests that are both Approved AND eligible are returned.
func TestListObservableManifests_MixedApprovalStatuses(t *testing.T) {
	c := makeListObservableCache(t)

	// Approved + AlwaysPull — must appear.
	osqManifest := &modules.ModuleMetadata{
		Name: "osquery", Version: "0.1.0", Publisher: "cfgms",
		Executors: []string{"steward"}, Kind: "steward", AlwaysPull: true,
	}
	putApproved(t, c, makeListObservableBundle(osqManifest, "hash-osq-mix-001"))

	// Pending + AlwaysPull — must NOT appear (approval gate blocks it).
	osqPendingManifest := &modules.ModuleMetadata{
		Name: "osquery-pending", Version: "0.1.0", Publisher: "cfgms",
		Executors: []string{"steward"}, Kind: "steward", AlwaysPull: true,
	}
	putPending(t, c, makeListObservableBundle(osqPendingManifest, "hash-osq-mix-002"))

	// Approved + ObserveWhen — must appear.
	hypervManifest := &modules.ModuleMetadata{
		Name: "hyperv", Version: "0.1.0", Publisher: "cfgms",
		Executors:   []string{"steward"},
		Kind:        "steward",
		ObserveWhen: []modules.ObservePredicate{{Fact: "hyperv_enabled", Equals: "true"}},
	}
	putApproved(t, c, makeListObservableBundle(hypervManifest, "hash-hyperv-mix-001"))

	// Approved + neither — must NOT appear.
	plainManifest := &modules.ModuleMetadata{
		Name: "plain", Version: "1.0.0", Publisher: "cfgms",
		Executors: []string{"steward"}, Kind: "steward",
	}
	putApproved(t, c, makeListObservableBundle(plainManifest, "hash-plain-mix-001"))

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.NoError(t, err)
	require.Len(t, got, 2, "only the Approved+eligible bundles must be returned")

	names := make(map[string]bool, len(got))
	for _, m := range got {
		names[m.Name] = true
	}
	assert.True(t, names["osquery"], "approved AlwaysPull bundle must appear")
	assert.True(t, names["hyperv"], "approved ObserveWhen bundle must appear")
	assert.False(t, names["osquery-pending"], "pending AlwaysPull bundle must not appear")
	assert.False(t, names["plain"], "plain bundle must not appear")
}

// ---------------------------------------------------------------------------
// ListObservableManifests error paths
// ---------------------------------------------------------------------------

// TestListObservableManifests_CacheListError verifies the error branch of
// ListObservableManifests: when the underlying cache cannot be enumerated, the
// adapter returns no manifests and propagates a wrapped error rather than an
// empty-but-successful result. An empty result would be indistinguishable from
// "no observable modules approved" and would silently disable Tier-2 dispatch.
//
// The failure is induced against a real ModuleCache — no mocks — by replacing
// the cache root directory with a regular file after construction. ModuleCache.List
// stats the root first specifically so this produces the same error on Linux and
// Windows. A merely absent root is not usable here: List treats that as an empty
// cache and returns (nil, nil) by design.
func TestListObservableManifests_CacheListError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "module-cache")
	c := makeListObservableCacheAt(t, root)

	// Replace the cache root directory with a regular file.
	require.NoError(t, os.RemoveAll(root))
	require.NoError(t, os.WriteFile(root, []byte("not a directory"), 0o600))

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.Error(t, err, "an unreadable cache root must surface as an error")
	assert.Nil(t, got, "no manifests may be returned when the cache cannot be listed")
	assert.ErrorContains(t, err, "list module cache", "error must be wrapped with the adapter's context")
}

// TestListObservableManifests_UnreadableBundleSkipped verifies the per-entry
// failure branch: an entry that appears in the cache catalog but whose bundle
// cannot be read is skipped, and the remaining readable entries are still
// returned. One corrupt bundle must not take down observe resolution for the
// whole fleet.
//
// The failure is induced against a real ModuleCache by deleting signatures.yaml
// from one stored bundle. List still reports the entry (it keys off manifest.yaml)
// while Get fails, which is exactly the state this branch exists to handle.
func TestListObservableManifests_UnreadableBundleSkipped(t *testing.T) {
	root := filepath.Join(t.TempDir(), "module-cache")
	c := makeListObservableCacheAt(t, root)

	brokenManifest := &modules.ModuleMetadata{
		Name: "osquery-broken", Version: "0.1.0", Publisher: "cfgms",
		Executors: []string{"steward"}, Kind: "steward", AlwaysPull: true,
	}
	putApproved(t, c, makeListObservableBundle(brokenManifest, "hash-osq-broken-001"))

	healthyManifest := &modules.ModuleMetadata{
		Name: "osquery", Version: "0.1.0", Publisher: "cfgms",
		Executors: []string{"steward"}, Kind: "steward", AlwaysPull: true,
	}
	putApproved(t, c, makeListObservableBundle(healthyManifest, "hash-osq-healthy-001"))

	// Locate the broken bundle's directory by walking the cache rather than
	// reconstructing the content-addressed layout, then remove a file Get
	// requires but List does not.
	removed := 0
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "signatures.yaml" {
			return nil
		}
		if filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path)))) != "osquery-broken" {
			return nil
		}
		if rmErr := os.Remove(path); rmErr != nil {
			return rmErr
		}
		removed++
		return nil
	}))
	require.Equal(t, 1, removed, "test setup must have corrupted exactly one bundle")

	adapter := &moduleManifestAdapter{cache: c}
	got, err := adapter.ListObservableManifests()
	require.NoError(t, err, "a single unreadable bundle must not fail the whole listing")
	require.Len(t, got, 1, "only the readable bundle may be returned")
	assert.Equal(t, "osquery", got[0].Name)
}
