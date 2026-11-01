// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cache_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestBundle builds a signed payload bundle through the production
// assemble/sign path. Distinct (name, version, tag) values give distinct bytes
// and therefore distinct content hashes.
func makeTestBundle(t *testing.T, publisher, name, version, tag string) *bundle.Bundle {
	t.Helper()
	return testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher:     publisher,
		Name:          name,
		Version:       version,
		Platforms:     []string{"linux-amd64", "windows-amd64"},
		BinaryContent: map[string][]byte{"linux-amd64": []byte("linux " + tag), "windows-amd64": []byte("windows " + tag)},
	}).Bundle
}

func makeTestCache(t *testing.T) *cache.ModuleCache {
	t.Helper()
	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	return c
}

// [REQUIRED TEST] Put then GetPayload returns the identical payload; Get returns metadata only.
func TestModuleCache_PutGet_RoundTrip(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")

	require.NoError(t, c.Put(b))

	full, err := c.GetPayload(b.ContentAddress(), "")
	require.NoError(t, err)
	assert.Equal(t, b.ManifestBytes, full.ManifestBytes)
	assert.Equal(t, b.BinaryContent, full.BinaryContent)
	assert.Equal(t, b.BinaryDigests, full.BinaryDigests)
	assert.Equal(t, b.Signatures, full.Signatures)
	assert.Equal(t, b.ContentHash, full.ContentHash)

	got, err := c.Get(b.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, b.Manifest.Name, got.Manifest.Name)
	assert.Equal(t, b.Manifest.Version, got.Manifest.Version)
	assert.Equal(t, b.Manifest.Publisher, got.Manifest.Publisher)
	assert.Equal(t, b.ContentHash, got.ContentHash)
	assert.Equal(t, b.BinaryDigests, got.BinaryDigests)
	assert.Equal(t, b.Signatures, got.Signatures)
	require.Len(t, got.Binaries, 2)
	for k, p := range got.Binaries {
		assert.True(t, filepath.IsAbs(p))
		assert.Equal(t, b.Binaries[k], filepath.Base(p))
		assert.FileExists(t, p)
	}
	assert.Empty(t, got.BinaryContent, "Get must not return binary bytes")
	assert.Empty(t, got.ManifestBytes)
}

// entryRoot returns the stored installation root of b under the cache at root.
func entryRoot(t *testing.T, root string, b *bundle.Bundle) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, b.Manifest.Publisher, b.Manifest.Name, b.Manifest.Version, "*", "root"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	return matches[0]
}

func makeCacheAt(t *testing.T) (*cache.ModuleCache, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "module-cache")
	c, err := cache.New(root)
	require.NoError(t, err)
	return c, root
}

// Put refuses a bundle without payload, a tampered binary and a wrong hash, and
// leaves no directory and no approval record behind.
func TestModuleCache_Put_RefusesInvalidPayload(t *testing.T) {
	good := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")

	noPayload := *good
	noPayload.ManifestBytes = nil
	noPayload.BinaryContent = nil

	partial := *good
	partial.BinaryContent = map[string][]byte{"linux-amd64": good.BinaryContent["linux-amd64"]}

	badBinary := *good
	badBinary.BinaryContent = map[string][]byte{
		"linux-amd64":   []byte("tampered"),
		"windows-amd64": good.BinaryContent["windows-amd64"],
	}

	badHash := *good
	badHash.ContentHash = makeTestBundle(t, "cfgms", "other", "1.0.0", "b").ContentHash

	badDigest := *good
	badDigest.BinaryDigests = map[string]string{"linux-amd64": good.BinaryDigests["linux-amd64"], "windows-amd64": good.BinaryDigests["linux-amd64"]}

	extra := *good
	extra.BinaryContent = map[string][]byte{"linux-amd64": good.BinaryContent["linux-amd64"], "windows-amd64": good.BinaryContent["windows-amd64"], "darwin-arm64": []byte("x")}

	cases := []struct {
		name string
		b    *bundle.Bundle
		is   error
	}{
		{"no payload", &noPayload, cache.ErrBundlePayloadMissing},
		{"digest without binary", &partial, cache.ErrBundlePayloadMissing},
		{"binary differs from digest", &badBinary, bundle.ErrContentHashMismatch},
		{"hash mismatch", &badHash, bundle.ErrContentHashMismatch},
		{"digest differs", &badDigest, bundle.ErrContentHashMismatch},
		{"binary without digest", &extra, bundle.ErrDigestListInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := makeCacheAt(t)
			err := c.Put(tc.b)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.is)

			ents, readErr := os.ReadDir(root)
			require.NoError(t, readErr)
			assert.Empty(t, ents, "a refused Put must leave nothing in the cache root")
			list, listErr := c.List()
			require.NoError(t, listErr)
			assert.Empty(t, list)
			_, statusErr := c.GetApprovalStatus(tc.b.ContentAddress())
			assert.Error(t, statusErr)
		})
	}
}

// [REQUIRED TEST] GetPayload fails with ErrContentHashMismatch when a stored
// binary was modified, for both the full and the single-platform read.
func TestModuleCache_GetPayload_DetectsAlteredBinary(t *testing.T) {
	c, root := makeCacheAt(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")
	require.NoError(t, c.Put(b))

	path := filepath.Join(entryRoot(t, root, b), b.Binaries["linux-amd64"])
	require.NoError(t, os.WriteFile(path, []byte("altered on disk"), 0o755))

	_, err := c.GetPayload(b.ContentAddress(), "")
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	_, err = c.GetPayload(b.ContentAddress(), "linux-amd64")
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)

	// The unaltered platform still verifies on its own.
	got, err := c.GetPayload(b.ContentAddress(), "windows-amd64")
	require.NoError(t, err)
	assert.Equal(t, b.BinaryContent["windows-amd64"], got.BinaryContent["windows-amd64"])
}

// [REQUIRED TEST] A single-platform read returns only that binary plus the full
// digest list, and the recomputed hash equals the signed hash.
func TestModuleCache_GetPayload_SinglePlatform(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")
	require.NoError(t, c.Put(b))

	got, err := c.GetPayload(b.ContentAddress(), "linux-amd64")
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{"linux-amd64": b.BinaryContent["linux-amd64"]}, got.BinaryContent)
	assert.Equal(t, b.BinaryDigests, got.BinaryDigests)
	assert.Equal(t, b.ManifestBytes, got.ManifestBytes)
	assert.Equal(t, b.ContentHash, got.ContentHash)

	_, err = c.GetPayload(b.ContentAddress(), "darwin-arm64")
	assert.Error(t, err)

	_, err = c.GetPayload(bundle.ContentAddress{Publisher: "cfgms", Name: "hyperv", Version: "0.2.1", ContentHash: "nope"}, "")
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// [REQUIRED TEST] Immutability: a second valid signed bundle for the same
// publisher/name/version is refused, concurrently or not, and the first entry
// is unchanged and still approved.
func TestModuleCache_Put_ImmutableUnderConcurrency(t *testing.T) {
	c := makeTestCache(t)
	first := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "first")
	second := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "second")
	require.NotEqual(t, first.ContentHash, second.ContentHash)

	require.NoError(t, c.Put(first))
	require.NoError(t, c.SetApprovalStatus(first.ContentAddress(), cache.ApprovalStatusApproved))

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				errs[i] = c.Put(second)
			} else {
				errs[i] = c.Put(first)
			}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if i%2 == 0 {
			assert.ErrorIs(t, err, cache.ErrContentAddressConflict)
		} else {
			assert.NoError(t, err)
		}
	}

	status, err := c.GetApprovalStatus(first.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)
	got, err := c.GetPayload(first.ContentAddress(), "")
	require.NoError(t, err)
	assert.Equal(t, first.BinaryContent, got.BinaryContent)
	_, err = c.Get(second.ContentAddress())
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
	list, err := c.List()
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

// [REQUIRED TEST] Signatures are stored and returned verbatim and still verify.
func TestModuleCache_Signatures_StoredVerbatim(t *testing.T) {
	c := makeTestCache(t)
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: "acme-corp", Name: "mod", Platforms: []string{"linux-amd64"}})
	require.NoError(t, c.Put(sb.Bundle))

	got, err := c.GetPayload(sb.ContentAddress(), "")
	require.NoError(t, err)
	require.Len(t, got.Signatures, 1)
	assert.Equal(t, sb.Signatures, got.Signatures)
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{Name: "acme-corp", PublicKey: sb.PublicKey, Algorithm: "ed25519"}))
	require.NoError(t, trust.VerifyBundleSignature(got, got.Signatures[0], store))
}

// [REQUIRED TEST] List skips a pre-change entry directory without error.
func TestModuleCache_List_SkipsPreChangeEntry(t *testing.T) {
	c, root := makeCacheAt(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")
	require.NoError(t, c.Put(b))

	old := filepath.Join(root, "cfgms", "old", "1.0.0", "oldhash")
	require.NoError(t, os.MkdirAll(old, 0o750))
	for _, f := range []string{"manifest.yaml", "signatures.yaml", "binaries.yaml", "content_hash.txt", "approval.yaml"} {
		require.NoError(t, os.WriteFile(filepath.Join(old, f), []byte("x: y\n"), 0o640))
	}

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, b.ContentAddress(), entries[0].Addr)

	_, err = c.Get(bundle.ContentAddress{Publisher: "cfgms", Name: "old", Version: "1.0.0", ContentHash: "oldhash"})
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// [REQUIRED TEST] Put of identical bundle (same content hash) is idempotent (no error, no duplicate).
func TestModuleCache_Put_Idempotent(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "abc123hash")

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
	b1 := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "hash-original")
	b2 := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "hash-different")
	require.NotEqual(t, b1.ContentHash, b2.ContentHash)

	require.NoError(t, c.Put(b1))
	err := c.Put(b2)
	assert.ErrorIs(t, err, cache.ErrContentAddressConflict)
}

// [REQUIRED TEST] TestModuleCache_Put_RefusesIdentityDisagreement is the mirror
// of TestModuleCache_Put_ConflictDifferentHash: the SAME content hash claimed
// under a DIFFERENT (publisher/name/version) identity. A publisher signature is
// made over the content hash alone, so replaying a previously-verified hash
// under a forged Name/Version must be refused rather than cached under the
// manifest's claimed identity (Issue #4341).
func TestModuleCache_Put_RefusesIdentityDisagreement(t *testing.T) {
	c, root := makeCacheAt(t)
	genuine := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "shared")
	require.NoError(t, c.Put(genuine))

	// A verified payload can no longer claim another identity for its hash (the
	// hash covers the manifest bytes), so the reverse index is the second line of
	// defence: record this hash under a different identity, as a replay would
	// have bound it, and the genuine bundle for the new location is refused.
	replayed := makeTestBundle(t, "cfgms", "not-hyperv", "0.2.1", "shared")
	idx := filepath.Join(root, ".cfgms-hash-index")
	require.NoError(t, os.MkdirAll(idx, 0o750))
	name := strings.NewReplacer("/", "_", "+", "-", "=", "").Replace(replayed.ContentHash) + ".txt"
	require.NoError(t, os.WriteFile(filepath.Join(idx, name), []byte(genuine.ContentAddress().IdentityKey()), 0o640))

	err := c.Put(replayed)
	require.Error(t, err)
	assert.ErrorIs(t, err, cache.ErrContentHashIdentityConflict)

	_, getErr := c.Get(replayed.ContentAddress())
	assert.ErrorIs(t, getErr, cache.ErrBundleNotFound)

	got, err := c.Get(genuine.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, genuine.Manifest.Name, got.Manifest.Name)
}

// A manifest whose bytes name another identity than the bundle claims is refused.
func TestModuleCache_Put_RefusesManifestIdentityMismatch(t *testing.T) {
	c := makeTestCache(t)
	b := *makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")
	meta := *b.Manifest
	meta.Version = "9.9.9"
	b.Manifest = &meta
	require.Error(t, c.Put(&b))
	list, err := c.List()
	require.NoError(t, err)
	assert.Empty(t, list)
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

	b1 := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "hash1")
	b2 := makeTestBundle(t, "cfgms", "file", "1.0.0", "hash2")
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
	require.NoError(t, c.Put(makeTestBundle(t, "cfgms", "firewall", "1.0.0", "hash1")))

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
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "abc123hash")
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

		valid := makeTestBundle(t, "cfgms", "mod", "1.0.0", "a")
		meta := *valid.Manifest
		meta.Name, meta.Version, meta.Publisher = tc.name, tc.version, tc.publisher
		b := *valid
		b.Manifest = &meta
		b.ContentHash = tc.contentHash
		putErr := c.Put(&b)
		assert.Error(t, putErr, "Put must reject addr %+v", addr)
	}
}

// TestModuleCache_List_ShowsApprovedStatus verifies List reflects updated status.
func TestModuleCache_List_ShowsApprovedStatus(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "hash1")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, cache.ApprovalStatusApproved, entries[0].Status)
}

// TestModuleCache_CompareAndSetApprovalStatus_LocalMode verifies the local
// (no store wired) CAS path succeeds on a match and fails on a mismatch,
// without touching the stored status.
func TestModuleCache_CompareAndSetApprovalStatus_LocalMode(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "abc123hash")
	require.NoError(t, c.Put(b))
	addr := b.ContentAddress()

	ok, err := c.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusApproved)
	require.NoError(t, err)
	assert.True(t, ok)

	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)

	// A second CAS against the now-stale "pending" expectation must be refused.
	ok, err = c.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusRejected)
	require.NoError(t, err)
	assert.False(t, ok, "a CAS against a stale expected status must not overwrite the current one")

	status, err = c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status, "the mismatched CAS must leave the stored status untouched")
}

// TestModuleCache_CompareAndSetApprovalStatus_NotFound returns ErrBundleNotFound
// for a missing bundle.
func TestModuleCache_CompareAndSetApprovalStatus_NotFound(t *testing.T) {
	c := makeTestCache(t)
	addr := bundle.ContentAddress{Publisher: "cfgms", Name: "missing", Version: "1.0.0", ContentHash: "nohash"}
	_, err := c.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusApproved)
	assert.ErrorIs(t, err, cache.ErrBundleNotFound)
}

// TestModuleCache_SetApprovalStore_DelegatesReadsAndWrites verifies that once a
// ModuleApprovalStore is wired via SetApprovalStore, Get/Set/CompareAndSet all
// delegate to it instead of the local approval.yaml file, and List() reflects
// the store's status.
func TestModuleCache_SetApprovalStore_DelegatesReadsAndWrites(t *testing.T) {
	c := makeTestCache(t)
	store := pkgtesting.SetupTestModuleApprovalStore()
	c.SetApprovalStore(store)

	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "abc123hash")
	require.NoError(t, c.Put(b))
	addr := b.ContentAddress()

	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusPending, status, "Put must seed the wired store, not just the local file")

	require.NoError(t, c.SetApprovalStatus(addr, cache.ApprovalStatusApproved))
	status, err = c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, cache.ApprovalStatusApproved, entries[0].Status, "List must reflect the wired store's status, not a stale local file")
}

// TestModuleCache_SharedApprovalStore_ConcurrentApproveRejectConverges simulates
// two controller nodes (two independent ModuleCache instances, each with its own
// local bundle-content directory) sharing one ModuleApprovalStore, racing an
// approve against a reject for the same bundle. Exactly one must win — this is
// the split-brain race Issue #3886 exists to close. Run with -race.
func TestModuleCache_SharedApprovalStore_ConcurrentApproveRejectConverges(t *testing.T) {
	sharedStore := pkgtesting.SetupTestModuleApprovalStore()

	nodeA := makeTestCache(t)
	nodeA.SetApprovalStore(sharedStore)
	nodeB := makeTestCache(t)
	nodeB.SetApprovalStore(sharedStore)

	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "shared-hash")
	// Both nodes need the bundle content locally (out of scope for this story,
	// but required for the local ErrBundleNotFound existence check to pass on
	// each node) — Put is deterministic, so both calls produce identical content.
	require.NoError(t, nodeA.Put(b))
	require.NoError(t, nodeB.Put(b))
	addr := b.ContentAddress()

	type casResult struct {
		ok  bool
		err error
	}
	var wg sync.WaitGroup
	results := make(chan casResult, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		ok, err := nodeA.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusApproved)
		results <- casResult{ok, err}
	}()
	go func() {
		defer wg.Done()
		ok, err := nodeB.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusRejected)
		results <- casResult{ok, err}
	}()
	wg.Wait()
	close(results)

	successes := 0
	for r := range results {
		require.NoError(t, r.err)
		if r.ok {
			successes++
		}
	}
	assert.Equal(t, 1, successes, "exactly one of the concurrent approve/reject decisions must win across the two simulated nodes")

	statusA, err := nodeA.GetApprovalStatus(addr)
	require.NoError(t, err)
	statusB, err := nodeB.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, statusA, statusB, "both nodes must observe the same winning status through the shared store")
}

// TestModuleCache_PutManifestContentPreserved verifies the manifest bytes are stored verbatim.
func TestModuleCache_PutManifestContentPreserved(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "a")
	require.NoError(t, c.Put(b))

	got, err := c.Get(b.ContentAddress())
	require.NoError(t, err)
	assert.Equal(t, "test module", got.Manifest.Description)
	assert.Equal(t, b.ContentHash, got.ContentHash)
	full, err := c.GetPayload(b.ContentAddress(), "")
	require.NoError(t, err)
	assert.Equal(t, b.ManifestBytes, full.ManifestBytes)
}

// TestModuleCache_PutDoesNotResetDecisionInSharedStore pins ingestion's
// insert-if-absent contract at the cache level. Bundle content stays node-local
// while approval status is shared, so the same bundle is Put on every node that
// resolves it — and the store is authoritative for all of them. An unconditional
// "seed as pending" write on the second node would therefore erase the rejection
// the first node's operator recorded, on every node at once.
func TestModuleCache_PutDoesNotResetDecisionInSharedStore(t *testing.T) {
	sharedStore := pkgtesting.SetupTestModuleApprovalStore()

	nodeA := makeTestCache(t)
	nodeA.SetApprovalStore(sharedStore)
	nodeB := makeTestCache(t)
	nodeB.SetApprovalStore(sharedStore)

	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "no-clobber-hash")
	require.NoError(t, nodeA.Put(b))
	addr := b.ContentAddress()

	ok, err := nodeA.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusRejected)
	require.NoError(t, err)
	require.True(t, ok)

	// Node B ingests the same bundle for the first time: its local cache has no
	// copy of the content, but the decision is already made.
	require.NoError(t, nodeB.Put(b))

	statusB, err := nodeB.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, statusB,
		"ingestion on a second node must not reset the shared status to pending")

	statusA, err := nodeA.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, statusA,
		"the rejecting node must keep enforcing its decision after a peer re-ingests the bundle")

	// A rejected bundle must also stay undecidable: the pending → approved
	// transition an auto-approval would make has nothing to act on.
	ok, err = nodeB.CompareAndSetApprovalStatus(addr, cache.ApprovalStatusPending, cache.ApprovalStatusApproved)
	require.NoError(t, err)
	assert.False(t, ok, "a rejected bundle must not be approvable from a peer node without a fresh decision")
}

// TestModuleCache_PutDoesNotResetLocalDecision is the single-node form: a
// rejected bundle re-ingested by a later cfg push keeps its status.
func TestModuleCache_PutDoesNotResetLocalDecision(t *testing.T) {
	c := makeTestCache(t)

	b := makeTestBundle(t, "cfgms", "hyperv", "0.2.1", "no-clobber-local-hash")
	require.NoError(t, c.Put(b))
	addr := b.ContentAddress()
	require.NoError(t, c.SetApprovalStatus(addr, cache.ApprovalStatusRejected))

	require.NoError(t, c.Put(b))

	status, err := c.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, status,
		"re-ingesting cached content must not reset its approval status")
}

// TestModuleCache_HasSharedApprovalStore reports which backend approval status
// lives in. The REST approve/reject handlers key their leadership gate on it, so
// a wrong answer either blocks decisions on a healthy cluster or lets every node
// decide against its own node-local files.
func TestModuleCache_HasSharedApprovalStore(t *testing.T) {
	c := makeTestCache(t)
	assert.False(t, c.HasSharedApprovalStore(), "a cache with no store wired is node-local")

	c.SetApprovalStore(pkgtesting.SetupTestModuleApprovalStore())
	assert.True(t, c.HasSharedApprovalStore(), "a wired cache reports cluster-visible status")
}

// Lookup resolves the single stored content address of a publisher/name/version,
// and reports ErrBundleNotFound for an unknown triple or an unsafe component.
func TestModuleCache_Lookup(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle(t, "acme-corp", "widget", "1.0.0", "a")
	require.NoError(t, c.Put(b))

	addr, err := c.Lookup("acme-corp", "widget", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, b.ContentAddress(), addr)

	for _, tc := range [][3]string{
		{"acme-corp", "widget", "1.0.1"},
		{"acme-corp", "other", "1.0.0"},
		{"other", "widget", "1.0.0"},
	} {
		_, err := c.Lookup(tc[0], tc[1], tc[2])
		assert.ErrorIs(t, err, cache.ErrBundleNotFound, "%v", tc)
	}
	for _, tc := range [][3]string{
		{"..", "widget", "1.0.0"},
		{"acme-corp", "a/b", "1.0.0"},
		{"acme-corp", "widget", ""},
		{".cfgms-hash-index", "widget", "1.0.0"},
	} {
		_, err := c.Lookup(tc[0], tc[1], tc[2])
		assert.Error(t, err, "%v", tc)
	}

	// A second, different bundle for the same triple is refused at ingest, so
	// the lookup keeps returning the original.
	other := makeTestBundle(t, "acme-corp", "widget", "1.0.0", "b")
	require.ErrorIs(t, c.Put(other), cache.ErrContentAddressConflict)
	addr, err = c.Lookup("acme-corp", "widget", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, b.ContentHash, addr.ContentHash)
}
