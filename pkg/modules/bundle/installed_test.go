// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// installBundle writes a bundle's manifest and binaries to a fresh directory and
// returns the root plus a Bundle whose ContentHash matches what was written.
func installBundle(t *testing.T, binaries map[string][]byte) (string, *bundle.Bundle) {
	t.Helper()

	root := t.TempDir()
	meta := makeTestMetadata()
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, bundle.ManifestFileName), manifestBytes, 0o600))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "binaries"), 0o700))
	paths := make(map[string]string, len(binaries))
	for key, content := range binaries {
		rel := filepath.ToSlash(filepath.Join("binaries", key))
		require.NoError(t, os.WriteFile(filepath.Join(root, "binaries", key), content, 0o600))
		paths[key] = rel
	}

	hash, err := bundle.ComputeContentHash(binaries, manifestBytes)
	require.NoError(t, err)

	return root, &bundle.Bundle{
		Manifest:    meta,
		Binaries:    paths,
		ContentHash: hash,
	}
}

func TestVerifyInstalledContent_UntamperedBundlePasses(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{
		"linux-amd64": []byte("osquery-binary-linux-amd64"),
		"linux-arm64": []byte("osquery-binary-linux-arm64"),
	})

	require.NoError(t, bundle.VerifyInstalledContent(b, root))
}

// TestVerifyInstalledContent_TamperedBinaryIsRefused proves the re-check catches
// a binary replaced on disk after installation — the bytes no longer reproduce
// the ContentHash that the publisher signature covers.
func TestVerifyInstalledContent_TamperedBinaryIsRefused(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{
		"linux-amd64": []byte("original-osquery-binary"),
	})

	tamperedPath := filepath.Join(root, "binaries", "linux-amd64")
	require.NoError(t, os.WriteFile(tamperedPath, []byte("TAMPERED-binary-injected-post-install"), 0o600))

	err := bundle.VerifyInstalledContent(b, root)
	require.Error(t, err, "a tampered binary must be refused, not accepted best-effort")
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	// The ADR-006 tuple must be in the message so audit logs identify the bundle.
	assert.Contains(t, err.Error(), "cfgms")
	assert.Contains(t, err.Error(), "test-module")
	assert.Contains(t, err.Error(), "1.0.0")
}

// TestVerifyInstalledContent_TamperedManifestIsRefused proves the manifest is
// covered too: an attacker cannot widen a behavioral envelope post-install.
func TestVerifyInstalledContent_TamperedManifestIsRefused(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{
		"linux-amd64": []byte("osquery-binary"),
	})

	require.NoError(t, os.WriteFile(
		filepath.Join(root, bundle.ManifestFileName),
		[]byte("name: test-module\nversion: 1.0.0\npublisher: attacker\n"),
		0o600,
	))

	assert.ErrorIs(t, bundle.VerifyInstalledContent(b, root), bundle.ErrContentHashMismatch)
}

func TestVerifyInstalledContent_MissingBinaryIsRefused(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{
		"linux-amd64": []byte("osquery-binary"),
	})

	require.NoError(t, os.Remove(filepath.Join(root, "binaries", "linux-amd64")))

	err := bundle.VerifyInstalledContent(b, root)
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestComputeInstalledContentHash_MatchesComputeContentHash pins the encoding
// contract: the on-disk re-check produces exactly the value ComputeContentHash
// produced at build time (base64), so no second bespoke digest encoding exists.
func TestComputeInstalledContentHash_MatchesComputeContentHash(t *testing.T) {
	binaries := map[string][]byte{
		"linux-amd64":   []byte("bin-a"),
		"windows-amd64": []byte("bin-b"),
	}
	root, b := installBundle(t, binaries)

	got, err := bundle.ComputeInstalledContentHash(b, root)
	require.NoError(t, err)
	assert.Equal(t, b.ContentHash, got)
	assert.Equal(t, b.ContentAddress().ContentHash, got)
}

func TestComputeInstalledContentHash_NilBundle(t *testing.T) {
	_, err := bundle.ComputeInstalledContentHash(nil, t.TempDir())
	require.Error(t, err)
}

// TestInstalledBinaryPath_RejectsEscapingPath verifies publisher-supplied paths
// cannot reach outside the installation root.
func TestInstalledBinaryPath_RejectsEscapingPath(t *testing.T) {
	root := t.TempDir()

	for _, rel := range []string{"../outside", "binaries/../../outside", ".."} {
		_, err := bundle.InstalledBinaryPath(root, rel)
		require.Error(t, err, "path %q must be rejected", rel)
		assert.ErrorIs(t, err, bundle.ErrBinaryPathEscapesRoot)
	}
}

func TestInstalledBinaryPath_AcceptsContainedPath(t *testing.T) {
	root := t.TempDir()

	got, err := bundle.InstalledBinaryPath(root, "binaries/linux-amd64")
	require.NoError(t, err)

	absRoot, err := filepath.Abs(root)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(absRoot, "binaries", "linux-amd64"), got)
}

func TestVerifyInstalledContent_EscapingBinaryPathIsRefused(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{
		"linux-amd64": []byte("osquery-binary"),
	})
	b.Binaries["linux-amd64"] = "../../etc/shadow"

	err := bundle.VerifyInstalledContent(b, root)
	require.Error(t, err)
	assert.ErrorIs(t, err, bundle.ErrBinaryPathEscapesRoot)
}

// TestVerifyInstalledContent_MissingManifestIsRefused ensures a bundle whose
// manifest was deleted post-install cannot pass verification.
func TestVerifyInstalledContent_MissingManifestIsRefused(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{
		"linux-amd64": []byte("osquery-binary"),
	})

	require.NoError(t, os.Remove(filepath.Join(root, bundle.ManifestFileName)))

	err := bundle.VerifyInstalledContent(b, root)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist), "want a not-exist error, got %v", err)
}

// installFullBundleAt writes a complete installation root at the given path:
// module.yaml, binaries under binaries/, and the BundleSidecarFileName sidecar
// written via bundle.WriteInstalledSidecar — the full shape bundle.ReadInstalled
// expects, as opposed to installBundle above which stops short of the sidecar.
func installFullBundleAt(t *testing.T, root, name string, binaries map[string][]byte, sigs []bundle.BundleSignature) *bundle.Bundle {
	t.Helper()

	require.NoError(t, os.MkdirAll(root, 0o700))

	meta := &modules.ModuleMetadata{
		Name:      name,
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
	}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, bundle.ManifestFileName), manifestBytes, 0o600))

	// Kind is yaml:"-" and is derived from executors by the validating parser, so
	// it is deliberately set only after the manifest bytes are produced: the file
	// on disk carries executors, and the in-memory Bundle carries the Kind that
	// ReadInstalled will derive from it.
	meta.Kind = "steward"

	paths := make(map[string]string, len(binaries))
	for key, content := range binaries {
		name := "bin-" + key
		require.NoError(t, os.WriteFile(filepath.Join(root, name), content, 0o600))
		paths[key] = name
	}

	hash, err := bundle.ComputeContentHash(binaries, manifestBytes)
	require.NoError(t, err)

	b := &bundle.Bundle{
		Manifest:      meta,
		Binaries:      paths,
		BinaryDigests: digestsOf(binaries),
		Signatures:    sigs,
		ContentHash:   hash,
	}
	require.NoError(t, bundle.WriteInstalledSidecar(b, root))

	return b
}

// installFullBundle is installFullBundleAt against a fresh t.TempDir().
func installFullBundle(t *testing.T, name string, binaries map[string][]byte, sigs []bundle.BundleSignature) (string, *bundle.Bundle) {
	t.Helper()
	root := t.TempDir()
	return root, installFullBundleAt(t, root, name, binaries, sigs)
}

// TestReadInstalled_RoundTrip proves an installed bundle round-trips: the
// Bundle reconstructed from disk equals the one that was written, field for
// field, including Signatures and ContentHash — the fields module.yaml alone
// cannot carry.
func TestReadInstalled_RoundTrip(t *testing.T) {
	root, want := installFullBundle(t, "osquery", map[string][]byte{
		ownKey:   []byte("osquery-binary-linux-amd64"),
		otherKey: []byte("osquery-binary-linux-arm64"),
	}, []bundle.BundleSignature{
		{Publisher: "cfgms", Algorithm: "ed25519", Signature: []byte("fake-64-byte-signature-placeholder-not-real-crypto-material!!!")},
	})

	got, err := bundle.ReadInstalled(root)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, want.Manifest, got.Manifest)
	assert.Equal(t, want.Binaries, got.Binaries)
	assert.Equal(t, want.Signatures, got.Signatures)
	assert.Equal(t, want.ContentHash, got.ContentHash)
}

// TestReadInstalled_DerivesManifestKind proves the reader goes through the
// canonical validating parser rather than a bare yaml.Unmarshal: Kind is
// yaml:"-" and is derived from executors at parse time, so a bare unmarshal
// would hand the caller an empty Kind — defeating the ADR-006 module-kind
// confinement boundary for any consumer that gates execution on it.
func TestReadInstalled_DerivesManifestKind(t *testing.T) {
	root, _ := installFullBundle(t, "osquery", map[string][]byte{ownKey: []byte("bin")}, nil)

	got, err := bundle.ReadInstalled(root)
	require.NoError(t, err)
	require.NotNil(t, got.Manifest)
	assert.Equal(t, "steward", got.Manifest.Kind,
		"Kind must be derived from executors by the validating parser, not left empty")
}

// TestReadInstalled_InvalidManifestIsRefused proves module.yaml is treated as
// publisher-supplied untrusted input: a manifest that does not satisfy the
// module contract is refused with ErrManifestInvalid and a nil Bundle, rather
// than half-parsed into a Bundle that later stages would have to re-check.
func TestReadInstalled_InvalidManifestIsRefused(t *testing.T) {
	cases := map[string]string{
		"no executors":       "name: osquery\nversion: 1.0.0\npublisher: cfgms\n",
		"two executors":      "name: osquery\nversion: 1.0.0\npublisher: cfgms\nexecutors: [steward, outpost]\n",
		"unknown executor":   "name: osquery\nversion: 1.0.0\npublisher: cfgms\nexecutors: [kernel]\n",
		"no publisher":       "name: osquery\nversion: 1.0.0\nexecutors: [steward]\n",
		"no name":            "version: 1.0.0\npublisher: cfgms\nexecutors: [steward]\n",
		"non-semver version": "name: osquery\nversion: not-a-version\npublisher: cfgms\nexecutors: [steward]\n",
		"unparsable yaml":    "name: [osquery\n",
	}

	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			root, b := installFullBundle(t, "osquery", map[string][]byte{ownKey: []byte("bin")}, nil)

			manifestBytes := []byte(manifest)
			require.NoError(t, os.WriteFile(filepath.Join(root, bundle.ManifestFileName), manifestBytes, 0o600))

			// Keep the sidecar consistent with the rewritten manifest so the test
			// fails on manifest validation, not on the content-hash re-check.
			hash, err := bundle.ComputeContentHash(map[string][]byte{ownKey: []byte("bin")}, manifestBytes)
			require.NoError(t, err)
			b.ContentHash = hash
			require.NoError(t, bundle.WriteInstalledSidecar(b, root))

			got, err := bundle.ReadInstalled(root)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.ErrorIs(t, err, bundle.ErrManifestInvalid)
		})
	}
}

// TestReadInstalled_SidecarHashIsAnUnsignedLocalAnchor pins the documented limit
// of ReadInstalled's content re-check, so the follow-on steward-wiring story
// cannot mistake it for an integrity gate.
//
// The expected ContentHash comes from bundle.yaml, which is steward-authored and
// never signed. An attacker with write access to the installation root — in
// scope per CFGMS's threat model, since stewards run on hosts that may be
// compromised — rewrites the binary and the sidecar's content_hash together, and
// the bundle reads back clean. What makes the hash trustworthy is publisher
// signature verification (pkg/modules/trust.VerifyBundleSignature via the
// steward trust enforcer's VerifyForLoad), which is the caller's step, not
// ReadInstalled's.
func TestReadInstalled_SidecarHashIsAnUnsignedLocalAnchor(t *testing.T) {
	root, b := installFullBundle(t, "osquery", map[string][]byte{
		ownKey: []byte("original-binary"),
	}, nil)

	// Rewrite the binary AND re-anchor the sidecar to the new bytes, which is
	// exactly what an attacker with write access to root does.
	tampered := []byte("TAMPERED-post-install")
	require.NoError(t, os.WriteFile(filepath.Join(root, "bin-"+ownKey), tampered, 0o600))

	manifestBytes, err := os.ReadFile(filepath.Join(root, bundle.ManifestFileName))
	require.NoError(t, err)
	rehashed, err := bundle.ComputeContentHash(map[string][]byte{ownKey: tampered}, manifestBytes)
	require.NoError(t, err)
	signedHash := b.ContentHash
	b.ContentHash = rehashed
	b.BinaryDigests = digestsOf(map[string][]byte{ownKey: tampered})
	require.NoError(t, bundle.WriteInstalledSidecar(b, root))

	got, err := bundle.ReadInstalled(root)
	require.NoError(t, err, "self-consistent tampering is accepted: the sidecar hash is unsigned")
	require.NotNil(t, got)
	assert.Equal(t, rehashed, got.ContentHash,
		"the returned ContentHash is the recomputed value, which only a publisher signature check can reject")
	assert.NotEqual(t, signedHash, got.ContentHash, "the signed hash no longer matches")
}

// TestReadInstalled_TamperedBinaryIsRefused proves the reader re-verifies
// content before returning: a binary modified on its own — leaving bundle.yaml's
// content_hash untouched — must not come back as a usable Bundle. This is the
// self-consistency half of the property only; see
// TestReadInstalled_SidecarHashIsAnUnsignedLocalAnchor for what it does not
// cover.
func TestReadInstalled_TamperedBinaryIsRefused(t *testing.T) {
	root, _ := installFullBundle(t, "osquery", map[string][]byte{
		ownKey: []byte("original-binary"),
	}, nil)

	require.NoError(t, os.WriteFile(filepath.Join(root, "bin-"+ownKey), []byte("TAMPERED-post-install"), 0o600))

	got, err := bundle.ReadInstalled(root)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
}

// TestReadInstalled_EscapingBinaryPathIsRefused proves a sidecar's Binaries map
// stays untrusted input on the read path exactly as it is on the write path:
// a publisher-supplied path that escapes root must be refused, not resolved.
func TestReadInstalled_EscapingBinaryPathIsRefused(t *testing.T) {
	root, b := installFullBundle(t, "osquery", map[string][]byte{
		ownKey: []byte("bin"),
	}, nil)

	b.Binaries[ownKey] = "../../etc/shadow"
	require.NoError(t, bundle.WriteInstalledSidecar(b, root))

	got, err := bundle.ReadInstalled(root)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, bundle.ErrBinaryPathEscapesRoot)
}

// TestReadInstalled_MissingSidecarIsRefused proves a missing sidecar returns a
// distinct, file-naming error rather than a partially populated Bundle.
func TestReadInstalled_MissingSidecarIsRefused(t *testing.T) {
	root := t.TempDir()
	meta := &modules.ModuleMetadata{Name: "osquery", Version: "1.0.0", Publisher: "cfgms", Executors: []string{"steward"}}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, bundle.ManifestFileName), manifestBytes, 0o600))

	got, err := bundle.ReadInstalled(root)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, bundle.ErrSidecarMissing)
	assert.Contains(t, err.Error(), bundle.BundleSidecarFileName)
}

// TestReadInstalled_MalformedSidecarIsRefused proves an unparsable sidecar
// returns a distinct, file-naming error rather than a partially populated
// Bundle.
func TestReadInstalled_MalformedSidecarIsRefused(t *testing.T) {
	root, _ := installFullBundle(t, "osquery", map[string][]byte{ownKey: []byte("bin")}, nil)

	require.NoError(t, os.WriteFile(filepath.Join(root, bundle.BundleSidecarFileName), []byte("not: [valid: yaml"), 0o600))

	got, err := bundle.ReadInstalled(root)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, bundle.ErrSidecarMalformed)
	assert.Contains(t, err.Error(), bundle.BundleSidecarFileName)
}

// TestReadInstalled_MissingManifestIsRefused proves a missing module.yaml
// returns a distinct, file-naming error rather than a partially populated
// Bundle.
func TestReadInstalled_MissingManifestIsRefused(t *testing.T) {
	root, _ := installFullBundle(t, "osquery", map[string][]byte{ownKey: []byte("bin")}, nil)

	require.NoError(t, os.Remove(filepath.Join(root, bundle.ManifestFileName)))

	got, err := bundle.ReadInstalled(root)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, bundle.ErrManifestMissing)
	assert.Contains(t, err.Error(), bundle.ManifestFileName)
}

// TestDiscoverInstalled_ReturnsSetKeyedByModuleName proves discovery enumerates
// every immediate subdirectory and keys the result by the manifest's module
// name, carrying each bundle's installation root alongside it.
func TestDiscoverInstalled_ReturnsSetKeyedByModuleName(t *testing.T) {
	parent := t.TempDir()

	osqueryRoot := filepath.Join(parent, "osquery")
	installFullBundleAt(t, osqueryRoot, "osquery", map[string][]byte{ownKey: []byte("osquery-bin")}, nil)

	firewallRoot := filepath.Join(parent, "firewall")
	installFullBundleAt(t, firewallRoot, "firewall", map[string][]byte{ownKey: []byte("firewall-bin")}, nil)

	got, err := bundle.DiscoverInstalled(parent)
	require.NoError(t, err)
	require.Len(t, got, 2)

	require.Contains(t, got, "osquery")
	assert.Equal(t, osqueryRoot, got["osquery"].Root)
	assert.Equal(t, "osquery", got["osquery"].Bundle.Manifest.Name)

	require.Contains(t, got, "firewall")
	assert.Equal(t, firewallRoot, got["firewall"].Root)
	assert.Equal(t, "firewall", got["firewall"].Bundle.Manifest.Name)
}

// TestDiscoverInstalled_MixedGoodAndBadIsSurfaced proves one unreadable
// installation root is skipped, not silently dropped: its error is surfaced to
// the caller while the good bundles are still returned.
func TestDiscoverInstalled_MixedGoodAndBadIsSurfaced(t *testing.T) {
	parent := t.TempDir()

	goodRoot := filepath.Join(parent, "osquery")
	installFullBundleAt(t, goodRoot, "osquery", map[string][]byte{ownKey: []byte("osquery-bin")}, nil)

	badRoot := filepath.Join(parent, "broken")
	require.NoError(t, os.MkdirAll(badRoot, 0o700))

	got, err := bundle.DiscoverInstalled(parent)
	require.Error(t, err, "a bad subdirectory must surface an error, not be silently dropped")
	assert.ErrorIs(t, err, bundle.ErrManifestMissing)
	assert.Contains(t, err.Error(), badRoot)

	require.Len(t, got, 1, "the good bundle must still be returned despite the bad one")
	require.Contains(t, got, "osquery")
	assert.Equal(t, goodRoot, got["osquery"].Root)
}

// TestDiscoverInstalled_DuplicateModuleNameIsHardError proves two installation
// roots declaring the same module name are refused as a hard error naming both
// roots, rather than the second silently overwriting the first in the map.
func TestDiscoverInstalled_DuplicateModuleNameIsHardError(t *testing.T) {
	parent := t.TempDir()

	firstRoot := filepath.Join(parent, "first")
	installFullBundleAt(t, firstRoot, "osquery", map[string][]byte{ownKey: []byte("bin-1")}, nil)

	secondRoot := filepath.Join(parent, "second")
	installFullBundleAt(t, secondRoot, "osquery", map[string][]byte{ownKey: []byte("bin-2")}, nil)

	got, err := bundle.DiscoverInstalled(parent)
	require.Error(t, err)
	assert.ErrorIs(t, err, bundle.ErrDuplicateModuleName)
	assert.Contains(t, err.Error(), firstRoot)
	assert.Contains(t, err.Error(), secondRoot)

	require.Len(t, got, 1, "the second root must not overwrite the first via a last-one-wins map write")
	require.Contains(t, got, "osquery")
	assert.Equal(t, firstRoot, got["osquery"].Root)
}

func TestDiscoverInstalled_NonexistentDirectory(t *testing.T) {
	_, err := bundle.DiscoverInstalled(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
}

// ownKey is the running platform's bundle key; otherKey is a different one.
var (
	ownKey   = runtime.GOOS + "-" + runtime.GOARCH
	otherKey = func() string {
		if ownKey == "darwin-arm64" {
			return "linux-amd64"
		}
		return "darwin-arm64"
	}()
)

func digestsOf(binaries map[string][]byte) map[string]string {
	out := make(map[string]string, len(binaries))
	for k, v := range binaries {
		sum := sha256.Sum256(v)
		out[k] = hex.EncodeToString(sum[:])
	}
	return out
}

// ReadInstalledMetadata returns the metadata of a full root without opening any
// binary: an altered binary does not fail it, an altered manifest does.
func TestReadInstalledMetadata_ReadsNoBinaryBytes(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Platforms: []string{"linux-amd64", "windows-amd64"}})
	root := filepath.Join(t.TempDir(), "root")
	sb.WriteRoot(t, root, bundle.WriteOptions{})

	got, err := bundle.ReadInstalledMetadata(root, bundle.ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, sb.ContentHash, got.ContentHash)
	assert.Equal(t, sb.BinaryDigests, got.BinaryDigests)
	assert.Equal(t, sb.Signatures, got.Signatures)
	assert.Len(t, got.Binaries, 2)
	assert.Empty(t, got.BinaryContent)
	assert.Empty(t, got.ManifestBytes)

	require.NoError(t, os.WriteFile(filepath.Join(root, sb.Binaries["linux-amd64"]), []byte("altered"), 0o755))
	_, err = bundle.ReadInstalledMetadata(root, bundle.ReadOptions{})
	require.NoError(t, err, "metadata reads never open a binary")
	_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)

	require.NoError(t, os.WriteFile(filepath.Join(root, bundle.ManifestFileName), []byte("name: x\n"), 0o644))
	_, err = bundle.ReadInstalledMetadata(root, bundle.ReadOptions{})
	assert.Error(t, err)
}

func TestReadInstalled_SetsInstallRoot(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{})
	root := filepath.Join(t.TempDir(), "mod")
	sb.WriteRoot(t, root, bundle.WriteOptions{})

	b, err := bundle.ReadInstalled(root)
	require.NoError(t, err)
	assert.Equal(t, root, b.InstallRoot)

	found, err := bundle.DiscoverInstalled(filepath.Dir(root))
	require.NoError(t, err)
	require.Len(t, found, 1)
	for _, ib := range found {
		assert.Equal(t, root, ib.Bundle.InstallRoot)
	}
}

func TestVerifyInstalled_DetectsChangesAndPins(t *testing.T) {
	platform := runtime.GOOS + "-" + runtime.GOARCH
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{})
	root := filepath.Join(t.TempDir(), "mod")
	sb.WriteRoot(t, root, bundle.WriteOptions{})

	require.NoError(t, bundle.VerifyInstalled(root, platform))
	require.NoError(t, bundle.VerifyInstalledPinned(root, platform, sb.ContentHash, sb.Binaries[platform]))
	assert.ErrorIs(t, bundle.VerifyInstalledPinned(root, platform, "", "elsewhere"), bundle.ErrContentHashMismatch)

	err := bundle.VerifyInstalledPinned(root, platform, "some-other-hash", "")
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	assert.Error(t, bundle.VerifyInstalled(root, ""))

	require.NoError(t, os.WriteFile(filepath.Join(root, "pad"), []byte("x"), 0o644))
	assert.ErrorIs(t, bundle.VerifyInstalled(root, platform), bundle.ErrUnexpectedEntry)
	require.NoError(t, os.Remove(filepath.Join(root, "pad")))

	bin := filepath.Join(root, testutil.BinaryFileName("testmod", platform))
	require.NoError(t, os.WriteFile(bin, []byte("changed"), 0o755))
	assert.ErrorIs(t, bundle.VerifyInstalled(root, platform), bundle.ErrContentHashMismatch)
}

// TestVerifyInstalled_StreamsLargeBinary hashes a binary far larger than the
// bundle package's in-memory metadata bound and checks the verification
// allocates a small, size-independent amount rather than buffering the file.
func TestVerifyInstalled_StreamsLargeBinary(t *testing.T) {
	platform := runtime.GOOS + "-" + runtime.GOARCH
	const size = 48 << 20 // well above the 1 MiB in-memory limit used for metadata files
	big := make([]byte, size)
	for i := range big {
		big[i] = byte(i * 7)
	}
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{BinaryContent: map[string][]byte{platform: big}})
	root := filepath.Join(t.TempDir(), "mod")
	sb.WriteRoot(t, root, bundle.WriteOptions{})

	// TotalAlloc is cumulative, so the before/after delta counts only the
	// bytes allocated by VerifyInstalled regardless of what is still live.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	require.NoError(t, bundle.VerifyInstalled(root, platform))
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	assert.Less(t, allocated, uint64(size/4),
		"verifying a %d byte binary allocated %d bytes: the binary must be streamed, not read into memory", size, allocated)
}
