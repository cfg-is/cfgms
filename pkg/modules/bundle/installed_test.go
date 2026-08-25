// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
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
