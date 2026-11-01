// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/testutil"
)

func trustFor(t *testing.T, publisher string, pub ed25519.PublicKey) trust.TrustStore {
	t.Helper()
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{Name: publisher, PublicKey: pub, Algorithm: "ed25519"}))
	return store
}

// twoPlatform builds a signed acme-corp bundle holding the running platform and one other.
func twoPlatform(t *testing.T) *testutil.SignedBundle {
	t.Helper()
	return testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher: "acme-corp", Name: "widget", Platforms: []string{ownKey, otherKey},
	})
}

// editSidecar rewrites root's bundle.yaml through fn.
func editSidecar(t *testing.T, root string, fn func(m map[string]any)) {
	t.Helper()
	path := filepath.Join(root, bundle.BundleSidecarFileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	m := map[string]any{}
	require.NoError(t, yaml.Unmarshal(raw, &m))
	fn(m)
	out, err := yaml.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, out, 0o600))
}

func flipFirstByte(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	data[0] ^= 0xff
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func newSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		// Creating a symlink needs a privilege some Windows runners lack; the
		// refusal is exercised on every other platform.
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		require.NoError(t, err)
	}
}

func TestRoundTrip_AssembleSignWriteReadVerifies(t *testing.T) {
	sb := twoPlatform(t)
	root := filepath.Join(t.TempDir(), "widget")
	sb.WriteRoot(t, root, bundle.WriteOptions{})

	got, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
	require.NoError(t, err)

	assert.Equal(t, sb.ContentHash, got.ContentHash)
	assert.Equal(t, sb.ManifestBytes, got.ManifestBytes)
	assert.Equal(t, sb.BinaryContent, got.BinaryContent)
	assert.Equal(t, sb.BinaryDigests, got.BinaryDigests)
	assert.Len(t, got.Binaries, 2)
	require.Len(t, got.Signatures, 1)
	assert.Equal(t, "acme-corp", got.Signatures[0].Publisher)
	require.NoError(t, trust.VerifyBundleSignature(got, got.Signatures[0], trustFor(t, "acme-corp", sb.PublicKey)))
	require.NoError(t, bundle.VerifyInstalledContent(got, root))

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(root, got.Binaries[ownKey]))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	}
}

func TestPayloadFieldsAreNotSerialized(t *testing.T) {
	sb := twoPlatform(t)
	out, err := yaml.Marshal(sb.Bundle)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "manifestbytes")
	assert.NotContains(t, string(out), "binarycontent")
}

func TestOwnPlatformMode(t *testing.T) {
	sb := twoPlatform(t)
	write := func(t *testing.T) string {
		root := filepath.Join(t.TempDir(), "widget")
		sb.WriteRoot(t, root, bundle.WriteOptions{Platform: ownKey})
		return root
	}
	own := bundle.ReadOptions{Platform: ownKey}

	t.Run("holds one binary and verifies", func(t *testing.T) {
		root := write(t)
		entries, err := os.ReadDir(root)
		require.NoError(t, err)
		assert.Len(t, entries, 3, "module.yaml, bundle.yaml and one binary")

		got, err := bundle.ReadInstalledPayload(root, own)
		require.NoError(t, err)
		assert.Equal(t, sb.ContentHash, got.ContentHash, "recomputed hash equals the signed one")
		assert.Len(t, got.Binaries, 1)
		assert.Len(t, got.BinaryDigests, 2, "the sidecar records the full digest list")
		assert.Len(t, got.BinaryContent, 1)
		require.NoError(t, trust.VerifyBundleSignature(got, got.Signatures[0], trustFor(t, "acme-corp", sb.PublicKey)))
		require.NoError(t, bundle.VerifyInstalledContent(got, root))

		_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrDigestListInvalid, "full mode needs every digest to have a file")
	})

	t.Run("missing digest for the platform is refused", func(t *testing.T) {
		root := write(t)
		editSidecar(t, root, func(m map[string]any) { delete(m["digests"].(map[string]any), ownKey) })
		_, err := bundle.ReadInstalledPayload(root, own)
		assert.ErrorIs(t, err, bundle.ErrDigestListInvalid)
	})

	t.Run("flipped binary byte is refused", func(t *testing.T) {
		root := write(t)
		flipFirstByte(t, filepath.Join(root, sb.Binaries[ownKey]))
		_, err := bundle.ReadInstalledPayload(root, own)
		assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
		_, err = bundle.ReadInstalled(root)
		assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	})

	t.Run("edited other-platform digest changes the recomputed hash", func(t *testing.T) {
		root := write(t)
		edit := func(m map[string]any) {
			m["digests"].(map[string]any)[otherKey] = strings.Repeat("ab", 32)
		}
		editSidecar(t, root, edit)
		_, err := bundle.ReadInstalledPayload(root, own)
		assert.ErrorIs(t, err, bundle.ErrContentHashMismatch, "the unsigned anchor no longer matches")

		// An attacker also re-anchors content_hash: the read succeeds, and the
		// recomputed hash differs from the signed one, so the signature fails.
		forged := *sb.Bundle
		forged.BinaryDigests = map[string]string{ownKey: sb.BinaryDigests[ownKey], otherKey: strings.Repeat("ab", 32)}
		hash := recompute(t, &forged)
		editSidecar(t, root, func(m map[string]any) { m["content_hash"] = hash })
		got, err := bundle.ReadInstalledPayload(root, own)
		require.NoError(t, err)
		assert.Equal(t, hash, got.ContentHash)
		assert.NotEqual(t, sb.ContentHash, got.ContentHash)
		assert.Error(t, trust.VerifyBundleSignature(got, got.Signatures[0], trustFor(t, "acme-corp", sb.PublicKey)))
	})
}

func recompute(t *testing.T, b *bundle.Bundle) string {
	t.Helper()
	digests := map[string][32]byte{}
	for k, v := range b.BinaryDigests {
		var d [32]byte
		for i := 0; i < 32; i++ {
			var x byte
			for _, c := range v[2*i : 2*i+2] {
				x = x<<4 | byte(strings.IndexRune("0123456789abcdef", c))
			}
			d[i] = x
		}
		digests[k] = d
	}
	h, err := bundle.ComputeContentHashFromDigests(digests, b.ManifestBytes)
	require.NoError(t, err)
	return h
}

func TestDiscoverInstalled_FindsPlatformOnlyAndStdlibRoots(t *testing.T) {
	parent := t.TempDir()

	third := twoPlatform(t)
	third.WriteRoot(t, filepath.Join(parent, "widget"), bundle.WriteOptions{Platform: ownKey})

	stdlib := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "stdmod"})
	stdlib.WriteRoot(t, filepath.Join(parent, "stdmod"), bundle.WriteOptions{})

	got, err := bundle.DiscoverInstalled(parent)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, third.ContentHash, got["widget"].Bundle.ContentHash)
	assert.Equal(t, stdlib.ContentHash, got["stdmod"].Bundle.ContentHash)
	assert.Equal(t, "steward", got["widget"].Bundle.Manifest.Kind)
}

func TestDiscoverInstalled_IgnoresStagingDirectories(t *testing.T) {
	parent := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(parent, ".cfgms-bundle-123"), 0o755))
	got, err := bundle.DiscoverInstalled(parent)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestVerifyInstalledContent_DigestLessBundleDerivesDigestsFromBinaries(t *testing.T) {
	root, b := installBundle(t, map[string][]byte{ownKey: []byte("a"), otherKey: []byte("b")})
	require.Empty(t, b.BinaryDigests)
	require.NoError(t, bundle.VerifyInstalledContent(b, root))

	flipFirstByte(t, filepath.Join(root, b.Binaries[otherKey]))
	assert.ErrorIs(t, bundle.VerifyInstalledContent(b, root), bundle.ErrContentHashMismatch)
}

func TestFullMode_RefusesInconsistentDigestLists(t *testing.T) {
	sb := twoPlatform(t)
	write := func(t *testing.T) string {
		root := filepath.Join(t.TempDir(), "widget")
		sb.WriteRoot(t, root, bundle.WriteOptions{})
		return root
	}

	t.Run("binary with no digest", func(t *testing.T) {
		root := write(t)
		editSidecar(t, root, func(m map[string]any) { delete(m["digests"].(map[string]any), otherKey) })
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrDigestListInvalid)
	})
	t.Run("digest with no file", func(t *testing.T) {
		root := write(t)
		require.NoError(t, os.Remove(filepath.Join(root, sb.Binaries[otherKey])))
		editSidecar(t, root, func(m map[string]any) { delete(m["binaries"].(map[string]any), otherKey) })
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrDigestListInvalid)
	})
	t.Run("present file whose digest differs", func(t *testing.T) {
		root := write(t)
		flipFirstByte(t, filepath.Join(root, sb.Binaries[otherKey]))
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	})
	t.Run("missing file listed in the sidecar", func(t *testing.T) {
		root := write(t)
		require.NoError(t, os.Remove(filepath.Join(root, sb.Binaries[otherKey])))
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

var badNames = []string{
	"..", "/etc/passwd", `C:\x`, "a:b", "NUL", "nul.exe", "x.", "x ", `..\x`, "a/b", `a\b`,
	"module.yaml", "bundle.yaml", "Module.YAML", "con", "COM1.txt", "lpt9", "", "a\x00b", "a<b",
	strings.Repeat("a", bundle.MaxBinaryFileNameLen+1),
}

func TestValidateBinaryFileName(t *testing.T) {
	for _, name := range badNames {
		assert.ErrorIs(t, bundle.ValidateBinaryFileName(name), bundle.ErrInvalidBinaryFileName, "%q", name)
	}
	for _, name := range []string{"cfgms-module-x", "cfgms-module-x.exe", "a.b.c", "console", strings.Repeat("a", bundle.MaxBinaryFileNameLen)} {
		assert.NoError(t, bundle.ValidateBinaryFileName(name), "%q", name)
	}
}

func TestFileNameTable_WriteAssembleRead(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: "acme-corp"})

	for _, name := range badNames {
		t.Run("write/"+name, func(t *testing.T) {
			b := *sb.Bundle
			b.Binaries = map[string]string{ownKey: name}
			err := bundle.WriteInstalled(&b, filepath.Join(t.TempDir(), "r"), bundle.WriteOptions{})
			assert.Error(t, err)
		})
		t.Run("assemble/"+name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "bin")
			require.NoError(t, os.WriteFile(src, []byte("x"), 0o600))
			manifest := filepath.Join(t.TempDir(), "module.yaml")
			require.NoError(t, os.WriteFile(manifest, sb.ManifestBytes, 0o600))
			_, err := bundle.Assemble(bundle.AssembleSpec{ManifestPath: manifest,
				Binaries: map[string]bundle.PlatformBinary{ownKey: {FileName: name, SourcePath: src}}})
			assert.Error(t, err)
		})
		t.Run("read/"+name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "r")
			sb.WriteRoot(t, root, bundle.WriteOptions{})
			editSidecar(t, root, func(m map[string]any) { m["binaries"] = map[string]any{ownKey: name} })
			_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
			assert.Error(t, err)
		})
	}

	t.Run("case duplicates", func(t *testing.T) {
		two := twoPlatform(t)
		b := *two.Bundle
		b.Binaries = map[string]string{ownKey: "Tool", otherKey: "tool"}
		assert.ErrorIs(t, bundle.WriteInstalled(&b, filepath.Join(t.TempDir(), "r"), bundle.WriteOptions{}), bundle.ErrInvalidBinaryFileName)
	})
	t.Run("non-allowlisted platform key", func(t *testing.T) {
		b := *sb.Bundle
		b.Binaries = map[string]string{"plan9-386": "tool"}
		assert.ErrorIs(t, bundle.WriteInstalled(&b, filepath.Join(t.TempDir(), "r"), bundle.WriteOptions{}), bundle.ErrInvalidBinaryFileName)

		src := filepath.Join(t.TempDir(), "bin")
		require.NoError(t, os.WriteFile(src, []byte("x"), 0o600))
		manifest := filepath.Join(t.TempDir(), "module.yaml")
		require.NoError(t, os.WriteFile(manifest, sb.ManifestBytes, 0o600))
		_, err := bundle.Assemble(bundle.AssembleSpec{ManifestPath: manifest,
			Binaries: map[string]bundle.PlatformBinary{"plan9-386": {FileName: "tool", SourcePath: src}}})
		assert.ErrorIs(t, err, bundle.ErrInvalidBinaryFileName)
	})
}

func TestSymlinkedFilesAreRefused(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: "acme-corp"})
	for _, name := range []string{bundle.ManifestFileName, bundle.BundleSidecarFileName, sb.Binaries[ownKey]} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "r")
			sb.WriteRoot(t, root, bundle.WriteOptions{})
			outside := filepath.Join(t.TempDir(), "outside")
			orig, err := os.ReadFile(filepath.Join(root, name))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(outside, orig, 0o600))
			require.NoError(t, os.Remove(filepath.Join(root, name)))
			newSymlink(t, outside, filepath.Join(root, name))

			_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
			assert.ErrorIs(t, err, bundle.ErrNotRegularFile)
			_, err = bundle.ReadInstalled(root)
			assert.ErrorIs(t, err, bundle.ErrNotRegularFile)
		})
	}
}

func TestOversizeAndOverCountAreRefusedBeforeReading(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: "acme-corp"})

	t.Run("oversize binary", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		sb.WriteRoot(t, root, bundle.WriteOptions{})
		// A sparse file: the size is claimed without the bytes being written.
		f, err := os.OpenFile(filepath.Join(root, sb.Binaries[ownKey]), os.O_WRONLY, 0)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(bundle.MaxBundleFileBytes+1))
		require.NoError(t, f.Close())

		_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrBundleTooLarge)
		_, err = bundle.ReadInstalled(root)
		assert.ErrorIs(t, err, bundle.ErrBundleTooLarge)
	})
	t.Run("oversize manifest", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		sb.WriteRoot(t, root, bundle.WriteOptions{})
		f, err := os.OpenFile(filepath.Join(root, bundle.ManifestFileName), os.O_WRONLY, 0)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(64<<20))
		require.NoError(t, f.Close())
		_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrBundleTooLarge)
	})
	t.Run("too many files", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		sb.WriteRoot(t, root, bundle.WriteOptions{})
		for i := 0; i <= bundle.MaxBundleFiles; i++ {
			require.NoError(t, os.WriteFile(filepath.Join(root, "extra"+string(rune('a'+i))), nil, 0o600))
		}
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrBundleTooLarge)
	})
	t.Run("assemble refuses oversize binary", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "bin")
		f, err := os.Create(src)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(bundle.MaxBundleFileBytes+1))
		require.NoError(t, f.Close())
		manifest := filepath.Join(t.TempDir(), "module.yaml")
		require.NoError(t, os.WriteFile(manifest, sb.ManifestBytes, 0o600))
		_, err = bundle.Assemble(bundle.AssembleSpec{ManifestPath: manifest,
			Binaries: map[string]bundle.PlatformBinary{ownKey: {FileName: "tool", SourcePath: src}}})
		assert.ErrorIs(t, err, bundle.ErrBundleTooLarge)
	})
}

func TestStrictReader(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: "acme-corp"})
	write := func(t *testing.T) string {
		root := filepath.Join(t.TempDir(), "r")
		sb.WriteRoot(t, root, bundle.WriteOptions{})
		return root
	}
	git := bundle.ReadOptions{IgnoreNames: []string{".git"}}

	t.Run("default refuses extra file, directory and symlink", func(t *testing.T) {
		root := write(t)
		require.NoError(t, os.WriteFile(filepath.Join(root, "extra"), []byte("x"), 0o600))
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)

		root = write(t)
		require.NoError(t, os.Mkdir(filepath.Join(root, "dir"), 0o755))
		_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)

		root = write(t)
		newSymlink(t, filepath.Join(root, bundle.ManifestFileName), filepath.Join(root, "link"))
		_, err = bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)
		_, err = bundle.ReadInstalled(root)
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)
	})
	t.Run("IgnoreNames ignores a real .git directory only", func(t *testing.T) {
		root := write(t)
		require.NoError(t, os.Mkdir(filepath.Join(root, ".git"), 0o755))
		got, err := bundle.ReadInstalledPayload(root, git)
		require.NoError(t, err)
		assert.Equal(t, sb.ContentHash, got.ContentHash)

		require.NoError(t, os.WriteFile(filepath.Join(root, "extra"), []byte("x"), 0o600))
		_, err = bundle.ReadInstalledPayload(root, git)
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry, "an extra file beside .git is still refused")
	})
	t.Run("a .git file is refused", func(t *testing.T) {
		root := write(t)
		require.NoError(t, os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /x"), 0o600))
		_, err := bundle.ReadInstalledPayload(root, git)
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)
	})
	t.Run("a .git symlink is refused", func(t *testing.T) {
		root := write(t)
		newSymlink(t, t.TempDir(), filepath.Join(root, ".git"))
		_, err := bundle.ReadInstalledPayload(root, git)
		assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)
	})
	t.Run("path-escaping binary entry", func(t *testing.T) {
		root := write(t)
		editSidecar(t, root, func(m map[string]any) { m["binaries"] = map[string]any{ownKey: "../../etc/shadow"} })
		_, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
		assert.ErrorIs(t, err, bundle.ErrBinaryPathEscapesRoot)
	})
}

func TestWriteInstalled_ExistingRootIsLeftByteIdentical(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: "acme-corp"})
	root := filepath.Join(t.TempDir(), "r")
	require.NoError(t, os.Mkdir(root, 0o755))
	marker := filepath.Join(root, "keep")
	require.NoError(t, os.WriteFile(marker, []byte("precious"), 0o600))

	err := bundle.WriteInstalled(sb.Bundle, root, bundle.WriteOptions{})
	assert.ErrorIs(t, err, bundle.ErrRootExists)

	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	got, err := os.ReadFile(marker)
	require.NoError(t, err)
	assert.Equal(t, "precious", string(got))

	siblings, err := os.ReadDir(filepath.Dir(root))
	require.NoError(t, err)
	assert.Len(t, siblings, 1, "no staging directory is left behind")
}

func TestWriteInstalled_RefusesBundlesThatDoNotReproduceTheirHash(t *testing.T) {
	sb := twoPlatform(t)
	dir := t.TempDir()

	t.Run("no payload", func(t *testing.T) {
		b := *sb.Bundle
		b.BinaryContent = nil
		assert.Error(t, bundle.WriteInstalled(&b, filepath.Join(dir, "a"), bundle.WriteOptions{}))
	})
	t.Run("tampered content hash", func(t *testing.T) {
		b := *sb.Bundle
		b.ContentHash = "dGFtcGVyZWQ="
		assert.ErrorIs(t, bundle.WriteInstalled(&b, filepath.Join(dir, "b"), bundle.WriteOptions{}), bundle.ErrContentHashMismatch)
	})
	t.Run("tampered binary", func(t *testing.T) {
		b := *sb.Bundle
		b.BinaryContent = map[string][]byte{ownKey: []byte("evil"), otherKey: sb.BinaryContent[otherKey]}
		assert.ErrorIs(t, bundle.WriteInstalled(&b, filepath.Join(dir, "c"), bundle.WriteOptions{}), bundle.ErrContentHashMismatch)
	})
	t.Run("manifest bytes disagree with identity", func(t *testing.T) {
		b := *sb.Bundle
		m := *b.Manifest
		m.Publisher = "someone-else"
		b.Manifest = &m
		assert.Error(t, bundle.WriteInstalled(&b, filepath.Join(dir, "d"), bundle.WriteOptions{}))
	})
	t.Run("unknown platform option", func(t *testing.T) {
		assert.Error(t, bundle.WriteInstalled(sb.Bundle, filepath.Join(dir, "e"), bundle.WriteOptions{Platform: "linux-riscv"}))
	})
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		assert.NoDirExists(t, filepath.Join(dir, n))
	}
}

func TestSign_RefusesInconsistentBundles(t *testing.T) {
	sb := twoPlatform(t)
	b := *sb.Bundle
	b.Signatures = nil
	b.ContentHash = "dGFtcGVyZWQ="
	assert.ErrorIs(t, bundle.Sign(&b, sb.PrivateKey), bundle.ErrContentHashMismatch)
	assert.Empty(t, b.Signatures)

	assert.Error(t, bundle.Sign(sb.Bundle, ed25519.PrivateKey("short")))
	assert.Error(t, bundle.Sign(nil, sb.PrivateKey))
}

func TestAssemble_RefusesInexactVersionAndEmptySpec(t *testing.T) {
	src := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.WriteFile(src, []byte("x"), 0o600))
	for _, v := range []string{"v1.0.0", "^1.0.0", ">=1.0.0", "latest", "1.0", "01.0.0"} {
		manifest := filepath.Join(t.TempDir(), "module.yaml")
		require.NoError(t, os.WriteFile(manifest,
			[]byte("name: x\nversion: \""+v+"\"\npublisher: acme-corp\nexecutors: [steward]\n"), 0o600))
		_, err := bundle.Assemble(bundle.AssembleSpec{ManifestPath: manifest,
			Binaries: map[string]bundle.PlatformBinary{ownKey: {FileName: "tool", SourcePath: src}}})
		assert.Error(t, err, v)
	}
	_, err := bundle.Assemble(bundle.AssembleSpec{ManifestPath: "x"})
	assert.Error(t, err)
}

func TestIsExactSemver(t *testing.T) {
	for _, v := range []string{"1.0.0", "0.0.1", "10.20.30", "1.0.0-rc.1", "1.0.0-alpha+build.5", "1.0.0+20130313144700"} {
		assert.True(t, bundle.IsExactSemver(v), v)
	}
	for _, v := range []string{"v1.0.0", "^1.0.0", ">=1.0.0", "~1.0.0", "latest", "", "1.0", "1", "1.0.0.0", "01.0.0", "1.0.0-", "1.0.0 ", " 1.0.0", "1.x.0", "1.0.0 || 2.0.0"} {
		assert.False(t, bundle.IsExactSemver(v), "%q", v)
	}
}
