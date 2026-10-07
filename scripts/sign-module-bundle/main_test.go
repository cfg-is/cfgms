// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

const testManifest = `name: demo
version: 1.2.3
description: demo module
publisher: cfgms
executors:
  - steward
requirements:
  os: [linux, windows]
  arch: [amd64]
`

// testSeed returns a deterministic non-dev seed and its base64 encoding.
func testSeed() ([]byte, string) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed, base64.StdEncoding.EncodeToString(seed)
}

// stageInputs writes a manifest and a stand-in module binary and returns an
// assembleSpec rooted in a fresh temp directory.
func stageInputs(t *testing.T, osName string, key ed25519.PrivateKey) assembleSpec {
	t.Helper()
	in := t.TempDir()
	manifest := filepath.Join(in, "module.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(testManifest), 0o600))
	binary := filepath.Join(in, "built-binary")
	require.NoError(t, os.WriteFile(binary, []byte("\x7fELF stand-in module binary"), 0o700))
	return assembleSpec{
		ManifestPath: manifest,
		BinaryPath:   binary,
		OS:           osName,
		Arch:         "amd64",
		Root:         filepath.Join(t.TempDir(), "demo"),
		Key:          key,
	}
}

func trustStoreFor(t *testing.T, pub ed25519.PublicKey) trust.TrustStore {
	t.Helper()
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name: publisherName, PublicKey: pub, Algorithm: "ed25519",
	}))
	return store
}

func TestPublisherKey_DefaultsToZeroSeedDevKey(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")
	// Pinned literal: if the dev key ever changes, every dev steward silently stops
	// loading bundles. This is also what scripts/sign-steward-binary documents.
	require.Equal(t, "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=", devPublicKey)

	priv, usedDev, err := publisherKey()
	require.NoError(t, err)

	assert.True(t, usedDev)
	assert.Equal(t, devPublicKey, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"default signing identity must remain the documented zero-seed dev key")
}

func TestPublisherKey_UsesSuppliedSeed(t *testing.T) {
	seed, enc := testSeed()
	t.Setenv(publisherSeedEnv, enc)

	priv, usedDev, err := publisherKey()
	require.NoError(t, err)

	assert.False(t, usedDev)
	assert.Equal(t, ed25519.NewKeyFromSeed(seed), priv)
}

func TestPublisherKey_RejectsMalformedSeed(t *testing.T) {
	tests := []struct {
		name string
		seed string
		want string
	}{
		{"not base64", "this is not base64!!", "decode " + publisherSeedEnv},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize-1)), "must decode to 32 bytes, got 31"},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize+1)), "must decode to 32 bytes, got 33"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(publisherSeedEnv, tc.seed)
			priv, _, err := publisherKey()
			require.Error(t, err)
			assert.Nil(t, priv)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// REQUIRED: a bundle signed by this signer verifies through the production
// verifier, an altered binary fails, and a wrong publisher name is refused.
func TestSignedBundle_VerifiesThroughTrustVerifier(t *testing.T) {
	seed, _ := testSeed()
	priv := ed25519.NewKeyFromSeed(seed)
	spec := stageInputs(t, "linux", priv)

	b, err := assembleRoot(spec)
	require.NoError(t, err)
	require.Len(t, b.Signatures, 1)
	assert.Equal(t, "cfgms", b.Signatures[0].Publisher)
	assert.Equal(t, "ed25519", b.Signatures[0].Algorithm)

	store := trustStoreFor(t, priv.Public().(ed25519.PublicKey))

	t.Run("verifies", func(t *testing.T) {
		require.NoError(t, trust.VerifyBundleSignature(b, b.Signatures[0], store))
	})

	t.Run("altered binary fails after signing", func(t *testing.T) {
		installed, err := bundle.ReadInstalled(spec.Root)
		require.NoError(t, err)
		binPath, err := bundle.InstalledBinaryPath(spec.Root, installed.Binaries["linux-amd64"])
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(binPath, []byte("tampered"), 0o700))

		// The sidecar's recorded hash is unsigned local metadata; the signed hash
		// no longer matches the bytes on disk.
		err = bundle.VerifyInstalledContent(b, spec.Root)
		require.Error(t, err)
		assert.True(t, errors.Is(err, bundle.ErrContentHashMismatch))
	})

	t.Run("altered content hash fails signature", func(t *testing.T) {
		tampered := *b
		tampered.ContentHash = "dGFtcGVyZWQ="
		err := trust.VerifyBundleSignature(&tampered, b.Signatures[0], store)
		assert.True(t, errors.Is(err, trust.ErrInvalidSignature))
	})

	t.Run("other publisher name refused", func(t *testing.T) {
		sig := b.Signatures[0]
		sig.Publisher = "someone-else"
		err := trust.VerifyBundleSignature(b, sig, store)
		assert.True(t, errors.Is(err, trust.ErrPublisherNotTrusted))
	})
}

func TestSignBundle_SignsExactlyContentHashBytes(t *testing.T) {
	seed, _ := testSeed()
	priv := ed25519.NewKeyFromSeed(seed)
	b := &bundle.Bundle{ContentHash: "abc="}

	sig := signBundle(b, priv)

	assert.True(t, ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(b.ContentHash), sig.Signature))
}

// REQUIRED: an assembled root round-trips through the #4425 reader and passes
// VerifyInstalledContent, for each platform shape (including the .exe name).
func TestAssembledRoot_RoundTripsThroughReader(t *testing.T) {
	seed, _ := testSeed()
	priv := ed25519.NewKeyFromSeed(seed)

	for _, osName := range []string{"linux", "windows"} {
		t.Run(osName, func(t *testing.T) {
			spec := stageInputs(t, osName, priv)
			want, err := assembleRoot(spec)
			require.NoError(t, err)

			got, err := bundle.ReadInstalled(spec.Root)
			require.NoError(t, err)
			require.NoError(t, bundle.VerifyInstalledContent(got, spec.Root))

			assert.Equal(t, want.ContentHash, got.ContentHash)
			assert.Equal(t, want.Signatures, got.Signatures)
			assert.Equal(t, "demo", got.Manifest.Name)

			key := osName + "-amd64"
			require.Len(t, got.Binaries, 1, "exactly one os-arch entry per root")
			wantName := "cfgms-module-demo"
			if osName == "windows" {
				wantName += ".exe"
			}
			assert.Equal(t, wantName, got.Binaries[key])

			store := trustStoreFor(t, priv.Public().(ed25519.PublicKey))
			require.NoError(t, trust.VerifyBundleSignature(got, got.Signatures[0], store))
		})
	}
}

func TestAssembledRoot_ManifestIsCopiedByteForByte(t *testing.T) {
	seed, _ := testSeed()
	spec := stageInputs(t, "linux", ed25519.NewKeyFromSeed(seed))
	// Odd formatting and trailing whitespace must survive untouched.
	odd := []byte(testManifest + "\n# trailing comment   \n\n")
	require.NoError(t, os.WriteFile(spec.ManifestPath, odd, 0o600))

	_, err := assembleRoot(spec)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(spec.Root, bundle.ManifestFileName))
	require.NoError(t, err)
	assert.Equal(t, odd, got)
}

// REQUIRED: assembling twice from the same inputs and seed is byte-identical,
// sidecar included, regardless of the umask or input file modes.
func TestAssembly_IsReproducible(t *testing.T) {
	seed, _ := testSeed()
	priv := ed25519.NewKeyFromSeed(seed)
	first := stageInputs(t, "linux", priv)
	second := first
	second.Root = filepath.Join(t.TempDir(), "demo")
	// Same inputs, different on-disk modes.
	require.NoError(t, os.Chmod(second.BinaryPath, 0o755))

	_, err := assembleRoot(first)
	require.NoError(t, err)
	_, err = assembleRoot(second)
	require.NoError(t, err)

	for _, name := range []string{bundle.ManifestFileName, bundle.BundleSidecarFileName, "cfgms-module-demo"} {
		a, err := os.ReadFile(filepath.Join(first.Root, name))
		require.NoError(t, err)
		b, err := os.ReadFile(filepath.Join(second.Root, name))
		require.NoError(t, err)
		assert.Equal(t, a, b, name)

		ai, err := os.Stat(filepath.Join(first.Root, name))
		require.NoError(t, err)
		bi, err := os.Stat(filepath.Join(second.Root, name))
		require.NoError(t, err)
		assert.Equal(t, ai.Mode(), bi.Mode(), "mode of "+name)
	}
}

func TestAssembleRoot_RejectsBadInputs(t *testing.T) {
	seed, _ := testSeed()
	priv := ed25519.NewKeyFromSeed(seed)

	t.Run("invalid manifest", func(t *testing.T) {
		spec := stageInputs(t, "linux", priv)
		require.NoError(t, os.WriteFile(spec.ManifestPath, []byte("name: [unterminated"), 0o600))
		_, err := assembleRoot(spec)
		require.Error(t, err)
	})
	t.Run("missing binary", func(t *testing.T) {
		spec := stageInputs(t, "linux", priv)
		spec.BinaryPath = filepath.Join(t.TempDir(), "absent")
		_, err := assembleRoot(spec)
		require.Error(t, err)
	})
	t.Run("hostile os", func(t *testing.T) {
		spec := stageInputs(t, "../escape", priv)
		_, err := assembleRoot(spec)
		require.Error(t, err)
	})
}

func TestRun_AssembleDevKeyPrintsDevBuildInvocation(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")
	spec := stageInputs(t, "linux", nil)

	var out, errOut bytes.Buffer
	err := run([]string{"assemble",
		"--manifest", spec.ManifestPath, "--binary", spec.BinaryPath,
		"--os", "linux", "--arch", "amd64", "--out", spec.Root}, &out, &errOut)
	require.NoError(t, err)

	assert.Contains(t, errOut.String(), "STEWARD_PUBLISHER_KEY="+devPublicKey)
	assert.NotContains(t, out.String()+errOut.String(), "CFGMS_PUBLISHER_SEED=",
		"the seed value must never be echoed")

	b, err := bundle.ReadInstalled(spec.Root)
	require.NoError(t, err)
	require.Len(t, b.Signatures, 1, "dev-key build must still emit a signature")
}

func TestRun_ReleaseRefusesDevKeyAndMissingSeed(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")
	spec := stageInputs(t, "linux", nil)
	args := []string{"assemble", "--release",
		"--manifest", spec.ManifestPath, "--binary", spec.BinaryPath,
		"--os", "linux", "--arch", "amd64", "--out", spec.Root}

	err := run(args, &bytes.Buffer{}, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), publisherSeedEnv)
	_, statErr := os.Stat(spec.Root)
	assert.True(t, os.IsNotExist(statErr), "nothing may be assembled")

	// An explicit dev seed (zero bytes) is refused too.
	t.Setenv(publisherSeedEnv, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)))
	err = run(args, &bytes.Buffer{}, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dev")
}

func TestRun_CheckKey(t *testing.T) {
	seed, enc := testSeed()
	pub := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	t.Run("matching key passes", func(t *testing.T) {
		t.Setenv(publisherSeedEnv, enc)
		require.NoError(t, run([]string{"check-key", "--expect-public-key", pub}, &bytes.Buffer{}, &bytes.Buffer{}))
	})
	t.Run("mismatched key fails", func(t *testing.T) {
		t.Setenv(publisherSeedEnv, enc)
		err := run([]string{"check-key", "--expect-public-key", devPublicKey}, &bytes.Buffer{}, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})
	t.Run("absent seed fails", func(t *testing.T) {
		t.Setenv(publisherSeedEnv, "")
		err := run([]string{"check-key", "--expect-public-key", devPublicKey}, &bytes.Buffer{}, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), publisherSeedEnv)
	})
	t.Run("dev seed fails even when it matches", func(t *testing.T) {
		t.Setenv(publisherSeedEnv, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)))
		err := run([]string{"check-key", "--expect-public-key", devPublicKey}, &bytes.Buffer{}, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dev")
	})
}

func TestRun_PubkeyPrintsPublicHalfOnly(t *testing.T) {
	seed, enc := testSeed()
	t.Setenv(publisherSeedEnv, enc)
	var out bytes.Buffer
	require.NoError(t, run([]string{"pubkey"}, &out, &bytes.Buffer{}))
	assert.Equal(t, base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))+"\n", out.String())
	assert.NotContains(t, out.String(), enc)
}

// The dev loop: a dev-signed bundle loads only on a steward built with the dev public
// key. A default-key build carries the all-zero placeholder and refuses every bundle.
func TestDevSignedBundle_LoadableOnlyWithDevPublicKey(t *testing.T) {
	t.Setenv(publisherSeedEnv, "")
	priv, usedDev, err := publisherKey()
	require.NoError(t, err)
	require.True(t, usedDev)
	b, err := assembleRoot(stageInputs(t, "linux", priv))
	require.NoError(t, err)
	require.Len(t, b.Signatures, 1, "dev signing must not emit an empty Signatures list")

	devPub, err := base64.StdEncoding.DecodeString(devPublicKey)
	require.NoError(t, err)
	require.NoError(t, trust.VerifyBundleSignature(b, b.Signatures[0], trustStoreFor(t, devPub)))

	placeholder := trustStoreFor(t, make([]byte, ed25519.PublicKeySize))
	err = trust.VerifyBundleSignature(b, b.Signatures[0], placeholder)
	assert.True(t, errors.Is(err, trust.ErrUntrustedPublisherKey))
}
