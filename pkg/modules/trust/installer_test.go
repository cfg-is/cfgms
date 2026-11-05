// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

func signInstaller(t *testing.T, priv ed25519.PrivateKey, hash, version, platform, arch string) bundle.BundleSignature {
	t.Helper()
	msg, err := trust.InstallerMessage(hash, version, platform, arch)
	require.NoError(t, err)
	return bundle.BundleSignature{Publisher: "cfgms", Algorithm: "ed25519", Signature: ed25519.Sign(priv, []byte(msg))}
}

func TestVerifyInstallerSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	store := stewardBinaryStore(t, pub)

	t.Run("valid signature verifies", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "v1.0.0", "windows", "amd64")
		require.NoError(t, trust.VerifyInstallerSignature(testContentHash, "v1.0.0", "windows", "amd64", sig, store))
	})

	t.Run("steward-binary signature fails as installer signature", func(t *testing.T) {
		sig := signStewardBinary(t, priv, testContentHash, "v1.0.0", "windows", "amd64")
		err := trust.VerifyInstallerSignature(testContentHash, "v1.0.0", "windows", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("installer signature fails as steward-binary signature", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "v1.0.0", "windows", "amd64")
		err := trust.VerifyStewardBinarySignature(testContentHash, "v1.0.0", "windows", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("signature for another platform fails", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "v1.0.0", "windows", "amd64")
		err := trust.VerifyInstallerSignature(testContentHash, "v1.0.0", "linux", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("signature for another arch fails", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "v1.0.0", "windows", "amd64")
		err := trust.VerifyInstallerSignature(testContentHash, "v1.0.0", "windows", "arm64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})
}

func TestInstallerMessage_InvalidFields(t *testing.T) {
	for _, c := range []struct{ name, hash, version, platform, arch string }{
		{"empty hash", "", "v1.0.0", "linux", "amd64"},
		{"empty platform", testContentHash, "v1.0.0", "", "amd64"},
		{"empty version", testContentHash, "", "linux", "amd64"},
		{"separator in version", testContentHash, "v1|2", "linux", "amd64"},
		{"empty arch", testContentHash, "v1.0.0", "linux", ""},
		{"separator in hash", "a|b", "v1.0.0", "linux", "amd64"},
		{"separator in platform", testContentHash, "v1.0.0", "li|nux", "amd64"},
		{"separator in arch", testContentHash, "v1.0.0", "linux", "am|d64"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := trust.InstallerMessage(c.hash, c.version, c.platform, c.arch)
			assert.ErrorIs(t, err, trust.ErrInvalidSignatureMessage)
		})
	}
}

func TestInstallerMessage_DomainSeparated(t *testing.T) {
	inst, err := trust.InstallerMessage(testContentHash, "v1.0.0", "linux", "amd64")
	require.NoError(t, err)
	sb, err := trust.StewardBinaryMessage(testContentHash, "v1.0.0", "linux", "amd64")
	require.NoError(t, err)
	assert.NotEqual(t, inst, sb)
	assert.Contains(t, inst, "cfgms-installer-v2|")
	assert.Contains(t, inst, "|v1.0.0|linux|amd64")
}

func TestInstallerMessage_VersionBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	store := stewardBinaryStore(t, pub)

	t.Run("signature for version X does not verify for version Y", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "v1.2.3", "linux", "amd64")
		require.NoError(t, trust.VerifyInstallerSignature(testContentHash, "v1.2.3", "linux", "amd64", sig, store))
		err := trust.VerifyInstallerSignature(testContentHash, "v1.2.4", "linux", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("v1-format message signature does not verify", func(t *testing.T) {
		legacy := "cfgms-installer-v1|" + testContentHash + "|linux|amd64"
		sig := bundle.BundleSignature{Publisher: "cfgms", Algorithm: "ed25519", Signature: ed25519.Sign(priv, []byte(legacy))}
		err := trust.VerifyInstallerSignature(testContentHash, "v1.2.3", "linux", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("leading v is canonicalized", func(t *testing.T) {
		a, err := trust.InstallerMessage(testContentHash, "0.9.41", "linux", "amd64")
		require.NoError(t, err)
		b, err := trust.InstallerMessage(testContentHash, "v0.9.41", "linux", "amd64")
		require.NoError(t, err)
		assert.Equal(t, a, b)
	})

	t.Run("pre-release differs from release", func(t *testing.T) {
		a, err := trust.InstallerMessage(testContentHash, "v1.2.3", "linux", "amd64")
		require.NoError(t, err)
		b, err := trust.InstallerMessage(testContentHash, "v1.2.3-rc1", "linux", "amd64")
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
	})
}
