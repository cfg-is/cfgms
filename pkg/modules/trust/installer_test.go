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

func signInstaller(t *testing.T, priv ed25519.PrivateKey, hash, platform, arch string) bundle.BundleSignature {
	t.Helper()
	msg, err := trust.InstallerMessage(hash, platform, arch)
	require.NoError(t, err)
	return bundle.BundleSignature{Publisher: "cfgms", Algorithm: "ed25519", Signature: ed25519.Sign(priv, []byte(msg))}
}

func TestVerifyInstallerSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	store := stewardBinaryStore(t, pub)

	t.Run("valid signature verifies", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "windows", "amd64")
		require.NoError(t, trust.VerifyInstallerSignature(testContentHash, "windows", "amd64", sig, store))
	})

	t.Run("steward-binary signature fails as installer signature", func(t *testing.T) {
		sig := signStewardBinary(t, priv, testContentHash, "v1.0.0", "windows", "amd64")
		err := trust.VerifyInstallerSignature(testContentHash, "windows", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("installer signature fails as steward-binary signature", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "windows", "amd64")
		err := trust.VerifyStewardBinarySignature(testContentHash, "v1.0.0", "windows", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("signature for another platform fails", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "windows", "amd64")
		err := trust.VerifyInstallerSignature(testContentHash, "linux", "amd64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})

	t.Run("signature for another arch fails", func(t *testing.T) {
		sig := signInstaller(t, priv, testContentHash, "windows", "amd64")
		err := trust.VerifyInstallerSignature(testContentHash, "windows", "arm64", sig, store)
		assert.ErrorIs(t, err, trust.ErrInvalidSignature)
	})
}

func TestInstallerMessage_InvalidFields(t *testing.T) {
	for _, c := range []struct{ name, hash, platform, arch string }{
		{"empty hash", "", "linux", "amd64"},
		{"empty platform", testContentHash, "", "amd64"},
		{"empty arch", testContentHash, "linux", ""},
		{"separator in hash", "a|b", "linux", "amd64"},
		{"separator in platform", testContentHash, "li|nux", "amd64"},
		{"separator in arch", testContentHash, "linux", "am|d64"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := trust.InstallerMessage(c.hash, c.platform, c.arch)
			assert.ErrorIs(t, err, trust.ErrInvalidSignatureMessage)
		})
	}
}

func TestInstallerMessage_DomainSeparated(t *testing.T) {
	inst, err := trust.InstallerMessage(testContentHash, "linux", "amd64")
	require.NoError(t, err)
	sb, err := trust.StewardBinaryMessage(testContentHash, "v1.0.0", "linux", "amd64")
	require.NoError(t, err)
	assert.NotEqual(t, inst, sb)
	assert.Contains(t, inst, "cfgms-installer-v1|")
	assert.NotContains(t, inst, "v1.0.0")
}
