// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// TestSignUploadContentVerifiesAgainstPublisherKey proves the signature the helper
// produces is over the canonical (hash, version, platform, arch) message and
// verifies with the public half of the fleet publisher key, and that changing any
// signed field invalidates it. It needs no Docker or controller.
func TestSignUploadContentVerifiesAgainstPublisherKey(t *testing.T) {
	content := []byte("steward-binary-bytes")
	sig := SignUploadContent(t, content, "v9.9.9-test", "linux", "amd64")

	rawSig, err := base64.RawURLEncoding.DecodeString(sig)
	require.NoError(t, err, "signature must be URL-safe base64 without padding")

	pub := UpgradePrivKey().Public().(ed25519.PublicKey)
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])

	msg, err := trust.StewardBinaryMessage(hash, "v9.9.9-test", "linux", "amd64")
	require.NoError(t, err)
	require.True(t, ed25519.Verify(pub, []byte(msg), rawSig), "signature must verify for the signed fields")

	for name, args := range map[string][4]string{
		"version":  {hash, "v9.9.10-test", "linux", "amd64"},
		"platform": {hash, "v9.9.9-test", "windows", "amd64"},
		"arch":     {hash, "v9.9.9-test", "linux", "arm64"},
		"content":  {hex.EncodeToString(make([]byte, sha256.Size)), "v9.9.9-test", "linux", "amd64"},
	} {
		other, err := trust.StewardBinaryMessage(args[0], args[1], args[2], args[3])
		require.NoError(t, err, name)
		require.False(t, ed25519.Verify(pub, []byte(other), rawSig), "signature must not verify when %s differs", name)
	}
}

// TestUpgradePrivKeyIsDeterministic pins the zero-seed key the fleet containers
// trust (CFGMS_TEST_STEWARD_PUBLISHER_KEY).
func TestUpgradePrivKeyIsDeterministic(t *testing.T) {
	pub := UpgradePrivKey().Public().(ed25519.PublicKey)
	require.Equal(t, "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=", base64.StdEncoding.EncodeToString(pub))
}

// TestBlobPaths checks the controller-side blob locations built from a version.
func TestBlobPaths(t *testing.T) {
	require.Equal(t,
		"/app/data/installers/fleet-root/fleet-child-a/steward-binaries/v1.2.3-linux-amd64",
		BlobPath("v1.2.3"))
	require.Equal(t, BlobPath("v1.2.3")+".meta.json", BlobMetaPath("v1.2.3"))
}
