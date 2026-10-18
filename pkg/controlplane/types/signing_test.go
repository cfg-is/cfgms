// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
)

func newTestSigner(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "CFGMS Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "controller.test", DNSNames: []string{"controller.test"}, ValidityDays: 1, KeySize: 2048,
	})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{PrivateKeyPEM: sc.PrivateKeyPEM, CertificatePEM: sc.CertificatePEM})
	require.NoError(t, err)
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: sc.CertificatePEM})
	require.NoError(t, err)
	return signer, verifier
}

func mustVersion(t *testing.T, c *SigningCapabilities, id string) uint32 {
	t.Helper()
	v, err := c.VersionFor(id)
	require.NoError(t, err)
	return v
}

func TestSigningCapabilities_VersionFor(t *testing.T) {
	var nilCaps *SigningCapabilities
	assert.Equal(t, SigningPayloadV1, mustVersion(t, nilCaps, "s1"))
	require.NoError(t, nilCaps.Record("s1", []uint32{2})) // must not panic

	caps := NewSigningCapabilities()
	assert.Equal(t, SigningPayloadV1, mustVersion(t, caps, "s1"), "unknown steward gets v1")

	require.NoError(t, caps.Record("s1", []uint32{1, 2}))
	require.NoError(t, caps.Record("s2", []uint32{1}))
	require.NoError(t, caps.Record("s3", []uint32{99}))
	require.NoError(t, caps.Record("s4", nil))
	assert.Equal(t, SigningPayloadV2, mustVersion(t, caps, "s1"))
	assert.Equal(t, SigningPayloadV1, mustVersion(t, caps, "s2"))
	assert.Equal(t, SigningPayloadV1, mustVersion(t, caps, "s3"), "unsupported versions are ignored")
	assert.Equal(t, SigningPayloadV1, mustVersion(t, caps, "s4"))

	// A later heartbeat without the capability (steward downgraded) revokes it.
	require.NoError(t, caps.Record("s1", nil))
	assert.Equal(t, SigningPayloadV1, mustVersion(t, caps, "s1"))
}

func TestSignCommand_PicksVersionPerSteward(t *testing.T) {
	signer, verifier := newTestSigner(t)
	caps := NewSigningCapabilities()
	require.NoError(t, caps.Record("new", []uint32{1, 2}))
	require.NoError(t, caps.Record("old", nil))

	for _, tc := range []struct {
		steward string
		version uint32
	}{{"new", SigningPayloadV2}, {"old", SigningPayloadV1}} {
		cmd := &Command{ID: "c-" + tc.steward, Type: CommandSyncConfig, StewardID: tc.steward,
			Timestamp: time.Now(), Term: 4}
		sc, err := SignCommand(cmd, signer, caps)
		require.NoError(t, err)
		require.NotNil(t, sc.Signature)

		want := tc.version
		if want == SigningPayloadV1 {
			assert.Zero(t, sc.Command.SigningPayloadVersion, "v1 leaves the field unset")
		} else {
			assert.Equal(t, want, sc.Command.SigningPayloadVersion)
		}
		b, err := CommandSigningBytesVersion(&sc.Command, InterfaceParamsToStringMap(sc.Command.Params), want)
		require.NoError(t, err)
		assert.NoError(t, verifier.Verify(b, sc.Signature))
		assert.Zero(t, cmd.SigningPayloadVersion, "input command is not mutated")
	}
}

func TestSignCommand_NilSignerLeavesUnsigned(t *testing.T) {
	caps := NewSigningCapabilities()
	require.NoError(t, caps.Record("s", []uint32{2}))
	sc, err := SignCommand(&Command{ID: "c", StewardID: "s"}, nil, caps)
	require.NoError(t, err)
	assert.Nil(t, sc.Signature)
	assert.Zero(t, sc.Command.SigningPayloadVersion)
}
