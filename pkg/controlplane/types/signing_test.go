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

func TestSignCommand_AlwaysSignsOverV2(t *testing.T) {
	signer, verifier := newTestSigner(t)

	cmd := &Command{ID: "c-never-seen", Type: CommandSyncConfig, StewardID: "never-seen",
		Timestamp: time.Now(), Term: 4}
	sc, err := SignCommand(cmd, signer)
	require.NoError(t, err)
	require.NotNil(t, sc.Signature)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)
	assert.Zero(t, cmd.SigningPayloadVersion, "input command is not mutated")

	b, err := CommandSigningBytesVersion(&sc.Command, InterfaceParamsToStringMap(sc.Command.Params), SigningPayloadV2)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(b, sc.Signature))

	// The term is covered: changing it after signing breaks the signature.
	tampered := sc.Command
	tampered.Term = 9_000_000
	b, err = CommandSigningBytesVersion(&tampered, InterfaceParamsToStringMap(tampered.Params), SigningPayloadV2)
	require.NoError(t, err)
	assert.Error(t, verifier.Verify(b, sc.Signature))
}

func TestSignCommand_NilSignerLeavesUnsignedButV2(t *testing.T) {
	sc, err := SignCommand(&Command{ID: "c", StewardID: "s"}, nil)
	require.NoError(t, err)
	assert.Nil(t, sc.Signature)
	assert.Equal(t, SigningPayloadV2, sc.Command.SigningPayloadVersion)
}
