// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// TestBuildAndSignActionEnvelope_HonoursSigningCredentialSelector signs a steward
// action under two connections and with an explicit selector, and verifies the
// signature over the envelope's canonical bytes with the matching certificate.
func TestBuildAndSignActionEnvelope_HonoursSigningCredentialSelector(t *testing.T) {
	env := newSigningTestEnv(t)
	keyA := env.issue(t, "signing-key.conn-a", "")
	keyB := env.issue(t, "signing-key.conn-b", "")
	action := operatorpayload.Action{Verb: "service.restart", TargetKind: "service", TargetName: "spooler"}

	verify := func(want *ecdsa.PrivateKey) {
		t.Helper()
		sig, envelope, err := buildAndSignActionEnvelope(action, "steward-1")
		require.NoError(t, err)
		canonical, err := operatorpayload.CanonicalBytes(envelope)
		require.NoError(t, err)
		assert.Equal(t, []string{"steward-1"}, envelope.Targets)
		requireSignedBy(t, sig, canonical, want)
		block, _ := pem.Decode([]byte(sig.PublicKey))
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		raw, err := base64.StdEncoding.DecodeString(sig.Value)
		require.NoError(t, err)
		digest := sha256.Sum256(canonical)
		assert.True(t, ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], raw))
	}

	env.connect(t, "conn-a")
	verify(keyA)

	signingCredentialSelector = "signing-key.conn-b"
	verify(keyB)

	signingCredentialSelector = "signing-key.absent"
	sig, _, err := buildAndSignActionEnvelope(action, "steward-1")
	require.Error(t, err)
	assert.Nil(t, sig)
	assert.Contains(t, err.Error(), "--signing-credential signing-key.absent")
}
