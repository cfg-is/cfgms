// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the COMMAND_TYPE_PUSH_SIGNING_CERT handler registered in
// setupCommandHandler (Issue #1816).
//
// Tests:
//   - TestStewardPushSigningCertPersistBeforeAck — persist failure leaves in-memory state unchanged
//   - TestStewardOverlapExpiryEnforcedClientSide — old cert rejected after overlap window closes
//   - TestStewardPushSigningCertRejectsInvalidCert — expired or non-CodeSigning cert rejected
package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// newCodeSigningCert creates a CA-signed cert with ExtKeyUsageCodeSigning.
func newCodeSigningCert(t *testing.T, ca *cfgcert.CA) []byte {
	t.Helper()
	cert, err := ca.GenerateSigningCertificate(&cfgcert.SigningCertConfig{
		CommonName:   "test-signing-cert",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	return cert.CertificatePEM
}

// newCodeSigningCertBase64 wraps newCodeSigningCert and base64-encodes the PEM.
func newCodeSigningCertBase64(t *testing.T, ca *cfgcert.CA) string {
	t.Helper()
	pem := newCodeSigningCert(t, ca)
	return base64.StdEncoding.EncodeToString(pem)
}

// newTestCA creates and initialises a throwaway CA for signing-cert tests.
func newTestCA(t *testing.T) *cfgcert.CA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Push Signing Cert Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	return ca
}

// minimalClientForPushTest creates a TransportClient with only the fields needed
// for the push-signing-cert handler tests (no control-plane, no data-plane).
func minimalClientForPushTest(t *testing.T) *TransportClient {
	t.Helper()
	c := &TransportClient{
		stewardID:       "test-steward",
		tenantID:        "test-tenant",
		heartbeatStop:   make(chan struct{}),
		convergenceStop: make(chan struct{}),
		logger:          newTestLogger(t),
	}
	return c
}

// buildPushCmd creates a SignedCommand for CommandPushSigningCert from the given params.
func buildPushCmd(params map[string]interface{}) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-push-" + time.Now().Format("150405.000000000"),
		Type:      cpTypes.CommandPushSigningCert,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params:    params,
	}}
}

// TestStewardPushSigningCertPersistBeforeAck verifies that if the identity persist
// function fails, the in-memory signing cert PEMs are left unchanged and the handler
// returns an error (persist-before-ack contract, Issue #1816).
func TestStewardPushSigningCertPersistBeforeAck(t *testing.T) {
	ca := newTestCA(t)
	certPEMb64 := newCodeSigningCertBase64(t, ca)

	persistErr := errors.New("disk full — persist failed")
	var persistCalled bool

	c := minimalClientForPushTest(t)
	originalPEMs := []string{"original-pem"}
	c.mu.Lock()
	c.signingCertPEMs = originalPEMs
	c.identityPersistFunc = func(pems []string, at *time.Time) error {
		persistCalled = true
		return persistErr
	}
	c.mu.Unlock()

	// Dispatch the push command directly.
	err := c.handlePushSigningCert(context.Background(), &cpTypes.Command{
		ID:        "cmd-persist-test",
		Type:      cpTypes.CommandPushSigningCert,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"cert_pem": certPEMb64,
		},
	})

	require.Error(t, err, "handler must return error when persist fails")
	assert.True(t, persistCalled, "persist func must have been called")

	// In-memory state must be unchanged.
	c.mu.RLock()
	currentPEMs := c.signingCertPEMs
	c.mu.RUnlock()
	require.Equal(t, originalPEMs, currentPEMs, "in-memory signingCertPEMs must be unchanged after persist failure")
}

// TestStewardOverlapExpiryEnforcedClientSide verifies that when time is past
// overlapExpiresAt, buildVerifierOnDemand uses only the newest cert and a config
// signed by the old cert is rejected (Issue #1816).
func TestStewardOverlapExpiryEnforcedClientSide(t *testing.T) {
	// Create two signing CAs / certs (old and new).
	oldCA := newTestCA(t)
	newCA := newTestCA(t)

	oldCertPEM := newCodeSigningCert(t, oldCA)
	newCertPEM := newCodeSigningCert(t, newCA)

	// Build a signer using the OLD cert key.
	oldCert, err := oldCA.GenerateSigningCertificate(&cfgcert.SigningCertConfig{
		CommonName:   "old-signing-key",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	oldSigner, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  oldCert.PrivateKeyPEM,
		CertificatePEM: oldCert.CertificatePEM,
	})
	require.NoError(t, err)

	data := []byte("config signed by old key")
	sig, err := oldSigner.Sign(data)
	require.NoError(t, err)

	// Client holds both old and new certs; overlap window is PAST.
	pastTime := time.Now().Add(-time.Minute)
	c := minimalClientForPushTest(t)
	c.mu.Lock()
	c.signingCertPEMs = []string{string(oldCertPEM), string(newCertPEM)}
	c.overlapExpiresAt = &pastTime
	c.mu.Unlock()

	verifier := c.buildVerifierOnDemand()
	require.NotNil(t, verifier, "verifier must not be nil")

	// Old cert was used to sign; past overlap expiry means only the NEW cert is in the
	// verifier — so the old-cert signature must fail.
	err = verifier.Verify(data, sig)
	assert.Error(t, err, "old-cert-signed config must be rejected after overlap_expires_at")
}

// TestStewardPushSigningCertRejectsInvalidCert verifies that the handler rejects
// certs that are expired or that lack ExtKeyUsageCodeSigning (Issue #1816).
func TestStewardPushSigningCertRejectsInvalidCert(t *testing.T) {
	ca := newTestCA(t)

	t.Run("expired_cert_rejected", func(t *testing.T) {
		// Build a raw x509 cert with CodeSigning EKU whose NotAfter is in the past.
		// The CA helper always generates valid certs, so we use crypto/x509 directly
		// to produce a backdated cert that exercises the time.Now().After(NotAfter) branch.
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, keyErr)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "expired-code-signing"},
			NotBefore:    time.Now().Add(-2 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour), // already expired
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		certDER, derErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, derErr)
		certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certB64 := base64.StdEncoding.EncodeToString(certPEMBytes)

		c := minimalClientForPushTest(t)
		err := c.handlePushSigningCert(context.Background(), &cpTypes.Command{
			ID: "cmd-expired", Type: cpTypes.CommandPushSigningCert,
			StewardID: "test-steward", TenantID: "test-tenant", Timestamp: time.Now(),
			Params: map[string]interface{}{"cert_pem": certB64},
		})
		require.Error(t, err, "expired cert must be rejected")
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("non_code_signing_eku_rejected", func(t *testing.T) {
		// Generate a client cert — it has ClientAuth EKU, not CodeSigning.
		clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
			CommonName:   "client-not-signing",
			Organization: "Test",
			ValidityDays: 1,
			KeySize:      2048,
		})
		require.NoError(t, err)
		clientCertB64 := base64.StdEncoding.EncodeToString(clientCert.CertificatePEM)

		c := minimalClientForPushTest(t)
		err = c.handlePushSigningCert(context.Background(), &cpTypes.Command{
			ID: "cmd-client-eku", Type: cpTypes.CommandPushSigningCert,
			StewardID: "test-steward", TenantID: "test-tenant", Timestamp: time.Now(),
			Params: map[string]interface{}{"cert_pem": clientCertB64},
		})
		require.Error(t, err, "client cert (ClientAuth EKU, not CodeSigning) must be rejected")
		assert.Contains(t, err.Error(), "ExtKeyUsageCodeSigning")
	})

	t.Run("valid_code_signing_cert_accepted", func(t *testing.T) {
		certPEMb64 := newCodeSigningCertBase64(t, ca)
		c := minimalClientForPushTest(t)
		err := c.handlePushSigningCert(context.Background(), &cpTypes.Command{
			ID: "cmd-valid", Type: cpTypes.CommandPushSigningCert,
			StewardID: "test-steward", TenantID: "test-tenant", Timestamp: time.Now(),
			Params: map[string]interface{}{"cert_pem": certPEMb64},
		})
		require.NoError(t, err, "valid CodeSigning cert must be accepted")

		c.mu.RLock()
		pems := c.signingCertPEMs
		c.mu.RUnlock()
		assert.Len(t, pems, 1, "one cert must be stored after push")
	})
}
