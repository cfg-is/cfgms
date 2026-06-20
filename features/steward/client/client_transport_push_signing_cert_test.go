// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the COMMAND_TYPE_PUSH_SIGNING_CERT handler registered in
// setupCommandHandler (Issue #1816).
//
// Tests:
//   - TestStewardPushSigningCertPersistBeforeAck — persist failure leaves in-memory state unchanged
//   - TestStewardOverlapExpiryEnforcedClientSide — old cert rejected after overlap window closes
//   - TestStewardPushSigningCertRejectsInvalidCert — expired or non-CodeSigning cert rejected
//   - TestCommandSigningDynamicAfterRotation — DynamicSigner switches to new cert after rotation (Issue #1844)
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
	"sync"
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

// TestCommandSigningDynamicAfterRotation verifies that a DynamicSigner-backed
// command publisher switches to the new signing cert after a rotation, and that a
// steward which receives the push_signing_cert refresh can verify the new-cert
// command (Issue #1844 acceptance criterion: rotate with retire_old=false, reconnect
// steward, issue command, assert command verification succeeds with the new signer).
func TestCommandSigningDynamicAfterRotation(t *testing.T) {
	ca := newTestCA(t)

	// Create two distinct signing certs: old (boot-time) and new (post-rotation).
	oldCert, err := ca.GenerateSigningCertificate(&cfgcert.SigningCertConfig{
		CommonName:   "old-signing-cert",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	newCert, err := ca.GenerateSigningCertificate(&cfgcert.SigningCertConfig{
		CommonName:   "new-signing-cert",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// resolverMu guards currentCert so updates are visible across goroutines
	// (the DynamicSigner may call the resolver from any goroutine).
	var resolverMu sync.Mutex
	currentCert := oldCert

	// DynamicSigner mirrors the controller's Issue #1844 fix: re-resolves the
	// current signing cert at each Sign call instead of caching the boot cert.
	dynamicSigner := signature.NewDynamicSigner(func() (string, func() (signature.SigningKeyExport, error), error) {
		resolverMu.Lock()
		c := currentCert
		resolverMu.Unlock()
		return c.SerialNumber, func() (signature.SigningKeyExport, error) {
			return signature.SigningKeyExport{
				CertificatePEM: c.CertificatePEM,
				PrivateKeyPEM:  c.PrivateKeyPEM,
			}, nil
		}, nil
	})

	// --- Step 1: Sign a command with the boot (old) cert ---
	bootData := []byte("command before rotation")
	bootSig, err := dynamicSigner.Sign(bootData)
	require.NoError(t, err)

	// --- Step 2: Steward connects, trusts only the old cert ---
	c := minimalClientForPushTest(t)
	c.mu.Lock()
	c.signingCertPEMs = []string{string(oldCert.CertificatePEM)}
	c.mu.Unlock()

	bootVerifier := c.buildVerifierOnDemand()
	require.NotNil(t, bootVerifier)
	require.NoError(t, bootVerifier.Verify(bootData, bootSig),
		"pre-rotation command must be verifiable by the old cert")

	// --- Step 3: Controller rotates signing cert (retire_old=false: overlap active) ---
	// The DynamicSigner's resolver now returns the new cert.
	resolverMu.Lock()
	currentCert = newCert
	resolverMu.Unlock()

	// --- Step 4: Steward receives push_signing_cert with new cert (refresh-on-connect) ---
	// retire_old is not set (defaults false), so both old and new certs are trusted
	// during the overlap window — matching the AC's "retire_old=false" scenario.
	newCertPEMb64 := base64.StdEncoding.EncodeToString(newCert.CertificatePEM)
	overlapDeadline := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	err = c.handlePushSigningCert(context.Background(), &cpTypes.Command{
		ID:        "push-new-cert",
		Type:      cpTypes.CommandPushSigningCert,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"cert_pem":           newCertPEMb64,
			"overlap_expires_at": overlapDeadline,
		},
	})
	require.NoError(t, err, "push_signing_cert with new cert must succeed")

	// Verify the steward now holds both certs (overlap window open).
	c.mu.RLock()
	pemCount := len(c.signingCertPEMs)
	c.mu.RUnlock()
	require.Equal(t, 2, pemCount, "steward must hold both old and new cert during overlap")

	// --- Step 5: Controller issues a command signed with the new cert ---
	// The DynamicSigner resolves the new cert because the resolver was updated in step 3.
	rotatedData := []byte("command after rotation")
	rotatedSig, err := dynamicSigner.Sign(rotatedData)
	require.NoError(t, err)

	// --- Step 6: Steward builds a new verifier (simulates reconnect after push_signing_cert) ---
	// Both old and new certs are in signingCertPEMs; the verifier is a MultiVerifier.
	reconnectVerifier := c.buildVerifierOnDemand()
	require.NotNil(t, reconnectVerifier)

	// Command signed with the NEW cert must be verified successfully (AC criterion 4).
	require.NoError(t, reconnectVerifier.Verify(rotatedData, rotatedSig),
		"post-rotation command signed with new cert must be verifiable after refresh")

	// Confirm the DynamicSigner actually switched certs: a verifier backed only by
	// the OLD cert must reject the post-rotation command, proving the DynamicSigner
	// resolved the new cert rather than replaying the cached boot cert.
	oldOnlyVerifier, verErr := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: oldCert.CertificatePEM,
	})
	require.NoError(t, verErr)
	require.Error(t, oldOnlyVerifier.Verify(rotatedData, rotatedSig),
		"post-rotation command must be rejected by old-cert-only verifier, confirming DynamicSigner switched certs")
}
