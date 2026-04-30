// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cfgis/cfgms/features/config/signature"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
)

// ---------------------------------------------------------------------------
// configTransferSession delivers a pre-built ConfigTransfer from ReceiveConfig.
// It is a real implementation of DataPlaneSession, not a mock — all method
// calls are handled explicitly and the transfer is returned without alteration.
// ---------------------------------------------------------------------------

type configTransferSession struct {
	transfer *dpTypes.ConfigTransfer
	err      error
}

var _ dataplaneInterfaces.DataPlaneSession = (*configTransferSession)(nil)

func (s *configTransferSession) ID() string                    { return "sig-test-session" }
func (s *configTransferSession) PeerID() string                { return "controller" }
func (s *configTransferSession) IsClosed() bool                { return false }
func (s *configTransferSession) LocalAddr() string             { return "127.0.0.1:0" }
func (s *configTransferSession) RemoteAddr() string            { return "127.0.0.1:1" }
func (s *configTransferSession) Close(_ context.Context) error { return nil }
func (s *configTransferSession) SendConfig(_ context.Context, _ *dpTypes.ConfigTransfer) error {
	return nil
}
func (s *configTransferSession) ReceiveConfig(_ context.Context) (*dpTypes.ConfigTransfer, error) {
	return s.transfer, s.err
}
func (s *configTransferSession) SendDNA(_ context.Context, _ *dpTypes.DNATransfer) error { return nil }
func (s *configTransferSession) ReceiveDNA(_ context.Context) (*dpTypes.DNATransfer, error) {
	return nil, nil
}
func (s *configTransferSession) SendBulk(_ context.Context, _ *dpTypes.BulkTransfer) error {
	return nil
}
func (s *configTransferSession) ReceiveBulk(_ context.Context) (*dpTypes.BulkTransfer, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newSigningCA creates a CA and returns it together with a ConfigSigner whose
// signing certificate was issued by that CA and a PEM string usable as
// signingCertPEM in TransportClient.
func newSigningCA(t *testing.T) (ca *cfgcert.CA, signer signature.Signer, certPEM string) {
	t.Helper()

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Signature Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	cert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "controller-signing-test",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	signer, err = signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  cert.PrivateKeyPEM,
		CertificatePEM: cert.CertificatePEM,
	})
	require.NoError(t, err)

	return ca, signer, string(cert.CertificatePEM)
}

// signedTransfer builds a ConfigTransfer whose Signature is produced by signer
// over the given data payload.
func signedTransfer(t *testing.T, signer signature.Signer, data []byte) *dpTypes.ConfigTransfer {
	t.Helper()
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	sigJSON, err := json.Marshal(sig)
	require.NoError(t, err)
	return &dpTypes.ConfigTransfer{
		ID:        "sig-transfer-test",
		Version:   "1.0",
		Data:      data,
		Signature: sigJSON,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestGetConfiguration_ValidSignature verifies that GetConfiguration succeeds
// when the ConfigTransfer carries a valid signature produced by a real signer
// and the TransportClient is configured with the matching verifier certificate.
func TestGetConfiguration_ValidSignature(t *testing.T) {
	_, signer, certPEM := newSigningCA(t)

	payload := []byte("valid config payload")
	transfer := signedTransfer(t, signer, payload)

	tc := &TransportClient{
		dataPlaneSession: &configTransferSession{transfer: transfer},
		signingCertPEM:   certPEM,
		logger:           newTestLogger(t),
	}

	gotData, gotVersion, err := tc.GetConfiguration(context.Background(), nil)
	require.NoError(t, err, "valid signature must pass verification")
	assert.Equal(t, payload, gotData)
	assert.Equal(t, "1.0", gotVersion)
}

// TestGetConfiguration_TamperedData_ReturnsDataLoss verifies that GetConfiguration
// returns codes.DataLoss when transfer.Data has been tampered after signing.
// This is the canonical integration test: real controller signer + real steward
// verifier; the tampered payload causes signature mismatch → DataLoss.
func TestGetConfiguration_TamperedData_ReturnsDataLoss(t *testing.T) {
	_, signer, certPEM := newSigningCA(t)

	originalData := []byte("original config payload")
	sig, err := signer.Sign(originalData)
	require.NoError(t, err)
	sigJSON, err := json.Marshal(sig)
	require.NoError(t, err)

	// Signature is over originalData but Data field is tampered.
	tampered := &dpTypes.ConfigTransfer{
		ID:        "tamper-test",
		Version:   "1.0",
		Data:      []byte("TAMPERED config payload"),
		Signature: sigJSON,
	}

	tc := &TransportClient{
		dataPlaneSession: &configTransferSession{transfer: tampered},
		signingCertPEM:   certPEM,
		logger:           newTestLogger(t),
	}

	_, _, err = tc.GetConfiguration(context.Background(), nil)
	require.Error(t, err)
	assert.Equal(t, codes.DataLoss, status.Code(err),
		"tampered data must return codes.DataLoss, got: %v", err)
}

// TestGetConfiguration_SkipsVerification_WhenNoCert verifies that GetConfiguration
// succeeds (skips verification) when no signing certificate is configured on the
// client — backward-compatible with controllers that do not sign.
func TestGetConfiguration_SkipsVerification_WhenNoCert(t *testing.T) {
	_, signer, _ := newSigningCA(t)

	payload := []byte("config payload — no cert configured")
	transfer := signedTransfer(t, signer, payload)

	// No signingCertPEM / serverCertPEM / caCertPEM / certPath configured.
	tc := &TransportClient{
		dataPlaneSession: &configTransferSession{transfer: transfer},
		logger:           newTestLogger(t),
	}

	gotData, _, err := tc.GetConfiguration(context.Background(), nil)
	require.NoError(t, err, "missing cert must skip verification (not fail)")
	assert.Equal(t, payload, gotData)
}

// TestGetConfiguration_SkipsVerification_WhenEmptySignature verifies that
// GetConfiguration succeeds without error when the ConfigTransfer carries no
// signature — backward-compatible with unsigned controller deployments.
func TestGetConfiguration_SkipsVerification_WhenEmptySignature(t *testing.T) {
	_, _, certPEM := newSigningCA(t)

	// Transfer with verifier cert configured but no Signature.
	transfer := &dpTypes.ConfigTransfer{
		ID:      "unsigned-transfer",
		Version: "1.0",
		Data:    []byte("unsigned config payload"),
	}

	tc := &TransportClient{
		dataPlaneSession: &configTransferSession{transfer: transfer},
		signingCertPEM:   certPEM,
		logger:           newTestLogger(t),
	}

	gotData, _, err := tc.GetConfiguration(context.Background(), nil)
	require.NoError(t, err, "empty signature must skip verification (not fail)")
	assert.Equal(t, transfer.Data, gotData)
}
