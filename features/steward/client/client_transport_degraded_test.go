// SPDX-License-Identifier: AGPL-3.0-only
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
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Resilient-startup / degraded-mode tests (Issue #2034)
// ---------------------------------------------------------------------------

// TestHeartbeatStatus_DefaultsToHealthy verifies that heartbeatStatus returns
// "healthy" when no statusFunc is configured — preserving backward compatibility.
// (Issue #2034 AC5)
func TestHeartbeatStatus_DefaultsToHealthy(t *testing.T) {
	c := &TransportClient{logger: logging.NewLogger("error")}
	assert.Equal(t, "healthy", c.heartbeatStatus())
}

// TestHeartbeatStatus_ReportsDegraded verifies that when statusFunc returns
// "degraded", heartbeatStatus forwards the degraded status to the heartbeat
// so the controller receives the real health state. (Issue #2034 AC5)
func TestHeartbeatStatus_ReportsDegraded(t *testing.T) {
	c := &TransportClient{
		logger:     logging.NewLogger("error"),
		statusFunc: func() string { return "degraded" },
	}
	assert.Equal(t, "degraded", c.heartbeatStatus())
}

// TestSetStatusFunc_UpdatesHeartbeatStatus verifies that SetStatusFunc wires
// the caller's health provider into subsequent heartbeatStatus calls and that
// switching from degraded to healthy works correctly. (Issue #2034 AC5)
func TestSetStatusFunc_UpdatesHeartbeatStatus(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{
		ControllerURL: "localhost:4433",
		Logger:        logging.NewLogger("error"),
	})
	require.NoError(t, err)

	// Before SetStatusFunc: default "healthy".
	assert.Equal(t, "healthy", c.heartbeatStatus())

	// Wire a degraded provider.
	c.SetStatusFunc(func() string { return "degraded" })
	assert.Equal(t, "degraded", c.heartbeatStatus())

	// Transition to healthy.
	c.SetStatusFunc(func() string { return "healthy" })
	assert.Equal(t, "healthy", c.heartbeatStatus())

	// Nil clears the func → falls back to "healthy".
	c.SetStatusFunc(nil)
	assert.Equal(t, "healthy", c.heartbeatStatus())
}

// ---------------------------------------------------------------------------
// Fail-closed test: config-signature failure is rejected even in degraded mode
// ---------------------------------------------------------------------------

// configTransferSessionDegraded is a real DataPlaneSession implementation
// used only in degraded-mode tests. Structurally identical to the one in
// client_transport_signature_test.go (same package, no duplication of logic).
type configTransferSessionDegraded struct {
	transfer *dpTypes.ConfigTransfer
	err      error
}

var _ dataplaneInterfaces.DataPlaneSession = (*configTransferSessionDegraded)(nil)

func (s *configTransferSessionDegraded) ID() string                    { return "degraded-test-session" }
func (s *configTransferSessionDegraded) PeerID() string                { return "controller" }
func (s *configTransferSessionDegraded) IsClosed() bool                { return false }
func (s *configTransferSessionDegraded) LocalAddr() string             { return "127.0.0.1:0" }
func (s *configTransferSessionDegraded) RemoteAddr() string            { return "127.0.0.1:1" }
func (s *configTransferSessionDegraded) Close(_ context.Context) error { return nil }
func (s *configTransferSessionDegraded) SendConfig(_ context.Context, _ *dpTypes.ConfigTransfer) error {
	return nil
}
func (s *configTransferSessionDegraded) ReceiveConfig(_ context.Context) (*dpTypes.ConfigTransfer, error) {
	return s.transfer, s.err
}
func (s *configTransferSessionDegraded) SendDNA(_ context.Context, _ *dpTypes.DNATransfer) error {
	return nil
}
func (s *configTransferSessionDegraded) ReceiveDNA(_ context.Context) (*dpTypes.DNATransfer, error) {
	return nil, nil
}
func (s *configTransferSessionDegraded) SendBulk(_ context.Context, _ *dpTypes.BulkTransfer) error {
	return nil
}
func (s *configTransferSessionDegraded) ReceiveBulk(_ context.Context) (*dpTypes.BulkTransfer, error) {
	return nil, nil
}

// newDegradedSigningCA creates a CA + signer pair for the degraded-mode tests.
func newDegradedSigningCA(t *testing.T) (ca *cfgcert.CA, signer signature.Signer, certPEM string) {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Degraded Test CA",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	cert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "controller-degraded-test",
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

// TestDegradedMode_ConfigSignatureFailure_StillRejected verifies AC5 fail-closed:
// when the steward is in degraded mode (statusFunc returns "degraded"), a config
// with a tampered signature is still rejected with codes.DataLoss — it is NOT
// applied as "degraded config". The fail-closed requirement from Issue #2034
// (security section: "must-fail-closed paths") is preserved under degraded mode.
func TestDegradedMode_ConfigSignatureFailure_StillRejected(t *testing.T) {
	_, signer, certPEM := newDegradedSigningCA(t)

	originalData := []byte("original config payload")
	sig, err := signer.Sign(originalData)
	require.NoError(t, err)
	sigJSON, err := json.Marshal(sig)
	require.NoError(t, err)

	// Build a ConfigTransfer where the signature is over originalData but the
	// Data field has been tampered — simulating an integrity violation.
	tampered := &dpTypes.ConfigTransfer{
		ID:        "degraded-tamper-test",
		Version:   "1.0",
		Data:      []byte("TAMPERED config payload"),
		Signature: sigJSON,
	}

	// Wire a degraded statusFunc — simulates a steward that has connected but
	// whose subsystems (DNA/WMI) are still pending at the time of config sync.
	tc := &TransportClient{
		dataPlaneSession: &configTransferSessionDegraded{transfer: tampered},
		signingCertPEMs:  []string{certPEM},
		logger:           logging.NewLogger("error"),
		statusFunc:       func() string { return "degraded" },
	}

	_, _, err = tc.GetConfiguration(context.Background(), nil)
	require.Error(t, err, "tampered config must be rejected even in degraded mode")
	assert.Equal(t, codes.DataLoss, status.Code(err),
		"tampered config must return codes.DataLoss in degraded mode, not be applied-degraded; got: %v", err)
}
