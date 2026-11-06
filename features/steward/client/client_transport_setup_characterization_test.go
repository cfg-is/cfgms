// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client characterizes the observable behavior of
// TransportClient.setupCommandHandler so its decomposition (Issue #5871) cannot
// change what is wired, refused or queued.
package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

const clienttransportsetupCharStewardID = "steward-setup-char"

func clienttransportsetupCharCAPEM(t *testing.T) string {
	t.Helper()
	pem, err := newTestCA(t).GetCACertificate()
	require.NoError(t, err)
	return string(pem)
}

func clienttransportsetupCharClient(t *testing.T, cfg *TransportConfig) *TransportClient {
	t.Helper()
	cfg.ControllerURL = "localhost:4433"
	cfg.Logger = newTestLogger(t)
	c, err := NewTransportClient(cfg)
	require.NoError(t, err)
	return c
}

// clienttransportsetupCharSignedReconnect returns a reconnect command signed by signer.
func clienttransportsetupCharSignedReconnect(t *testing.T, signer signature.Signer, id string) *cpTypes.SignedCommand {
	t.Helper()
	cmd := &cpTypes.Command{
		ID:        id,
		Type:      cpTypes.CommandReconnect,
		StewardID: clienttransportsetupCharStewardID,
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}
	rawParams := cpTypes.InterfaceParamsToStringMap(cmd.Params)
	signingBytes, err := cpTypes.CommandSigningBytes(cmd, rawParams)
	require.NoError(t, err)
	sig, err := signer.Sign(signingBytes)
	require.NoError(t, err)
	return &cpTypes.SignedCommand{Command: *cmd, Signature: sig, RawParams: rawParams}
}

func TestClienttransportsetupChar_PolicyRefusals(t *testing.T) {
	validCA := clienttransportsetupCharCAPEM(t)
	required := stewardconfig.ScriptSigningConfig{
		Policy:             stewardconfig.ScriptSigningPolicyRequired,
		RequireSignedAdhoc: true,
	}

	tests := []struct {
		name       string
		cfg        TransportConfig
		publicBeta bool
		wantErr    string
	}{
		{
			name:    "require_signed_adhoc without CA is refused",
			cfg:     TransportConfig{ScriptSigning: required},
			wantErr: "require_signed_adhoc requires a valid controller CA certificate",
		},
		{
			name:    "require_signed_adhoc with unusable CA is refused",
			cfg:     TransportConfig{ScriptSigning: required, CACertPEM: "not a pem"},
			wantErr: "require_signed_adhoc requires a valid controller CA certificate",
		},
		{
			name:       "public beta with unusable CA names the signing roots",
			cfg:        TransportConfig{ScriptSigning: required, CACertPEM: "not a pem"},
			publicBeta: true,
			wantErr:    "public-beta connected execution requires valid controller signing roots",
		},
		{
			name:       "public beta without CA names the signing roots",
			cfg:        TransportConfig{ScriptSigning: required},
			publicBeta: true,
			wantErr:    "public-beta connected execution requires valid controller signing roots",
		},
		{
			name:       "public beta without require_signed_adhoc is refused",
			cfg:        TransportConfig{CACertPEM: validCA},
			publicBeta: true,
			wantErr:    "public-beta connected execution requires require_signed_adhoc: true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clienttransportsetupCharClient(t, &tt.cfg)
			// NewTransportClient refuses public beta on these inputs first; set the
			// flag afterwards to reach setupCommandHandler's own checks.
			c.publicBeta = tt.publicBeta
			h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
			require.Error(t, err)
			assert.Nil(t, h)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestClienttransportsetupChar_OperatorCertVerificationSkippedOnlyWithoutUsableRoots(t *testing.T) {
	optional := stewardconfig.ScriptSigningConfig{Policy: stewardconfig.ScriptSigningPolicyOptional}

	t.Run("no CA outside public beta builds the handler", func(t *testing.T) {
		c := clienttransportsetupCharClient(t, &TransportConfig{ScriptSigning: optional})
		h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
		require.NoError(t, err)
		require.NotNil(t, h)
		t.Cleanup(h.Wait)
	})
	t.Run("unusable CA outside public beta builds the handler", func(t *testing.T) {
		c := clienttransportsetupCharClient(t, &TransportConfig{ScriptSigning: optional, CACertPEM: "garbage"})
		h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
		require.NoError(t, err)
		require.NotNil(t, h)
		t.Cleanup(h.Wait)
	})
	t.Run("valid CA with require_signed_adhoc builds the handler", func(t *testing.T) {
		c := clienttransportsetupCharClient(t, &TransportConfig{
			CACertPEM: clienttransportsetupCharCAPEM(t),
			ScriptSigning: stewardconfig.ScriptSigningConfig{
				Policy:             stewardconfig.ScriptSigningPolicyRequired,
				RequireSignedAdhoc: true,
			},
		})
		h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
		require.NoError(t, err)
		require.NotNil(t, h)
		t.Cleanup(h.Wait)
	})
}

func TestClienttransportsetupChar_VerifierBuiltOnDemandFromStoredPEMs(t *testing.T) {
	ca := newTestCA(t)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	cert, err := ca.GenerateSigningCertificate(&cfgcert.SigningCertConfig{CommonName: "setup-char", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)

	c := clienttransportsetupCharClient(t, &TransportConfig{
		CACertPEM:       string(caPEM),
		SigningCertPEMs: []string{string(cert.CertificatePEM)},
	})
	h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
	require.NoError(t, err)
	t.Cleanup(h.Wait)
	assert.True(t, h.HasVerifier(), "a stored signing cert yields a verifier")

	// Not cached: a second setup reads the PEMs again, so a handler built after
	// the set changed verifies against the new set.
	c.mu.Lock()
	c.signingCertPEMs = nil
	c.mu.Unlock()
	h2, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
	require.NoError(t, err)
	t.Cleanup(h2.Wait)
	assert.Equal(t, c.buildVerifierOnDemand() != nil, h2.HasVerifier())
}

func TestClienttransportsetupChar_StatusEventsQueuedWhileControllerUnreachable(t *testing.T) {
	ca := newTestCA(t)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	cert, err := ca.GenerateSigningCertificate(&cfgcert.SigningCertConfig{CommonName: "setup-char", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{PrivateKeyPEM: cert.PrivateKeyPEM, CertificatePEM: cert.CertificatePEM})
	require.NoError(t, err)

	c := clienttransportsetupCharClient(t, &TransportConfig{
		CACertPEM:       string(caPEM),
		SigningCertPEMs: []string{string(cert.CertificatePEM)},
	})
	queue, err := NewOfflineQueue(OfflineQueueConfig{})
	require.NoError(t, err)
	c.mu.Lock()
	c.offlineQueue = queue
	c.controlPlane = nil
	c.mu.Unlock()

	h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
	require.NoError(t, err)

	// Reconnect with no control plane fails inside the handler; the failure
	// status event must be queued rather than lost.
	require.NoError(t, h.HandleCommand(context.Background(),
		clienttransportsetupCharSignedReconnect(t, signer, "setup-char-queue")))
	h.Wait()
	assert.Greater(t, queue.Len(), 0, "status events published while unreachable are queued")
}

func TestClienttransportsetupChar_SyncDNAWithoutSessionReportsFailureToQueue(t *testing.T) {
	c := clienttransportsetupCharClient(t, &TransportConfig{})
	queue, err := NewOfflineQueue(OfflineQueueConfig{})
	require.NoError(t, err)
	c.mu.Lock()
	c.offlineQueue = queue
	c.mu.Unlock()

	h, err := c.setupCommandHandler(context.Background(), clienttransportsetupCharStewardID)
	require.NoError(t, err)

	require.NoError(t, h.HandleCommand(context.Background(), &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "setup-char-dna",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: clienttransportsetupCharStewardID,
		Timestamp: time.Now(),
	}}))
	h.Wait()
	assert.Greater(t, queue.Len(), 0, "sync_dna with no data plane session reports a failure event")
}
