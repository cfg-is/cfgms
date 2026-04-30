// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/service"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	dataplaneTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Register storage providers required by CreateOSSStorageManager.
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testConfigStream is a test double for grpc.ServerStreamingServer[transportpb.ConfigChunk].
// HandleGRPC calls only Send(); the remaining ServerStream methods are no-ops.
type testConfigStream struct {
	chunks []*transportpb.ConfigChunk
}

func (s *testConfigStream) Send(c *transportpb.ConfigChunk) error {
	s.chunks = append(s.chunks, c)
	return nil
}
func (s *testConfigStream) SetHeader(metadata.MD) error  { return nil }
func (s *testConfigStream) SendHeader(metadata.MD) error { return nil }
func (s *testConfigStream) SetTrailer(metadata.MD)       {}
func (s *testConfigStream) Context() context.Context     { return context.Background() }
func (s *testConfigStream) SendMsg(interface{}) error    { return nil }
func (s *testConfigStream) RecvMsg(interface{}) error    { return nil }

// newTestCA creates and initialises a fresh CA backed by in-memory key material.
func newTestCA(t *testing.T) *cfgcert.CA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Transport Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	return ca
}

// peerContextWithCA generates a real client certificate from ca with cn as its
// Common Name and returns a context carrying that certificate as the gRPC peer.
func peerContextWithCA(t *testing.T, ca *cfgcert.CA, cn string) context.Context {
	t.Helper()
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   cn,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block, "PEM decode of client cert must succeed")
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{x509Cert},
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// createTestService returns a ConfigurationServiceV2 backed by real flatfile+SQLite
// storage rooted in a temporary directory that is cleaned up after the test.
func createTestService(t *testing.T) *service.ConfigurationServiceV2 {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(
		tmpDir+"/flatfile",
		tmpDir+"/cfgms.db",
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })
	return service.NewConfigurationServiceV2(logging.NewNoopLogger(), storageManager, nil)
}

// minimalStewardConfig returns a valid StewardConfig for stewardID.
func minimalStewardConfig(stewardID string) *stewardconfig.StewardConfig {
	return &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   stewardID,
			Mode: stewardconfig.ModeController,
			Logging: stewardconfig.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: stewardconfig.ErrorHandlingConfig{
				ModuleLoadFailure:  stewardconfig.ActionContinue,
				ResourceFailure:    stewardconfig.ActionWarn,
				ConfigurationError: stewardconfig.ActionFail,
			},
		},
		Modules: map[string]string{
			"directory": "directory",
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-dir",
				Module: "directory",
				Config: map[string]interface{}{
					"path":        "/tmp/cfgms-test",
					"permissions": "755",
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// HandleGRPC — mTLS peer validation tests
// ---------------------------------------------------------------------------

// TestHandleGRPC_MissingPeerCert verifies that a request arriving with no peer
// in context (no mTLS certificate at all) is rejected with Unauthenticated.
func TestHandleGRPC_MissingPeerCert(t *testing.T) {
	svc := createTestService(t)
	h := NewConfigHandler(svc, logging.NewNoopLogger(), nil)

	req := &transportpb.ConfigSyncRequest{StewardId: "steward-xyz"}
	stream := &testConfigStream{}

	// context.Background() carries no peer info.
	err := h.HandleGRPC(context.Background(), req, stream)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Empty(t, stream.chunks, "no chunks should be sent on auth failure")
}

// TestHandleGRPC_StewardIDMismatch verifies that when the steward ID in the
// request does not match the CN from the peer's mTLS certificate the handler
// returns PermissionDenied without leaking the actual CN or steward ID values.
func TestHandleGRPC_StewardIDMismatch(t *testing.T) {
	ca := newTestCA(t)
	svc := createTestService(t)
	h := NewConfigHandler(svc, logging.NewNoopLogger(), nil)

	// Peer authenticates as "steward-alice".
	ctx := peerContextWithCA(t, ca, "steward-alice")

	// Request claims to be "steward-bob" — intentional mismatch.
	req := &transportpb.ConfigSyncRequest{StewardId: "steward-bob"}
	stream := &testConfigStream{}

	err := h.HandleGRPC(ctx, req, stream)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Error message must not include the CN or steward ID (no information disclosure).
	msg := status.Convert(err).Message()
	assert.NotContains(t, msg, "steward-alice", "error must not disclose the peer CN")
	assert.NotContains(t, msg, "steward-bob", "error must not disclose the request steward ID")

	assert.Empty(t, stream.chunks, "no chunks should be sent on permission denied")
}

// TestHandleGRPC_MatchingStewardIDProceedsNormally verifies that when the steward
// ID in the request matches the CN from the peer's mTLS certificate the auth
// check passes and the handler successfully streams config chunks to the client.
func TestHandleGRPC_MatchingStewardIDProceedsNormally(t *testing.T) {
	const stewardID = "steward-matching"

	ca := newTestCA(t)
	svc := createTestService(t)
	h := NewConfigHandler(svc, logging.NewNoopLogger(), nil)

	// Store a real configuration so GetConfiguration returns OK.
	err := svc.SetConfiguration(context.Background(), "default", stewardID, minimalStewardConfig(stewardID))
	require.NoError(t, err)

	ctx := peerContextWithCA(t, ca, stewardID)
	req := &transportpb.ConfigSyncRequest{StewardId: stewardID}
	stream := &testConfigStream{}

	err = h.HandleGRPC(ctx, req, stream)

	require.NoError(t, err, "matching steward ID must allow the request through")
	assert.NotEmpty(t, stream.chunks, "at least one config chunk must be sent on success")
}

// ---------------------------------------------------------------------------
// HandleGRPC — ConfigTransfer.Signature population tests
// ---------------------------------------------------------------------------

// newTestSignerFromCA generates a server certificate from ca and builds a
// real ConfigSigner from its private key for use in HandleGRPC tests.
func newTestSignerFromCA(t *testing.T, ca *cfgcert.CA) signature.Signer {
	t.Helper()
	cert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "controller-signing",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  cert.PrivateKeyPEM,
		CertificatePEM: cert.CertificatePEM,
	})
	require.NoError(t, err)
	return signer
}

// assembleConfigTransfer reassembles the chunks captured by testConfigStream into
// a ConfigTransfer by sorting, concatenating, and JSON-unmarshalling.
func assembleConfigTransfer(t *testing.T, stream *testConfigStream) *dataplaneTypes.ConfigTransfer {
	t.Helper()
	require.NotEmpty(t, stream.chunks, "must have at least one chunk")

	sorted := make([]*transportpb.ConfigChunk, len(stream.chunks))
	copy(sorted, stream.chunks)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ChunkIndex < sorted[j].ChunkIndex
	})

	var data []byte
	for _, c := range sorted {
		data = append(data, c.Data...)
	}

	var transfer dataplaneTypes.ConfigTransfer
	err := json.Unmarshal(data, &transfer)
	require.NoError(t, err, "chunks must reassemble to a valid ConfigTransfer JSON")
	return &transfer
}

// TestHandleGRPC_PopulatesSignatureWhenSignerSet verifies that HandleGRPC stores a
// non-empty JSON-encoded ConfigSignature in ConfigTransfer.Signature when a signer
// is configured, and that the signature covers the serialised proto config payload.
func TestHandleGRPC_PopulatesSignatureWhenSignerSet(t *testing.T) {
	const stewardID = "steward-signed"

	ca := newTestCA(t)
	svc := createTestService(t)
	signer := newTestSignerFromCA(t, ca)
	h := NewConfigHandler(svc, logging.NewNoopLogger(), signer)

	err := svc.SetConfiguration(context.Background(), "default", stewardID, minimalStewardConfig(stewardID))
	require.NoError(t, err)

	ctx := peerContextWithCA(t, ca, stewardID)
	req := &transportpb.ConfigSyncRequest{StewardId: stewardID}
	stream := &testConfigStream{}

	err = h.HandleGRPC(ctx, req, stream)
	require.NoError(t, err)

	transfer := assembleConfigTransfer(t, stream)

	assert.NotEmpty(t, transfer.Signature,
		"ConfigTransfer.Signature must be populated when a signer is configured")
	assert.NotEmpty(t, transfer.Data,
		"ConfigTransfer.Data must contain the serialised proto payload")

	// The signature must be a valid JSON-encoded ConfigSignature.
	var sig signature.ConfigSignature
	err = json.Unmarshal(transfer.Signature, &sig)
	require.NoError(t, err, "transfer.Signature must be valid JSON ConfigSignature")
	assert.True(t, sig.Algorithm.IsValid(), "signature algorithm must be valid")
	assert.NotEmpty(t, sig.Signature, "signature bytes must be non-empty")
}

// TestHandleGRPC_NoSignatureWhenSignerNil verifies that HandleGRPC leaves
// ConfigTransfer.Signature empty when no signer is configured.
func TestHandleGRPC_NoSignatureWhenSignerNil(t *testing.T) {
	const stewardID = "steward-unsigned"

	ca := newTestCA(t)
	svc := createTestService(t)
	h := NewConfigHandler(svc, logging.NewNoopLogger(), nil) // nil signer

	err := svc.SetConfiguration(context.Background(), "default", stewardID, minimalStewardConfig(stewardID))
	require.NoError(t, err)

	ctx := peerContextWithCA(t, ca, stewardID)
	req := &transportpb.ConfigSyncRequest{StewardId: stewardID}
	stream := &testConfigStream{}

	err = h.HandleGRPC(ctx, req, stream)
	require.NoError(t, err)

	transfer := assembleConfigTransfer(t, stream)
	assert.Empty(t, transfer.Signature,
		"ConfigTransfer.Signature must be empty when no signer is configured")
}
