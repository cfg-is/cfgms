// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// readbackLogStream is a minimal real-shaped client stream feeding entries to
// LogStreamHandler.HandleGRPC.
type readbackLogStream struct {
	entries []*transportpb.LogEntry
	pos     int
	ctx     context.Context
}

func (s *readbackLogStream) Recv() (*transportpb.LogEntry, error) {
	if s.pos >= len(s.entries) {
		return nil, io.EOF
	}
	e := s.entries[s.pos]
	s.pos++
	return e, nil
}
func (s *readbackLogStream) SendAndClose(*transportpb.LogStreamResponse) error { return nil }
func (s *readbackLogStream) SetHeader(metadata.MD) error                       { return nil }
func (s *readbackLogStream) SendHeader(metadata.MD) error                      { return nil }
func (s *readbackLogStream) SetTrailer(metadata.MD)                            {}
func (s *readbackLogStream) Context() context.Context                          { return s.ctx }
func (s *readbackLogStream) SendMsg(interface{}) error                         { return nil }
func (s *readbackLogStream) RecvMsg(interface{}) error                         { return nil }

// readbackPeerContext returns a context carrying a CA-issued client certificate
// whose CN is stewardID, as the gRPC peer.
func readbackPeerContext(t *testing.T, stewardID string) context.Context {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{Organization: "CFGMS Readback Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: stewardID, ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	p := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates:  []*x509.Certificate{x509Cert},
		VerifiedChains:    [][]*x509.Certificate{{x509Cert}},
		HandshakeComplete: true,
	}}}
	return peer.NewContext(ctxkeys.WithSystem(context.Background()), p)
}

// TestGetStewardLogs_ReadsBackEntryWrittenByLogStreamHandler streams an entry
// through the real LogStreamHandler into an asynchronously batching manager
// (production settings: large batch, long flush interval) and reads it back
// over the REST API without the test ever calling Flush. The handler flushes
// before reading, so every entry the stream handler accepted is visible.
func TestGetStewardLogs_ReadsBackEntryWrittenByLogStreamHandler(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "readback-host", "os": "linux",
	})

	mgr, err := logging.NewLoggingManager(&logging.LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":        t.TempDir(),
			"file_prefix":      "steward-events",
			"max_file_size":    10 * 1024 * 1024,
			"compress_rotated": false,
		},
		Level:         "DEBUG",
		ServiceName:   "test-controller",
		Component:     "steward-events",
		AsyncWrites:   true,
		BatchSize:     1000,
		FlushInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, mgr.Close()) })
	server.SetStewardEventLoggingManager(mgr)

	h := controllerTransport.NewLogStreamHandler(mgr, server.controllerService, logging.NewNoopLogger(),
		controllerTransport.DefaultLogStreamConfig())
	const msg = "readback-marker-4857"
	require.NoError(t, h.HandleGRPC(&readbackLogStream{
		ctx: readbackPeerContext(t, stewardID),
		entries: []*transportpb.LogEntry{{
			StewardId: stewardID,
			Level:     transportpb.Severity_SEVERITY_INFO,
			Message:   msg,
			Timestamp: timestamppb.Now(),
		}},
	}))

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), msg,
		"entry written by the log-stream handler must be readable through the API without an explicit Flush")
}
