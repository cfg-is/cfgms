// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	controllertransport "github.com/cfgis/cfgms/features/controller/transport"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// readbackLogStream is a minimal client-streaming server stream that replays
// fixed LogEntry messages to LogStreamHandler.HandleGRPC.
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

var _ grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse] = (*readbackLogStream)(nil)

// readbackPeerContext returns a context whose gRPC peer carries a real client
// certificate issued by a fresh CA with the given Common Name.
func readbackPeerContext(t *testing.T, cn string) context.Context {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS API Readback Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   cn,
		ValidityDays: 1,
		KeySize:      2048,
	})
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

// TestGetStewardLogs_ReadsBackEntryWrittenByLogStreamHandler covers the full
// delivery path: a steward LogStream entry written through LogStreamHandler into
// the steward-event LoggingManager is returned by GET /stewards/{id}/logs, and
// only for the steward that sent it.
func TestGetStewardLogs_ReadsBackEntryWrittenByLogStreamHandler(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "readback-host", "os": "linux",
	})
	otherID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "readback-other-host", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	handler := controllertransport.NewLogStreamHandler(
		mgr, server.controllerService, logging.NewNoopLogger(),
		controllertransport.DefaultLogStreamConfig(),
	)

	send := func(id, msg string) {
		t.Helper()
		stream := &readbackLogStream{
			ctx: readbackPeerContext(t, id),
			entries: []*transportpb.LogEntry{{
				StewardId: id,
				Level:     transportpb.Severity_SEVERITY_INFO,
				Message:   msg,
				Timestamp: timestamppb.Now(),
			}},
		}
		require.NoError(t, handler.HandleGRPC(stream))
	}
	send(stewardID, "converged via log stream")
	send(otherID, "event from another steward")
	require.NoError(t, mgr.Flush(context.Background()))

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	events := body.Data.(map[string]interface{})["events"].([]interface{})

	require.Len(t, events, 1, "only the path steward's streamed entry must be returned")
	detection := events[0].(map[string]interface{})["detection"].(map[string]interface{})
	assert.Equal(t, "converged via log stream", detection["message"])
}
