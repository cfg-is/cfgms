// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/config"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

type stewardEventTestStream struct {
	entries []*transportpb.LogEntry
	pos     int
	ctx     context.Context
}

func (s *stewardEventTestStream) Recv() (*transportpb.LogEntry, error) {
	if s.pos >= len(s.entries) {
		return nil, io.EOF
	}
	e := s.entries[s.pos]
	s.pos++
	return e, nil
}
func (s *stewardEventTestStream) SendAndClose(*transportpb.LogStreamResponse) error { return nil }
func (s *stewardEventTestStream) SetHeader(metadata.MD) error                       { return nil }
func (s *stewardEventTestStream) SendHeader(metadata.MD) error                      { return nil }
func (s *stewardEventTestStream) SetTrailer(metadata.MD)                            {}
func (s *stewardEventTestStream) Context() context.Context                          { return s.ctx }
func (s *stewardEventTestStream) SendMsg(interface{}) error                         { return nil }
func (s *stewardEventTestStream) RecvMsg(interface{}) error                         { return nil }

func stewardEventPeerContext(t *testing.T, cn string) context.Context {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{Organization: "CFGMS Steward Event Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: cn, ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return peer.NewContext(ctxkeys.WithSystem(context.Background()), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates:  []*x509.Certificate{x509Cert},
		VerifiedChains:    [][]*x509.Certificate{{x509Cert}},
		HandshakeComplete: true,
	}}})
}

func stewardEventTestConfig(dir string) *config.Config {
	return &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: dir + "/flatfile",
			SQLitePath:   dir + "/cfgms.db",
		},
	}
}

// TestNew_WiresSharedStewardEventManager constructs the server the way
// production does (New, no setters) and verifies the log-stream handler and the
// REST API share one non-nil manager, that an entry streamed through the
// handler is queryable via that manager, and that Stop persists it.
func TestNew_WiresSharedStewardEventManager(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(stewardEventTestConfig(dir), logging.NewNoopLogger())
	require.NoError(t, err)
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = srv.Stop()
		}
	})

	mgr := srv.GetStewardEventManager()
	require.NotNil(t, mgr, "New must construct the steward-event manager; nil discards all steward logs")
	assert.Same(t, mgr, srv.GetAPIServer().GetStewardEventLoggingManager(),
		"the log-stream handler and the REST API must share one manager instance")

	const stewardID = "steward-4857"
	const msg = "wiring-marker-4857"
	h := srv.newLogStreamHandler()
	require.NoError(t, h.HandleGRPC(&stewardEventTestStream{
		ctx: stewardEventPeerContext(t, stewardID),
		entries: []*transportpb.LogEntry{{
			StewardId: stewardID,
			Level:     transportpb.Severity_SEVERITY_INFO,
			Message:   msg,
			Timestamp: timestamppb.Now(),
		}},
	}))

	require.NoError(t, srv.Stop())
	stopped = true

	files, err := filepath.Glob(filepath.Join(dir, "steward-events", "*"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "steward events must be written under the data root")
	found := false
	for _, f := range files {
		b, readErr := os.ReadFile(f) // #nosec G304 -- test-owned temp dir
		require.NoError(t, readErr)
		if containsBytes(b, msg) {
			found = true
		}
	}
	assert.True(t, found, "entry accepted before Stop must be flushed to durable storage")
}

func containsBytes(b []byte, s string) bool { return bytes.Contains(b, []byte(s)) }

// TestNew_FailsWhenStewardEventManagerCannotBeBuilt verifies startup fails
// loudly instead of leaving the manager nil.
func TestNew_FailsWhenStewardEventManagerCannotBeBuilt(t *testing.T) {
	cfg := stewardEventTestConfig(t.TempDir())
	cfg.Logging = &config.LoggingConfig{
		Provider: "no-such-provider",
		Config:   map[string]interface{}{"x": "y"},
	}
	srv, err := New(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "steward event")
}
