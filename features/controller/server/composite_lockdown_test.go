// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	stewardosquery "github.com/cfgis/cfgms/features/steward/osquery"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// ---------------------------------------------------------------------------
// Inventory: every RPC of the generated service descriptor is classified.
// ---------------------------------------------------------------------------

func TestCompositeLockdown_InventoryCoversServiceDescriptor(t *testing.T) {
	desc := transportpb.StewardTransport_ServiceDesc
	seen := map[string]bool{}
	for _, m := range desc.Methods {
		seen[m.MethodName] = true
	}
	for _, s := range desc.Streams {
		seen[s.StreamName] = true
	}
	require.NotEmpty(t, seen)

	for name := range seen {
		class, ok := rpcLockdownClassification[name]
		assert.True(t, ok, "RPC %s has no lockdown classification: add it to rpcLockdownClassification", name)
		assert.NotEmpty(t, class)
	}
	for name := range rpcLockdownClassification {
		assert.True(t, seen[name], "classification names %s, which is not an RPC of the service descriptor", name)
	}
}

func TestCompositeLockdown_InventoryRecordsRegisterAndMintingRoutes(t *testing.T) {
	assert.Equal(t, classExempt, rpcLockdownClassification["Register"], "gRPC Register is an admission ack that mints nothing")

	apiSrc, err := os.ReadFile("../api/server.go")
	require.NoError(t, err)
	for route, owner := range httpMintingRoutes {
		path := strings.Fields(route)[1]
		assert.Contains(t, string(apiSrc), `"`+path+`"`, "route %s is listed but not registered", route)
		assert.NotEmpty(t, owner, "route %s needs an owning story", route)
	}
	assert.Contains(t, httpMintingRoutes, "POST /api/v1/register")
	assert.Contains(t, httpMintingRoutes, "POST /api/v1/stewards/{device_id}/refresh/complete")
}

// Every RPC that hands data to a steward is refuse; nothing serving config,
// bundles or secrets is accept or exempt.
func TestCompositeLockdown_ServingRPCsAreRefused(t *testing.T) {
	for _, name := range []string{"SyncConfig", "FetchModuleBundle", "IssueInitialCredential"} {
		assert.Equal(t, classRefuse, rpcLockdownClassification[name], name)
	}
}

// ---------------------------------------------------------------------------
// Per-RPC behavior for a tampered steward, through the composite server.
// ---------------------------------------------------------------------------

type lockdownEnv struct {
	t         *testing.T
	ld        *fleet.Lockdown
	composite *compositeTransportServer
	cp        *recordingHandler
	osquery   *stewardosquery.OsqueryHandler
}

func newLockdownEnv(t *testing.T) *lockdownEnv {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	for id, st := range map[string]business.StewardStatus{
		"tampered-1": business.StewardStatusTampered,
		"normal-1":   business.StewardStatusActive,
	} {
		require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
			ID: id, TenantID: "tenant-a", Hostname: id, Platform: "linux", Status: st,
			RegisteredAt: time.Now(), LastSeen: time.Now(),
		}))
	}
	logger := logging.NewNoopLogger()
	ld := fleet.NewLockdown(store, logger)
	cp := newRecordingHandler()
	c := newCompositeTransportServer(cp, logger)
	queue := controllerTransport.NewTenantQueue()
	c.SetConfigHandler(controllerTransport.NewConfigHandler(nil, logger, nil).WithLockdown(ld))
	c.SetModuleBundleHandler(controllerTransport.NewModuleBundleHandler(nil, nil, nil, queue, logger).WithLockdown(ld))
	c.SetCredentialHandler(controllerTransport.NewCredentialHandler(nil, nil, nil, logger).WithLockdown(ld))
	c.SetDNAHandler(controllerTransport.NewDNAHandler(logger, queue, nil))
	c.SetBulkHandler(controllerTransport.NewBulkHandler(logger, queue).WithLockdown(ld))
	c.SetLogStreamHandler(controllerTransport.NewLogStreamHandler(nil, nil, logger, controllerTransport.DefaultLogStreamConfig()))
	c.SetTelemetryHandler(controllerTransport.NewTelemetryHandler(logger, nil).WithLockdown(ld))
	c.SetTerminalHandler(controllerTransport.NewTerminalHandler(logger, nil, nil, nil, nil, nil))
	osq := stewardosquery.NewOsqueryHandler(logger, "").WithLockdown(ld)
	c.SetOsqueryHandler(osq)
	return &lockdownEnv{t: t, ld: ld, composite: c, cp: cp, osquery: osq}
}

func requireLockdownRefusal(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, controlplaneInterfaces.IsLockedDown(err), "want the typed lockdown refusal, got %v", err)
}

type streamBase struct{ ctx context.Context }

func (s streamBase) SetHeader(metadata.MD) error  { return nil }
func (s streamBase) SendHeader(metadata.MD) error { return nil }
func (s streamBase) SetTrailer(metadata.MD)       {}
func (s streamBase) Context() context.Context     { return s.ctx }
func (s streamBase) SendMsg(interface{}) error    { return nil }
func (s streamBase) RecvMsg(interface{}) error    { return nil }

type cfgOut struct {
	streamBase
	sent int
}

func (s *cfgOut) Send(*transportpb.ConfigChunk) error { s.sent++; return nil }

type bundleOut struct {
	streamBase
	sent int
}

func (s *bundleOut) Send(*transportpb.ModuleBundleChunk) error { s.sent++; return nil }

type dnaIn struct{ streamBase }

func (s *dnaIn) Recv() (*transportpb.DNAChunk, error)            { return nil, io.EOF }
func (s *dnaIn) SendAndClose(*transportpb.DNASyncResponse) error { return nil }

type bulkIO struct {
	streamBase
	in []*transportpb.BulkChunk
}

func (s *bulkIO) Recv() (*transportpb.BulkChunk, error) {
	if len(s.in) == 0 {
		return nil, io.EOF
	}
	c := s.in[0]
	s.in = s.in[1:]
	return c, nil
}
func (s *bulkIO) Send(*transportpb.BulkChunk) error { return nil }

type logIn struct{ streamBase }

func (s *logIn) Recv() (*transportpb.LogEntry, error)              { return nil, io.EOF }
func (s *logIn) SendAndClose(*transportpb.LogStreamResponse) error { return nil }

type telemetryIO struct{ streamBase }

func (s *telemetryIO) Recv() (*transportpb.TelemetrySnapshot, error) { return nil, io.EOF }
func (s *telemetryIO) Send(*transportpb.TelemetryRequest) error      { return nil }

type terminalIO struct{ streamBase }

func (s *terminalIO) Recv() (*transportpb.TerminalData, error) { return nil, io.EOF }
func (s *terminalIO) Send(*transportpb.TerminalData) error     { return nil }

type osqueryIO struct {
	streamBase
	in   chan *transportpb.OsqueryQueryResponse
	sent chan *transportpb.OsqueryQueryRequest
}

func (s *osqueryIO) Recv() (*transportpb.OsqueryQueryResponse, error) {
	r, ok := <-s.in
	if !ok {
		return nil, io.EOF
	}
	return r, nil
}
func (s *osqueryIO) Send(r *transportpb.OsqueryQueryRequest) error { s.sent <- r; return nil }

var (
	_ grpc.ServerStreamingServer[transportpb.ConfigChunk]                                         = (*cfgOut)(nil)
	_ grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]                                   = (*bundleOut)(nil)
	_ grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest] = (*osqueryIO)(nil)
)

func TestCompositeLockdown_PerRPCClassificationForTamperedSteward(t *testing.T) {
	e := newLockdownEnv(t)
	ctx := stewardEventPeerContext(t, "tampered-1")
	base := streamBase{ctx: ctx}

	t.Run("Register is an exempt admission ack", func(t *testing.T) {
		assert.Equal(t, classExempt, rpcLockdownClassification["Register"])
		_, err := e.composite.Register(ctx, nil)
		require.NoError(t, err)
		assert.True(t, e.cp.called["Register"])
	})

	t.Run("Ping accept", func(t *testing.T) {
		assert.Equal(t, classAccept, rpcLockdownClassification["Ping"])
		_, err := e.composite.Ping(ctx, &transportpb.PingRequest{})
		require.NoError(t, err)
	})

	t.Run("ControlChannel accept inbound", func(t *testing.T) {
		assert.Equal(t, classAccept, rpcLockdownClassification["ControlChannel"])
		require.NoError(t, e.composite.ControlChannel(nil))
		assert.True(t, e.cp.called["ControlChannel"])
	})

	t.Run("SyncConfig refuse", func(t *testing.T) {
		assert.Equal(t, classRefuse, rpcLockdownClassification["SyncConfig"])
		out := &cfgOut{streamBase: base}
		requireLockdownRefusal(t, e.composite.SyncConfig(&transportpb.ConfigSyncRequest{StewardId: "tampered-1"}, out))
		assert.Zero(t, out.sent)
	})

	t.Run("FetchModuleBundle refuse", func(t *testing.T) {
		assert.Equal(t, classRefuse, rpcLockdownClassification["FetchModuleBundle"])
		out := &bundleOut{streamBase: base}
		requireLockdownRefusal(t, e.composite.FetchModuleBundle(&transportpb.FetchModuleBundleRequest{}, out))
		assert.Zero(t, out.sent)
	})

	t.Run("IssueInitialCredential refuse", func(t *testing.T) {
		assert.Equal(t, classRefuse, rpcLockdownClassification["IssueInitialCredential"])
		_, err := e.composite.IssueInitialCredential(ctx, &transportpb.IssueInitialCredentialRequest{})
		requireLockdownRefusal(t, err)
	})

	t.Run("SyncDNA accept", func(t *testing.T) {
		assert.Equal(t, classAccept, rpcLockdownClassification["SyncDNA"])
		err := e.composite.SyncDNA(&dnaIn{base})
		assert.False(t, controlplaneInterfaces.IsLockedDown(err), "DNA from a tampered steward is accepted, got %v", err)
		assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("BulkTransfer accepts upload", func(t *testing.T) {
		assert.Equal(t, classAccept, rpcLockdownClassification["BulkTransfer"])
		require.NoError(t, e.composite.BulkTransfer(&bulkIO{streamBase: base, in: []*transportpb.BulkChunk{{TransferId: "r", Data: []byte("x"), IsLast: true}}}))
	})

	t.Run("LogStream accept", func(t *testing.T) {
		assert.Equal(t, classAccept, rpcLockdownClassification["LogStream"])
		err := e.composite.LogStream(&logIn{base})
		assert.False(t, controlplaneInterfaces.IsLockedDown(err), "log stream from a tampered steward is accepted, got %v", err)
		assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("TelemetryStream accept inbound", func(t *testing.T) {
		assert.Equal(t, classAccept, rpcLockdownClassification["TelemetryStream"])
		require.NoError(t, e.composite.TelemetryStream(&telemetryIO{base}))
	})

	t.Run("Terminal operator-only", func(t *testing.T) {
		assert.Equal(t, classOperatorOnly, rpcLockdownClassification["Terminal"])
		// The steward-opened stream only attaches to a session an operator opened;
		// a tampered steward with no such session reaches nothing.
		err := e.composite.Terminal(&terminalIO{base})
		assert.False(t, controlplaneInterfaces.IsLockedDown(err), "terminal keeps its own proof gate, got %v", err)
		// The open command that creates the session is operator-origin only.
		assert.Equal(t, controlplaneInterfaces.LockdownOperatorOnly, controlplaneInterfaces.CommandLockdownPolicy[controlplaneTypes.CommandOpenTerminal])
	})

	t.Run("OsqueryQuery operator-only", func(t *testing.T) {
		assert.Equal(t, classOperatorOnly, rpcLockdownClassification["OsqueryQuery"])
		// A tampered steward may open the stream (inbound accepted); a
		// controller-originated query on it needs the operator marker.
		stream := &osqueryIO{streamBase: base, in: make(chan *transportpb.OsqueryQueryResponse, 1), sent: make(chan *transportpb.OsqueryQueryRequest, 1)}
		done := make(chan error, 1)
		go func() { done <- e.composite.OsqueryQuery(stream) }()
		_, err := e.osquery.QuerySteward(context.Background(), "tampered-1", "file_info", nil)
		assert.ErrorIs(t, err, controlplaneInterfaces.ErrStewardLockedDown)
		close(stream.in)
		require.NoError(t, <-done)
	})
}

// The OsqueryQuery refusal and the marker-allowed path, isolated from stream timing.
func TestCompositeLockdown_OsqueryQueryNeedsOperatorMarker(t *testing.T) {
	e := newLockdownEnv(t)
	ctx := stewardEventPeerContext(t, "tampered-1")
	stream := &osqueryIO{streamBase: streamBase{ctx: ctx}, in: make(chan *transportpb.OsqueryQueryResponse, 1), sent: make(chan *transportpb.OsqueryQueryRequest, 1)}
	done := make(chan error, 1)
	go func() { done <- e.composite.OsqueryQuery(stream) }()
	defer func() {
		close(stream.in)
		assert.NoError(t, <-done, "the osquery stream ends cleanly when the steward closes it")
	}()

	qctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := e.osquery.QuerySteward(qctx, "tampered-1", "file_info", nil)
	require.Error(t, err)
	assert.True(t, err == controlplaneInterfaces.ErrStewardLockedDown, "unmarked query is refused (or not yet connected), got %v", err)
	select {
	case <-stream.sent:
		t.Fatal("a refused query must not reach the steward")
	default:
	}

	opCtx := controlplaneInterfaces.WithOperatorOrigin(qctx, "operator-1")
	go func() {
		req := <-stream.sent
		stream.in <- &transportpb.OsqueryQueryResponse{StewardId: req.GetStewardId(), CatalogId: req.GetCatalogId()}
	}()
	require.Eventually(t, func() bool {
		_, err := e.osquery.QuerySteward(opCtx, "tampered-1", "file_info", nil)
		return err == nil
	}, 3*time.Second, 10*time.Millisecond, "the operator-marked query is allowed")
}
