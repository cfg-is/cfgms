// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/terminal"
	termshell "github.com/cfgis/cfgms/features/terminal/shell"
	"github.com/cfgis/cfgms/pkg/audit"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// ---------------------------------------------------------------------------
// Test double: grpc.BidiStreamingServer[TerminalData, TerminalData]
// ---------------------------------------------------------------------------

// testTerminalStream simulates the steward's bidi gRPC stream.
// Pre-load frames in recvCh; close recvCh to signal EOF.
type testTerminalStream struct {
	ctx    context.Context
	recvCh chan *transportpb.TerminalData

	mu   sync.Mutex
	sent []*transportpb.TerminalData

	// sentCh, when non-nil, is signaled once after every Send appends a frame.
	// Tests use it to synchronize on the send goroutine draining relay.inputCh
	// without resorting to time.Sleep. Buffered + non-blocking so Send never stalls.
	sentCh chan struct{}
}

func newTestTerminalStream(ctx context.Context, initial ...*transportpb.TerminalData) *testTerminalStream {
	ch := make(chan *transportpb.TerminalData, len(initial)+16)
	for _, f := range initial {
		ch <- f
	}
	return &testTerminalStream{ctx: ctx, recvCh: ch}
}

func (s *testTerminalStream) Recv() (*transportpb.TerminalData, error) {
	select {
	case f, ok := <-s.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return f, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *testTerminalStream) Send(f *transportpb.TerminalData) error {
	s.mu.Lock()
	s.sent = append(s.sent, f)
	s.mu.Unlock()
	if s.sentCh != nil {
		select {
		case s.sentCh <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *testTerminalStream) getSent() []*transportpb.TerminalData {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*transportpb.TerminalData, len(s.sent))
	copy(out, s.sent)
	return out
}

func (s *testTerminalStream) SetHeader(metadata.MD) error  { return nil }
func (s *testTerminalStream) SendHeader(metadata.MD) error { return nil }
func (s *testTerminalStream) SetTrailer(metadata.MD)       {}
func (s *testTerminalStream) Context() context.Context     { return s.ctx }
func (s *testTerminalStream) SendMsg(interface{}) error    { return nil }
func (s *testTerminalStream) RecvMsg(interface{}) error    { return nil }

// ---------------------------------------------------------------------------
// Real TerminalCommandPublisher harness
// ---------------------------------------------------------------------------
//
// These tests exercise the real CFGMS command publisher — features/controller/
// commands.Publisher — wired to the real gRPC-over-QUIC control-plane provider.
// No stubs or mocks: PublishCommand signs the command and sends it over a live
// mTLS transport, exactly as production does. When a steward client is connected,
// the command it receives off the wire is recorded so the dispatch path can be
// asserted end-to-end; when no steward is connected, PublishCommand fails with
// the real "steward not connected" error, reproducing the offline case.

// newRealTerminalCommandPublisher builds a real commands.Publisher backed by a
// real gRPC control-plane server. When connectedStewardID is non-empty a real
// steward client connects over mTLS and subscribes to commands; every received
// SignedCommand is delivered on the returned channel. When it is empty no steward
// connects, so PublishCommand returns the genuine "steward not connected" error.
func newRealTerminalCommandPublisher(t *testing.T, connectedStewardID string) (*commands.Publisher, <-chan *controlplaneTypes.SignedCommand) {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	serverTLS, err := cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	reg := registry.NewRegistry()
	server := cpgrpc.New(cpgrpc.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() { server.ForceStop() })

	received := make(chan *controlplaneTypes.SignedCommand, 4)

	if connectedStewardID != "" {
		clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
			CommonName:   connectedStewardID,
			ValidityDays: 1,
			KeySize:      2048,
		})
		require.NoError(t, err)
		clientTLS, err := cfgcert.CreateClientTLSConfig(
			clientCert.CertificatePEM, clientCert.PrivateKeyPEM, caPEM, "localhost", tls.VersionTLS13)
		require.NoError(t, err)
		clientTLS.NextProtos = []string{quictransport.ALPNProtocol}

		client := cpgrpc.New(cpgrpc.ModeClient)
		require.NoError(t, client.Initialize(ctx, map[string]interface{}{
			"mode":       "client",
			"addr":       server.ListenAddr(),
			"tls_config": clientTLS,
			"steward_id": connectedStewardID,
		}))
		require.NoError(t, client.Start(ctx))
		t.Cleanup(func() { _ = client.Stop(context.Background()) })

		require.NoError(t, client.SubscribeCommands(ctx, connectedStewardID,
			func(_ context.Context, sc *controlplaneTypes.SignedCommand) error {
				select {
				case received <- sc:
				default:
				}
				return nil
			}))

		require.Eventually(t, func() bool { return reg.Count() == 1 }, 10*time.Second, 10*time.Millisecond,
			"steward must register with the control-plane server before commands can be delivered")
	}

	pub, err := commands.New(&commands.Config{
		ControlPlane: server,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	return pub, received
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTerminalSessionManager creates a real DefaultSessionManager with recording
// enabled and an isolated storage directory.
func newTerminalSessionManager(t *testing.T) terminal.SessionManager {
	t.Helper()
	cfg := &terminal.Config{
		SessionTimeout:       5 * time.Minute,
		MaxSessions:          10,
		RecordSessions:       true,
		RecordingStoragePath: t.TempDir(),
	}
	mgr, err := terminal.NewSessionManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	// Stop closes live sessions and the recorder synchronously. t.Cleanup is LIFO
	// and the storage path came from the t.TempDir() above, so this runs before the
	// directory is removed — otherwise a session finalizing during teardown can
	// write its .rec.meta sidecar after RemoveAll listed the directory, and the
	// cleanup fails with "directory not empty".
	t.Cleanup(func() {
		require.NoError(t, mgr.Stop(context.Background()))
	})
	return mgr
}

// registerPendingRelay injects a pre-built relay into h as ServeWebSocket would,
// and returns the relay and the session it wraps.
func registerPendingRelay(t *testing.T, h *TerminalHandler, mgr terminal.SessionManager, stewardID string) (*terminalRelay, *terminal.Session) {
	t.Helper()
	sess, err := mgr.CreateSession(context.Background(), &terminal.SessionRequest{
		TenantID:  "t1",
		StewardID: stewardID,
		UserID:    "u1",
		Shell:     termshell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	})
	require.NoError(t, err)

	relay := &terminalRelay{
		sessionID: sess.ID,
		stewardID: stewardID,
		tenantID:  "t1",
		userID:    "u1",
		session:   sess,
		inputCh:   make(chan inputMsg, terminalInputBufSize),
		grpcReady: make(chan struct{}),
		done:      make(chan struct{}),
	}
	h.registerRelay(sess.ID, relay)
	t.Cleanup(func() { h.unregisterRelay(sess.ID) })
	return relay, sess
}

// startHandleGRPCTerminal starts HandleGRPC in a goroutine and blocks until the
// handler binds the relay (via onGRPCBound). Returns a wait function.
func startHandleGRPCTerminal(t *testing.T, h *TerminalHandler, stream *testTerminalStream) func() error {
	t.Helper()
	bound := make(chan struct{}, 1)
	h.onGRPCBound = func(_ string) {
		select {
		case bound <- struct{}{}:
		default:
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- h.HandleGRPC(stream) }()
	select {
	case <-bound:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleGRPC did not bind within deadline")
	}
	return func() error {
		select {
		case err := <-errCh:
			return err
		case <-time.After(3 * time.Second):
			t.Fatal("HandleGRPC did not return within deadline")
			return nil
		}
	}
}

// ---------------------------------------------------------------------------
// [REQUIRED] Relay: steward frame → session output channel
// ---------------------------------------------------------------------------

// TestTerminalHandler_HandleGRPC_RelaysDataToSessionOutput is the primary relay
// correctness test. It verifies that a TerminalData frame from the steward stream
// reaches the session's OutputChan, correlated by session_id.
func TestTerminalHandler_HandleGRPC_RelaysDataToSessionOutput(t *testing.T) {
	const stewardID = "steward-relay"

	ca := newTestCA(t)
	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	relay, sess := registerPendingRelay(t, h, mgr, stewardID)

	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, cancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer cancel()

	payload := []byte("hello from steward\r\n")
	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID, Data: payload},
	)

	waitDone := startHandleGRPCTerminal(t, h, stream)
	close(stream.recvCh)
	require.NoError(t, waitDone())

	select {
	case got := <-sess.OutputChan():
		assert.Equal(t, payload, got, "steward payload must reach session.OutputChan()")
	case <-time.After(time.Second):
		t.Fatal("steward payload did not reach session output channel")
	}

	// relay.grpcReady must be closed, proving correlation by session_id succeeded.
	select {
	case <-relay.grpcReady:
	default:
		t.Fatal("relay.grpcReady must be closed after HandleGRPC binds the relay")
	}
}

// TestTerminalHandler_HandleGRPC_InputRelayedToStewardStream verifies that
// messages pushed to relay.inputCh (browser input) are forwarded to the steward.
func TestTerminalHandler_HandleGRPC_InputRelayedToStewardStream(t *testing.T) {
	const stewardID = "steward-input"

	ca := newTestCA(t)
	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	relay, sess := registerPendingRelay(t, h, mgr, stewardID)

	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, cancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer cancel()

	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID}, // correlation frame, no payload
	)
	// Signal the test the instant the send goroutine drains relay.inputCh and
	// forwards a frame via stream.Send — deterministic readiness, no time.Sleep.
	stream.sentCh = make(chan struct{}, 1)

	waitDone := startHandleGRPCTerminal(t, h, stream)

	inputPayload := []byte("ls -la\n")
	relay.inputCh <- inputMsg{data: inputPayload}

	// Wait for the send goroutine to actually forward the frame before asserting.
	select {
	case <-stream.sentCh:
	case <-time.After(3 * time.Second):
		t.Fatal("browser input was not forwarded to the steward stream within deadline")
	}

	close(stream.recvCh)
	require.NoError(t, waitDone())

	sent := stream.getSent()
	require.NotEmpty(t, sent, "browser input must be forwarded to steward gRPC stream")
	assert.Equal(t, sess.ID, sent[0].GetSessionId())
	assert.Equal(t, inputPayload, sent[0].GetData())
}

// ---------------------------------------------------------------------------
// HandleGRPC error cases
// ---------------------------------------------------------------------------

// TestTerminalHandler_HandleGRPC_RequiresMTLS verifies that a connection without
// a peer certificate is rejected with Unauthenticated. The steward mTLS
// requirements are unchanged by the browser-path additions.
func TestTerminalHandler_HandleGRPC_RequiresMTLS(t *testing.T) {
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream := newTestTerminalStream(ctx,
		&transportpb.TerminalData{SessionId: "any-session", Data: []byte("x")},
	)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"HandleGRPC must reject connections without mTLS peer certificate")
}

// TestTerminalHandler_HandleGRPC_StewardIDMismatch verifies that a steward whose
// certificate CN does not match the relay's steward_id receives PermissionDenied.
func TestTerminalHandler_HandleGRPC_StewardIDMismatch(t *testing.T) {
	const targetSteward = "steward-correct"
	const impostor = "steward-impostor"

	ca := newTestCA(t)
	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	_, sess := registerPendingRelay(t, h, mgr, targetSteward)

	peerCtx := peerContextWithCA(t, ca, impostor)
	peerCtx, cancel := context.WithTimeout(peerCtx, 2*time.Second)
	defer cancel()

	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID, Data: []byte("evil")},
	)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestTerminalHandler_HandleGRPC_UnknownSessionID verifies that HandleGRPC
// returns NotFound when the session_id is absent from the relay map.
func TestTerminalHandler_HandleGRPC_UnknownSessionID(t *testing.T) {
	ca := newTestCA(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil, nil)

	peerCtx := peerContextWithCA(t, ca, "steward-x")
	peerCtx, cancel := context.WithTimeout(peerCtx, 2*time.Second)
	defer cancel()

	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: "does-not-exist", Data: []byte("x")},
	)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestTerminalHandler_HandleGRPC_DuplicateStreamRejected verifies that a second
// HandleGRPC stream for an already-bound session_id is rejected with
// FailedPrecondition rather than panicking ("close of closed channel").
// Regression test for the double-close vulnerability: a compromised or buggy
// steward retrying an open stream for a live session must be rejected cleanly.
func TestTerminalHandler_HandleGRPC_DuplicateStreamRejected(t *testing.T) {
	const stewardID = "steward-dup"

	ca := newTestCA(t)
	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	_, sess := registerPendingRelay(t, h, mgr, stewardID)

	peerCtx, cancel := context.WithTimeout(
		peerContextWithCA(t, ca, stewardID), 5*time.Second)
	defer cancel()

	// First stream: binds the relay (grpcReady is closed inside bindRelay path).
	stream1 := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID},
	)
	waitDone1 := startHandleGRPCTerminal(t, h, stream1)

	// Second stream: same session_id, same steward CN. Must be rejected with
	// FailedPrecondition, not cause a "close of closed channel" panic.
	peerCtx2, cancel2 := context.WithTimeout(
		peerContextWithCA(t, ca, stewardID), 2*time.Second)
	defer cancel2()
	stream2 := newTestTerminalStream(peerCtx2,
		&transportpb.TerminalData{SessionId: sess.ID},
	)

	err := h.HandleGRPC(stream2)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err),
		"duplicate gRPC stream for an already-bound session_id must be rejected, not panic")

	// Tear down the first stream cleanly.
	close(stream1.recvCh)
	require.NoError(t, waitDone1())
}

// TestTerminalHandler_HandleGRPC_EmptySessionID verifies that a first frame
// without session_id returns InvalidArgument.
func TestTerminalHandler_HandleGRPC_EmptySessionID(t *testing.T) {
	ca := newTestCA(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil, nil)

	peerCtx := peerContextWithCA(t, ca, "steward-noid")
	peerCtx, cancel := context.WithTimeout(peerCtx, 2*time.Second)
	defer cancel()

	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{Data: []byte("x")}, // missing SessionId
	)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// [SECURITY] Browser disconnect tears the steward stream down
// ---------------------------------------------------------------------------

// TestTerminalHandler_HandleGRPC_ReturnsWhenBrowserDisconnects is the regression
// test for the orphaned-shell finding (Issue #2761): on WebSocket close,
// ServeWebSocket closes relay.done, and HandleGRPC must return. Returning is what
// ends the server-side bidi stream, which makes the steward's terminal bridge see
// EOF and close its PTY. Previously the handler stayed parked in stream.Recv()
// forever, so a privileged interactive shell kept running on the managed endpoint
// after the admin's browser went away — with its session already terminated, so
// nothing it emitted was recorded.
func TestTerminalHandler_HandleGRPC_ReturnsWhenBrowserDisconnects(t *testing.T) {
	const stewardID = "steward-disconnect"

	ca := newTestCA(t)
	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	relay, sess := registerPendingRelay(t, h, mgr, stewardID)

	// Long-lived peer context: only the browser disconnect may end the handler.
	peerCtx, cancel := context.WithTimeout(peerContextWithCA(t, ca, stewardID), 30*time.Second)
	defer cancel()

	// The steward stream stays open (recvCh is never closed) — exactly the
	// production case where the endpoint's shell is idle but alive.
	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID},
	)
	waitDone := startHandleGRPCTerminal(t, h, stream)

	// Browser goes away: ServeWebSocket's deferred cleanup closes the relay and
	// terminates the session.
	relay.close()
	require.NoError(t, mgr.TerminateSession(context.Background(), sess.ID))

	// waitDone fails the test if HandleGRPC does not return within its deadline.
	assert.NoError(t, waitDone(),
		"HandleGRPC must return once the browser relay is closed, ending the steward stream")
}

// TestTerminalHandler_HandleGRPC_StopsRelayingWhenSessionClosed asserts that once
// the session is closed, the handler ends the stream instead of logging a warning
// for every subsequent steward frame. A high-volume command (`yes`) on a
// disconnected session would otherwise turn into unbounded warn-level log flooding,
// amplified across a 50k-steward fleet.
func TestTerminalHandler_HandleGRPC_StopsRelayingWhenSessionClosed(t *testing.T) {
	const stewardID = "steward-flood"

	ca := newTestCA(t)
	mgr := newTerminalSessionManager(t)
	capturingLogger := logging.NewCapturingLogger()
	h := NewTerminalHandler(capturingLogger, nil, mgr, nil, nil, nil)

	_, sess := registerPendingRelay(t, h, mgr, stewardID)

	peerCtx, cancel := context.WithTimeout(peerContextWithCA(t, ca, stewardID), 30*time.Second)
	defer cancel()

	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID},
	)
	waitDone := startHandleGRPCTerminal(t, h, stream)

	// Session terminated (browser closed) while the steward keeps producing output.
	require.NoError(t, mgr.TerminateSession(context.Background(), sess.ID))
	for i := 0; i < 10; i++ {
		stream.recvCh <- &transportpb.TerminalData{SessionId: sess.ID, Data: []byte("y\n")}
	}

	require.Error(t, waitDone(),
		"HandleGRPC must end the stream when the session can no longer accept output")

	assert.LessOrEqual(t, len(capturingLogger.WarnMessages), 1,
		"a closed session must not produce a warn log per steward frame, got: %v",
		capturingLogger.WarnMessages)
}

// ---------------------------------------------------------------------------
// ServeWebSocket HTTP-level tests
// ---------------------------------------------------------------------------

// TestTerminalHandler_ServeWebSocket_MissingStewardID verifies 400 when
// {steward_id} is absent from the path.
func TestTerminalHandler_ServeWebSocket_MissingStewardID(t *testing.T) {
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestTerminalHandler_ServeWebSocket_ForbiddenOrigin verifies 403 for a
// non-same-origin, non-allowlisted Origin. The rejection confirms origin policy
// is enforced — not client-certificate absence.
func TestTerminalHandler_ServeWebSocket_ForbiddenOrigin(t *testing.T) {
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/steward-1", nil)
	req.Host = "app.internal"
	req.Header.Set("Origin", "https://attacker.example.com")
	req = mux.SetURLVars(req, map[string]string{"steward_id": "steward-1"})
	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"non-same-origin Origin must be rejected with 403, not rejected for mTLS")
}

// TestTerminalHandler_ServeWebSocket_AllowlistOriginAccepted verifies that an
// origin on the explicit allowlist passes the origin check.
func TestTerminalHandler_ServeWebSocket_AllowlistOriginAccepted(t *testing.T) {
	// Real publisher with no steward connected: the origin check runs before
	// command dispatch, so an allowlisted origin must not be rejected with 403
	// regardless of the (offline) publish outcome.
	pub, _ := newRealTerminalCommandPublisher(t, "")
	h := NewTerminalHandler(logging.NewNoopLogger(), pub, newTerminalSessionManager(t), nil, []string{"admin.example.com"}, nil)
	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/steward-1", nil)
	req.Host = "app.internal"
	req.Header.Set("Origin", "https://admin.example.com")
	req = mux.SetURLVars(req, map[string]string{"steward_id": "steward-1"})
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-allowlist")
	ctx = context.WithValue(ctx, ctxkeys.UserIDKey, "user-allowlist")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"allowlisted origin must not be rejected with 403")
}

// [REQUIRED] TestTerminalHandler_ServeWebSocket_OfflineSteward verifies that
// command-publisher failure (steward offline / no active ControlChannel) returns
// 503 quickly, without hanging or upgrading the WS connection.
func TestTerminalHandler_ServeWebSocket_OfflineSteward(t *testing.T) {
	startTime := time.Now()

	// Real publisher with no steward connected: PublishCommand returns the genuine
	// "steward not connected" error, which the handler must translate to 503.
	pub, _ := newRealTerminalCommandPublisher(t, "")
	h := NewTerminalHandler(logging.NewNoopLogger(), pub, newTerminalSessionManager(t), nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/offline-steward", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req = mux.SetURLVars(req, map[string]string{"steward_id": "offline-steward"})
	// Set tenant and user so session creation succeeds before command dispatch.
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-offline")
	ctx = context.WithValue(ctx, ctxkeys.UserIDKey, "user-offline")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)

	elapsed := time.Since(startTime)
	assert.Less(t, elapsed, 5*time.Second, "offline steward must fail fast, not hang")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"offline steward must return 503 before WebSocket upgrade")
}

// [REQUIRED] TestTerminalHandler_ServeWebSocket_DispatchesOpenTerminalCommand
// verifies that ServeWebSocket dispatches COMMAND_TYPE_OPEN_TERMINAL with the
// correct steward_id, session_id, shell, cols, and rows.
func TestTerminalHandler_ServeWebSocket_DispatchesOpenTerminalCommand(t *testing.T) {
	const stewardID = "dispatch-steward"

	// Real publisher with a real steward connected over mTLS. The OPEN_TERMINAL
	// command travels the actual publish path and is captured off the wire.
	pub, received := newRealTerminalCommandPublisher(t, stewardID)
	h := NewTerminalHandler(logging.NewNoopLogger(), pub, newTerminalSessionManager(t), nil, nil, nil)

	testShell := termshell.GetDefaultShell()
	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/"+stewardID+"?shell="+testShell+"&cols=120&rows=40", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req = mux.SetURLVars(req, map[string]string{"steward_id": stewardID})
	// Set tenant and user so session creation succeeds before command dispatch.
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-dispatch")
	ctx = context.WithValue(ctx, ctxkeys.UserIDKey, "user-dispatch")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)

	// The command is delivered asynchronously over the real transport; wait for
	// the connected steward to receive it.
	var sc *controlplaneTypes.SignedCommand
	select {
	case sc = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("OPEN_TERMINAL command was not delivered to the connected steward")
	}

	require.NotNil(t, sc)
	assert.Equal(t, stewardID, sc.Command.StewardID)
	assert.Equal(t, controlplaneTypes.CommandOpenTerminal, sc.Command.Type)
	// RawParams preserves the exact string-encoded params that crossed the wire.
	require.NotNil(t, sc.RawParams)
	assert.NotEmpty(t, sc.RawParams["session_id"])
	assert.Equal(t, testShell, sc.RawParams["shell"])
	assert.Equal(t, "120", sc.RawParams["cols"])
	assert.Equal(t, "40", sc.RawParams["rows"])

	// Exactly one command must be dispatched.
	select {
	case extra := <-received:
		t.Fatalf("expected exactly one OPEN_TERMINAL command, got a second: %+v", extra.Command)
	case <-time.After(200 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// [REQUIRED] steward mTLS path is unchanged
// ---------------------------------------------------------------------------

// TestTerminalHandler_MTLSConfigUnchanged verifies that DefaultAuthConfig still
// enforces RequireMTLS and all steward-leg security properties. The browser-path
// additions must not weaken the steward leg.
func TestTerminalHandler_MTLSConfigUnchanged(t *testing.T) {
	cfg := terminal.DefaultAuthConfig()
	assert.True(t, cfg.RequireMTLS, "steward path: RequireMTLS must remain true")
	assert.True(t, cfg.ClientCertRequired, "steward path: ClientCertRequired must remain true")
	assert.True(t, cfg.IPBindingEnabled, "steward path: IPBindingEnabled must remain true")
	assert.True(t, cfg.TLSFingerprintCheck, "steward path: TLSFingerprintCheck must remain true")
}

// TestCreateBrowserSession_SucceedsWithoutClientCert verifies that
// CreateBrowserSession succeeds with a plain background context (no TLS, no
// client cert), proving the browser path is decoupled from the mTLS steward path.
func TestCreateBrowserSession_SucceedsWithoutClientCert(t *testing.T) {
	mgr := newTerminalSessionManager(t)

	sess, err := terminal.CreateBrowserSession(
		context.Background(),
		mgr,
		nil, // audit manager not required for this assertion
		terminal.BrowserSessionOptions{
			UserID:    "admin-browser",
			TenantID:  "tenant-1",
			StewardID: "steward-abc",
			Shell:     termshell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		},
		nil, // logger not required for this assertion
	)
	require.NoError(t, err, "CreateBrowserSession must not require a client certificate")
	require.NotNil(t, sess)
	assert.NotEmpty(t, sess.ID)
	assert.Equal(t, "admin-browser", sess.UserID)
	assert.Equal(t, "steward-abc", sess.StewardID)
}

// TestCreateBrowserSession_AuditFailureIsLogged verifies that a failed audit
// write is not silently discarded: it must be surfaced via the supplied
// logger's Warn level so an operator has a signal that the audit trail for a
// terminal session has a gap. Session creation itself must still succeed —
// audit failures must not block the terminal from opening.
func TestCreateBrowserSession_AuditFailureIsLogged(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "terminal-test")
	require.NoError(t, err)

	mgr := newTerminalSessionManager(t)
	capturingLogger := logging.NewCapturingLogger()

	// Stopping the audit manager first makes every subsequent RecordEvent call
	// fail deterministically ("audit manager is stopped") without touching the
	// underlying store, so session creation (which does not depend on the
	// audit manager) can still be exercised normally.
	require.NoError(t, auditMgr.Stop(context.Background()))

	sess, err := terminal.CreateBrowserSession(
		context.Background(),
		mgr,
		auditMgr,
		terminal.BrowserSessionOptions{
			TenantID:  "tenant-1",
			UserID:    "admin-browser",
			StewardID: "steward-abc",
			Shell:     termshell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		},
		capturingLogger,
	)
	require.NoError(t, err, "audit failure must not block terminal session creation")
	require.NotNil(t, sess)

	require.Len(t, capturingLogger.WarnEntries, 1, "audit RecordEvent failure must be logged at Warn level")
	assert.Contains(t, capturingLogger.WarnMessages[0], "audit")
	assert.Equal(t, "steward-abc", capturingLogger.WarnEntries[0]["steward_id"])
}

// ---------------------------------------------------------------------------
// [REQUIRED] Audit record + session recording both produced
// ---------------------------------------------------------------------------

// TestTerminalHandler_AuditAndRecordingBothProduced verifies the two hard
// requirements from the acceptance criteria: a browser terminal session must
// produce both an audit record (via audit.Manager) and a session recording
// (via the Recorder wired into DefaultSessionManager with RecordSessions: true).
func TestTerminalHandler_AuditAndRecordingBothProduced(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "terminal-test")
	require.NoError(t, err)

	mgr := newTerminalSessionManager(t)

	opts := terminal.BrowserSessionOptions{
		UserID:    "audit-test-user",
		TenantID:  "tenant-audit",
		StewardID: "steward-audit",
		Shell:     termshell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
		ClientIP:  "192.0.2.42",
	}

	ctx := context.Background()
	sess, err := terminal.CreateBrowserSession(ctx, mgr, auditMgr, opts, nil)
	require.NoError(t, err)
	require.NotNil(t, sess)

	// Produce steward output so the recorder has data to persist.
	require.NoError(t, sess.HandleOutput(ctx, []byte("$ echo hello\r\nhello\r\n")))

	terminal.EndBrowserSession(ctx, auditMgr,
		opts.TenantID, opts.UserID, sess.ID, opts.StewardID, "test-cleanup", nil)

	// Flush ensures all enqueued audit events reach the store before querying.
	require.NoError(t, auditMgr.Flush(ctx))

	// --- Verify audit records ---
	now := time.Now()
	start := now.Add(-time.Minute)
	tr := &business.TimeRange{Start: &start}

	startEvents, listErr := storageManager.GetAuditStore().GetAuditsByAction(ctx, "terminal.session.start", tr)
	require.NoError(t, listErr)
	var startFound bool
	for _, ev := range startEvents {
		if ev.SessionID == sess.ID && ev.UserID == opts.UserID {
			startFound = true
			break
		}
	}
	assert.True(t, startFound, "audit start record must be produced on session open")

	endEvents, listErr := storageManager.GetAuditStore().GetAuditsByAction(ctx, "terminal.session.end", tr)
	require.NoError(t, listErr)
	var endFound bool
	for _, ev := range endEvents {
		if ev.SessionID == sess.ID && ev.UserID == opts.UserID {
			endFound = true
			break
		}
	}
	assert.True(t, endFound, "audit end record must be produced on session close")

	// --- Verify session recording ---
	rec, recErr := mgr.GetSessionRecording(sess.ID)
	require.NoError(t, recErr)
	require.NotNil(t, rec, "session recording must exist (recorder wired by DefaultSessionManager with RecordSessions: true)")
}

// ---------------------------------------------------------------------------
// [SECURITY] Browser input is recorded, fail-closed, before it reaches the shell
// ---------------------------------------------------------------------------

// browserTerminalFixture holds a live browser ↔ steward relay built over the real
// production path: HTTP upgrade → CreateBrowserSession → steward stream
// correlation → runWSRelay.
type browserTerminalFixture struct {
	conn     *websocket.Conn
	sess     *terminal.Session
	stream   *testTerminalStream
	waitGRPC func() error
	served   chan struct{} // closed when ServeWebSocket returns
}

// startBrowserTerminal serves h over a real HTTP server, connects a real
// WebSocket client, and binds a steward gRPC stream to the session that
// ServeWebSocket created, leaving the relay running in both directions.
func startBrowserTerminal(t *testing.T, h *TerminalHandler, mgr terminal.SessionManager, stewardID string) *browserTerminalFixture {
	t.Helper()

	ca := newTestCA(t)

	served := make(chan struct{})
	router := mux.NewRouter()
	router.HandleFunc("/terminal/{steward_id}", func(w http.ResponseWriter, r *http.Request) {
		defer close(served)
		ctx := context.WithValue(r.Context(), ctxkeys.UserIDKey, "admin-browser")
		ctx = context.WithValue(ctx, ctxkeys.TenantID, "tenant-1")
		h.ServeWebSocket(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/terminal/" + stewardID
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{srv.URL}})
	require.NoError(t, err, "WebSocket upgrade must succeed")
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	t.Cleanup(func() { _ = conn.Close() })

	// The session is created before the upgrade completes, so it exists by the
	// time Dial returns — no polling needed.
	sessions := mgr.GetActiveSessions()
	require.Len(t, sessions, 1, "ServeWebSocket must create exactly one session")
	sess := sessions[0]

	peerCtx, cancel := context.WithTimeout(peerContextWithCA(t, ca, stewardID), 10*time.Second)
	t.Cleanup(cancel)

	stream := newTestTerminalStream(peerCtx, &transportpb.TerminalData{SessionId: sess.ID})
	stream.sentCh = make(chan struct{}, 8)
	waitGRPC := startHandleGRPCTerminal(t, h, stream)

	return &browserTerminalFixture{conn: conn, sess: sess, stream: stream, waitGRPC: waitGRPC, served: served}
}

// waitStewardFrame blocks until the relay forwards one browser frame to the
// steward stream.
func waitStewardFrame(t *testing.T, stream *testTerminalStream) {
	t.Helper()
	select {
	case <-stream.sentCh:
	case <-time.After(5 * time.Second):
		t.Fatal("browser frame was not forwarded to the steward stream within deadline")
	}
}

// waitServed blocks until ServeWebSocket returns (relay torn down, session
// terminated, recording finalized).
func waitServed(t *testing.T, fx *browserTerminalFixture) {
	t.Helper()
	select {
	case <-fx.served:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeWebSocket did not return within deadline")
	}
}

// TestServeWebSocket_RecordsBrowserInputAndResize is the regression test for the
// one-sided audit trail (Issue #2761): browser→steward input used to be pushed
// straight onto relay.inputCh, so the recording of a privileged interactive shell
// contained only bytes the endpoint chose to return. A compromised steward — an
// explicit CFGMS threat-model case — therefore controlled 100% of its own audit
// trail, while the operator's keystrokes, the one thing the controller knows
// first-hand, were discarded. Keystrokes and resizes must both be recorded.
func TestServeWebSocket_RecordsBrowserInputAndResize(t *testing.T) {
	const stewardID = "steward-input-audit"

	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	fx := startBrowserTerminal(t, h, mgr, stewardID)

	keystrokes := []byte("whoami\n")
	require.NoError(t, fx.conn.WriteJSON(terminal.TerminalMessage{
		Type: terminal.MessageTypeData,
		Data: keystrokes,
	}))
	waitStewardFrame(t, fx.stream)

	require.NoError(t, fx.conn.WriteJSON(terminal.TerminalMessage{
		Type: terminal.MessageTypeResize,
		Data: []byte(`{"cols":120,"rows":40}`),
	}))
	waitStewardFrame(t, fx.stream)

	// Browser leaves: the relay is torn down and the session terminated, which
	// finalizes the recording on disk.
	require.NoError(t, fx.conn.Close())
	require.NoError(t, fx.waitGRPC())
	waitServed(t, fx)

	sent := fx.stream.getSent()
	require.Len(t, sent, 2, "both browser frames must reach the steward")
	assert.Equal(t, keystrokes, sent[0].GetData())
	assert.True(t, sent[1].GetIsResize())
	assert.Equal(t, int32(120), sent[1].GetCols())
	assert.Equal(t, int32(40), sent[1].GetRows())

	rec, err := mgr.GetSessionRecording(fx.sess.ID)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Contains(t, string(rec.Data), "whoami\n",
		"operator keystrokes must be captured in the session recording")
	assert.Contains(t, string(rec.Data), "\x1b[8;40;120t",
		"browser resize must be captured in the session recording")
}

// TestServeWebSocket_UnrecordableInputIsNotForwardedToSteward asserts the
// fail-closed half of the contract: when a keystroke cannot be recorded, it is
// not forwarded, and the relay is torn down so the endpoint's PTY ends instead of
// executing input that lands in no audit trail.
func TestServeWebSocket_UnrecordableInputIsNotForwardedToSteward(t *testing.T) {
	const stewardID = "steward-input-failclosed"

	mgr := newTerminalSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil, nil)

	fx := startBrowserTerminal(t, h, mgr, stewardID)

	// Terminate the session underneath the live relay: its recording is finalized,
	// so no further keystroke can be captured.
	require.NoError(t, mgr.TerminateSession(context.Background(), fx.sess.ID))

	require.NoError(t, fx.conn.WriteJSON(terminal.TerminalMessage{
		Type: terminal.MessageTypeData,
		Data: []byte("SECRET-COMMAND\n"),
	}))

	// HandleGRPC returning proves the relay was torn down by the unrecordable
	// keystroke; the steward stream ends and the PTY with it.
	require.NoError(t, fx.waitGRPC())
	waitServed(t, fx)

	for _, f := range fx.stream.getSent() {
		assert.NotContains(t, string(f.GetData()), "SECRET-COMMAND",
			"input that could not be recorded must never reach the steward")
	}

	rec, err := mgr.GetSessionRecording(fx.sess.ID)
	require.NoError(t, err)
	assert.NotContains(t, string(rec.Data), "SECRET-COMMAND")
}

// ---------------------------------------------------------------------------
// [SECURITY] Audited client IP is not forgeable via forwarding headers
// ---------------------------------------------------------------------------

// TestTerminalClientIP_IgnoresForwardingHeadersFromUntrustedPeer asserts the
// default posture: with no trusted proxies configured, X-Forwarded-For and
// X-Real-IP are ignored entirely. terminalClientIP feeds the only source
// address recorded in the terminal.session.start audit event for an interactive
// privileged shell, so a client must not be able to choose what gets logged.
func TestTerminalClientIP_IgnoresForwardingHeadersFromUntrustedPeer(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{name: "no headers"},
		{name: "forged X-Forwarded-For", headers: map[string]string{"X-Forwarded-For": "10.9.9.9"}},
		{name: "forged X-Real-IP", headers: map[string]string{"X-Real-IP": "10.9.9.9"}},
		{name: "both forged", headers: map[string]string{
			"X-Forwarded-For": "10.9.9.9, 172.16.0.1",
			"X-Real-IP":       "10.9.9.9",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/terminal", nil)
			r.RemoteAddr = "203.0.113.7:44321"
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			// nil trustedProxies is the production default (no
			// registration.trusted_proxies configured).
			assert.Equal(t, "203.0.113.7", terminalClientIP(r, nil),
				"forwarding headers must be ignored when the peer is not a trusted proxy")
		})
	}
}

// TestTerminalClientIP_HonorsForwardingHeadersFromTrustedProxy verifies the
// legitimate reverse-proxy deployment still records the real browser address.
func TestTerminalClientIP_HonorsForwardingHeadersFromTrustedProxy(t *testing.T) {
	trusted := parseTrustedProxyCIDRs([]string{"192.168.10.0/24"}, logging.NewNoopLogger())
	require.Len(t, trusted, 1)

	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "single hop X-Forwarded-For",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.23"},
			want:    "198.51.100.23",
		},
		{
			// nginx's proxy_add_x_forwarded_for APPENDS, so a client-supplied
			// value survives as the leftmost entry. Selecting the rightmost
			// non-proxy hop is what makes the result un-forgeable.
			name:    "client-prepended forgery is discarded",
			headers: map[string]string{"X-Forwarded-For": "10.9.9.9, 198.51.100.23"},
			want:    "198.51.100.23",
		},
		{
			// Chained trusted proxies are skipped right-to-left until the first
			// address the outermost proxy actually observed.
			name:    "trusted proxy hops are skipped",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.23, 192.168.10.5, 192.168.10.6"},
			want:    "198.51.100.23",
		},
		{
			name:    "garbage hops are skipped",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.23, not-an-ip"},
			want:    "198.51.100.23",
		},
		{
			name:    "X-Real-IP used when no X-Forwarded-For",
			headers: map[string]string{"X-Real-IP": "198.51.100.23"},
			want:    "198.51.100.23",
		},
		{
			name:    "non-IP X-Real-IP falls back to peer",
			headers: map[string]string{"X-Real-IP": "not-an-ip"},
			want:    "192.168.10.5",
		},
		{
			name:    "all hops trusted falls back to peer",
			headers: map[string]string{"X-Forwarded-For": "192.168.10.6"},
			want:    "192.168.10.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/terminal", nil)
			r.RemoteAddr = "192.168.10.5:44321"
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, terminalClientIP(r, trusted))
		})
	}
}

// TestTerminalClientIP_IPv6PeerWithoutHeaders asserts IPv6 peer addresses are
// split on the correct separator. A LastIndex(":") split would truncate an IPv6
// literal and record a malformed forensic address.
func TestTerminalClientIP_IPv6PeerWithoutHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/terminal", nil)
	r.RemoteAddr = "[2001:db8::1]:44321"
	assert.Equal(t, "2001:db8::1", terminalClientIP(r, nil))
}

// TestParseTrustedProxyCIDRs_SkipsMalformedEntries asserts a bad config line is
// dropped rather than widening trust or blocking controller startup.
func TestParseTrustedProxyCIDRs_SkipsMalformedEntries(t *testing.T) {
	nets := parseTrustedProxyCIDRs(
		[]string{"not-a-cidr", " 192.168.10.0/24 ", "10.0.0.1"}, logging.NewNoopLogger())
	require.Len(t, nets, 1, "only the well-formed CIDR must be trusted")
	assert.True(t, nets[0].Contains(net.ParseIP("192.168.10.7")))
}

// TestServeWebSocket_AuditsUnforgeableClientIP is the end-to-end assertion: a
// client sending a forged X-Forwarded-For to a directly-reachable controller has
// its real TCP peer address recorded in the terminal.session.start audit event.
func TestServeWebSocket_AuditsUnforgeableClientIP(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "terminal-test")
	require.NoError(t, err)

	mgr := newTerminalSessionManager(t)
	// No trusted proxies: the controller is reached directly.
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, auditMgr, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-1/stewards/steward-abc/terminal", nil)
	req.RemoteAddr = "203.0.113.7:44321"
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	// Same-origin is required by the upgrade's origin check, which runs before
	// session creation.
	req.Header.Set("Origin", "https://"+req.Host)
	req = mux.SetURLVars(req, map[string]string{"steward_id": "steward-abc"})
	ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-browser")
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "tenant-1")
	req = req.WithContext(ctx)

	// No WebSocket upgrade headers: the upgrade fails after session creation and
	// the audit start event has already been recorded, which is what we assert.
	h.ServeWebSocket(httptest.NewRecorder(), req)

	require.NoError(t, auditMgr.Flush(context.Background()))

	now := time.Now()
	start := now.Add(-time.Minute)
	events, err := storageManager.GetAuditStore().GetAuditsByAction(
		context.Background(), "terminal.session.start", &business.TimeRange{Start: &start})
	require.NoError(t, err)
	require.NotEmpty(t, events, "terminal.session.start audit event must be recorded")

	var checked bool
	for _, ev := range events {
		if ev.UserID != "admin-browser" {
			continue
		}
		checked = true
		assert.Equal(t, "203.0.113.7", ev.Details["client_ip"],
			"audited client_ip must be the TCP peer, never the forged X-Forwarded-For")
	}
	assert.True(t, checked, "audit event for the test user must be present")
}
