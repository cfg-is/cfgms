// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
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
	defer s.mu.Unlock()
	s.sent = append(s.sent, f)
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
// Test double: TerminalCommandPublisher
// ---------------------------------------------------------------------------

type stubCommandPublisher struct {
	mu       sync.Mutex
	commands []publishedCmd
	err      error
}

type publishedCmd struct {
	stewardID string
	cmdType   controlplaneTypes.CommandType
	params    map[string]interface{}
}

func (p *stubCommandPublisher) PublishCommand(_ context.Context, stewardID string, cmdType controlplaneTypes.CommandType, params map[string]interface{}) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return "", p.err
	}
	p.commands = append(p.commands, publishedCmd{stewardID: stewardID, cmdType: cmdType, params: params})
	return "cmd-" + stewardID, nil
}

func (p *stubCommandPublisher) getCommands() []publishedCmd {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]publishedCmd, len(p.commands))
	copy(out, p.commands)
	return out
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
		Shell:     "bash",
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
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil)

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
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil)

	relay, sess := registerPendingRelay(t, h, mgr, stewardID)

	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, cancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer cancel()

	stream := newTestTerminalStream(peerCtx,
		&transportpb.TerminalData{SessionId: sess.ID}, // correlation frame, no payload
	)

	waitDone := startHandleGRPCTerminal(t, h, stream)

	inputPayload := []byte("ls -la\n")
	relay.inputCh <- inputMsg{data: inputPayload}

	time.Sleep(50 * time.Millisecond)

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
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil)

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
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, mgr, nil, nil)

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
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil)

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

// TestTerminalHandler_HandleGRPC_EmptySessionID verifies that a first frame
// without session_id returns InvalidArgument.
func TestTerminalHandler_HandleGRPC_EmptySessionID(t *testing.T) {
	ca := newTestCA(t)
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil)

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
// ServeWebSocket HTTP-level tests
// ---------------------------------------------------------------------------

// TestTerminalHandler_ServeWebSocket_MissingStewardID verifies 400 when
// {steward_id} is absent from the path.
func TestTerminalHandler_ServeWebSocket_MissingStewardID(t *testing.T) {
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil)
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
	h := NewTerminalHandler(logging.NewNoopLogger(), nil, newTerminalSessionManager(t), nil, nil)
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
	pub := &stubCommandPublisher{}
	h := NewTerminalHandler(logging.NewNoopLogger(), pub, newTerminalSessionManager(t), nil, []string{"admin.example.com"})
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

	pub := &stubCommandPublisher{err: assert.AnError}
	h := NewTerminalHandler(logging.NewNoopLogger(), pub, newTerminalSessionManager(t), nil, nil)

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
	pub := &stubCommandPublisher{}
	h := NewTerminalHandler(logging.NewNoopLogger(), pub, newTerminalSessionManager(t), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/terminal/ws/dispatch-steward?shell=bash&cols=120&rows=40", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req = mux.SetURLVars(req, map[string]string{"steward_id": "dispatch-steward"})
	// Set tenant and user so session creation succeeds before command dispatch.
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-dispatch")
	ctx = context.WithValue(ctx, ctxkeys.UserIDKey, "user-dispatch")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)

	cmds := pub.getCommands()
	require.Len(t, cmds, 1, "exactly one OPEN_TERMINAL command must be dispatched")
	assert.Equal(t, "dispatch-steward", cmds[0].stewardID)
	assert.Equal(t, controlplaneTypes.CommandOpenTerminal, cmds[0].cmdType)
	assert.NotEmpty(t, cmds[0].params["session_id"])
	assert.Equal(t, "bash", cmds[0].params["shell"])
	assert.Equal(t, int32(120), cmds[0].params["cols"])
	assert.Equal(t, int32(40), cmds[0].params["rows"])
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
			Shell:     "bash",
			Cols:      80,
			Rows:      24,
		},
	)
	require.NoError(t, err, "CreateBrowserSession must not require a client certificate")
	require.NotNil(t, sess)
	assert.NotEmpty(t, sess.ID)
	assert.Equal(t, "admin-browser", sess.UserID)
	assert.Equal(t, "steward-abc", sess.StewardID)
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
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
		ClientIP:  "192.0.2.42",
	}

	ctx := context.Background()
	sess, err := terminal.CreateBrowserSession(ctx, mgr, auditMgr, opts)
	require.NoError(t, err)
	require.NotNil(t, sess)

	// Produce steward output so the recorder has data to persist.
	require.NoError(t, sess.HandleOutput(ctx, []byte("$ echo hello\r\nhello\r\n")))

	terminal.EndBrowserSession(ctx, auditMgr,
		opts.TenantID, opts.UserID, sess.ID, opts.StewardID, "test-cleanup")

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
