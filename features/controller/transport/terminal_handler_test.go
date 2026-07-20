// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/audit"
	cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// ---------------------------------------------------------------------------
// testBidiStream — fake grpc.BidiStreamingServer for TerminalData
// ---------------------------------------------------------------------------

type testBidiStream struct {
	ctx     context.Context
	recvCh  chan *transportpb.TerminalData
	mu      sync.Mutex
	sent    []*transportpb.TerminalData
	sendErr error
	// sentSignal, when non-nil, receives a non-blocking notification after each
	// successful Send so tests can block on delivery instead of polling.
	sentSignal chan struct{}
}

func newTestBidiStream(ctx context.Context) *testBidiStream {
	return &testBidiStream{
		ctx:    ctx,
		recvCh: make(chan *transportpb.TerminalData, 32),
	}
}

func (s *testBidiStream) Recv() (*transportpb.TerminalData, error) {
	select {
	case <-s.ctx.Done():
		return nil, io.EOF
	case msg, ok := <-s.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	}
}

func (s *testBidiStream) Send(msg *transportpb.TerminalData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, proto.Clone(msg).(*transportpb.TerminalData))
	if s.sentSignal != nil {
		select {
		case s.sentSignal <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *testBidiStream) getSent() []*transportpb.TerminalData {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*transportpb.TerminalData, len(s.sent))
	copy(out, s.sent)
	return out
}

func (s *testBidiStream) SetHeader(metadata.MD) error  { return nil }
func (s *testBidiStream) SendHeader(metadata.MD) error { return nil }
func (s *testBidiStream) SetTrailer(metadata.MD)       {}
func (s *testBidiStream) Context() context.Context     { return s.ctx }
func (s *testBidiStream) SendMsg(interface{}) error    { return nil }
func (s *testBidiStream) RecvMsg(interface{}) error    { return nil }

// Compile-time interface check.
var _ grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData] = (*testBidiStream)(nil)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestSessionManager creates a DefaultSessionManager with an isolated
// recording directory in t.TempDir() and recording enabled.
func newTestSessionManager(t *testing.T) terminal.SessionManager {
	t.Helper()
	mgr, err := terminal.NewSessionManager(&terminal.Config{
		RecordSessions:       true,
		RecordingStoragePath: t.TempDir(),
		SessionTimeout:       30 * time.Minute,
		MaxSessions:          100,
	}, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		if dsm, ok := mgr.(*terminal.DefaultSessionManager); ok {
			_ = dsm.Stop(context.Background())
		}
	})
	return mgr
}

// newTestSession creates a new session via mgr and injects a RelayExecutor so
// that WriteData forwards through channels rather than a local shell process.
func newTestSession(t *testing.T, mgr terminal.SessionManager, stewardID string) *terminal.Session {
	t.Helper()
	ctx := context.Background()
	session, err := mgr.CreateSession(ctx, &terminal.SessionRequest{
		TenantID:  "test-tenant",
		StewardID: stewardID,
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	})
	require.NoError(t, err)
	relayExec := terminal.NewRelayExecutor()
	session.SetExecutor(relayExec)
	return session
}

// withTestTenant injects a test tenant ID into every request context.
func withTestTenant(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxkeys.TenantID, "test-tenant")
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------------------------------------------------------------------------
// Test 1: TerminalData frame from simulated steward → session.OutputChan
// ---------------------------------------------------------------------------

// TestTerminalHandlerRelayGRPCToSession verifies that data received from the
// steward's gRPC Terminal stream is forwarded to the WS session's outputCh so
// that the WebSocket write goroutine can relay it to the browser.
func TestTerminalHandlerRelayGRPCToSession(t *testing.T) {
	const stewardID = "steward-relay-test"
	mgr := newTestSessionManager(t)

	h := NewTerminalHandler(logging.NewNoopLogger())

	// Create a session and register a pending relay — mirrors what
	// relaySessionManager.CreateSession does.
	session := newTestSession(t, mgr, stewardID)
	relayExec := terminal.NewRelayExecutor()
	session.SetExecutor(relayExec)
	h.register(session.ID, stewardID, session, relayExec)

	// The relay requires the dialing steward's mTLS identity to match the
	// registered target steward, so dial with a matching client cert CN.
	ca := newTestCA(t)
	ctx, cancel := context.WithTimeout(peerContextWithCA(t, ca, stewardID), 5*time.Second)
	defer cancel()

	stream := newTestBidiStream(ctx)

	// First frame carries the session_id (handshake).
	sentinel := []byte("CFGMS_RELAY_SENTINEL_2761")
	stream.recvCh <- &transportpb.TerminalData{
		SessionId: session.ID,
		Data:      sentinel, // piggybacked on first frame
	}

	// HandleGRPC runs until context expires or stream closes.
	handleDone := make(chan error, 1)
	go func() {
		handleDone <- h.HandleGRPC(stream)
	}()

	// The piggybacked payload should arrive on session.OutputChan.
	select {
	case data := <-session.OutputChan():
		assert.Equal(t, sentinel, data, "steward payload must arrive on session.OutputChan")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for relay data on session.OutputChan")
	}

	// Additional steward-to-browser frame sent after the handshake.
	extra := []byte("CFGMS_EXTRA_OUTPUT")
	stream.recvCh <- &transportpb.TerminalData{
		SessionId: session.ID,
		Data:      extra,
	}
	select {
	case data := <-session.OutputChan():
		assert.Equal(t, extra, data, "extra steward payload must also be relayed")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for extra relay data on session.OutputChan")
	}

	// Close stream and ensure HandleGRPC exits without error.
	close(stream.recvCh)
	cancel()
	select {
	case err := <-handleDone:
		// nil or context-cancelled are both acceptable exit conditions.
		if err != nil {
			assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded,
				"HandleGRPC must only return a non-nil error on genuine stream failures, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandleGRPC did not exit after stream close")
	}
}

// ---------------------------------------------------------------------------
// Test 2: Offline steward → CreateSession returns error (no hang/leak)
// ---------------------------------------------------------------------------

// TestRelaySessionManagerOfflineSteward verifies that CreateSession returns a
// clear error immediately when the target steward has no active ControlChannel
// in the registry, rather than hanging or leaking a pending relay entry.
func TestRelaySessionManagerOfflineSteward(t *testing.T) {
	baseMgr := newTestSessionManager(t)
	th := NewTerminalHandler(logging.NewNoopLogger())

	// An empty registry has no registered connections.
	reg := registry.NewRegistry()

	rsm := NewRelaySessionManager(baseMgr, th, nil, reg, nil, nil, logging.NewNoopLogger())

	ctx := context.Background()
	_, err := rsm.CreateSession(ctx, &terminal.SessionRequest{
		TenantID:  "test-tenant",
		StewardID: "offline-steward",
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	})
	require.Error(t, err, "CreateSession must return an error when steward is offline")
	assert.Contains(t, err.Error(), "not connected",
		"error message must indicate the steward is not connected")

	// No pending relay must have been registered (no leak).
	th.mu.RLock()
	pending := len(th.pending)
	th.mu.RUnlock()
	assert.Equal(t, 0, pending, "no pending relay must be registered when steward is offline")

	// No session must have been created in the base manager.
	assert.Empty(t, baseMgr.GetActiveSessions(),
		"base manager must have no active sessions after offline rejection")
}

// ---------------------------------------------------------------------------
// Test: dispatch failure → rollback (unregister + terminate) + error propagated
// ---------------------------------------------------------------------------

// TestRelaySessionManagerDispatchFailureRollsBack verifies the error path added
// to CreateSession: when PublishCommand fails to dispatch COMMAND_TYPE_OPEN_TERMINAL
// to the steward, CreateSession must (1) return the dispatch error, (2) unregister
// the pending relay, and (3) tear down the base session so nothing leaks.
//
// A real commands.Publisher is wired over a real gRPC control plane provider in
// server mode whose connection registry is empty, so SendCommand returns a
// genuine "steward not connected" error — no fakes or mocks.
func TestRelaySessionManagerDispatchFailureRollsBack(t *testing.T) {
	const stewardID = "steward-dispatch-fail"

	baseMgr := newTestSessionManager(t)
	th := NewTerminalHandler(logging.NewNoopLogger())

	// Real control plane provider in server mode with an empty steward registry.
	// SendCommand consults this registry and fails when the target is absent.
	cp := cpgrpc.New(cpgrpc.ModeServer)
	require.NoError(t, cp.Initialize(context.Background(), map[string]interface{}{
		"grpc_server": grpc.NewServer(),
		"registry":    registry.NewRegistry(),
	}))
	publisher, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	// nil connRegistry so the online pre-check is skipped and we exercise the
	// dispatch path itself; the dispatch fails because cp's registry is empty.
	rsm := NewRelaySessionManager(baseMgr, th, publisher, nil, nil, nil, logging.NewNoopLogger())

	_, err = rsm.CreateSession(context.Background(), &terminal.SessionRequest{
		TenantID:  "test-tenant",
		StewardID: stewardID,
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	})
	require.Error(t, err, "CreateSession must return an error when dispatch fails")
	assert.Contains(t, err.Error(), "failed to dispatch open_terminal",
		"the returned error must identify the dispatch failure")

	// The pending relay must have been unregistered during rollback.
	th.mu.RLock()
	pending := len(th.pending)
	th.mu.RUnlock()
	assert.Equal(t, 0, pending, "pending relay must be unregistered after dispatch failure")

	// The base session must have been torn down (no leak).
	assert.Empty(t, baseMgr.GetActiveSessions(),
		"base manager must have no active sessions after dispatch-failure rollback")
}

// ---------------------------------------------------------------------------
// Test 3: Non-allowlisted Origin → HTTP 403 from WS handler
// ---------------------------------------------------------------------------

// TestTerminalWebSocketBadOriginRejected verifies that the terminal WebSocket
// handler rejects connections whose Origin header is not same-origin and not in
// the configured allowlist, returning HTTP 403 Forbidden.
func TestTerminalWebSocketBadOriginRejected(t *testing.T) {
	baseMgr := newTestSessionManager(t)
	th := NewTerminalHandler(logging.NewNoopLogger())
	rsm := NewRelaySessionManager(baseMgr, th, nil, nil, nil, nil, logging.NewNoopLogger())

	// No origin allowlist — only same-origin connections are accepted.
	wsHandler, err := terminal.NewWebSocketHandler(rsm, logging.NewNoopLogger(), nil)
	require.NoError(t, err)

	server := httptest.NewServer(withTestTenant(http.HandlerFunc(wsHandler.HandleWebSocket)))
	defer server.Close()

	// Craft a non-WebSocket GET request with a cross-origin Origin header.
	// We send a plain HTTP request (not a WebSocket dial) because the Go HTTP
	// client cannot dial a WebSocket; the 403 is returned before the upgrade.
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL+"?steward_id=s1&user_id=u1&shell=bash",
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Origin", "http://evil.example.com")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"WebSocket upgrade from a non-allowlisted origin must be rejected with 403")
}

// ---------------------------------------------------------------------------
// Test 4: Session open+close → audit record + session recording exists
// ---------------------------------------------------------------------------

// TestRelaySessionManagerAuditAndRecording verifies that:
//  1. A terminal.session.start audit event is recorded when CreateSession succeeds.
//  2. A terminal.session.end audit event is recorded when TerminateSession is called.
//  3. A session recording file is written by the underlying DefaultSessionManager.
func TestRelaySessionManagerAuditAndRecording(t *testing.T) {
	// Set up a real audit manager backed by a real storage stack.
	storageManager := pkgtesting.SetupTestStorage(t)
	auditStore := storageManager.GetAuditStore()
	auditMgr, err := audit.NewManager(auditStore, "terminal-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = auditMgr.Stop(ctx)
	})

	recDir := t.TempDir()
	baseMgr, err := terminal.NewSessionManager(&terminal.Config{
		RecordSessions:       true,
		RecordingStoragePath: recDir,
		SessionTimeout:       30 * time.Minute,
		MaxSessions:          100,
	}, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		if dsm, ok := baseMgr.(*terminal.DefaultSessionManager); ok {
			_ = dsm.Stop(context.Background())
		}
	})

	th := NewTerminalHandler(logging.NewNoopLogger())
	// nil registry → skips online check (test convenience only).
	// nil commandPublisher → skips dispatch (test convenience only).
	rsm := NewRelaySessionManager(baseMgr, th, nil, nil, auditMgr, nil, logging.NewNoopLogger())

	ctx := context.Background()
	session, err := rsm.CreateSession(ctx, &terminal.SessionRequest{
		TenantID:  "test-tenant",
		StewardID: "test-steward",
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	})
	require.NoError(t, err)
	require.NotNil(t, session)

	// Write some data to the session so there is something to record.
	require.NoError(t, session.HandleOutput(ctx, []byte("hello from steward")))

	// Terminate the session to flush the recording and write the end event.
	require.NoError(t, rsm.TerminateSession(ctx, session.ID))

	// Flush the audit drain goroutine before querying the store.
	flushCtx, flushCancel := context.WithTimeout(ctx, 10*time.Second)
	defer flushCancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	// --- Verify audit start event ---
	startEntries, err := auditStore.GetAuditsByAction(ctx, "terminal.session.start", nil)
	require.NoError(t, err)
	require.NotEmpty(t, startEntries, "terminal.session.start audit entry must exist")
	var foundStart bool
	for _, e := range startEntries {
		if e.SessionID == session.ID {
			foundStart = true
			assert.Equal(t, business.AuditResultSuccess, e.Result)
			assert.Equal(t, business.AuditEventSystemAccess, e.EventType)
		}
	}
	assert.True(t, foundStart, "terminal.session.start audit entry for session %q not found", session.ID)

	// --- Verify audit end event ---
	endEntries, err := auditStore.GetAuditsByAction(ctx, "terminal.session.end", nil)
	require.NoError(t, err)
	require.NotEmpty(t, endEntries, "terminal.session.end audit entry must exist")
	var foundEnd bool
	for _, e := range endEntries {
		if e.SessionID == session.ID {
			foundEnd = true
			assert.Equal(t, business.AuditResultSuccess, e.Result)
		}
	}
	assert.True(t, foundEnd, "terminal.session.end audit entry for session %q not found", session.ID)

	// --- Verify session recording exists ---
	recording, err := baseMgr.GetSessionRecording(session.ID)
	require.NoError(t, err, "session recording must be retrievable after termination")
	assert.NotNil(t, recording, "session recording must not be nil")
	// The recording must contain at least the steward output injected above.
	totalBytes := len(recording.Data)
	for _, ev := range recording.Events {
		totalBytes += len(ev.Data)
	}
	assert.Greater(t, totalBytes, 0, "session recording must contain recorded data")
}

// ---------------------------------------------------------------------------
// Test: browser→steward relay via RelayExecutor.InputChan
// ---------------------------------------------------------------------------

// TestTerminalHandlerBrowserToStewardRelay verifies that data written by the
// WebSocket handler (via session.WriteData → RelayExecutor.WriteData) is
// forwarded to the steward's gRPC stream by HandleGRPC.
func TestTerminalHandlerBrowserToStewardRelay(t *testing.T) {
	const stewardID = "steward-b2s-test"
	mgr := newTestSessionManager(t)

	h := NewTerminalHandler(logging.NewNoopLogger())
	session := newTestSession(t, mgr, stewardID)

	// Use the relay executor that was installed by newTestSession.
	relayExec := terminal.NewRelayExecutor()
	session.SetExecutor(relayExec)
	h.register(session.ID, stewardID, session, relayExec)

	// Dial with a client cert CN matching the registered steward so the mTLS
	// identity binding in HandleGRPC is satisfied.
	ca := newTestCA(t)
	ctx, cancel := context.WithTimeout(peerContextWithCA(t, ca, stewardID), 5*time.Second)
	defer cancel()

	stream := newTestBidiStream(ctx)
	// Block on send delivery instead of polling with time.Sleep.
	stream.sentSignal = make(chan struct{}, 8)

	// Handshake frame — no data payload.
	stream.recvCh <- &transportpb.TerminalData{SessionId: session.ID}

	handleDone := make(chan error, 1)
	go func() {
		handleDone <- h.HandleGRPC(stream)
	}()

	// Write browser input via WriteData (browser→executor→inputCh).
	browserInput := []byte("ls -la\n")
	writeCtx := context.Background()
	require.NoError(t, session.WriteData(writeCtx, browserInput))

	// Block until HandleGRPC forwards a frame to the steward stream, then verify
	// the forwarded payload — no wall-clock polling.
	select {
	case <-stream.sentSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for browser input to be forwarded to the steward stream")
	}
	var found bool
	for _, msg := range stream.getSent() {
		if strings.Contains(string(msg.GetData()), string(browserInput)) {
			found = true
			break
		}
	}
	assert.True(t, found, "browser input must be forwarded to the steward stream by HandleGRPC")

	cancel()
	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleGRPC did not exit after context cancellation")
	}
}

// ---------------------------------------------------------------------------
// Security: mTLS peer-identity binding on the Terminal relay (Issue #2761)
// ---------------------------------------------------------------------------

// TestTerminalHandler_MissingPeerCert verifies that HandleGRPC rejects a stream
// with no mTLS peer certificate in context with codes.Unauthenticated, before
// any session correlation happens. Without this, the interactive admin relay
// could be joined by an unauthenticated caller.
func TestTerminalHandler_MissingPeerCert(t *testing.T) {
	h := NewTerminalHandler(logging.NewNoopLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream := newTestBidiStream(ctx)

	err := h.HandleGRPC(stream)

	require.Error(t, err, "HandleGRPC must reject a stream with no mTLS peer identity")
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"missing mTLS peer certificate must yield Unauthenticated")
}

// TestTerminalHandler_StewardIDMismatch verifies that a steward whose mTLS peer
// CN does not match the target steward recorded on the pending relay is rejected
// with codes.PermissionDenied — a leaked/guessed session_id from another fleet
// steward (including cross-tenant) must not be able to hijack the relay.
func TestTerminalHandler_StewardIDMismatch(t *testing.T) {
	const targetSteward = "steward-target"
	const attackerSteward = "steward-attacker"

	mgr := newTestSessionManager(t)
	h := NewTerminalHandler(logging.NewNoopLogger())

	// Register the pending relay against the legitimate target steward.
	session := newTestSession(t, mgr, targetSteward)
	relayExec := terminal.NewRelayExecutor()
	session.SetExecutor(relayExec)
	h.register(session.ID, targetSteward, session, relayExec)

	// Dial in as a different, attacker steward holding a valid fleet mTLS cert.
	ca := newTestCA(t)
	ctx, cancel := context.WithTimeout(peerContextWithCA(t, ca, attackerSteward), 2*time.Second)
	defer cancel()

	stream := newTestBidiStream(ctx)
	// Present the (correct) session_id in the handshake frame; only the peer
	// identity differs from the target.
	stream.recvCh <- &transportpb.TerminalData{SessionId: session.ID}

	err := h.HandleGRPC(stream)

	require.Error(t, err, "cross-identity dial-in must be rejected")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"steward whose mTLS CN differs from the target must get PermissionDenied")

	// The relay must remain registered (the legitimate steward can still join)
	// and the WS-side connected signal must NOT have fired for the attacker.
	h.mu.RLock()
	relay, stillPending := h.pending[session.ID]
	h.mu.RUnlock()
	require.True(t, stillPending, "an unauthorized dial-in must not tear down the pending relay")
	select {
	case <-relay.connectedCh:
		t.Fatal("connectedCh must not be closed by an unauthorized (mismatched) steward")
	default:
	}
}
