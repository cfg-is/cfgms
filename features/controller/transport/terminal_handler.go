// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// pendingRelay holds the in-flight relay state for a terminal session that
// has been created on the WebSocket side but not yet joined by the steward.
type pendingRelay struct {
	stewardID   string // target steward the session was dispatched to (mTLS binding)
	session     *terminal.Session
	exec        *terminal.RelayExecutor
	connectedCh chan struct{} // closed once the steward dials in
}

// TerminalHandler handles inbound Terminal bidirectional gRPC streams from
// stewards.  On each stream, it:
//
//  1. Reads the first TerminalData frame to extract the session_id.
//  2. Correlates session_id to the WS-side Session registered by
//     relaySessionManager.CreateSession.
//  3. Runs two relay goroutines for the life of the session:
//     steward→browser: stream.Recv → session.HandleOutput → session.outputCh
//     browser→steward: RelayExecutor.InputChan / ResizeChan → stream.Send
type TerminalHandler struct {
	mu      sync.RWMutex
	pending map[string]*pendingRelay
	logger  logging.Logger
}

// NewTerminalHandler creates a TerminalHandler.
func NewTerminalHandler(logger logging.Logger) *TerminalHandler {
	return &TerminalHandler{
		pending: make(map[string]*pendingRelay),
		logger:  logger,
	}
}

// register stores a pending relay entry created at WS-session creation time.
// stewardID is the target steward the session was dispatched to; HandleGRPC
// requires the dialing steward's mTLS identity to match it before relaying.
func (h *TerminalHandler) register(sessionID, stewardID string, session *terminal.Session, exec *terminal.RelayExecutor) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending[sessionID] = &pendingRelay{
		stewardID:   stewardID,
		session:     session,
		exec:        exec,
		connectedCh: make(chan struct{}),
	}
}

// unregister removes the pending relay entry for sessionID (called on disconnect
// or on error during session creation).
func (h *TerminalHandler) unregister(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.pending, sessionID)
}

// peerStewardIDFromContext extracts the authenticated steward ID (mTLS peer
// certificate CN) from the gRPC stream context, mirroring the extraction done
// by DNAHandler, BulkHandler, ConfigHandler and LogStreamHandler.
func peerStewardIDFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer information in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("peer auth info is not mTLS")
	}
	return quictransport.PeerStewardID(tlsInfo.State)
}

// HandleGRPC processes the Terminal bidirectional streaming RPC from a steward.
func (h *TerminalHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]) error {
	ctx := stream.Context()

	// Establish the dialing steward's mTLS identity up front. The Terminal relay
	// carries an interactive admin shell, so a session_id alone must never be
	// sufficient to join — parity with the other security-critical data-plane
	// handlers (DNAHandler/ConfigHandler/BulkHandler/LogStreamHandler).
	peerID, err := peerStewardIDFromContext(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}

	firstFrame, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "expected initial TerminalData frame")
	}

	sessionID := firstFrame.GetSessionId()
	if sessionID == "" {
		return status.Error(codes.InvalidArgument, "session_id required in first TerminalData frame")
	}

	h.mu.RLock()
	relay, ok := h.pending[sessionID]
	h.mu.RUnlock()
	if !ok {
		return status.Errorf(codes.NotFound, "no pending terminal session for session_id %q", logging.SanitizeLogValue(sessionID))
	}

	// Bind the authenticated peer to the target steward recorded at session
	// creation. A leaked or guessed session_id presented by any other fleet
	// steward (including cross-tenant) must not be able to hijack the relay,
	// capture admin keystrokes, or inject output into the admin browser.
	if relay.stewardID != peerID {
		return status.Error(codes.PermissionDenied, "steward ID mismatch")
	}

	// Signal WebSocket side that the steward has connected.
	close(relay.connectedCh)

	if h.logger != nil {
		h.logger.Info("Terminal relay established",
			"session_id", logging.RedactedID(sessionID))
	}

	// Any payload piggybacked on the first frame goes directly to the browser.
	// A closed-session error means the WS side is already gone: tear down the
	// relay rather than proceeding to run goroutines with nothing to feed.
	if len(firstFrame.GetData()) > 0 {
		if outErr := relay.session.HandleOutput(ctx, firstFrame.GetData()); outErr != nil {
			h.unregister(sessionID)
			return nil
		}
	}

	relayErrCh := make(chan error, 2)

	// browser→steward: relay data/resize frames from the RelayExecutor channels.
	go func() {
		for {
			select {
			case <-ctx.Done():
				relayErrCh <- nil
				return
			case data, open := <-relay.exec.InputChan():
				if !open {
					relayErrCh <- nil
					return
				}
				if sendErr := stream.Send(&transportpb.TerminalData{
					SessionId: sessionID,
					Data:      data,
				}); sendErr != nil {
					relayErrCh <- sendErr
					return
				}
			case dims, open := <-relay.exec.ResizeChan():
				if !open {
					relayErrCh <- nil
					return
				}
				if sendErr := stream.Send(&transportpb.TerminalData{
					SessionId: sessionID,
					IsResize:  true,
					Cols:      dims[0],
					Rows:      dims[1],
				}); sendErr != nil {
					relayErrCh <- sendErr
					return
				}
			}
		}
	}()

	// steward→browser: receive frames and push output to the WS session channel.
	go func() {
		for {
			frame, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF {
					relayErrCh <- nil
				} else {
					relayErrCh <- recvErr
				}
				return
			}
			if data := frame.GetData(); len(data) > 0 {
				// A closed-session error is actionable: the WS session is gone,
				// so stop receiving and discarding steward frames and exit the
				// goroutine instead of spinning until context cancellation.
				if outErr := relay.session.HandleOutput(ctx, data); outErr != nil {
					relayErrCh <- nil
					return
				}
			}
		}
	}()

	relayErr := <-relayErrCh
	h.unregister(sessionID)

	if relayErr != nil && relayErr != io.EOF {
		if st, ok2 := status.FromError(relayErr); ok2 && st.Code() == codes.Canceled {
			return nil // normal WS close — not an error
		}
		return relayErr
	}
	return nil
}

// relaySessionManager wraps a SessionManager to add controller-side relay
// behaviour at CreateSession time:
//
//  1. Rejects session creation when the target steward is not connected.
//  2. Replaces the platform shell executor with a channel-based RelayExecutor.
//  3. Registers the relay in TerminalHandler so HandleGRPC can correlate it.
//  4. Dispatches COMMAND_TYPE_OPEN_TERMINAL to the steward.
//  5. Records terminal.session.start / terminal.session.end audit events when
//     auditManager is non-nil (Issue #2761: RBAC-gated, recorded sessions).
//
// When authManager is non-nil (AC 2, Issue #2761), TerminateSession routes
// through AuthenticatedTerminalManager for session token cleanup, session
// monitor removal, and audit logging instead of the relay's own audit path.
type relaySessionManager struct {
	base             terminal.SessionManager
	terminalHandler  *TerminalHandler
	commandPublisher *commands.Publisher
	connRegistry     registry.Registry
	auditManager     *audit.Manager
	authManager      *terminal.AuthenticatedTerminalManager
	logger           logging.Logger
}

// NewRelaySessionManager returns a SessionManager suitable for the controller
// WebSocket handler. All session creation side-effects described on
// relaySessionManager are applied atomically from the caller's perspective.
// auditManager may be nil — when non-nil, session.start / session.end audit
// events are recorded. authManager may be nil; when non-nil it takes over
// TerminateSession for session token cleanup and security audit logging
// (Issue #2761 AC 2: AuthenticatedTerminalManager constructed and used).
func NewRelaySessionManager(
	base terminal.SessionManager,
	terminalHandler *TerminalHandler,
	commandPublisher *commands.Publisher,
	connRegistry registry.Registry,
	auditManager *audit.Manager,
	authManager *terminal.AuthenticatedTerminalManager,
	logger logging.Logger,
) terminal.SessionManager {
	return &relaySessionManager{
		base:             base,
		terminalHandler:  terminalHandler,
		commandPublisher: commandPublisher,
		connRegistry:     connRegistry,
		auditManager:     auditManager,
		authManager:      authManager,
		logger:           logger,
	}
}

func (m *relaySessionManager) CreateSession(ctx context.Context, req *terminal.SessionRequest) (*terminal.Session, error) {
	// Fail fast when the target steward has no active ControlChannel.
	if m.connRegistry != nil {
		if _, online := m.connRegistry.Get(req.StewardID); !online {
			return nil, fmt.Errorf("steward %q is not connected", logging.SanitizeLogValue(req.StewardID))
		}
	}

	session, err := m.base.CreateSession(ctx, req)
	if err != nil {
		return nil, err
	}

	// Replace the platform shell executor with a channel-based relay executor
	// so WriteData from the WebSocket handler is forwarded to the steward
	// stream rather than a (non-running) local shell process.
	relayExec := terminal.NewRelayExecutor()
	session.SetExecutor(relayExec)

	// Register before dispatching the command so HandleGRPC can correlate
	// immediately when the steward dials in.
	m.terminalHandler.register(session.ID, req.StewardID, session, relayExec)

	// Dispatch COMMAND_TYPE_OPEN_TERMINAL to the target steward.
	if m.commandPublisher != nil {
		// Clamp terminal dimensions to int32 range before conversion; session.go
		// already defaults <=0 to 80/24, so the lower bound is only a safety net.
		var cols, rows int32
		if req.Cols > 0 && req.Cols <= math.MaxInt32 {
			cols = int32(req.Cols) //nolint:gosec // bounds-checked above
		} else {
			cols = 80
		}
		if req.Rows > 0 && req.Rows <= math.MaxInt32 {
			rows = int32(req.Rows) //nolint:gosec // bounds-checked above
		} else {
			rows = 24
		}
		params := map[string]interface{}{
			"session_id": session.ID,
			"shell":      req.Shell,
			"cols":       cols,
			"rows":       rows,
		}
		if _, dispatchErr := m.commandPublisher.PublishCommand(
			ctx, req.StewardID, controlplaneTypes.CommandOpenTerminal, params,
		); dispatchErr != nil {
			m.terminalHandler.unregister(session.ID)
			// Roll back the base session. If teardown itself fails the session
			// would otherwise leak in the base manager with no trace, so surface
			// the inconsistency rather than discarding the error.
			if termErr := m.base.TerminateSession(ctx, session.ID); termErr != nil && m.logger != nil {
				m.logger.Warn("failed to terminate terminal session during dispatch rollback",
					"session_id", logging.RedactedID(session.ID),
					"steward_id", logging.SanitizeLogValue(req.StewardID),
					"error", termErr)
			}
			return nil, fmt.Errorf("failed to dispatch open_terminal to steward %q: %w",
				logging.SanitizeLogValue(req.StewardID), dispatchErr)
		}
	}

	if m.auditManager != nil {
		// Session recording is a documented compliance requirement (Issue #2761).
		// A silent audit failure would make compliance gaps undetectable, so the
		// error is logged even though it is intentionally non-fatal for the session.
		if err := m.auditManager.RecordEvent(ctx,
			audit.NewEventBuilder().
				Tenant(req.TenantID).
				Type(business.AuditEventSystemAccess).
				Action("terminal.session.start").
				User(req.UserID, business.AuditUserTypeHuman).
				Session(session.ID).
				Resource("terminal", req.StewardID, "").
				Result(business.AuditResultSuccess).
				Severity(business.AuditSeverityMedium).
				Details(map[string]interface{}{
					"shell": req.Shell,
				}),
		); err != nil && m.logger != nil {
			m.logger.Warn("failed to record terminal.session.start audit event",
				"session_id", logging.RedactedID(session.ID),
				"steward_id", logging.SanitizeLogValue(req.StewardID),
				"error", err)
		}
	}

	if m.logger != nil {
		m.logger.Info("Terminal relay session created, awaiting steward dial-in",
			"session_id", logging.RedactedID(session.ID),
			"steward_id", logging.SanitizeLogValue(req.StewardID))
	}

	return session, nil
}

func (m *relaySessionManager) GetSession(sessionID string) (*terminal.Session, error) {
	return m.base.GetSession(sessionID)
}

func (m *relaySessionManager) TerminateSession(ctx context.Context, sessionID string) error {
	m.terminalHandler.unregister(sessionID)

	// When AuthenticatedTerminalManager is wired (Issue #2761 AC 2), route
	// termination through it: it handles base session teardown, session token
	// invalidation, session monitor removal, and session.end audit logging.
	// This avoids double-auditing since authManager.TerminateSession records
	// terminal.session.end internally via its own auditManager.
	if m.authManager != nil {
		return m.authManager.TerminateSession(ctx, sessionID, "relay_terminated")
	}

	if err := m.base.TerminateSession(ctx, sessionID); err != nil {
		return err
	}
	if m.auditManager != nil {
		// A missing end-of-session audit record is undetectable otherwise; log the
		// failure so the compliance gap is observable in production (Issue #2761).
		if err := m.auditManager.RecordEvent(ctx,
			audit.NewEventBuilder().
				Tenant(audit.SystemTenantID).
				Type(business.AuditEventSystemAccess).
				Action("terminal.session.end").
				User(audit.SystemUserID, business.AuditUserTypeHuman).
				Session(sessionID).
				Resource("session", sessionID, "").
				Result(business.AuditResultSuccess).
				Severity(business.AuditSeverityMedium),
		); err != nil && m.logger != nil {
			m.logger.Warn("failed to record terminal.session.end audit event",
				"session_id", logging.RedactedID(sessionID),
				"error", err)
		}
	}
	return nil
}

func (m *relaySessionManager) GetActiveSessions() []*terminal.Session {
	return m.base.GetActiveSessions()
}

func (m *relaySessionManager) RecordData(sessionID string, data []byte, direction terminal.DataDirection) error {
	return m.base.RecordData(sessionID, data, direction)
}

func (m *relaySessionManager) GetSessionRecording(sessionID string) (*terminal.SessionRecording, error) {
	return m.base.GetSessionRecording(sessionID)
}
