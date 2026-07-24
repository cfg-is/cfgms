// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	terminalGRPCConnectTimeout = 30 * time.Second
	terminalPingInterval       = 54 * time.Second
	terminalWriteTimeout       = 10 * time.Second
	terminalInputBufSize       = 64
	// maxTerminalDim caps terminal columns/rows before int32 conversion to
	// prevent integer overflow on 64-bit platforms where int is 64-bit.
	maxTerminalDim = 65535
)

// TerminalCommandPublisher dispatches COMMAND_TYPE_OPEN_TERMINAL to a steward.
type TerminalCommandPublisher interface {
	PublishCommand(ctx context.Context, stewardID string, cmdType controlplaneTypes.CommandType, params map[string]interface{}) (string, error)
}

// inputMsg carries a single input frame from the browser to the steward.
type inputMsg struct {
	data   []byte
	resize bool
	rows   int32
	cols   int32
}

// terminalRelay tracks the relay state for one browser ↔ steward terminal session.
type terminalRelay struct {
	sessionID string
	stewardID string
	tenantID  string
	userID    string
	session   *terminal.Session // carries outputCh and recorder
	inputCh   chan inputMsg     // browser → steward (buffered; drained by HandleGRPC)
	grpcReady chan struct{}     // closed when HandleGRPC binds the stream
	done      chan struct{}     // closed when either side ends the relay
	closeOnce sync.Once
	bound     bool // set under h.mu by bindRelay; duplicate gRPC streams are rejected
}

func (r *terminalRelay) close() {
	r.closeOnce.Do(func() { close(r.done) })
}

// TerminalHandler handles Terminal bidi RPCs from stewards (HandleGRPC) and
// relays I/O to/from browser WebSocket clients (ServeWebSocket). Sessions are
// correlated by the session_id carried in the first TerminalData frame and in
// the COMMAND_TYPE_OPEN_TERMINAL params dispatched to the steward.
type TerminalHandler struct {
	logger         logging.Logger
	commandPub     TerminalCommandPublisher
	sessionMgr     terminal.SessionManager
	auditMgr       *audit.Manager
	allowedOrigins []string
	upgrader       websocket.Upgrader

	mu     sync.Mutex
	relays map[string]*terminalRelay // session_id → relay

	// onGRPCBound is called (without holding mu) after HandleGRPC binds a relay.
	// Nil in production; set in tests to signal readiness without time.Sleep.
	onGRPCBound func(sessionID string)
}

// NewTerminalHandler creates a TerminalHandler. allowedOrigins lists additional
// allowed Origin hosts for WebSocket upgrade (same-origin is always accepted).
func NewTerminalHandler(
	logger logging.Logger,
	commandPub TerminalCommandPublisher,
	sessionMgr terminal.SessionManager,
	auditMgr *audit.Manager,
	allowedOrigins []string,
) *TerminalHandler {
	h := &TerminalHandler{
		logger:         logger,
		commandPub:     commandPub,
		sessionMgr:     sessionMgr,
		auditMgr:       auditMgr,
		allowedOrigins: allowedOrigins,
		relays:         make(map[string]*terminalRelay),
	}
	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			return terminalOriginAllowed(r, allowedOrigins)
		},
	}
	return h
}

// HandleGRPC processes a Terminal bidi RPC opened by a steward after receiving
// COMMAND_TYPE_OPEN_TERMINAL. It extracts the mTLS peer CN, correlates the
// stream to a pending browser WS session by session_id, and relays TerminalData
// frames bidirectionally.
func (h *TerminalHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]) error {
	ctx := stream.Context()

	peerID, err := extractMTLSPeerID(ctx)
	if err != nil {
		return err
	}

	// First frame from steward carries the session_id for correlation.
	first, recvErr := stream.Recv()
	if recvErr != nil {
		if recvErr == io.EOF {
			return nil
		}
		return fmt.Errorf("terminal: recv first frame: %w", recvErr)
	}

	sessionID := first.GetSessionId()
	if sessionID == "" {
		return status.Error(codes.InvalidArgument, "terminal: session_id required in first frame")
	}

	relay, found := h.lookupRelay(sessionID)
	if !found {
		return status.Errorf(codes.NotFound, "terminal: unknown session_id")
	}

	// Security: verify the connecting steward matches the command dispatch target.
	if relay.stewardID != peerID {
		return status.Error(codes.PermissionDenied, "terminal: steward ID mismatch")
	}

	// Atomically mark relay as gRPC-bound. A second stream for the same session_id
	// (e.g. a compromised steward retrying) is rejected here rather than reaching
	// close(relay.grpcReady) and causing a "close of closed channel" panic.
	if !h.bindRelay(sessionID) {
		return status.Error(codes.FailedPrecondition, "terminal: session already has an active gRPC stream")
	}

	// Signal the browser-side goroutine that the gRPC stream is ready.
	close(relay.grpcReady) // safe: bindRelay ensures at-most-once
	if h.onGRPCBound != nil {
		h.onGRPCBound(sessionID)
	}

	// Deliver any payload in the first frame (steward may piggyback initial output).
	if len(first.GetData()) > 0 {
		if outErr := relay.session.HandleOutput(ctx, first.GetData()); outErr != nil {
			relay.close()
			return fmt.Errorf("terminal: relay first frame output: %w", outErr)
		}
	}

	// Send goroutine: drain inputCh → stream.Send (browser → steward).
	sendErrCh := make(chan error, 1)
	go func() {
		for {
			select {
			case msg, ok := <-relay.inputCh:
				if !ok {
					sendErrCh <- nil
					return
				}
				frame := &transportpb.TerminalData{
					SessionId: sessionID,
					Data:      msg.data,
					IsResize:  msg.resize,
				}
				if msg.resize {
					frame.Rows = msg.rows
					frame.Cols = msg.cols
				}
				if sendErr := stream.Send(frame); sendErr != nil {
					sendErrCh <- sendErr
					return
				}
			case <-relay.done:
				sendErrCh <- nil
				return
			case <-ctx.Done():
				sendErrCh <- nil
				return
			}
		}
	}()

	// Recv loop: steward → browser relay via session output channel.
	var finalErr error
	for {
		frame, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				finalErr = err
			}
			break
		}
		if len(frame.GetData()) > 0 {
			if outErr := relay.session.HandleOutput(ctx, frame.GetData()); outErr != nil {
				if h.logger != nil {
					h.logger.Warn("terminal: HandleOutput failed",
						"session_id", logging.RedactedID(sessionID), "error", outErr)
				}
			}
		}
	}

	relay.close()
	<-sendErrCh
	return finalErr
}

// ServeWebSocket upgrades an HTTP request to a WebSocket connection and relays
// terminal data between the browser and the steward's Terminal gRPC stream.
// The {steward_id} path variable (gorilla/mux) carries the target steward ID.
// Authentication and RBAC are enforced upstream by requirePermission middleware.
func (h *TerminalHandler) ServeWebSocket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	stewardID := vars["steward_id"]
	if stewardID == "" {
		http.Error(w, "missing steward_id", http.StatusBadRequest)
		return
	}

	// Origin check before session creation to avoid resource allocation on bad actors.
	if !terminalOriginAllowed(r, h.allowedOrigins) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	userID, _ := ctx.Value(ctxkeys.UserIDKey).(string)
	tenantID, _ := ctx.Value(ctxkeys.TenantID).(string)

	q := r.URL.Query()
	shell := q.Get("shell")
	if shell == "" {
		shell = "bash"
	}
	if !terminal.ValidateShell(shell) {
		http.Error(w, "unsupported shell", http.StatusBadRequest)
		return
	}
	// cols/rows are uint16 (parseTerminalInt bitSize=16), so they are inherently
	// bounded to [0, 65535] — no explicit cap is needed before the int32 dispatch
	// conversion below.
	cols := parseTerminalInt(q.Get("cols"), 80)
	rows := parseTerminalInt(q.Get("rows"), 24)
	clientIP := terminalClientIP(r)

	// Create terminal session (includes recording + audit start event).
	sess, err := terminal.CreateBrowserSession(ctx, h.sessionMgr, h.auditMgr, terminal.BrowserSessionOptions{
		UserID:    userID,
		TenantID:  tenantID,
		StewardID: stewardID,
		Shell:     shell,
		Cols:      int(cols),
		Rows:      int(rows),
		ClientIP:  clientIP,
	})
	if err != nil {
		if h.logger != nil {
			// Sanitize err.Error() explicitly: the error message may embed
			// stewardID (user-controlled) from session-creation internals.
			h.logger.Error("terminal: session creation failed",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		http.Error(w, "failed to create terminal session", http.StatusInternalServerError)
		return
	}

	relay := &terminalRelay{
		sessionID: sess.ID,
		stewardID: stewardID,
		tenantID:  tenantID,
		userID:    userID,
		session:   sess,
		inputCh:   make(chan inputMsg, terminalInputBufSize),
		grpcReady: make(chan struct{}),
		done:      make(chan struct{}),
	}

	h.registerRelay(sess.ID, relay)
	defer func() {
		h.unregisterRelay(sess.ID)
		relay.close()
		terminal.EndBrowserSession(
			context.Background(), h.auditMgr,
			tenantID, userID, sess.ID, stewardID, "websocket closed",
		)
		// Close session to flush the recorder.
		if h.sessionMgr != nil {
			_ = h.sessionMgr.TerminateSession(context.Background(), sess.ID)
		}
	}()

	// Dispatch COMMAND_TYPE_OPEN_TERMINAL to the steward.
	if h.commandPub != nil {
		// cols/rows are uint16, so int32(cols)/int32(rows) are widening conversions
		// that are provably in range [0, 65535] — no bounds guard is required and
		// CodeQL's go/incorrect-integer-conversion does not flag a uint16→int32 cast.
		_, cmdErr := h.commandPub.PublishCommand(ctx, stewardID, controlplaneTypes.CommandOpenTerminal, map[string]interface{}{
			"session_id": sess.ID,
			"shell":      shell,
			"cols":       int32(cols),
			"rows":       int32(rows),
		})
		if cmdErr != nil {
			if h.logger != nil {
				h.logger.Warn("terminal: dispatch open-terminal command failed",
					"steward_id", logging.SanitizeLogValue(stewardID),
					"session_id", logging.RedactedID(sess.ID),
					// Sanitize cmdErr.Error() explicitly: the error message may
					// embed stewardID (user-controlled) from PublishCommand internals.
					"error", logging.SanitizeLogValue(cmdErr.Error()))
			}
			http.Error(w, "steward unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	// Upgrade to WebSocket. Upgrader.CheckOrigin already validated origin above;
	// we set the check to pass here to avoid a double-check.
	conn, upgradeErr := h.upgrader.Upgrade(w, r, nil)
	if upgradeErr != nil {
		if h.logger != nil {
			h.logger.Warn("terminal: WebSocket upgrade failed",
				"steward_id", logging.SanitizeLogValue(stewardID), "error", upgradeErr)
		}
		return
	}
	defer conn.Close() //nolint:errcheck // cleanup error in defer is unactionable

	// Wait for the steward to open its Terminal gRPC stream.
	select {
	case <-relay.grpcReady:
		// stream is ready — proceed with relay
	case <-time.After(terminalGRPCConnectTimeout):
		terminalSendWSError(conn, "steward did not connect within timeout")
		return
	case <-ctx.Done():
		return
	}

	// Bidirectional relay between browser WS and steward gRPC stream.
	h.runWSRelay(ctx, conn, relay, sess)
}

// runWSRelay manages the WS ↔ gRPC relay for one session.
func (h *TerminalHandler) runWSRelay(ctx context.Context, conn *websocket.Conn, relay *terminalRelay, sess *terminal.Session) {
	conn.SetReadLimit(65536)
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(terminalPingInterval + 10*time.Second))
	})
	_ = conn.SetReadDeadline(time.Now().Add(terminalPingInterval + 10*time.Second))

	// WS reader goroutine: browser input → inputCh.
	wsGone := make(chan struct{})
	go func() {
		defer func() {
			relay.close()
			close(wsGone)
		}()
		for {
			var msg terminal.TerminalMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			switch msg.Type {
			case terminal.MessageTypeData:
				select {
				case relay.inputCh <- inputMsg{data: msg.Data}:
				case <-relay.done:
					return
				}
			case terminal.MessageTypeResize:
				var req terminal.ResizeRequest
				if jsonErr := json.Unmarshal(msg.Data, &req); jsonErr == nil && req.Cols > 0 && req.Rows > 0 {
					if req.Cols > maxTerminalDim {
						req.Cols = maxTerminalDim
					}
					if req.Rows > maxTerminalDim {
						req.Rows = maxTerminalDim
					}
					select {
					case relay.inputCh <- inputMsg{resize: true, rows: int32(req.Rows), cols: int32(req.Cols)}: // safe: bounded above
					case <-relay.done:
						return
					}
				}
			case terminal.MessageTypeClose:
				return
			}
		}
	}()

	// WS writer loop: steward output → browser.
	pingTicker := time.NewTicker(terminalPingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-wsGone:
			return
		case <-relay.done:
			terminalSendWSError(conn, "steward disconnected")
			return
		case <-ctx.Done():
			return
		case data := <-sess.OutputChan():
			_ = conn.SetWriteDeadline(time.Now().Add(terminalWriteTimeout))
			if err := conn.WriteJSON(terminal.TerminalMessage{
				Type: terminal.MessageTypeData,
				Data: data,
			}); err != nil {
				return
			}
		case <-pingTicker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(terminalWriteTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// registerRelay stores relay in the correlation map.
func (h *TerminalHandler) registerRelay(sessionID string, relay *terminalRelay) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.relays[sessionID] = relay
}

// unregisterRelay removes relay from the correlation map.
func (h *TerminalHandler) unregisterRelay(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.relays, sessionID)
}

// lookupRelay finds the relay for the given session_id.
func (h *TerminalHandler) lookupRelay(sessionID string) (*terminalRelay, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	relay, ok := h.relays[sessionID]
	return relay, ok
}

// bindRelay atomically marks the relay as gRPC-bound. Returns false if the relay
// is already bound (a second stream for the same session_id must be rejected).
func (h *TerminalHandler) bindRelay(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	relay, ok := h.relays[sessionID]
	if !ok || relay.bound {
		return false
	}
	relay.bound = true
	return true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// terminalOriginAllowed returns true when the request's Origin host matches
// r.Host (same-origin) or appears in allowlist. Absent/unparseable Origin is rejected.
func terminalOriginAllowed(r *http.Request, allowlist []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, a := range allowlist {
		if strings.EqualFold(u.Host, a) {
			return true
		}
	}
	return false
}

// terminalSendWSError sends a JSON error frame on conn, ignoring write errors.
func terminalSendWSError(conn *websocket.Conn, msg string) {
	_ = conn.SetWriteDeadline(time.Now().Add(terminalWriteTimeout))
	_ = conn.WriteJSON(terminal.TerminalMessage{
		Type:  terminal.MessageTypeError,
		Error: msg,
	})
}

// parseTerminalInt parses a query-string terminal dimension with a positive-integer
// constraint. It returns a uint16 so callers get a value whose type range is provably
// [0, 65535]: the subsequent widening int32 conversion at the command-dispatch site is
// therefore statically in range, which CodeQL's go/incorrect-integer-conversion accepts
// without any explicit bounds guard (a uint16→int32 conversion can never overflow).
func parseTerminalInt(s string, def uint16) uint16 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 16) // bitSize=16 → [0, 65535], fits uint16 exactly
	if err != nil || v == 0 {
		return def
	}
	return uint16(v)
}

// terminalClientIP extracts the client IP from the request (proxy-aware).
func terminalClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	addr := r.RemoteAddr
	if colon := strings.LastIndex(addr, ":"); colon != -1 {
		addr = addr[:colon]
	}
	return addr
}
