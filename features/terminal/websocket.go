package terminal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultWebSocketHandler implements WebSocket handling for terminal sessions
type DefaultWebSocketHandler struct {
	upgrader       websocket.Upgrader
	sessionManager SessionManager
	logger         logging.Logger
}

// NewWebSocketHandler creates a new WebSocket handler
func NewWebSocketHandler(sessionManager SessionManager, logger logging.Logger) (*DefaultWebSocketHandler, error) {
	if sessionManager == nil {
		return nil, fmt.Errorf("session manager cannot be nil")
	}

	handler := &DefaultWebSocketHandler{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
		},
		sessionManager: sessionManager,
		logger:         logger,
	}

	return handler, nil
}

// HandleWebSocket handles WebSocket connections for terminal sessions
func (h *DefaultWebSocketHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Extract session parameters from query string
	sessionReq, err := h.parseSessionRequest(r)
	if err != nil {
		h.logger.Warn("Invalid session request", "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Invalid session request: %v", err), http.StatusBadRequest)
		return
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket connection", "error", err, "remote_addr", r.RemoteAddr)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			// Log error but continue - connection cleanup
		}
	}()

	// Create terminal session
	ctx := r.Context()
	session, err := h.sessionManager.CreateSession(ctx, sessionReq)
	if err != nil {
		h.logger.Error("Failed to create terminal session", "error", err, "remote_addr", r.RemoteAddr)
		h.sendError(conn, fmt.Sprintf("Failed to create session: %v", err))
		return
	}

	h.logger.Info("WebSocket terminal session established",
		"session_id", session.ID,
		"steward_id", session.StewardID,
		"user_id", session.UserID,
		"remote_addr", r.RemoteAddr)

	// Handle the WebSocket session
	h.handleSession(ctx, conn, session)

	// Clean up session when WebSocket closes
	if manager, ok := h.sessionManager.(*DefaultSessionManager); ok {
		manager.RequestCleanup(session.ID)
	}

	h.logger.Info("WebSocket terminal session ended",
		"session_id", session.ID,
		"duration", time.Since(session.CreatedAt))
}

// parseSessionRequest extracts session parameters from HTTP request
func (h *DefaultWebSocketHandler) parseSessionRequest(r *http.Request) (*SessionRequest, error) {
	query := r.URL.Query()

	// Required parameters
	stewardID := query.Get("steward_id")
	if stewardID == "" {
		return nil, fmt.Errorf("steward_id is required")
	}

	userID := query.Get("user_id")
	if userID == "" {
		return nil, fmt.Errorf("user_id is required")
	}

	shell := query.Get("shell")
	if shell == "" {
		shell = "bash" // Default shell
	}

	if !ValidateShell(shell) {
		return nil, fmt.Errorf("unsupported shell: %s", shell)
	}

	// Optional parameters with defaults
	cols := 80
	rows := 24

	if colsStr := query.Get("cols"); colsStr != "" {
		if c, err := strconv.Atoi(colsStr); err == nil && c > 0 {
			cols = c
		}
	}

	if rowsStr := query.Get("rows"); rowsStr != "" {
		if r, err := strconv.Atoi(rowsStr); err == nil && r > 0 {
			rows = r
		}
	}

	// Parse environment variables (optional)
	env := make(map[string]string)
	if envStr := query.Get("env"); envStr != "" {
		if err := json.Unmarshal([]byte(envStr), &env); err != nil {
			// If parsing fails, just use empty environment
			env = make(map[string]string)
		}
	}

	// Set default terminal environment variables
	if _, exists := env["TERM"]; !exists {
		env["TERM"] = "xterm-256color"
	}

	return &SessionRequest{
		StewardID: stewardID,
		UserID:    userID,
		Shell:     shell,
		Cols:      cols,
		Rows:      rows,
		Env:       env,
	}, nil
}

// handleSession manages the WebSocket session lifecycle
func (h *DefaultWebSocketHandler) handleSession(ctx context.Context, conn *websocket.Conn, session *Session) {
	// Set up channels for handling messages
	done := make(chan struct{})
	
	// Start reading messages from WebSocket
	go h.readMessages(ctx, conn, session, done)

	// Start sending messages to WebSocket (from steward)
	go h.writeMessages(ctx, conn, session, done)

	// Wait for session to end
	<-done
}

// readMessages reads messages from the WebSocket client
func (h *DefaultWebSocketHandler) readMessages(ctx context.Context, conn *websocket.Conn, session *Session, done chan struct{}) {
	defer close(done)

	conn.SetReadLimit(8192) // 8KB message limit
	if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		// Log error but continue
	}
	conn.SetPongHandler(func(string) error {
		if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		// Log error but continue
	}
		return nil
	})

	for {
		select {
		case <-ctx.Done():
			return
		default:
			var msg TerminalMessage
			err := conn.ReadJSON(&msg)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					h.logger.Warn("WebSocket read error", "session_id", session.ID, "error", err)
				}
				return
			}

			if err := h.handleMessage(ctx, &msg, session); err != nil {
				h.logger.Error("Failed to handle message", "session_id", session.ID, "error", err)
				h.sendError(conn, fmt.Sprintf("Message handling error: %v", err))
			}
		}
	}
}

// writeMessages writes messages to the WebSocket client
func (h *DefaultWebSocketHandler) writeMessages(ctx context.Context, conn *websocket.Conn, session *Session, done chan struct{}) {
	ticker := time.NewTicker(54 * time.Second) // Send ping every 54 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		// Log error but continue
	}
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				h.logger.Warn("Failed to send ping", "session_id", session.ID, "error", err)
				return
			}
		// In a real implementation, this would include a channel for receiving
		// output data from the steward and sending it to the WebSocket client
		}
	}
}

// handleMessage processes a message from the WebSocket client
func (h *DefaultWebSocketHandler) handleMessage(ctx context.Context, msg *TerminalMessage, session *Session) error {
	switch msg.Type {
	case MessageTypeData:
		// Send input data to the terminal session
		return session.WriteData(ctx, msg.Data)

	case MessageTypeResize:
		// Parse resize request
		var resizeReq ResizeRequest
		if err := json.Unmarshal(msg.Data, &resizeReq); err != nil {
			return fmt.Errorf("invalid resize request: %w", err)
		}

		// Resize the terminal
		return session.Resize(ctx, resizeReq.Cols, resizeReq.Rows)

	case MessageTypeClose:
		// Close the session
		return session.Close(ctx)

	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// sendError sends an error message to the WebSocket client
func (h *DefaultWebSocketHandler) sendError(conn *websocket.Conn, errorMsg string) {
	msg := &TerminalMessage{
		Type:      MessageTypeError,
		Error:     errorMsg,
		Timestamp: time.Now(),
	}

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		// Log error but continue
	}
	if err := conn.WriteJSON(msg); err != nil {
		h.logger.Warn("Failed to send error message", "error", err)
	}
}

// sendData sends data to the WebSocket client
func (h *DefaultWebSocketHandler) sendData(conn *websocket.Conn, sessionID string, data []byte) error {
	msg := &TerminalMessage{
		Type:      MessageTypeData,
		SessionID: sessionID,
		Data:      data,
		Timestamp: time.Now(),
	}

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		// Log error but continue
	}
	return conn.WriteJSON(msg)
}