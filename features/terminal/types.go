// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/terminal/shell"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MessageType represents the type of WebSocket message
type MessageType string

const (
	MessageTypeData         MessageType = "data"
	MessageTypeResize       MessageType = "resize"
	MessageTypeClose        MessageType = "close"
	MessageTypeError        MessageType = "error"
	MessageTypeTokenRefresh MessageType = "token-refresh"
)

// DataDirection represents the direction of terminal data flow
type DataDirection int

const (
	DataDirectionInput DataDirection = iota
	DataDirectionOutput
)

// TerminalMessage represents a WebSocket message for terminal communication
type TerminalMessage struct {
	Type      MessageType `json:"type"`
	SessionID string      `json:"session_id,omitempty"`
	Data      []byte      `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Token     string      `json:"token,omitempty"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`
	Timestamp time.Time   `json:"timestamp,omitempty"`
}

// SessionRequest represents a request to create a new terminal session
type SessionRequest struct {
	TenantID  string            `json:"tenant_id"`
	StewardID string            `json:"steward_id"`
	UserID    string            `json:"user_id"`
	Shell     string            `json:"shell"`
	Cols      int               `json:"cols"`
	Rows      int               `json:"rows"`
	Env       map[string]string `json:"env,omitempty"`
}

// Session represents an active terminal session
type Session struct {
	ID           string            `json:"id"`
	StewardID    string            `json:"steward_id"`
	UserID       string            `json:"user_id"`
	Shell        string            `json:"shell"`
	Cols         int               `json:"cols"`
	Rows         int               `json:"rows"`
	CreatedAt    time.Time         `json:"created_at"`
	LastActivity time.Time         `json:"last_activity"`
	Environment  map[string]string `json:"environment,omitempty"`
	closed       bool
	recorder     Recorder
	executor     shell.Executor
	outputCh     chan []byte // buffered relay channel: steward → WebSocket client
	logger       logging.Logger
	mu           sync.RWMutex // Mutex for thread-safe access to session fields
}

// SessionMetadata contains metadata about a terminal session
type SessionMetadata struct {
	SessionID   string            `json:"session_id"`
	StewardID   string            `json:"steward_id"`
	UserID      string            `json:"user_id"`
	Shell       string            `json:"shell"`
	CreatedAt   time.Time         `json:"created_at"`
	EndedAt     *time.Time        `json:"ended_at,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// SessionRecording represents a recorded terminal session
type SessionRecording struct {
	SessionID string          `json:"session_id"`
	Metadata  SessionMetadata `json:"metadata"`
	StartTime time.Time       `json:"start_time"`
	EndTime   time.Time       `json:"end_time"`
	Data      []byte          `json:"data"`
	Events    []RecordEvent   `json:"events"`
	Size      int64           `json:"size"`
}

// RecordEvent represents a single recorded event in a terminal session
type RecordEvent struct {
	Timestamp time.Time     `json:"timestamp"`
	Direction DataDirection `json:"direction"`
	Data      []byte        `json:"data"`
	Size      int           `json:"size"`
}

// Config contains configuration for the terminal system
type Config struct {
	SessionTimeout time.Duration `json:"session_timeout"`
	MaxSessions    int           `json:"max_sessions"`
	RecordSessions bool          `json:"record_sessions"`
	// RecordingStoragePath is the recorder's on-disk storage directory. It is
	// REQUIRED when RecordSessions is true — there is no implicit fallback,
	// because recordings hold cleartext secrets and must never land in a shared
	// or world-writable location. Callers derive it from their data directory so
	// concurrent managers never share a single fixed directory.
	RecordingStoragePath string `json:"recording_storage_path,omitempty"`
}

// RecorderConfig contains configuration for session recording
type RecorderConfig struct {
	StoragePath    string `json:"storage_path"`
	MaxRecordingMB int    `json:"max_recording_mb"`
	Compression    bool   `json:"compression"`
}

// ResizeRequest represents a terminal resize request
type ResizeRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// SessionManager interface defines session management operations
type SessionManager interface {
	CreateSession(ctx context.Context, req *SessionRequest) (*Session, error)
	GetSession(sessionID string) (*Session, error)
	TerminateSession(ctx context.Context, sessionID string) error
	GetActiveSessions() []*Session
	RecordData(sessionID string, data []byte, direction DataDirection) error
	GetSessionRecording(sessionID string) (*SessionRecording, error)
	// Stop closes every live session and the recorder, which finalizes each
	// recording (its .meta sidecar carries the HMAC chain head). It is part of the
	// contract because a manager that is never stopped leaves recordings without
	// that sidecar, and an unsidecarred recording is discarded as unverifiable on
	// the next start — losing the audit trail of the sessions that were live at
	// shutdown. Stop is idempotent.
	Stop(ctx context.Context) error
}

// Recorder interface defines session recording operations
type Recorder interface {
	RecordData(sessionID string, data []byte, direction DataDirection) error
	GetRecording(sessionID string) (*SessionRecording, error)
	Close() error
}

// WebSocketHandler interface defines WebSocket handling operations
type WebSocketHandler interface {
	HandleWebSocket(w http.ResponseWriter, r *http.Request)
}

// SupportedShells contains the list of supported shell types
var SupportedShells = map[string]bool{
	"bash":       true,
	"zsh":        true,
	"sh":         true,
	"powershell": true,
	"cmd":        true,
}

// ValidateShell checks if the given shell is supported
func ValidateShell(shell string) bool {
	return SupportedShells[shell]
}

// DefaultConfig returns the default terminal configuration
func DefaultConfig() *Config {
	return &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}
}

// DefaultRecorderConfig returns the default recorder configuration.
//
// StoragePath is deliberately empty and has no built-in fallback: recordings
// contain every keystroke and output byte of privileged shells (passwords, tokens,
// key material), so the directory MUST be an explicit deployment-owned path under
// the component's data directory. Defaulting to a shared, predictable, world-
// writable location such as /tmp would leak cleartext secrets to any local account
// and let a pre-created directory or symlink hijack the files.
func DefaultRecorderConfig() *RecorderConfig {
	return &RecorderConfig{
		MaxRecordingMB: 100,
		Compression:    true,
	}
}
