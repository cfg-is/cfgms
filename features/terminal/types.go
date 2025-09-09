package terminal

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/terminal/shell"
)

// MessageType represents the type of WebSocket message
type MessageType string

const (
	MessageTypeData   MessageType = "data"
	MessageTypeResize MessageType = "resize"
	MessageTypeClose  MessageType = "close"
	MessageTypeError  MessageType = "error"
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
	Timestamp time.Time   `json:"timestamp,omitempty"`
}

// SessionRequest represents a request to create a new terminal session
type SessionRequest struct {
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
	mu           sync.RWMutex      // Mutex for thread-safe access to session fields
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

// ShellExecutor interface defines shell execution operations
type ShellExecutor interface {
	Start(ctx context.Context, session *Session) error
	WriteData(ctx context.Context, data []byte) error
	Resize(ctx context.Context, cols, rows int) error
	Close(ctx context.Context) error
	OutputChannel() <-chan []byte
	ErrorChannel() <-chan error
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

// DefaultRecorderConfig returns the default recorder configuration
func DefaultRecorderConfig() *RecorderConfig {
	return &RecorderConfig{
		StoragePath:    "/tmp/cfgms-recordings",
		MaxRecordingMB: 100,
		Compression:    true,
	}
}