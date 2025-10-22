// Package interfaces defines the runtime storage interface for session and runtime state management
package interfaces

import (
	"context"
	"fmt"
	"time"
)

// RuntimeStore interface defines operations for session and runtime state storage
// This interface supports both ephemeral (in-memory) and durable (persistent) storage
// Only sessions marked as persistent need to survive controller restarts
type RuntimeStore interface {
	// Session Management
	// Only sessions with Persistent=true need durable storage (git/database providers)
	// Ephemeral sessions (Persistent=false) can use in-memory storage and be lost on restart
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, sessionID string, session *Session) error
	DeleteSession(ctx context.Context, sessionID string) error
	ListSessions(ctx context.Context, filters *SessionFilter) ([]*Session, error)

	// Session Lifecycle Management
	SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error
	CleanupExpiredSessions(ctx context.Context) (int, error)
	ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error)

	// Runtime State Management (for application state, not configuration)
	// Runtime state is typically ephemeral and does not need durable storage
	// Only use durable storage if the state is critical for system recovery
	SetRuntimeState(ctx context.Context, key string, value interface{}) error
	GetRuntimeState(ctx context.Context, key string) (interface{}, error)
	DeleteRuntimeState(ctx context.Context, key string) error
	ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error)

	// Batch Operations for Performance
	CreateSessionsBatch(ctx context.Context, sessions []*Session) error
	DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error

	// Session Queries
	GetSessionsByUser(ctx context.Context, userID string) ([]*Session, error)
	GetSessionsByTenant(ctx context.Context, tenantID string) ([]*Session, error)
	GetSessionsByType(ctx context.Context, sessionType SessionType) ([]*Session, error)
	GetActiveSessionsCount(ctx context.Context) (int64, error)

	// Health and Maintenance
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*RuntimeStoreStats, error)
	Vacuum(ctx context.Context) error // Cleanup/optimize storage
}

// Session represents a session in the runtime storage system
type Session struct {
	// Core session identity
	SessionID   string      `json:"session_id"`
	UserID      string      `json:"user_id"`
	TenantID    string      `json:"tenant_id"`
	SessionType SessionType `json:"session_type"`

	// Session lifecycle
	CreatedAt    time.Time     `json:"created_at"`
	LastActivity time.Time     `json:"last_activity"`
	ExpiresAt    time.Time     `json:"expires_at"`
	Status       SessionStatus `json:"status"`

	// Persistence control
	Persistent bool `json:"persistent"` // If true, session must survive controller restarts

	// Session context and metadata
	ClientInfo *ClientInfo       `json:"client_info,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`

	// Session-specific data (varies by session type)
	SessionData interface{} `json:"session_data,omitempty"`

	// Security and compliance
	SecurityContext map[string]interface{} `json:"security_context,omitempty"`
	ComplianceFlags []string               `json:"compliance_flags,omitempty"`

	// Audit fields
	CreatedBy  string     `json:"created_by,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
	ModifiedBy string     `json:"modified_by,omitempty"`
}

// SessionType defines different types of sessions
type SessionType string

const (
	SessionTypeTerminal  SessionType = "terminal"  // Terminal/SSH sessions
	SessionTypeAPI       SessionType = "api"       // API authentication sessions
	SessionTypeJIT       SessionType = "jit"       // Just-in-Time access sessions
	SessionTypeWebSocket SessionType = "websocket" // WebSocket connection sessions
	SessionTypeService   SessionType = "service"   // Service-to-service sessions
	SessionTypeWeb       SessionType = "web"       // Web interface sessions
	SessionTypeBatch     SessionType = "batch"     // Batch/automated process sessions
)

// SessionStatus defines session status
type SessionStatus string

const (
	SessionStatusActive     SessionStatus = "active"     // Session is active
	SessionStatusInactive   SessionStatus = "inactive"   // Session is inactive but not expired
	SessionStatusExpired    SessionStatus = "expired"    // Session has expired
	SessionStatusTerminated SessionStatus = "terminated" // Session was manually terminated
	SessionStatusSuspended  SessionStatus = "suspended"  // Session is suspended (security)
)

// ClientInfo contains client-specific information
type ClientInfo struct {
	IPAddress       string `json:"ip_address,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	Platform        string `json:"platform,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	Location        string `json:"location,omitempty"`
	SecurityContext string `json:"security_context,omitempty"`
}

// SessionFilter defines filtering options for session queries
type SessionFilter struct {
	// Identity filters
	UserID   string        `json:"user_id,omitempty"`
	TenantID string        `json:"tenant_id,omitempty"`
	Type     SessionType   `json:"type,omitempty"`
	Status   SessionStatus `json:"status,omitempty"`

	// Time-based filters
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	ActiveAfter   *time.Time `json:"active_after,omitempty"`
	ActiveBefore  *time.Time `json:"active_before,omitempty"`

	// Client filters
	IPAddress string `json:"ip_address,omitempty"`
	Platform  string `json:"platform,omitempty"`

	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	// Security filters
	SecurityFlags   []string `json:"security_flags,omitempty"`
	ComplianceFlags []string `json:"compliance_flags,omitempty"`
}

// RuntimeStoreStats provides statistics about the runtime store
type RuntimeStoreStats struct {
	// Session statistics
	TotalSessions    int64            `json:"total_sessions"`
	ActiveSessions   int64            `json:"active_sessions"`
	ExpiredSessions  int64            `json:"expired_sessions"`
	SessionsByType   map[string]int64 `json:"sessions_by_type"`
	SessionsByStatus map[string]int64 `json:"sessions_by_status"`

	// Runtime state statistics
	RuntimeStateKeys int64 `json:"runtime_state_keys"`
	RuntimeStateSize int64 `json:"runtime_state_size_bytes"`

	// Performance statistics
	AverageSessionLifetime time.Duration `json:"average_session_lifetime"`
	SessionCreationRate    float64       `json:"sessions_per_second"`
	LastCleanupAt          *time.Time    `json:"last_cleanup_at,omitempty"`
	LastCleanupDuration    time.Duration `json:"last_cleanup_duration"`

	// Storage statistics
	StorageSize       int64      `json:"storage_size_bytes"`
	LastMaintenanceAt *time.Time `json:"last_maintenance_at,omitempty"`

	// Provider-specific statistics
	ProviderStats map[string]interface{} `json:"provider_stats,omitempty"`
}

// Terminal-specific session data structures

// TerminalSessionData contains terminal-specific session information
type TerminalSessionData struct {
	StewardID        string            `json:"steward_id"`
	Shell            string            `json:"shell"`
	Cols             int               `json:"cols"`
	Rows             int               `json:"rows"`
	Environment      map[string]string `json:"environment,omitempty"`
	CommandHistory   []string          `json:"command_history,omitempty"`
	RecordingEnabled bool              `json:"recording_enabled"`
	RecordingPath    string            `json:"recording_path,omitempty"`
}

// JIT-specific session data structures

// JITSessionData contains JIT access session information
type JITSessionData struct {
	RequestID      string            `json:"request_id"`
	TargetID       string            `json:"target_id"`
	Permissions    []string          `json:"permissions"`
	Roles          []string          `json:"roles,omitempty"`
	ResourceIDs    []string          `json:"resource_ids,omitempty"`
	ApprovedBy     string            `json:"approved_by"`
	ApprovalReason string            `json:"approval_reason"`
	GrantedAt      time.Time         `json:"granted_at"`
	ExtensionsUsed int               `json:"extensions_used"`
	MaxExtensions  int               `json:"max_extensions"`
	Conditions     map[string]string `json:"conditions,omitempty"`
}

// API-specific session data structures

// APISessionData contains API session information
type APISessionData struct {
	TokenHash        string         `json:"token_hash"`
	RefreshTokenHash string         `json:"refresh_token_hash,omitempty"`
	Scopes           []string       `json:"scopes,omitempty"`
	RateLimitState   map[string]int `json:"rate_limit_state,omitempty"`
	RequestCount     int64          `json:"request_count"`
	LastRequestAt    *time.Time     `json:"last_request_at,omitempty"`
	UserAgent        string         `json:"user_agent,omitempty"`
}

// WebSocket-specific session data structures

// WebSocketSessionData contains WebSocket connection session information
type WebSocketSessionData struct {
	ConnectionID      string     `json:"connection_id"`
	Protocol          string     `json:"protocol,omitempty"`
	Subprotocols      []string   `json:"subprotocols,omitempty"`
	MessageCount      int64      `json:"message_count"`
	BytesTransferred  int64      `json:"bytes_transferred"`
	LastMessageAt     *time.Time `json:"last_message_at,omitempty"`
	TerminalSessionID string     `json:"terminal_session_id,omitempty"` // Link to terminal session
}

// Validation methods

// Validate validates a session object
func (s *Session) Validate() error {
	if s.SessionID == "" {
		return fmt.Errorf("session ID is required")
	}
	if s.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	if s.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if s.SessionType == "" {
		return fmt.Errorf("session type is required")
	}
	if s.CreatedAt.IsZero() {
		return fmt.Errorf("created at is required")
	}
	if s.ExpiresAt.IsZero() {
		return fmt.Errorf("expires at is required")
	}
	if s.ExpiresAt.Before(s.CreatedAt) {
		return fmt.Errorf("expires at must be after created at")
	}

	return nil
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns true if the session is active and not expired
func (s *Session) IsActive() bool {
	return s.Status == SessionStatusActive && !s.IsExpired()
}

// UpdateActivity updates the last activity timestamp
func (s *Session) UpdateActivity() {
	s.LastActivity = time.Now()
}

// Extend extends the session expiry time
func (s *Session) Extend(duration time.Duration) {
	s.ExpiresAt = s.ExpiresAt.Add(duration)
	s.UpdateActivity()
}
