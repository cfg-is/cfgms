// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package session defines interfaces and types for unified session management
package session

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SessionManager defines the unified interface for session management
// This interface abstracts session operations across different storage backends
type SessionManager interface {
	// Session lifecycle
	CreateSession(ctx context.Context, req *SessionCreateRequest) (*interfaces.Session, error)
	GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error)
	UpdateSession(ctx context.Context, sessionID string, updates *SessionUpdateRequest) (*interfaces.Session, error)
	TerminateSession(ctx context.Context, sessionID string, reason string) error

	// Session queries
	ListSessions(ctx context.Context, filter *interfaces.SessionFilter) ([]*interfaces.Session, error)
	GetActiveSessionsCount(ctx context.Context) (int64, error)

	// Session management
	ExtendSessionTTL(ctx context.Context, sessionID string, additionalTTL time.Duration) error
	CleanupExpiredSessions(ctx context.Context) (int, error)

	// Health and statistics
	GetStats(ctx context.Context) (*SessionManagerStats, error)
	HealthCheck(ctx context.Context) error

	// Lifecycle
	Stop(ctx context.Context) error
}

// SessionCreateRequest contains parameters for creating a new session
type SessionCreateRequest struct {
	SessionID       string                 `json:"session_id"`
	UserID          string                 `json:"user_id"`
	TenantID        string                 `json:"tenant_id"`
	SessionType     interfaces.SessionType `json:"session_type"`
	Timeout         time.Duration          `json:"timeout"`
	ClientInfo      *interfaces.ClientInfo `json:"client_info,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
	SessionData     interface{}            `json:"session_data,omitempty"`
	SecurityContext map[string]interface{} `json:"security_context,omitempty"`
	ComplianceFlags []string               `json:"compliance_flags,omitempty"`
	CreatedBy       string                 `json:"created_by,omitempty"`
}

// Validate validates a session create request
func (r *SessionCreateRequest) Validate() error {
	if r.SessionID == "" {
		return fmt.Errorf("session ID is required")
	}
	if r.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	if r.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if r.SessionType == "" {
		return fmt.Errorf("session type is required")
	}
	if r.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if r.Timeout > 24*time.Hour {
		return fmt.Errorf("timeout cannot exceed 24 hours")
	}

	return nil
}

// SessionUpdateRequest contains parameters for updating an existing session
type SessionUpdateRequest struct {
	LastActivity *time.Time               `json:"last_activity,omitempty"`
	ExpiresAt    *time.Time               `json:"expires_at,omitempty"`
	Status       interfaces.SessionStatus `json:"status,omitempty"`
	Metadata     map[string]string        `json:"metadata,omitempty"`
	SessionData  interface{}              `json:"session_data,omitempty"`
	ModifiedBy   string                   `json:"modified_by,omitempty"`
}

// SessionManagerStats provides statistics across all session stores
type SessionManagerStats struct {
	EphemeralStats  *interfaces.RuntimeStoreStats `json:"ephemeral_stats,omitempty"`
	PersistentStats *interfaces.RuntimeStoreStats `json:"persistent_stats,omitempty"`
	TotalSessions   int64                         `json:"total_sessions"`
	ActiveSessions  int64                         `json:"active_sessions"`
}

// SessionManagerConfig contains configuration for session managers
type SessionManagerConfig struct {
	// Storage configuration
	EphemeralProviderName  string                 `json:"ephemeral_provider_name"`
	PersistentProviderName string                 `json:"persistent_provider_name,omitempty"`
	StorageConfig          map[string]interface{} `json:"storage_config"`

	// Session configuration
	SessionConfig *Config `json:"session_config"`
}

// Terminal-specific types and helpers

// TerminalSessionRequest extends SessionCreateRequest for terminal sessions
type TerminalSessionRequest struct {
	SessionCreateRequest
	StewardID   string            `json:"steward_id"`
	Shell       string            `json:"shell"`
	Cols        int               `json:"cols"`
	Rows        int               `json:"rows"`
	Environment map[string]string `json:"environment,omitempty"`
}

// NewTerminalSessionRequest creates a terminal session request
func NewTerminalSessionRequest(sessionID, userID, tenantID, stewardID, shell string, cols, rows int) *TerminalSessionRequest {
	return &TerminalSessionRequest{
		SessionCreateRequest: SessionCreateRequest{
			SessionID:   sessionID,
			UserID:      userID,
			TenantID:    tenantID,
			SessionType: interfaces.SessionTypeTerminal,
			Timeout:     30 * time.Minute, // Default terminal timeout
			SessionData: &interfaces.TerminalSessionData{
				StewardID: stewardID,
				Shell:     shell,
				Cols:      cols,
				Rows:      rows,
			},
		},
		StewardID: stewardID,
		Shell:     shell,
		Cols:      cols,
		Rows:      rows,
	}
}

// JIT-specific types and helpers

// JITSessionRequest extends SessionCreateRequest for JIT access sessions
type JITSessionRequest struct {
	SessionCreateRequest
	RequestID      string   `json:"request_id"`
	TargetID       string   `json:"target_id"`
	Permissions    []string `json:"permissions"`
	Roles          []string `json:"roles,omitempty"`
	ResourceIDs    []string `json:"resource_ids,omitempty"`
	ApprovedBy     string   `json:"approved_by"`
	ApprovalReason string   `json:"approval_reason"`
}

// NewJITSessionRequest creates a JIT session request
func NewJITSessionRequest(sessionID, userID, tenantID, requestID, targetID string,
	permissions []string, approvedBy, approvalReason string, duration time.Duration) *JITSessionRequest {

	return &JITSessionRequest{
		SessionCreateRequest: SessionCreateRequest{
			SessionID:   sessionID,
			UserID:      userID,
			TenantID:    tenantID,
			SessionType: interfaces.SessionTypeJIT,
			Timeout:     duration,
			SessionData: &interfaces.JITSessionData{
				RequestID:      requestID,
				TargetID:       targetID,
				Permissions:    permissions,
				ApprovedBy:     approvedBy,
				ApprovalReason: approvalReason,
				GrantedAt:      time.Now(),
			},
			ComplianceFlags: []string{"jit_access", "requires_audit"},
		},
		RequestID:      requestID,
		TargetID:       targetID,
		Permissions:    permissions,
		ApprovedBy:     approvedBy,
		ApprovalReason: approvalReason,
	}
}

// API-specific types and helpers

// APISessionRequest extends SessionCreateRequest for API sessions
type APISessionRequest struct {
	SessionCreateRequest
	TokenHash    string   `json:"token_hash"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
}

// NewAPISessionRequest creates an API session request
func NewAPISessionRequest(sessionID, userID, tenantID, tokenHash string,
	scopes []string, userAgent string, duration time.Duration) *APISessionRequest {

	return &APISessionRequest{
		SessionCreateRequest: SessionCreateRequest{
			SessionID:   sessionID,
			UserID:      userID,
			TenantID:    tenantID,
			SessionType: interfaces.SessionTypeAPI,
			Timeout:     duration,
			SessionData: &interfaces.APISessionData{
				TokenHash: tokenHash,
				Scopes:    scopes,
				UserAgent: userAgent,
			},
		},
		TokenHash: tokenHash,
		Scopes:    scopes,
		UserAgent: userAgent,
	}
}

// WebSocket-specific types and helpers

// WebSocketSessionRequest extends SessionCreateRequest for WebSocket sessions
type WebSocketSessionRequest struct {
	SessionCreateRequest
	ConnectionID      string   `json:"connection_id"`
	Protocol          string   `json:"protocol,omitempty"`
	Subprotocols      []string `json:"subprotocols,omitempty"`
	TerminalSessionID string   `json:"terminal_session_id,omitempty"`
}

// NewWebSocketSessionRequest creates a WebSocket session request
func NewWebSocketSessionRequest(sessionID, userID, tenantID, connectionID string,
	protocol string, terminalSessionID string) *WebSocketSessionRequest {

	return &WebSocketSessionRequest{
		SessionCreateRequest: SessionCreateRequest{
			SessionID:   sessionID,
			UserID:      userID,
			TenantID:    tenantID,
			SessionType: interfaces.SessionTypeWebSocket,
			Timeout:     2 * time.Hour, // WebSocket sessions can be long-lived
			SessionData: &interfaces.WebSocketSessionData{
				ConnectionID:      connectionID,
				Protocol:          protocol,
				TerminalSessionID: terminalSessionID,
			},
		},
		ConnectionID:      connectionID,
		Protocol:          protocol,
		TerminalSessionID: terminalSessionID,
	}
}
