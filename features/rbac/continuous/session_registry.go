// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SessionRegistry manages active sessions for continuous authorization
type SessionRegistry struct {
	// Session storage
	sessions       map[string]*AuthorizedSession // sessionID -> session
	userSessions   map[string][]string           // userID -> []sessionID
	tenantSessions map[string][]string           // tenantID -> []sessionID

	// Permission mappings
	sessionPermissions map[string]map[string]time.Time // sessionID -> permissionID -> expiry

	// Control
	mutex       sync.RWMutex
	started     bool
	stopChannel chan struct{}

	// Configuration
	sessionTimeout  time.Duration
	cleanupInterval time.Duration

	// Statistics
	stats SessionRegistryStats
}

// AuthorizedSession represents a session in the continuous authorization system
type AuthorizedSession struct {
	SessionID    string    `json:"session_id"`
	SubjectID    string    `json:"subject_id"`
	TenantID     string    `json:"tenant_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	ExpiresAt    time.Time `json:"expires_at"`

	// Session context
	SessionType SessionType       `json:"session_type"`
	ClientInfo  *ClientInfo       `json:"client_info"`
	Metadata    map[string]string `json:"metadata"`

	// Permission state
	GrantedPermissions map[string]PermissionGrant `json:"granted_permissions"`
	ActiveDelegations  []string                   `json:"active_delegations"`
	JITPermissions     map[string]time.Time       `json:"jit_permissions"`

	// Security state
	ThreatLevel        ThreatLevel         `json:"threat_level"`
	SecurityViolations []SecurityViolation `json:"security_violations"`
	ComplianceStatus   string              `json:"compliance_status"`

	// Control flags
	RequiresContinuousAuth bool      `json:"requires_continuous_auth"`
	AutoTerminate          bool      `json:"auto_terminate"`
	TerminationScheduled   time.Time `json:"termination_scheduled,omitempty"`

	mutex sync.RWMutex
}

// SessionType defines different types of sessions
type SessionType string

const (
	SessionTypeAPI      SessionType = "api"      // API session
	SessionTypeTerminal SessionType = "terminal" // Terminal session
	SessionTypeService  SessionType = "service"  // Service-to-service
	SessionTypeWeb      SessionType = "web"      // Web interface session
	SessionTypeBatch    SessionType = "batch"    // Batch/automated process
)

// ClientInfo contains client-specific information
type ClientInfo struct {
	IPAddress       string `json:"ip_address"`
	UserAgent       string `json:"user_agent"`
	Platform        string `json:"platform"`
	DeviceID        string `json:"device_id,omitempty"`
	Location        string `json:"location,omitempty"`
	SecurityContext string `json:"security_context,omitempty"`
}

// PermissionGrant represents a granted permission with context
type PermissionGrant struct {
	PermissionID string                 `json:"permission_id"`
	GrantedAt    time.Time              `json:"granted_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	GrantedBy    string                 `json:"granted_by"` // "rbac", "jit", "delegation"
	Conditions   map[string]interface{} `json:"conditions"`
	UsageCount   int                    `json:"usage_count"`
	LastUsed     time.Time              `json:"last_used"`
}

// SecurityViolation represents a security violation for a session
type SecurityViolation struct {
	ViolationID string                 `json:"violation_id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	DetectedAt  time.Time              `json:"detected_at"`
	Context     map[string]interface{} `json:"context"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  time.Time              `json:"resolved_at,omitempty"`
}

// SessionStatus represents the current status of a session
type SessionStatus struct {
	SessionID          string        `json:"session_id"`
	Status             string        `json:"status"` // "active", "expired", "terminated", "suspended"
	IsValid            bool          `json:"is_valid"`
	LastValidation     time.Time     `json:"last_validation"`
	ActivePermissions  int           `json:"active_permissions"`
	ExpiresIn          time.Duration `json:"expires_in"`
	RequiresReauth     bool          `json:"requires_reauth"`
	SecurityAlerts     int           `json:"security_alerts"`
	ComplianceStatus   string        `json:"compliance_status"`
	RecommendedActions []string      `json:"recommended_actions"`
}

// SessionRegistryStats contains statistics about the session registry
type SessionRegistryStats struct {
	TotalSessions      int                 `json:"total_sessions"`
	ActiveSessions     int                 `json:"active_sessions"`
	ExpiredSessions    int                 `json:"expired_sessions"`
	TerminatedSessions int                 `json:"terminated_sessions"`
	AverageSessionTime time.Duration       `json:"average_session_time"`
	SessionsByType     map[SessionType]int `json:"sessions_by_type"`
	SessionsByTenant   map[string]int      `json:"sessions_by_tenant"`
	LastCleanup        time.Time           `json:"last_cleanup"`

	mutex sync.RWMutex
}

// ThreatLevel represents the security threat level of a session
type ThreatLevel string

const (
	ThreatLevelMinimal  ThreatLevel = "minimal"  // Very low risk
	ThreatLevelLow      ThreatLevel = "low"      // Normal operations
	ThreatLevelMedium   ThreatLevel = "medium"   // Some concern
	ThreatLevelHigh     ThreatLevel = "high"     // Elevated risk
	ThreatLevelCritical ThreatLevel = "critical" // Immediate threat
)

// NewSessionRegistry creates a new session registry
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		sessions:           make(map[string]*AuthorizedSession),
		userSessions:       make(map[string][]string),
		tenantSessions:     make(map[string][]string),
		sessionPermissions: make(map[string]map[string]time.Time),
		stopChannel:        make(chan struct{}),
		sessionTimeout:     2 * time.Hour,    // 2 hour default session timeout
		cleanupInterval:    15 * time.Minute, // 15 minute cleanup interval
		stats: SessionRegistryStats{
			SessionsByType:   make(map[SessionType]int),
			SessionsByTenant: make(map[string]int),
		},
	}
}

// Start initializes and starts the session registry
func (sr *SessionRegistry) Start(ctx context.Context) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	if sr.started {
		return fmt.Errorf("session registry is already started")
	}

	// Start background cleanup process
	go sr.cleanupLoop(ctx)

	sr.started = true
	return nil
}

// Stop gracefully stops the session registry
func (sr *SessionRegistry) Stop() error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	if !sr.started {
		return fmt.Errorf("session registry is not started")
	}

	close(sr.stopChannel)
	sr.started = false
	return nil
}

// RegisterSession registers a new session for continuous authorization
func (sr *SessionRegistry) RegisterSession(ctx context.Context, sessionID, subjectID, tenantID string, metadata map[string]string) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	// Check if session already exists
	if _, exists := sr.sessions[sessionID]; exists {
		return fmt.Errorf("session %s already registered", sessionID)
	}

	now := time.Now()

	// Create new authorized session
	session := &AuthorizedSession{
		SessionID:              sessionID,
		SubjectID:              subjectID,
		TenantID:               tenantID,
		CreatedAt:              now,
		LastActivity:           now,
		ExpiresAt:              now.Add(sr.sessionTimeout),
		SessionType:            sr.determineSessionType(metadata),
		ClientInfo:             sr.extractClientInfo(metadata),
		Metadata:               metadata,
		GrantedPermissions:     make(map[string]PermissionGrant),
		ActiveDelegations:      make([]string, 0),
		JITPermissions:         make(map[string]time.Time),
		ThreatLevel:            ThreatLevelLow,
		SecurityViolations:     make([]SecurityViolation, 0),
		ComplianceStatus:       "compliant",
		RequiresContinuousAuth: sr.requiresContinuousAuth(metadata),
	}

	// Store session
	sr.sessions[sessionID] = session

	// Update user and tenant mappings
	sr.userSessions[subjectID] = append(sr.userSessions[subjectID], sessionID)
	sr.tenantSessions[tenantID] = append(sr.tenantSessions[tenantID], sessionID)

	// Initialize permission tracking
	sr.sessionPermissions[sessionID] = make(map[string]time.Time)

	// Update statistics
	sr.updateStats()

	return nil
}

// UnregisterSession removes a session from the registry
func (sr *SessionRegistry) UnregisterSession(ctx context.Context, sessionID string) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Remove from main storage
	delete(sr.sessions, sessionID)
	delete(sr.sessionPermissions, sessionID)

	// Remove from user sessions
	if userSessions, ok := sr.userSessions[session.SubjectID]; ok {
		sr.userSessions[session.SubjectID] = sr.removeSessionFromSlice(userSessions, sessionID)
		if len(sr.userSessions[session.SubjectID]) == 0 {
			delete(sr.userSessions, session.SubjectID)
		}
	}

	// Remove from tenant sessions
	if tenantSessions, ok := sr.tenantSessions[session.TenantID]; ok {
		sr.tenantSessions[session.TenantID] = sr.removeSessionFromSlice(tenantSessions, sessionID)
		if len(sr.tenantSessions[session.TenantID]) == 0 {
			delete(sr.tenantSessions, session.TenantID)
		}
	}

	// Update statistics
	sr.updateStats()

	return nil
}

// ValidateSession checks if a session is valid and active
func (sr *SessionRegistry) ValidateSession(ctx context.Context, sessionID, subjectID string) (bool, error) {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return false, fmt.Errorf("session %s not found", sessionID)
	}

	// Verify subject ID matches
	if session.SubjectID != subjectID {
		return false, fmt.Errorf("subject ID mismatch for session %s", sessionID)
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		return false, nil // Session expired
	}

	// Check if session is terminated
	if session.AutoTerminate && !session.TerminationScheduled.IsZero() && time.Now().After(session.TerminationScheduled) {
		return false, nil // Session scheduled for termination
	}

	return true, nil
}

// GetSessionStatus returns the current status of a session
func (sr *SessionRegistry) GetSessionStatus(ctx context.Context, sessionID string) (*SessionStatus, error) {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()

	now := time.Now()
	status := "active"
	isValid := true

	// Determine status
	if now.After(session.ExpiresAt) {
		status = "expired"
		isValid = false
	} else if session.AutoTerminate && !session.TerminationScheduled.IsZero() && now.After(session.TerminationScheduled) {
		status = "terminated"
		isValid = false
	}

	// Count active permissions
	activePermissions := 0
	for _, grant := range session.GrantedPermissions {
		if now.Before(grant.ExpiresAt) {
			activePermissions++
		}
	}

	// Count security alerts
	securityAlerts := 0
	for _, violation := range session.SecurityViolations {
		if !violation.Resolved {
			securityAlerts++
		}
	}

	// Generate recommendations
	recommendations := sr.generateSessionRecommendations(session)

	return &SessionStatus{
		SessionID:          sessionID,
		Status:             status,
		IsValid:            isValid,
		LastValidation:     now,
		ActivePermissions:  activePermissions,
		ExpiresIn:          session.ExpiresAt.Sub(now),
		RequiresReauth:     session.RequiresContinuousAuth,
		SecurityAlerts:     securityAlerts,
		ComplianceStatus:   session.ComplianceStatus,
		RecommendedActions: recommendations,
	}, nil
}

// UpdateSessionActivity updates the last activity time for a session
func (sr *SessionRegistry) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	session.LastActivity = time.Now()
	session.mutex.Unlock()

	return nil
}

// GrantSessionPermission grants a permission to a session
func (sr *SessionRegistry) GrantSessionPermission(ctx context.Context, sessionID, permissionID, grantedBy string, expiresAt time.Time, conditions map[string]interface{}) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Create permission grant
	grant := PermissionGrant{
		PermissionID: permissionID,
		GrantedAt:    time.Now(),
		ExpiresAt:    expiresAt,
		GrantedBy:    grantedBy,
		Conditions:   conditions,
		UsageCount:   0,
	}

	// Store permission grant
	session.GrantedPermissions[permissionID] = grant

	// Update permission tracking
	sr.sessionPermissions[sessionID][permissionID] = expiresAt

	return nil
}

// RevokeSessionPermission revokes a permission from a session
func (sr *SessionRegistry) RevokeSessionPermission(ctx context.Context, sessionID, permissionID string) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Remove permission grant
	delete(session.GrantedPermissions, permissionID)

	// Remove from permission tracking
	if permissions, ok := sr.sessionPermissions[sessionID]; ok {
		delete(permissions, permissionID)
	}

	return nil
}

// GetUserSessions returns all active sessions for a user
func (sr *SessionRegistry) GetUserSessions(ctx context.Context, subjectID, tenantID string) ([]*AuthorizedSession, error) {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	sessionIDs, exists := sr.userSessions[subjectID]
	if !exists {
		return []*AuthorizedSession{}, nil
	}

	sessions := make([]*AuthorizedSession, 0)
	for _, sessionID := range sessionIDs {
		if session, ok := sr.sessions[sessionID]; ok {
			if tenantID == "" || session.TenantID == tenantID {
				// Return a copy to prevent external modifications - copy fields individually to avoid copying mutex
				sessionCopy := &AuthorizedSession{
					SessionID:              session.SessionID,
					SubjectID:              session.SubjectID,
					TenantID:               session.TenantID,
					CreatedAt:              session.CreatedAt,
					LastActivity:           session.LastActivity,
					ExpiresAt:              session.ExpiresAt,
					SessionType:            session.SessionType,
					ClientInfo:             session.ClientInfo,
					Metadata:               session.Metadata,
					GrantedPermissions:     session.GrantedPermissions,
					ActiveDelegations:      append([]string{}, session.ActiveDelegations...),
					JITPermissions:         session.JITPermissions,
					ThreatLevel:            session.ThreatLevel,
					SecurityViolations:     append([]SecurityViolation{}, session.SecurityViolations...),
					ComplianceStatus:       session.ComplianceStatus,
					RequiresContinuousAuth: session.RequiresContinuousAuth,
					AutoTerminate:          session.AutoTerminate,
					TerminationScheduled:   session.TerminationScheduled,
				}
				sessions = append(sessions, sessionCopy)
			}
		}
	}

	return sessions, nil
}

// GetTenantSessions returns all active sessions for a tenant
func (sr *SessionRegistry) GetTenantSessions(ctx context.Context, tenantID string) ([]*AuthorizedSession, error) {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	sessionIDs, exists := sr.tenantSessions[tenantID]
	if !exists {
		return []*AuthorizedSession{}, nil
	}

	sessions := make([]*AuthorizedSession, 0)
	for _, sessionID := range sessionIDs {
		if session, ok := sr.sessions[sessionID]; ok {
			// Return a copy to prevent external modifications - copy fields individually to avoid copying mutex
			sessionCopy := &AuthorizedSession{
				SessionID:              session.SessionID,
				SubjectID:              session.SubjectID,
				TenantID:               session.TenantID,
				CreatedAt:              session.CreatedAt,
				LastActivity:           session.LastActivity,
				ExpiresAt:              session.ExpiresAt,
				SessionType:            session.SessionType,
				ClientInfo:             session.ClientInfo,
				Metadata:               session.Metadata,
				GrantedPermissions:     session.GrantedPermissions,
				ActiveDelegations:      append([]string{}, session.ActiveDelegations...),
				JITPermissions:         session.JITPermissions,
				ThreatLevel:            session.ThreatLevel,
				SecurityViolations:     append([]SecurityViolation{}, session.SecurityViolations...),
				ComplianceStatus:       session.ComplianceStatus,
				RequiresContinuousAuth: session.RequiresContinuousAuth,
				AutoTerminate:          session.AutoTerminate,
				TerminationScheduled:   session.TerminationScheduled,
			}
			sessions = append(sessions, sessionCopy)
		}
	}

	return sessions, nil
}

// GetAllSessions returns all active sessions
func (sr *SessionRegistry) GetAllSessions() []*AuthorizedSession {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	sessions := make([]*AuthorizedSession, 0, len(sr.sessions))
	for _, session := range sr.sessions {
		// Return a copy to prevent external modifications - copy fields individually to avoid copying mutex
		sessionCopy := &AuthorizedSession{
			SessionID:              session.SessionID,
			SubjectID:              session.SubjectID,
			TenantID:               session.TenantID,
			CreatedAt:              session.CreatedAt,
			LastActivity:           session.LastActivity,
			ExpiresAt:              session.ExpiresAt,
			SessionType:            session.SessionType,
			ClientInfo:             session.ClientInfo,
			Metadata:               session.Metadata,
			GrantedPermissions:     session.GrantedPermissions,
			ActiveDelegations:      append([]string{}, session.ActiveDelegations...),
			JITPermissions:         session.JITPermissions,
			ThreatLevel:            session.ThreatLevel,
			SecurityViolations:     append([]SecurityViolation{}, session.SecurityViolations...),
			ComplianceStatus:       session.ComplianceStatus,
			RequiresContinuousAuth: session.RequiresContinuousAuth,
			AutoTerminate:          session.AutoTerminate,
			TerminationScheduled:   session.TerminationScheduled,
		}
		sessions = append(sessions, sessionCopy)
	}

	return sessions
}

// GetSessionCount returns the total number of active sessions
func (sr *SessionRegistry) GetSessionCount() int {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()
	return len(sr.sessions)
}

// ScheduleSessionTermination schedules a session for termination
func (sr *SessionRegistry) ScheduleSessionTermination(ctx context.Context, sessionID string, terminationTime time.Time, reason string) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	session.AutoTerminate = true
	session.TerminationScheduled = terminationTime
	session.mutex.Unlock()

	return nil
}

// RecordSecurityViolation records a security violation for a session
func (sr *SessionRegistry) RecordSecurityViolation(ctx context.Context, sessionID string, violation SecurityViolation) error {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	session, exists := sr.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Add violation to session
	session.SecurityViolations = append(session.SecurityViolations, violation)

	// Update threat level based on violations
	sr.updateSessionThreatLevel(session)

	return nil
}

// GetRegistryStats returns current registry statistics
func (sr *SessionRegistry) GetRegistryStats() *SessionRegistryStats {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	// Return a copy to prevent external modifications - access sr.stats directly to avoid copying mutex
	sr.stats.mutex.RLock()
	statsCopy := SessionRegistryStats{
		TotalSessions:      sr.stats.TotalSessions,
		ActiveSessions:     sr.stats.ActiveSessions,
		ExpiredSessions:    sr.stats.ExpiredSessions,
		TerminatedSessions: sr.stats.TerminatedSessions,
		AverageSessionTime: sr.stats.AverageSessionTime,
		SessionsByType:     make(map[SessionType]int),
		SessionsByTenant:   make(map[string]int),
		LastCleanup:        sr.stats.LastCleanup,
	}

	// Copy maps
	for k, v := range sr.stats.SessionsByType {
		statsCopy.SessionsByType[k] = v
	}
	for k, v := range sr.stats.SessionsByTenant {
		statsCopy.SessionsByTenant[k] = v
	}

	sr.stats.mutex.RUnlock()
	return &statsCopy
}

// Background processes

// cleanupLoop periodically cleans up expired sessions
func (sr *SessionRegistry) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(sr.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sr.stopChannel:
			return
		case <-ticker.C:
			sr.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions removes expired sessions from the registry
func (sr *SessionRegistry) cleanupExpiredSessions() {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	// Find expired sessions
	for sessionID, session := range sr.sessions {
		if now.After(session.ExpiresAt) || (session.AutoTerminate && !session.TerminationScheduled.IsZero() && now.After(session.TerminationScheduled)) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	// Remove expired sessions
	for _, sessionID := range expiredSessions {
		if session, exists := sr.sessions[sessionID]; exists {
			// Remove from user sessions
			if userSessions, ok := sr.userSessions[session.SubjectID]; ok {
				sr.userSessions[session.SubjectID] = sr.removeSessionFromSlice(userSessions, sessionID)
				if len(sr.userSessions[session.SubjectID]) == 0 {
					delete(sr.userSessions, session.SubjectID)
				}
			}

			// Remove from tenant sessions
			if tenantSessions, ok := sr.tenantSessions[session.TenantID]; ok {
				sr.tenantSessions[session.TenantID] = sr.removeSessionFromSlice(tenantSessions, sessionID)
				if len(sr.tenantSessions[session.TenantID]) == 0 {
					delete(sr.tenantSessions, session.TenantID)
				}
			}

			// Remove from main storage
			delete(sr.sessions, sessionID)
			delete(sr.sessionPermissions, sessionID)
		}
	}

	// Update statistics
	sr.updateStats()
	sr.stats.mutex.Lock()
	sr.stats.LastCleanup = now
	sr.stats.ExpiredSessions += len(expiredSessions)
	sr.stats.mutex.Unlock()
}

// Helper methods

func (sr *SessionRegistry) determineSessionType(metadata map[string]string) SessionType {
	if sessionType, ok := metadata["session_type"]; ok {
		switch sessionType {
		case "api":
			return SessionTypeAPI
		case "terminal":
			return SessionTypeTerminal
		case "service":
			return SessionTypeService
		case "web":
			return SessionTypeWeb
		case "batch":
			return SessionTypeBatch
		}
	}
	return SessionTypeAPI // Default
}

func (sr *SessionRegistry) extractClientInfo(metadata map[string]string) *ClientInfo {
	return &ClientInfo{
		IPAddress:       metadata["ip_address"],
		UserAgent:       metadata["user_agent"],
		Platform:        metadata["platform"],
		DeviceID:        metadata["device_id"],
		Location:        metadata["location"],
		SecurityContext: metadata["security_context"],
	}
}

func (sr *SessionRegistry) requiresContinuousAuth(metadata map[string]string) bool {
	// Sessions with elevated privileges or sensitive operations require continuous auth
	return metadata["requires_continuous_auth"] == "true" ||
		metadata["session_type"] == "terminal" ||
		metadata["privilege_level"] == "high"
}

func (sr *SessionRegistry) removeSessionFromSlice(sessions []string, sessionID string) []string {
	for i, id := range sessions {
		if id == sessionID {
			return append(sessions[:i], sessions[i+1:]...)
		}
	}
	return sessions
}

func (sr *SessionRegistry) updateSessionThreatLevel(session *AuthorizedSession) {
	// Calculate threat level based on security violations
	recentViolations := 0
	criticalViolations := 0
	cutoff := time.Now().Add(-10 * time.Minute)

	for _, violation := range session.SecurityViolations {
		if violation.DetectedAt.After(cutoff) && !violation.Resolved {
			recentViolations++
			if violation.Severity == "critical" {
				criticalViolations++
			}
		}
	}

	// Update threat level
	if criticalViolations > 0 {
		session.ThreatLevel = ThreatLevelCritical
	} else if recentViolations > 3 {
		session.ThreatLevel = ThreatLevelHigh
	} else if recentViolations > 1 {
		session.ThreatLevel = ThreatLevelMedium
	} else {
		session.ThreatLevel = ThreatLevelLow
	}
}

func (sr *SessionRegistry) generateSessionRecommendations(session *AuthorizedSession) []string {
	recommendations := make([]string, 0)

	// Check for expired permissions
	now := time.Now()
	expiredPermissions := 0
	for _, grant := range session.GrantedPermissions {
		if now.After(grant.ExpiresAt) {
			expiredPermissions++
		}
	}

	if expiredPermissions > 0 {
		recommendations = append(recommendations, "renew_expired_permissions")
	}

	// Check threat level
	if session.ThreatLevel >= ThreatLevelHigh {
		recommendations = append(recommendations, "implement_additional_security_measures")
	}

	// Check session duration
	if now.Sub(session.CreatedAt) > 4*time.Hour {
		recommendations = append(recommendations, "consider_session_renewal")
	}

	return recommendations
}

func (sr *SessionRegistry) updateStats() {
	sr.stats.mutex.Lock()
	defer sr.stats.mutex.Unlock()

	// Reset counters
	sr.stats.ActiveSessions = len(sr.sessions)
	sr.stats.SessionsByType = make(map[SessionType]int)
	sr.stats.SessionsByTenant = make(map[string]int)

	// Calculate statistics
	totalDuration := time.Duration(0)
	for _, session := range sr.sessions {
		sr.stats.SessionsByType[session.SessionType]++
		sr.stats.SessionsByTenant[session.TenantID]++
		totalDuration += time.Since(session.CreatedAt)
	}

	if sr.stats.ActiveSessions > 0 {
		sr.stats.AverageSessionTime = totalDuration / time.Duration(sr.stats.ActiveSessions)
	}

	sr.stats.TotalSessions = sr.stats.ActiveSessions + sr.stats.ExpiredSessions + sr.stats.TerminatedSessions
}
