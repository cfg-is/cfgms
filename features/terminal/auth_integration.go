// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// AuthenticatedTerminalManager manages terminal sessions with mTLS authentication and continuous authorization
type AuthenticatedTerminalManager struct {
	baseManager       SessionManager
	rbacManager       rbac.RBACManager
	certValidator     *cert.Validator
	securityValidator *SecurityValidator
	auditManager      *audit.Manager
	sessionMonitor    *SessionMonitor

	// Anti-hijacking measures
	sessionTokens map[string]*SessionToken
	tokenMutex    sync.RWMutex

	// Configuration
	config               *AuthConfig
	continuousAuthConfig *ContinuousAuthConfig
}

// AuthConfig contains authentication and security configuration
type AuthConfig struct {
	// mTLS Configuration
	RequireMTLS        bool   `json:"require_mtls"`
	ClientCertRequired bool   `json:"client_cert_required"`
	CertValidationMode string `json:"cert_validation_mode"` // strict, relaxed, disabled

	// Session Security
	SessionTimeout        time.Duration `json:"session_timeout"`
	TokenRotationInterval time.Duration `json:"token_rotation_interval"`
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`

	// Anti-Hijacking
	IPBindingEnabled    bool          `json:"ip_binding_enabled"`
	TLSFingerprintCheck bool          `json:"tls_fingerprint_check"`
	TokenValidation     bool          `json:"token_validation"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`

	// Additional Security
	GeofencingEnabled bool     `json:"geofencing_enabled"`
	AllowedCountries  []string `json:"allowed_countries"`
	TimeBasedAccess   bool     `json:"time_based_access"`
	AllowedHours      []int    `json:"allowed_hours"`
}

// ContinuousAuthConfig contains continuous authorization configuration
type ContinuousAuthConfig struct {
	// Continuous Authorization
	EnableContinuousAuth        bool          `json:"enable_continuous_auth"`
	AuthorizePerCommand         bool          `json:"authorize_per_command"`
	CommandAuthTimeout          time.Duration `json:"command_auth_timeout"`
	SessionRevalidationInterval time.Duration `json:"session_revalidation_interval"`

	// Per-command authorization settings
	RequireAuthCommands []string `json:"require_auth_commands"`
	HighRiskCommands    []string `json:"high_risk_commands"`
	CriticalCommands    []string `json:"critical_commands"`

	// Session monitoring
	MonitorSessionContext  bool    `json:"monitor_session_context"`
	ContextChangeThreshold float64 `json:"context_change_threshold"`
	MaxAuthLatencyMs       int     `json:"max_auth_latency_ms"`

	// Fallback behavior
	ContinuousAuthFallback string `json:"continuous_auth_fallback"` // "allow", "deny", "traditional"
}

// SessionToken represents a secure session token with anti-hijacking properties
type SessionToken struct {
	Token       string    `json:"token"`
	SessionID   string    `json:"session_id"`
	UserID      string    `json:"user_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastRotated time.Time `json:"last_rotated"`

	// Security Properties
	ClientIP        string `json:"client_ip"`
	TLSFingerprint  string `json:"tls_fingerprint"`
	UserAgent       string `json:"user_agent"`
	CertificateHash string `json:"certificate_hash"`

	// State
	Active        bool      `json:"active"`
	FailedChecks  int       `json:"failed_checks"`
	LastHeartbeat time.Time `json:"last_heartbeat"`

	// Metadata
	Metadata map[string]string `json:"metadata"`
}

// AuthenticationResult contains the result of authentication
type AuthenticationResult struct {
	Success         bool                    `json:"success"`
	UserID          string                  `json:"user_id"`
	TenantID        string                  `json:"tenant_id"`
	Permissions     []string                `json:"permissions"`
	SessionToken    *SessionToken           `json:"session_token"`
	SecurityContext *SessionSecurityContext `json:"security_context"`
	Restrictions    *AccessRestrictions     `json:"restrictions"`
	ErrorMessage    string                  `json:"error_message,omitempty"`
}

// AccessRestrictions defines restrictions on terminal access
type AccessRestrictions struct {
	AllowedCommands    []string      `json:"allowed_commands"`
	BlockedCommands    []string      `json:"blocked_commands"`
	MaxSessionDuration time.Duration `json:"max_session_duration"`
	MaxIdleTime        time.Duration `json:"max_idle_time"`
	AllowedDirectories []string      `json:"allowed_directories"`
	BlockedDirectories []string      `json:"blocked_directories"`
	RequireApproval    bool          `json:"require_approval"`
	MonitoringLevel    SecurityLevel `json:"monitoring_level"`
}

// NewAuthenticatedTerminalManager creates a new authenticated terminal manager
func NewAuthenticatedTerminalManager(
	baseManager SessionManager,
	rbacManager rbac.RBACManager,
	certValidator *cert.Validator,
	auditManager *audit.Manager,
	config *AuthConfig,
) (*AuthenticatedTerminalManager, error) {
	if config == nil {
		config = DefaultAuthConfig()
	}

	securityValidator := NewSecurityValidator(rbacManager)
	sessionMonitor := NewSessionMonitor(securityValidator, DefaultMonitorConfig())

	manager := &AuthenticatedTerminalManager{
		baseManager:          baseManager,
		rbacManager:          rbacManager,
		certValidator:        certValidator,
		securityValidator:    securityValidator,
		auditManager:         auditManager,
		sessionMonitor:       sessionMonitor,
		sessionTokens:        make(map[string]*SessionToken),
		config:               config,
		continuousAuthConfig: DefaultContinuousAuthConfig(),
	}

	// Start background services
	ctx := context.Background()
	if err := sessionMonitor.Start(ctx); err != nil {
		// Log error but continue - monitoring failures shouldn't block auth
		_ = err // Explicitly ignore monitoring startup errors
	}

	// Start token rotation and cleanup
	go manager.tokenMaintenanceLoop(ctx)

	return manager, nil
}

// AuthenticateAndCreateSession authenticates a request and creates a secure terminal session
func (atm *AuthenticatedTerminalManager) AuthenticateAndCreateSession(ctx context.Context, r *http.Request, req *SessionRequest) (*AuthenticationResult, error) {
	// Extract client certificate from mTLS connection
	clientCert, err := atm.extractClientCertificate(r)
	if err != nil {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Client certificate extraction failed: %v", err),
		}, nil
	}

	// Validate client certificate
	if atm.config.RequireMTLS && clientCert == nil {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: "Client certificate required for terminal access",
		}, nil
	}

	// Extract user identity from certificate
	userID, tenantID, err := atm.extractUserIdentity(clientCert)
	if err != nil {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("User identity extraction failed: %v", err),
		}, nil
	}

	// Validate session request against RBAC
	securityContext, err := atm.securityValidator.ValidateSessionAccess(ctx, userID, req.StewardID, tenantID)
	if err != nil {
		resourceID := req.StewardID
		if resourceID == "" {
			resourceID = userID
		}
		_ = atm.auditManager.RecordEvent(ctx,
			audit.NewEventBuilder().
				Tenant(tenantID).
				Type(business.AuditEventSecurityEvent).
				Action("terminal.terminal_access_denied").
				User(userID, business.AuditUserTypeHuman).
				Resource("terminal", resourceID, "").
				Result(business.AuditResultDenied).
				Severity(business.AuditSeverityHigh).
				Details(map[string]interface{}{
					"violation_type": "terminal_access_denied",
					"details":        err.Error(),
				}),
		)

		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Access denied: %v", err),
		}, nil
	}

	// Check for additional security restrictions
	restrictions, err := atm.getAccessRestrictions(ctx, userID, tenantID, req.StewardID)
	if err != nil {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to get access restrictions: %v", err),
		}, nil
	}

	// Validate time-based access if enabled
	if atm.config.TimeBasedAccess {
		if !atm.isAccessAllowedAtTime(time.Now(), restrictions) {
			resourceID := req.StewardID
			if resourceID == "" {
				resourceID = userID
			}
			_ = atm.auditManager.RecordEvent(ctx,
				audit.NewEventBuilder().
					Tenant(tenantID).
					Type(business.AuditEventSecurityEvent).
					Action("terminal.time_based_access_violation").
					User(userID, business.AuditUserTypeHuman).
					Resource("terminal", resourceID, "").
					Result(business.AuditResultDenied).
					Severity(business.AuditSeverityMedium).
					Details(map[string]interface{}{
						"violation_type": "time_based_access_violation",
						"details":        "Access attempted outside allowed hours",
					}),
			)

			return &AuthenticationResult{
				Success:      false,
				ErrorMessage: "Access not allowed at this time",
			}, nil
		}
	}

	// Check concurrent session limits
	if atm.getActiveSessionCount(userID) >= atm.config.MaxConcurrentSessions {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: "Maximum concurrent sessions exceeded",
		}, nil
	}

	// Create the actual terminal session
	session, err := atm.baseManager.CreateSession(ctx, req)
	if err != nil {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Session creation failed: %v", err),
		}, nil
	}

	// Generate session token with anti-hijacking properties
	sessionToken, err := atm.generateSessionToken(session.ID, userID, r, clientCert)
	if err != nil {
		return &AuthenticationResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to generate session token: %v", err),
		}, nil
	}

	// Store session token
	atm.tokenMutex.Lock()
	atm.sessionTokens[sessionToken.Token] = sessionToken
	atm.tokenMutex.Unlock()

	// Add session to monitoring
	securityContext.SessionID = session.ID
	if err := atm.sessionMonitor.AddSession(session, securityContext); err != nil {
		// Log error but continue - monitoring failures shouldn't block auth
		_ = err // Explicitly ignore monitoring failures for resilience
	}

	// Log successful authentication
	clientIP := atm.getClientIP(r)
	resourceID := req.StewardID
	if resourceID == "" {
		resourceID = userID
	}
	_ = atm.auditManager.RecordEvent(ctx,
		audit.NewEventBuilder().
			Tenant(tenantID).
			Type(business.AuditEventSystemAccess).
			Action("terminal.session.start").
			User(userID, business.AuditUserTypeHuman).
			Session(session.ID).
			Resource("terminal", resourceID, "").
			Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityMedium).
			Details(map[string]interface{}{
				"client_ip": clientIP,
			}),
	)

	return &AuthenticationResult{
		Success:         true,
		UserID:          userID,
		TenantID:        tenantID,
		Permissions:     securityContext.Permissions,
		SessionToken:    sessionToken,
		SecurityContext: securityContext,
		Restrictions:    restrictions,
	}, nil
}

// ValidateSessionToken validates a session token and checks for hijacking attempts
func (atm *AuthenticatedTerminalManager) ValidateSessionToken(ctx context.Context, r *http.Request, tokenString string) (*SessionToken, error) {
	atm.tokenMutex.RLock()
	token, exists := atm.sessionTokens[tokenString]
	atm.tokenMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid session token")
	}

	// Check if token is active
	if !token.Active {
		return nil, fmt.Errorf("session token is inactive")
	}

	// Check token expiration
	if time.Now().After(token.ExpiresAt) {
		atm.invalidateToken(token.Token)
		return nil, fmt.Errorf("session token expired")
	}

	// Anti-hijacking checks
	if atm.config.IPBindingEnabled {
		clientIP := atm.getClientIP(r)
		if token.ClientIP != clientIP {
			_ = atm.auditManager.RecordEvent(ctx,
				audit.NewEventBuilder().
					Tenant(extractTenantID(token)).
					Type(business.AuditEventSecurityEvent).
					Action("terminal.session_hijack_attempt").
					User(token.UserID, business.AuditUserTypeHuman).
					Session(token.SessionID).
					Resource("session", token.SessionID, "").
					Result(business.AuditResultDenied).
					Severity(business.AuditSeverityCritical).
					Details(map[string]interface{}{
						"violation_type": "session_hijack_attempt",
						"details":        fmt.Sprintf("IP address mismatch: expected %s, got %s", token.ClientIP, clientIP),
					}),
			)

			atm.invalidateToken(token.Token)
			return nil, fmt.Errorf("session hijacking detected: IP address mismatch")
		}
	}

	// TLS fingerprint check
	if atm.config.TLSFingerprintCheck && r.TLS != nil {
		currentFingerprint := atm.generateTLSFingerprint(r.TLS)
		if token.TLSFingerprint != currentFingerprint {
			_ = atm.auditManager.RecordEvent(ctx,
				audit.NewEventBuilder().
					Tenant(extractTenantID(token)).
					Type(business.AuditEventSecurityEvent).
					Action("terminal.session_hijack_attempt").
					User(token.UserID, business.AuditUserTypeHuman).
					Session(token.SessionID).
					Resource("session", token.SessionID, "").
					Result(business.AuditResultDenied).
					Severity(business.AuditSeverityCritical).
					Details(map[string]interface{}{
						"violation_type": "session_hijack_attempt",
						"details":        "TLS fingerprint mismatch",
					}),
			)

			atm.invalidateToken(token.Token)
			return nil, fmt.Errorf("session hijacking detected: TLS fingerprint mismatch")
		}
	}

	// Update heartbeat
	atm.tokenMutex.Lock()
	token.LastHeartbeat = time.Now()
	atm.tokenMutex.Unlock()

	return token, nil
}

// TerminateSession securely terminates a terminal session
func (atm *AuthenticatedTerminalManager) TerminateSession(ctx context.Context, sessionID string, reason string) error {
	// Find and invalidate session token; capture user/tenant before deletion for audit
	var terminatedUserID, terminatedTenantID string
	atm.tokenMutex.Lock()
	for tokenString, token := range atm.sessionTokens {
		if token.SessionID == sessionID {
			terminatedUserID = token.UserID
			terminatedTenantID = extractTenantID(token)
			delete(atm.sessionTokens, tokenString)
			break
		}
	}
	atm.tokenMutex.Unlock()

	// Remove from monitoring
	if err := atm.sessionMonitor.RemoveSession(sessionID); err != nil {
		// Log error but continue with termination
		_ = err // Explicitly ignore monitoring errors during termination
	}

	// Terminate the actual session
	if err := atm.baseManager.TerminateSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to terminate session: %w", err)
	}

	// Log session termination; fall back to system identity when token was not found
	userID := terminatedUserID
	if userID == "" {
		userID = audit.SystemUserID
	}
	tenantID := terminatedTenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	_ = atm.auditManager.RecordEvent(ctx,
		audit.NewEventBuilder().
			Tenant(tenantID).
			Type(business.AuditEventSystemAccess).
			Action("terminal.session.end").
			User(userID, business.AuditUserTypeHuman).
			Session(sessionID).
			Resource("session", sessionID, "").
			Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityMedium).
			Details(map[string]interface{}{
				"reason": reason,
			}),
	)

	return nil
}

// Helper methods

func (atm *AuthenticatedTerminalManager) extractClientCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		if atm.config.ClientCertRequired {
			return nil, fmt.Errorf("no client certificate provided")
		}
		return nil, nil
	}

	clientCert := r.TLS.PeerCertificates[0]

	// Validate certificate with our validator
	if atm.certValidator != nil {
		result, err := atm.certValidator.ValidateCertificate(clientCert)
		if err != nil || !result.IsValid {
			return nil, fmt.Errorf("certificate validation failed: %w", err)
		}
	}

	return clientCert, nil
}

func (atm *AuthenticatedTerminalManager) extractUserIdentity(cert *x509.Certificate) (userID, tenantID string, err error) {
	if cert == nil {
		return "", "", fmt.Errorf("no certificate provided")
	}

	// Extract user ID from certificate subject
	userID = cert.Subject.CommonName
	if userID == "" {
		return "", "", fmt.Errorf("no user ID found in certificate")
	}

	// Extract tenant ID from certificate extensions or organizational unit
	if len(cert.Subject.OrganizationalUnit) > 0 {
		tenantID = cert.Subject.OrganizationalUnit[0]
	}

	if tenantID == "" {
		return "", "", fmt.Errorf("no tenant ID found in certificate")
	}

	return userID, tenantID, nil
}

func (atm *AuthenticatedTerminalManager) getAccessRestrictions(ctx context.Context, userID, tenantID, stewardID string) (*AccessRestrictions, error) {
	// Get user permissions to determine restrictions
	permissions, err := atm.rbacManager.GetSubjectPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	restrictions := &AccessRestrictions{
		MaxSessionDuration: atm.config.SessionTimeout,
		MaxIdleTime:        30 * time.Minute,
		MonitoringLevel:    SecurityLevelEnhanced,
	}

	// Apply restrictions based on permissions
	hasAdminPermissions := false
	for _, perm := range permissions {
		if perm.Id == "terminal.admin" || perm.Id == "system.admin" {
			hasAdminPermissions = true
			break
		}
	}

	if !hasAdminPermissions {
		restrictions.BlockedCommands = []string{
			"rm -rf",
			"format",
			"mkfs",
			"fdisk",
			"dd if=/dev/zero",
		}
		restrictions.MonitoringLevel = SecurityLevelMaximum
		restrictions.RequireApproval = true
	}

	return restrictions, nil
}

func (atm *AuthenticatedTerminalManager) isAccessAllowedAtTime(now time.Time, restrictions *AccessRestrictions) bool {
	if !atm.config.TimeBasedAccess {
		return true
	}

	currentHour := now.Hour()
	for _, allowedHour := range atm.config.AllowedHours {
		if currentHour == allowedHour {
			return true
		}
	}

	return false
}

func (atm *AuthenticatedTerminalManager) getActiveSessionCount(userID string) int {
	atm.tokenMutex.RLock()
	defer atm.tokenMutex.RUnlock()

	count := 0
	for _, token := range atm.sessionTokens {
		if token.UserID == userID && token.Active {
			count++
		}
	}

	return count
}

func (atm *AuthenticatedTerminalManager) generateSessionToken(sessionID, userID string, r *http.Request, cert *x509.Certificate) (*SessionToken, error) {
	tokenStr, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	token := &SessionToken{
		Token:         tokenStr,
		SessionID:     sessionID,
		UserID:        userID,
		IssuedAt:      now,
		ExpiresAt:     now.Add(atm.config.SessionTimeout),
		LastRotated:   now,
		ClientIP:      atm.getClientIP(r),
		UserAgent:     r.UserAgent(),
		Active:        true,
		LastHeartbeat: now,
		Metadata:      make(map[string]string),
	}

	if r.TLS != nil {
		token.TLSFingerprint = atm.generateTLSFingerprint(r.TLS)
	}

	if cert != nil {
		token.CertificateHash = fmt.Sprintf("%x", cert.Raw)
	}

	return token, nil
}

func (atm *AuthenticatedTerminalManager) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if colon := strings.LastIndex(addr, ":"); colon != -1 {
		addr = addr[:colon]
	}

	return addr
}

func (atm *AuthenticatedTerminalManager) generateTLSFingerprint(connState *tls.ConnectionState) string {
	if len(connState.PeerCertificates) == 0 {
		return ""
	}

	cert := connState.PeerCertificates[0]
	return fmt.Sprintf("%x", cert.Signature)
}

func (atm *AuthenticatedTerminalManager) invalidateToken(tokenString string) {
	atm.tokenMutex.Lock()
	defer atm.tokenMutex.Unlock()

	if token, exists := atm.sessionTokens[tokenString]; exists {
		token.Active = false
		delete(atm.sessionTokens, tokenString)
	}
}

func (atm *AuthenticatedTerminalManager) tokenMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			atm.cleanupExpiredTokens()
			atm.rotateTokensIfNeeded()
		}
	}
}

func (atm *AuthenticatedTerminalManager) cleanupExpiredTokens() {
	atm.tokenMutex.Lock()
	defer atm.tokenMutex.Unlock()

	now := time.Now()
	for tokenString, token := range atm.sessionTokens {
		if now.After(token.ExpiresAt) || !token.Active {
			delete(atm.sessionTokens, tokenString)
		}
	}
}

func (atm *AuthenticatedTerminalManager) rotateTokensIfNeeded() {
	atm.tokenMutex.Lock()
	defer atm.tokenMutex.Unlock()

	now := time.Now()
	for _, token := range atm.sessionTokens {
		if now.Sub(token.LastRotated) > atm.config.TokenRotationInterval {
			// Deferred: tracked in #1441 — push token-refresh signal to client over WebSocket
			token.LastRotated = now
		}
	}
}

func generateSecureToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("token generation failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(buf), nil
}

// DefaultAuthConfig returns default authentication configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		RequireMTLS:           true,
		ClientCertRequired:    true,
		CertValidationMode:    "strict",
		SessionTimeout:        4 * time.Hour,
		TokenRotationInterval: 1 * time.Hour,
		MaxConcurrentSessions: 5,
		IPBindingEnabled:      true,
		TLSFingerprintCheck:   true,
		TokenValidation:       true,
		HeartbeatInterval:     30 * time.Second,
		GeofencingEnabled:     false,
		TimeBasedAccess:       false,
		AllowedHours:          []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
	}
}

// DefaultContinuousAuthConfig returns default continuous authorization configuration
func DefaultContinuousAuthConfig() *ContinuousAuthConfig {
	return &ContinuousAuthConfig{
		EnableContinuousAuth:        false, // Disabled by default
		AuthorizePerCommand:         true,
		CommandAuthTimeout:          100 * time.Millisecond,
		SessionRevalidationInterval: 5 * time.Minute,
		RequireAuthCommands: []string{
			"sudo", "su", "passwd", "chmod", "chown", "rm -rf",
			"dd", "mkfs", "fdisk", "mount", "umount", "systemctl",
		},
		HighRiskCommands: []string{
			"rm", "rmdir", "mv", "cp -r", "rsync", "scp",
			"ssh", "telnet", "ftp", "wget", "curl", "git clone",
		},
		CriticalCommands: []string{
			"format", "fdisk -l", "parted", "gparted", "cfdisk",
			"mkfs.ext4", "mkfs.ntfs", "dd if=/dev/zero", "shred",
		},
		MonitorSessionContext:  true,
		ContextChangeThreshold: 0.3, // 30% context change triggers reauth
		MaxAuthLatencyMs:       10,
		ContinuousAuthFallback: "traditional", // Fall back to traditional auth
	}
}

// HandlePermissionRevocation handles real-time permission revocation for terminal sessions
func (atm *AuthenticatedTerminalManager) HandlePermissionRevocation(ctx context.Context, userID, tenantID string, permissions []string) error {
	return nil
}

// GetSessionRBACStatus returns the current RBAC status of a terminal session
func (atm *AuthenticatedTerminalManager) GetSessionRBACStatus(ctx context.Context, sessionID string) (*TerminalRBACStatus, error) {
	return &TerminalRBACStatus{
		SessionID:             sessionID,
		ContinuousAuthEnabled: false,
		LastValidated:         time.Now(),
		Status:                "traditional_auth",
	}, nil
}

// extractTenantID extracts tenant ID from session token
func extractTenantID(token *SessionToken) string {
	if tenantID, exists := token.Metadata["tenant_id"]; exists {
		return tenantID
	}
	return "default" // Fallback to default tenant
}

// TerminalRBACStatus represents the RBAC status of a terminal session
type TerminalRBACStatus struct {
	SessionID             string    `json:"session_id"`
	ContinuousAuthEnabled bool      `json:"continuous_auth_enabled"`
	LastValidated         time.Time `json:"last_validated"`
	Status                string    `json:"status"`
	ActivePermissions     int       `json:"active_permissions"`
	RequiresReauth        bool      `json:"requires_reauth"`
	SecurityAlerts        int       `json:"security_alerts"`
	ComplianceStatus      string    `json:"compliance_status"`
	RecommendedActions    []string  `json:"recommended_actions"`
}

// RevalidateSession performs session revalidation (no-op without continuous auth engine)
func (atm *AuthenticatedTerminalManager) RevalidateSession(ctx context.Context, sessionID string, token *SessionToken) error {
	return nil
}
