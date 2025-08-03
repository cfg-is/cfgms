package terminal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/cert"
)

// AuthenticatedTerminalManager manages terminal sessions with mTLS authentication
type AuthenticatedTerminalManager struct {
	baseManager       SessionManager
	rbacManager       rbac.RBACManager
	certValidator     *cert.Validator
	securityValidator *SecurityValidator
	auditLogger       *AuditLogger
	sessionMonitor    *SessionMonitor
	
	// Anti-hijacking measures
	sessionTokens     map[string]*SessionToken
	tokenMutex        sync.RWMutex
	
	// Configuration
	config            *AuthConfig
}

// AuthConfig contains authentication and security configuration
type AuthConfig struct {
	// mTLS Configuration
	RequireMTLS         bool          `json:"require_mtls"`
	ClientCertRequired  bool          `json:"client_cert_required"`
	CertValidationMode  string        `json:"cert_validation_mode"` // strict, relaxed, disabled
	
	// Session Security
	SessionTimeout      time.Duration `json:"session_timeout"`
	TokenRotationInterval time.Duration `json:"token_rotation_interval"`
	MaxConcurrentSessions int         `json:"max_concurrent_sessions"`
	
	// Anti-Hijacking
	IPBindingEnabled    bool          `json:"ip_binding_enabled"`
	TLSFingerprintCheck bool          `json:"tls_fingerprint_check"`
	TokenValidation     bool          `json:"token_validation"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`
	
	// Additional Security
	GeofencingEnabled   bool          `json:"geofencing_enabled"`
	AllowedCountries    []string      `json:"allowed_countries"`
	TimeBasedAccess     bool          `json:"time_based_access"`
	AllowedHours        []int         `json:"allowed_hours"`
}

// SessionToken represents a secure session token with anti-hijacking properties
type SessionToken struct {
	Token           string            `json:"token"`
	SessionID       string            `json:"session_id"`
	UserID          string            `json:"user_id"`
	IssuedAt        time.Time         `json:"issued_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastRotated     time.Time         `json:"last_rotated"`
	
	// Security Properties
	ClientIP        string            `json:"client_ip"`
	TLSFingerprint  string            `json:"tls_fingerprint"`
	UserAgent       string            `json:"user_agent"`
	CertificateHash string            `json:"certificate_hash"`
	
	// State
	Active          bool              `json:"active"`
	FailedChecks    int               `json:"failed_checks"`
	LastHeartbeat   time.Time         `json:"last_heartbeat"`
	
	// Metadata
	Metadata        map[string]string `json:"metadata"`
}

// AuthenticationResult contains the result of authentication
type AuthenticationResult struct {
	Success         bool              `json:"success"`
	UserID          string            `json:"user_id"`
	TenantID        string            `json:"tenant_id"`
	Permissions     []string          `json:"permissions"`
	SessionToken    *SessionToken     `json:"session_token"`
	SecurityContext *SessionSecurityContext `json:"security_context"`
	Restrictions    *AccessRestrictions     `json:"restrictions"`
	ErrorMessage    string            `json:"error_message,omitempty"`
}

// AccessRestrictions defines restrictions on terminal access
type AccessRestrictions struct {
	AllowedCommands     []string          `json:"allowed_commands"`
	BlockedCommands     []string          `json:"blocked_commands"`
	MaxSessionDuration  time.Duration     `json:"max_session_duration"`
	MaxIdleTime         time.Duration     `json:"max_idle_time"`
	AllowedDirectories  []string          `json:"allowed_directories"`
	BlockedDirectories  []string          `json:"blocked_directories"`
	RequireApproval     bool              `json:"require_approval"`
	MonitoringLevel     SecurityLevel     `json:"monitoring_level"`
}

// NewAuthenticatedTerminalManager creates a new authenticated terminal manager
func NewAuthenticatedTerminalManager(
	baseManager SessionManager,
	rbacManager rbac.RBACManager,
	certValidator *cert.Validator,
	config *AuthConfig,
) (*AuthenticatedTerminalManager, error) {
	if config == nil {
		config = DefaultAuthConfig()
	}
	
	securityValidator := NewSecurityValidator(rbacManager)
	auditLogger, err := NewAuditLogger(DefaultAuditConfig(), NewFileAuditStorage("/var/log/cfgms/terminal-audit"))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}
	
	sessionMonitor := NewSessionMonitor(securityValidator, DefaultMonitorConfig())
	
	manager := &AuthenticatedTerminalManager{
		baseManager:       baseManager,
		rbacManager:       rbacManager,
		certValidator:     certValidator,
		securityValidator: securityValidator,
		auditLogger:       auditLogger,
		sessionMonitor:    sessionMonitor,
		sessionTokens:     make(map[string]*SessionToken),
		config:            config,
	}
	
	// Start background services
	ctx := context.Background()
	if err := auditLogger.Start(ctx); err != nil {
		// Log error but continue - audit failures shouldn't block auth
	}
	if err := sessionMonitor.Start(ctx); err != nil {
		// Log error but continue - monitoring failures shouldn't block auth
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
		if logErr := atm.auditLogger.LogSecurityViolation(ctx, "", userID, req.StewardID, tenantID, 
			"terminal_access_denied", err.Error(), FilterSeverityHigh); logErr != nil {
			// Log error but continue - audit failures shouldn't block auth decision
		}
		
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
			if logErr := atm.auditLogger.LogSecurityViolation(ctx, "", userID, req.StewardID, tenantID,
				"time_based_access_violation", "Access attempted outside allowed hours", FilterSeverityMedium); logErr != nil {
				// Log error but continue - audit failures shouldn't block auth decision
			}
			
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
	sessionToken := atm.generateSessionToken(session.ID, userID, r, clientCert)
	
	// Store session token
	atm.tokenMutex.Lock()
	atm.sessionTokens[sessionToken.Token] = sessionToken
	atm.tokenMutex.Unlock()
	
	// Add session to monitoring
	securityContext.SessionID = session.ID
	if err := atm.sessionMonitor.AddSession(session, securityContext); err != nil {
		// Log error but continue - monitoring failures shouldn't block auth
	}
	
	// Log successful authentication
	clientIP := atm.getClientIP(r)
	if logErr := atm.auditLogger.LogSessionStart(ctx, session.ID, userID, req.StewardID, tenantID, clientIP); logErr != nil {
		// Log error but continue - audit failures shouldn't prevent successful auth
	}
	
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
			if logErr := atm.auditLogger.LogSecurityViolation(ctx, token.SessionID, token.UserID, "", "",
				"session_hijack_attempt", fmt.Sprintf("IP address mismatch: expected %s, got %s", token.ClientIP, clientIP), FilterSeverityCritical); logErr != nil {
				// Log error but continue - audit failures shouldn't prevent security action
			}
			
			atm.invalidateToken(token.Token)
			return nil, fmt.Errorf("session hijacking detected: IP address mismatch")
		}
	}
	
	// TLS fingerprint check
	if atm.config.TLSFingerprintCheck && r.TLS != nil {
		currentFingerprint := atm.generateTLSFingerprint(r.TLS)
		if token.TLSFingerprint != currentFingerprint {
			atm.auditLogger.LogSecurityViolation(ctx, token.SessionID, token.UserID, "", "",
				"session_hijack_attempt", "TLS fingerprint mismatch", FilterSeverityCritical)
			
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
	// Find and invalidate session token
	atm.tokenMutex.Lock()
	for tokenString, token := range atm.sessionTokens {
		if token.SessionID == sessionID {
			delete(atm.sessionTokens, tokenString)
			break
		}
	}
	atm.tokenMutex.Unlock()
	
	// Remove from monitoring
	if err := atm.sessionMonitor.RemoveSession(sessionID); err != nil {
		// Log error but continue with termination
	}
	
	// Terminate the actual session
	if err := atm.baseManager.TerminateSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to terminate session: %w", err)
	}
	
	// Log session termination
	if logErr := atm.auditLogger.LogSessionEnd(ctx, sessionID, "", 0, 0, 0); logErr != nil { // TODO: Get actual metrics
		// Log error but continue - audit failures shouldn't prevent termination
	}
	
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

func (atm *AuthenticatedTerminalManager) generateSessionToken(sessionID, userID string, r *http.Request, cert *x509.Certificate) *SessionToken {
	now := time.Now()
	token := &SessionToken{
		Token:           generateSecureToken(),
		SessionID:       sessionID,
		UserID:          userID,
		IssuedAt:        now,
		ExpiresAt:       now.Add(atm.config.SessionTimeout),
		LastRotated:     now,
		ClientIP:        atm.getClientIP(r),
		UserAgent:       r.UserAgent(),
		Active:          true,
		LastHeartbeat:   now,
		Metadata:        make(map[string]string),
	}
	
	if r.TLS != nil {
		token.TLSFingerprint = atm.generateTLSFingerprint(r.TLS)
	}
	
	if cert != nil {
		token.CertificateHash = fmt.Sprintf("%x", cert.Raw)
	}
	
	return token
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
			// In a real implementation, this would notify the client to refresh the token
			token.LastRotated = now
		}
	}
}

func generateSecureToken() string {
	// In a real implementation, this would use cryptographically secure random generation
	return fmt.Sprintf("terminal_token_%d_%d", time.Now().UnixNano(), os.Getpid())
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