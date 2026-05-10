// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// Context keys
	apiKeyContextKey       contextKey = "api_key"
	userIDContextKey       contextKey = "user_id"
	authDecisionContextKey contextKey = "auth_decision"
	principalContextKey    contextKey = "principal"
)

// Principal represents an authenticated entity — either an mTLS admin cert or an API key.
// Admin principals (IsAdmin == true) are set exclusively by the cert-auth path after
// admin-extension verification. API-key principals are converted from APIKey structs.
type Principal struct {
	ID          string
	Name        string
	IsAdmin     bool
	Permissions []string
	TenantID    string
	// Cert-auth fields — non-empty only when IsAdmin == true (H3)
	CertSerial      string
	CertFingerprint string
	CertNotAfter    time.Time
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log the request
		duration := time.Since(start)
		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", logging.SanitizeLogValue(r.URL.Path),
			"status", wrapped.statusCode,
			"duration", duration,
			"remote_addr", logging.SanitizeLogValue(r.RemoteAddr),
			"user_agent", logging.SanitizeLogValue(r.Header.Get("User-Agent")),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// corsMiddleware handles CORS headers
// H-AUTH-3: Validate origin against allowed origins list (security audit finding)
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is in allowed list
		allowed := false
		if s.corsConfig != nil && origin != "" {
			for _, allowedOrigin := range s.corsConfig.AllowedOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}
		}

		// Only set CORS headers if origin is allowed
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			if allowed {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// contentTypeMiddleware sets appropriate content type headers
func (s *Server) contentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set default content type for API responses
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
		}

		next.ServeHTTP(w, r)
	})
}

// extractAdminPrincipal inspects r.TLS.PeerCertificates[0] for the CFGMS admin extension.
// Returns a non-nil *Principal when the cert carries the admin marker AND is not revoked.
// Chain verification is done at the TLS layer (VerifyClientCertIfGiven + ClientCAs).
// Returns nil when no cert is presented, the cert lacks the admin marker, or the cert
// serial is in the revoked-serials list (Story D: C2 fix).
func (s *Server) extractAdminPrincipal(r *http.Request) *Principal {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	peerCert := r.TLS.PeerCertificates[0]
	if !cert.HasAdminMarker(peerCert) {
		return nil
	}
	serial := peerCert.SerialNumber.String()
	// Story D: C2 fix — check revocation on every cert-auth request.
	// certManager may be nil in OSS deployments that haven't initialised cert management.
	if s.certManager != nil && s.certManager.IsRevoked(serial) {
		return nil
	}
	fpSum := sha256.Sum256(peerCert.Raw)
	return &Principal{
		ID:              peerCert.Subject.CommonName,
		Name:            "mtls-admin:" + peerCert.Subject.CommonName,
		IsAdmin:         true,
		TenantID:        "default",
		CertSerial:      serial,
		CertFingerprint: hex.EncodeToString(fpSum[:]),
		CertNotAfter:    peerCert.NotAfter,
	}
}

// hasHeaderCredentials reports whether the request carries an API key or Bearer token header.
func hasHeaderCredentials(r *http.Request) bool {
	if r.Header.Get("X-API-Key") != "" {
		return true
	}
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// authenticationMiddleware validates incoming requests via mTLS admin cert or API key.
// States: (a) admin-marked cert only → admin principal; (b) admin-marked cert + header → 400;
// (c) cert without admin marker → fall through to API-key auth; (d) no cert → API-key auth.
// M-AUTH-1: Load API keys from secret store on-demand if not in cache.
func (s *Server) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test endpoints require explicit opt-in via CFGMS_ENABLE_TEST_ENDPOINTS=true.
		// Without this env var, test endpoints require authentication like everything else.
		if os.Getenv("CFGMS_ENABLE_TEST_ENDPOINTS") == "true" {
			if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/api/v1/test/stewards/") && strings.HasSuffix(r.URL.Path, "/config") {
				s.logger.Warn("Test endpoint accessed with authentication bypass",
					"path", logging.SanitizeLogValue(r.URL.Path), "method", r.Method, "remote_addr", logging.SanitizeLogValue(r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/test/stewards/") && strings.HasSuffix(r.URL.Path, "/quic/connect") {
				s.logger.Warn("Test endpoint accessed with authentication bypass",
					"path", logging.SanitizeLogValue(r.URL.Path), "method", r.Method, "remote_addr", logging.SanitizeLogValue(r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}
		}

		// H2: mTLS-presented identity always wins.
		if adminPrincipal := s.extractAdminPrincipal(r); adminPrincipal != nil {
			// H2/L5: Conflicting credentials — cert AND header present → reject.
			if hasHeaderCredentials(r) {
				s.writeErrorResponse(w, http.StatusBadRequest,
					"Conflicting credentials: mTLS admin cert and API key header cannot both be present",
					"CONFLICTING_CREDENTIALS")
				return
			}
			// Cert-auth success: set principal context and proceed.
			ctx := context.WithValue(r.Context(), principalContextKey, adminPrincipal)
			ctx = context.WithValue(ctx, userIDContextKey, logging.SanitizeLogValue(adminPrincipal.ID))
			ctx = context.WithValue(ctx, ctxkeys.TenantID, adminPrincipal.TenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// State (c)/(d): no admin cert presented — use API-key path.

		// Extract API key from header
		apiKeyStr := r.Header.Get("X-API-Key")
		if apiKeyStr == "" {
			// Also check Authorization header for Bearer token
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKeyStr = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKeyStr == "" {
			s.writeErrorResponse(w, http.StatusUnauthorized, "API key required", "MISSING_API_KEY")
			return
		}

		// Check memory cache first
		s.mu.RLock()
		keyInfo, exists := s.apiKeys[apiKeyStr]
		s.mu.RUnlock()

		// M-AUTH-1: If not in cache, try to load from secret store
		if !exists {
			loadedKey, err := s.loadAPIKeyFromStore(r.Context(), apiKeyStr)
			if err != nil {
				s.logger.Debug("Failed to load API key from store", "error", err)
				s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid API key", "INVALID_API_KEY")
				return
			}
			keyInfo = loadedKey
		}

		// Check if key is expired
		if keyInfo.ExpiresAt != nil && time.Now().After(*keyInfo.ExpiresAt) {
			s.writeErrorResponse(w, http.StatusUnauthorized, "API key expired", "EXPIRED_API_KEY")
			return
		}

		// Convert API key to Principal for uniform authorization handling.
		principal := &Principal{
			ID:          keyInfo.ID,
			Name:        keyInfo.Name,
			IsAdmin:     false,
			Permissions: keyInfo.Permissions,
			TenantID:    keyInfo.TenantID,
		}

		// Add key info and principal to request context
		ctx := context.WithValue(r.Context(), apiKeyContextKey, keyInfo)
		ctx = context.WithValue(ctx, principalContextKey, principal)
		ctx = context.WithValue(ctx, userIDContextKey, keyInfo.ID)
		ctx = context.WithValue(ctx, ctxkeys.TenantID, keyInfo.TenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// M-AUTH-1: loadAPIKeyFromStore loads an API key from the secret store and caches it
func (s *Server) loadAPIKeyFromStore(ctx context.Context, apiKey string) (*APIKey, error) {
	// Hash the API key for lookup
	keyHash := hashAPIKey(apiKey)

	// Search for the API key in secret store across all tenants
	// We need to search all tenants since we don't know which tenant the key belongs to
	tenants := []string{"default"} // Start with default tenant

	for _, tenantID := range tenants {
		secretKey := fmt.Sprintf("%s/%s", tenantID, keyHash)
		secret, err := s.secretStore.GetSecret(ctx, secretKey)
		if err != nil {
			continue // Try next tenant
		}

		// Found the API key! Parse metadata and create APIKey object
		keyInfo := &APIKey{
			ID:          secret.Metadata["id"],
			Key:         apiKey, // Store plaintext key in memory for fast lookup
			Name:        secret.Description,
			Permissions: parsePermissions(secret.Metadata["permissions"]),
			CreatedAt:   secret.CreatedAt,
			ExpiresAt:   secret.ExpiresAt,
			TenantID:    secret.TenantID,
		}

		// Cache in memory for future requests
		s.mu.Lock()
		s.apiKeys[apiKey] = keyInfo
		s.mu.Unlock()

		s.logger.Debug("Loaded API key from secret store",
			"id", keyInfo.ID,
			"tenant_id", keyInfo.TenantID)

		return keyInfo, nil
	}

	return nil, fmt.Errorf("API key not found in secret store")
}

// writeErrorResponse writes a standardized error response
func (s *Server) writeErrorResponse(w http.ResponseWriter, statusCode int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error: &APIError{
			Code:    code,
			Message: message,
		},
		Timestamp: time.Now().UTC(),
	}

	_ = json.NewEncoder(w).Encode(errorResponse)
}

// writeSuccessResponse writes a standardized success response
func (s *Server) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	s.writeResponse(w, http.StatusOK, data)
}

// writeResponse writes a standardized API response
func (s *Server) writeResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}
}

// AuthorizationDecision contains the result of an authorization check
type AuthorizationDecision struct {
	Granted         bool                   `json:"granted"`
	PermissionID    string                 `json:"permission_id"`
	Resource        string                 `json:"resource"`
	Action          string                 `json:"action"`
	Decision        string                 `json:"decision"`
	Reason          string                 `json:"reason"`
	CheckedAt       time.Time              `json:"checked_at"`
	DurationMs      int64                  `json:"duration_ms"`
	SubjectID       string                 `json:"subject_id"`
	TenantID        string                 `json:"tenant_id"`
	ConditionalVars map[string]interface{} `json:"conditional_vars,omitempty"`
}

// requirePermission creates middleware that enforces specific permission requirements.
// Admin principals (IsAdmin == true) short-circuit to ALLOW for any permission.
func (s *Server) requirePermission(resourceType, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip permission check if RBAC service is not available
			if s.rbacService == nil {
				s.logger.Warn("RBAC service not available, skipping permission check")
				next.ServeHTTP(w, r)
				return
			}

			// Get authenticated principal from context (set by authenticationMiddleware).
			principal, ok := r.Context().Value(principalContextKey).(*Principal)
			if !ok {
				s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
				return
			}

			userID, _ := r.Context().Value(userIDContextKey).(string)
			tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)

			// Build resource identifier from URL path variables
			resource := s.buildResourceIdentifier(r, resourceType)

			permissionID := s.buildPermissionID(resourceType, action)
			if !s.hasPermission(principal, permissionID) {
				decision := &AuthorizationDecision{
					Granted:      false,
					PermissionID: permissionID,
					Resource:     resource,
					Action:       action,
					Decision:     "DENY",
					Reason:       "Principal lacks required permission: " + permissionID,
					CheckedAt:    time.Now(),
					SubjectID:    userID,
					TenantID:     tenantID,
				}

				s.auditAuthorizationDecision(r, decision)
				s.writeAuthorizationError(w, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS", decision)
				return
			}

			// Principal has required permission — grant access.
			reason := "API key has required permission: " + permissionID
			if principal.IsAdmin {
				reason = "Admin principal granted full access"
			}
			decision := &AuthorizationDecision{
				Granted:      true,
				PermissionID: permissionID,
				Resource:     resource,
				Action:       action,
				Decision:     "ALLOW",
				Reason:       reason,
				CheckedAt:    time.Now(),
				SubjectID:    userID,
				TenantID:     tenantID,
			}

			// Add decision to context
			ctx := context.WithValue(r.Context(), authDecisionContextKey, decision)

			s.logger.Debug("Access granted",
				"subject_id", userID,
				"is_admin", principal.IsAdmin,
				"permission_id", permissionID,
				"resource", resource,
			)

			// Audit the authorization decision
			s.auditAuthorizationDecision(r, decision)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// buildResourceIdentifier constructs a resource identifier from the request
func (s *Server) buildResourceIdentifier(r *http.Request, resourceType string) string {
	vars := mux.Vars(r)

	switch resourceType {
	case "steward":
		if stewardID := vars["id"]; stewardID != "" {
			return "steward:" + stewardID
		}
		return "steward:*"
	case "certificate":
		if serial := vars["serial"]; serial != "" {
			return "certificate:" + serial
		}
		return "certificate:*"
	case "rbac":
		if id := vars["id"]; id != "" {
			return "rbac:" + id
		}
		return "rbac:*"
	case "api-key":
		if id := vars["id"]; id != "" {
			return "api-key:" + id
		}
		return "api-key:*"
	case "monitoring":
		return "monitoring:*"
	default:
		return resourceType + ":*"
	}
}

// buildPermissionID constructs a permission ID from resource type and action
func (s *Server) buildPermissionID(resourceType, action string) string {
	return resourceType + ":" + action
}

// generateRequestID generates a unique request ID for tracing
func (s *Server) generateRequestID() string {
	return uuid.New().String()
}

// writeAuthorizationError writes an authorization error response with decision metadata
func (s *Server) writeAuthorizationError(w http.ResponseWriter, message, code string, decision *AuthorizationDecision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	errorResponse := ErrorResponse{
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: map[string]interface{}{
				"authorization_decision": decision,
			},
		},
		Timestamp: time.Now().UTC(),
	}

	_ = json.NewEncoder(w).Encode(errorResponse)
}

// auditAuthorizationDecision logs authorization decisions for security auditing (H3).
func (s *Server) auditAuthorizationDecision(r *http.Request, decision *AuthorizationDecision) {
	auditFields := map[string]interface{}{
		"event_type":     "api_authorization",
		"timestamp":      decision.CheckedAt.UTC().Format(time.RFC3339Nano),
		"subject_id":     logging.SanitizeLogValue(decision.SubjectID),
		"tenant_id":      logging.SanitizeLogValue(decision.TenantID),
		"permission_id":  logging.SanitizeLogValue(decision.PermissionID),
		"resource":       logging.SanitizeLogValue(decision.Resource),
		"action":         logging.SanitizeLogValue(decision.Action),
		"decision":       logging.SanitizeLogValue(decision.Decision),
		"granted":        decision.Granted,
		"reason":         logging.SanitizeLogValue(decision.Reason),
		"duration_ms":    decision.DurationMs,
		"request_path":   logging.SanitizeLogValue(r.URL.Path),
		"request_method": logging.SanitizeLogValue(r.Method),
		"remote_addr":    logging.SanitizeLogValue(r.RemoteAddr),
		"user_agent":     logging.SanitizeLogValue(r.Header.Get("User-Agent")),
		"request_id":     logging.SanitizeLogValue(s.getRequestID(r)),
		"severity":       s.getAuditSeverity(decision),
	}

	// H3: Include auth method and cert details in audit log.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal != nil && principal.IsAdmin {
		auditFields["auth_method"] = "cert"
		auditFields["cert_serial"] = logging.SanitizeLogValue(principal.CertSerial)
		auditFields["cert_fingerprint"] = logging.SanitizeLogValue(principal.CertFingerprint)
		auditFields["cert_not_after"] = principal.CertNotAfter.UTC().Format(time.RFC3339)
	} else {
		auditFields["auth_method"] = "api_key"
	}

	if decision.ConditionalVars != nil {
		auditFields["conditional_vars"] = logging.SanitizeFieldsRecursive(decision.ConditionalVars)
	}

	if decision.Granted {
		s.logger.Info("Authorization audit", flattenFieldsToKV(auditFields)...)
	} else {
		s.logger.Warn("Authorization audit - access denied", flattenFieldsToKV(auditFields)...)
	}
}

// flattenFieldsToKV converts a map to a sorted flat key/value slice for variadic logger calls.
// Keys are sorted alphabetically to make log output deterministic.
func flattenFieldsToKV(fields map[string]interface{}) []interface{} {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]interface{}, 0, 2*len(fields))
	for _, k := range keys {
		out = append(out, k, fields[k])
	}
	return out
}

// getRequestID extracts or generates a request ID for audit correlation
func (s *Server) getRequestID(r *http.Request) string {
	// Check if request ID was set by upstream proxy/load balancer
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		return reqID
	}
	if reqID := r.Header.Get("X-Correlation-ID"); reqID != "" {
		return reqID
	}

	// Generate one if not present
	return s.generateRequestID()
}

// getAuditSeverity determines audit severity based on authorization decision
func (s *Server) getAuditSeverity(decision *AuthorizationDecision) string {
	if !decision.Granted {
		// Failed authorization attempts are high severity
		if strings.Contains(decision.Reason, "Cross-tenant") {
			return "CRITICAL" // Cross-tenant violations are critical
		}
		return "HIGH" // Regular permission denials are high
	}

	// Successful authorizations for sensitive resources
	if strings.Contains(decision.PermissionID, "delete") ||
		strings.Contains(decision.PermissionID, "admin") ||
		strings.Contains(decision.Resource, "rbac") {
		return "MEDIUM" // Sensitive operations get medium severity
	}

	return "LOW" // Regular authorized operations
}

// hasPermission checks whether principal has permissionID.
// Admin principals (IsAdmin == true) short-circuit to true regardless of permissionID.
// C1: "*" is treated as a literal permission name — it will not match any real permissionID.
func (s *Server) hasPermission(principal *Principal, permissionID string) bool {
	if principal == nil {
		return false
	}
	if principal.IsAdmin {
		return true
	}
	for _, p := range principal.Permissions {
		if p == permissionID {
			return true
		}
	}
	return false
}
