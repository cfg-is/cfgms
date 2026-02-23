// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// Context keys
	apiKeyContextKey       contextKey = "api_key"
	userIDContextKey       contextKey = "user_id"
	tenantIDContextKey     contextKey = "tenant_id"
	authDecisionContextKey contextKey = "auth_decision"
)

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
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", duration,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
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

// authenticationMiddleware validates API keys for protected endpoints
// M-AUTH-1: Load API keys from secret store on-demand if not in cache
func (s *Server) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test endpoints require explicit opt-in via CFGMS_ENABLE_TEST_ENDPOINTS=true.
		// Without this env var, test endpoints require authentication like everything else.
		if os.Getenv("CFGMS_ENABLE_TEST_ENDPOINTS") == "true" {
			if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/api/v1/test/stewards/") && strings.HasSuffix(r.URL.Path, "/config") {
				s.logger.Warn("Test endpoint accessed with authentication bypass",
					"path", sanitizeLogValue(r.URL.Path), "method", r.Method, "remote_addr", sanitizeLogValue(r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/test/stewards/") && strings.HasSuffix(r.URL.Path, "/quic/connect") {
				s.logger.Warn("Test endpoint accessed with authentication bypass",
					"path", sanitizeLogValue(r.URL.Path), "method", r.Method, "remote_addr", sanitizeLogValue(r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}
		}

		// Extract API key from header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header for Bearer token
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			s.writeErrorResponse(w, http.StatusUnauthorized, "API key required", "MISSING_API_KEY")
			return
		}

		// Check memory cache first
		s.mu.RLock()
		keyInfo, exists := s.apiKeys[apiKey]
		s.mu.RUnlock()

		// M-AUTH-1: If not in cache, try to load from secret store
		if !exists {
			loadedKey, err := s.loadAPIKeyFromStore(r.Context(), apiKey)
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

		// Add key info to request context
		ctx := context.WithValue(r.Context(), apiKeyContextKey, keyInfo)
		ctx = context.WithValue(ctx, userIDContextKey, keyInfo.ID)
		ctx = context.WithValue(ctx, tenantIDContextKey, keyInfo.TenantID)

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

// requirePermission creates middleware that enforces specific permission requirements
func (s *Server) requirePermission(resourceType, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip permission check if RBAC service is not available
			if s.rbacService == nil {
				s.logger.Warn("RBAC service not available, skipping permission check")
				next.ServeHTTP(w, r)
				return
			}

			// Get authentication context
			apiKey, ok := r.Context().Value(apiKeyContextKey).(*APIKey)
			if !ok {
				s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
				return
			}

			userID, _ := r.Context().Value(userIDContextKey).(string)
			tenantID, _ := r.Context().Value(tenantIDContextKey).(string)

			// Build resource identifier from URL path variables
			resource := s.buildResourceIdentifier(r, resourceType)

			// Check API key permissions first (simple permission check)
			permissionID := s.buildPermissionID(resourceType, action)
			if !s.hasAPIKeyPermission(apiKey, permissionID) {
				decision := &AuthorizationDecision{
					Granted:      false,
					PermissionID: permissionID,
					Resource:     resource,
					Action:       action,
					Decision:     "DENY",
					Reason:       "API key lacks required permission: " + permissionID,
					CheckedAt:    time.Now(),
					SubjectID:    userID,
					TenantID:     tenantID,
				}

				s.auditAuthorizationDecision(r, decision)
				s.writeAuthorizationError(w, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS", decision)
				return
			}

			// API key has correct permissions - grant access and skip RBAC check
			decision := &AuthorizationDecision{
				Granted:      true,
				PermissionID: permissionID,
				Resource:     resource,
				Action:       action,
				Decision:     "ALLOW",
				Reason:       "API key has required permission: " + permissionID,
				CheckedAt:    time.Now(),
				SubjectID:    userID,
				TenantID:     tenantID,
			}

			// Add decision to context
			ctx := context.WithValue(r.Context(), authDecisionContextKey, decision)

			s.logger.Debug("Access granted via API key permission",
				"subject_id", userID,
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
	return time.Now().Format("20060102150405.999999999")
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

// auditAuthorizationDecision logs authorization decisions for security auditing
func (s *Server) auditAuthorizationDecision(r *http.Request, decision *AuthorizationDecision) {
	// Create comprehensive audit log entry
	auditFields := map[string]interface{}{
		"event_type":     "api_authorization",
		"timestamp":      decision.CheckedAt.UTC().Format(time.RFC3339Nano),
		"subject_id":     decision.SubjectID,
		"tenant_id":      decision.TenantID,
		"permission_id":  decision.PermissionID,
		"resource":       decision.Resource,
		"action":         decision.Action,
		"decision":       decision.Decision,
		"granted":        decision.Granted,
		"reason":         decision.Reason,
		"duration_ms":    decision.DurationMs,
		"request_path":   r.URL.Path,
		"request_method": r.Method,
		"remote_addr":    r.RemoteAddr,
		"user_agent":     r.Header.Get("User-Agent"),
		"request_id":     s.getRequestID(r),
		"severity":       s.getAuditSeverity(decision),
	}

	// Add conditional variables if present
	if decision.ConditionalVars != nil {
		auditFields["conditional_vars"] = decision.ConditionalVars
	}

	// Log at appropriate level based on decision outcome
	if decision.Granted {
		s.logger.Info("Authorization audit", auditFields)
	} else {
		// Failed authorization attempts need higher visibility
		s.logger.Warn("Authorization audit - access denied", auditFields)
	}

	// If RBAC manager supports audit trail, also log there
	if s.rbacManager != nil {
		s.auditToRBACManager(decision, r)
	}
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

// hasAPIKeyPermission checks if an API key has a specific permission
func (s *Server) hasAPIKeyPermission(apiKey *APIKey, permissionID string) bool {
	if apiKey == nil || apiKey.Permissions == nil {
		s.logger.Debug("API key permission check failed - nil key or permissions",
			"key_id", func() string {
				if apiKey != nil {
					return apiKey.ID
				}
				return "nil"
			}())
		return false
	}

	s.logger.Debug("Checking API key permission",
		"key_id", apiKey.ID,
		"required_permission", permissionID,
		"available_permissions", apiKey.Permissions)

	for _, permission := range apiKey.Permissions {
		if permission == permissionID {
			s.logger.Debug("API key permission granted",
				"key_id", apiKey.ID,
				"permission", permissionID)
			return true
		}
	}

	s.logger.Debug("API key permission denied",
		"key_id", apiKey.ID,
		"required_permission", permissionID,
		"available_permissions", apiKey.Permissions)
	return false
}

// auditToRBACManager sends audit information to RBAC manager if supported
func (s *Server) auditToRBACManager(decision *AuthorizationDecision, r *http.Request) {
	// This would integrate with the RBAC manager's audit trail
	// For now, we'll just log that we would send it
	s.logger.Debug("Would audit to RBAC manager",
		"subject_id", decision.SubjectID,
		"decision", decision.Decision,
		"resource", decision.Resource,
	)
}

// sanitizeLogValue removes control characters (newlines, carriage returns, tabs)
// from user-supplied values before logging to prevent log injection (CWE-117).
func sanitizeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return '_'
		}
		return r
	}, s)
}
