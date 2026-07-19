// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	tenantsecurity "github.com/cfgis/cfgms/features/tenant/security"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// Context keys
	apiKeyContextKey       contextKey = "api_key"
	authDecisionContextKey contextKey = "auth_decision"
	principalContextKey    contextKey = "principal"
	// targetTenantContextKey carries the explicitly requested target tenant for the
	// isolation check. Set by test helpers or upstream middleware; takes precedence
	// over URL-derived tenant. Empty means same-tenant (no cross-tenant check).
	targetTenantContextKey contextKey = "target_tenant"
	// cookieAuthContextKey is set to true when authentication succeeds via the
	// cfgms_session cookie (Issue #2493: CSRF middleware uses this to distinguish
	// cookie-authenticated requests from Bearer/API-key/mTLS requests).
	cookieAuthContextKey contextKey = "cookie_authenticated"
	// webSessionIDContextKey carries the session ID of a cookie-authenticated
	// web session. Set alongside cookieAuthContextKey (Issue #2493: CSRF token lookup).
	webSessionIDContextKey contextKey = "web_session_id"
)

// Principal represents an authenticated entity — either an mTLS admin cert, an API key,
// a cfg-CLI Bearer session (ADR-014), or a web session cookie (ADR-018).
//
// Assurance is the identity assurance level (ADR-021 Decision 1). It is the authoritative
// gating field: Assurance >= AssuranceBasic covers the three human-authenticated paths
// (mTLS admin cert, cfg-CLI Bearer session, web session cookie); AssuranceMachine covers
// API-key principals.
type Principal struct {
	ID           string
	Name         string
	Assurance    session.AssuranceLevel
	LastProvenAt time.Time // time of last strong-factor proof; set by mTLS path (others: follow-on story)
	Permissions  []string
	TenantID     string
	// Cert-auth fields — non-empty only for mTLS principals (Assurance == AssuranceStrong, H3)
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
		ID:        peerCert.Subject.CommonName,
		Name:      "mtls-admin:" + peerCert.Subject.CommonName,
		Assurance: session.AssuranceStrong,
		// Admin principals have NO tenant scope. Earlier this was
		// hardcoded to "default" which silently restricted every admin
		// read to tenant "default" — `cfg steward list` returned 0
		// records on any deployment with non-default tenants (caught
		// during the CFG-70-02 launcher install: the host's steward
		// registered with tenant_id=infra-hyperv via its regtoken; the
		// admin bundle's cert had Assurance=AssuranceBasic but TenantID="default"
		// so handleListStewards never saw it). Empty means
		// isEmptyFilter() returns true for the admin-no-query case →
		// GetAllStewards() returns every tenant's stewards.
		// Handlers that need a fallback tenant for admin WRITES (e.g.
		// handlers_configs.go) already substitute "default" when this
		// field is empty.
		TenantID:        "",
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
// Issue #1675: relay-injected principals bypass normal auth when relayPrincipalKey is set.
func (s *Server) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Issue #1675: relay principal — pre-validated by RelayHandler after grant check.
		// The relayPrincipalKey is set only in the relay handler after LookupGrant succeeds,
		// so this path can only be reached via an internal in-process call, never from the
		// network. The principalContextKey is also set by the relay handler before calling
		// ServeHTTP, so the context already carries both keys.
		if injected, ok := r.Context().Value(relayPrincipalKey).(*Principal); ok && injected != nil {
			// principalContextKey is already set by the relay handler; just proceed.
			_ = injected // already in context
			next.ServeHTTP(w, r)
			return
		}

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

			// Issue #2098: test-mode status update and audit count endpoints (no auth in test mode).
			if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/api/v1/test/stewards/") && strings.HasSuffix(r.URL.Path, "/status") {
				s.logger.Warn("Test endpoint accessed with authentication bypass",
					"path", logging.SanitizeLogValue(r.URL.Path), "method", r.Method, "remote_addr", logging.SanitizeLogValue(r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == "GET" && r.URL.Path == "/api/v1/test/audit/count" {
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
			ctx = context.WithValue(ctx, ctxkeys.UserIDKey, logging.SanitizeLogValue(adminPrincipal.ID))
			ctx = context.WithValue(ctx, ctxkeys.TenantID, adminPrincipal.TenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// State (c)/(d): no admin cert presented.

		// Session-token path (Issue #2232): intercept Bearer tokens that are 43 chars
		// (base64url without padding for 32 random bytes — length-distinguishable from
		// API keys, which use base64url with padding: 44 chars). Only attempted when a
		// sessionManager is wired; falls through to API-key path otherwise.
		//
		// Contract:
		//   - Token present, 43 chars, manager wired, valid   → admin Principal from session + X-Session-Token header
		//   - Token present, 43 chars, manager wired, invalid → 401 (no fallthrough to API-key)
		//   - Token present, non-43 chars OR manager nil       → fall through to API-key path
		if s.sessionManager != nil {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
				// sessionTokenLen is the exact length of a session token:
				// base64.RawURLEncoding of 32 bytes = 43 chars (no padding).
				const sessionTokenLen = 43
				if len(bearerToken) == sessionTokenLen {
					sess, err := s.sessionManager.Validate(r.Context(), bearerToken)
					if err != nil {
						switch {
						case errors.Is(err, session.ErrSessionRevoked):
							s.writeErrorResponse(w, http.StatusUnauthorized, "Session has been revoked", "SESSION_REVOKED")
						case errors.Is(err, session.ErrSessionExpired):
							s.writeErrorResponse(w, http.StatusUnauthorized, "Session has expired", "SESSION_EXPIRED")
						default:
							s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid session token", "INVALID_SESSION_TOKEN")
						}
						return
					}
					// Renew the session to reset idle TTL; set X-Session-Token when
					// a new token is issued (empty string = prior-token grace path,
					// no new token to publish). The raw new token is never logged.
					_, newToken, renewErr := s.sessionManager.Renew(r.Context(), bearerToken)
					if renewErr == nil && newToken != "" {
						w.Header().Set("X-Session-Token", newToken)
					}
					// Build a Principal from session state.
					sessionPrincipal := &Principal{
						ID:        sess.PrincipalID,
						Name:      "session:" + logging.SanitizeLogValue(sess.PrincipalID),
						Assurance: session.AssuranceBasic,
						// TenantID mirrors the issuing admin cert; "" means no tenant scope
						// (same semantics as extractAdminPrincipal for mTLS admin certs).
						TenantID: sess.TenantID,
					}
					ctx := context.WithValue(r.Context(), principalContextKey, sessionPrincipal)
					ctx = context.WithValue(ctx, ctxkeys.UserIDKey, logging.SanitizeLogValue(sess.PrincipalID))
					ctx = context.WithValue(ctx, ctxkeys.TenantID, sess.TenantID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		// Web session cookie path (Issue #2492, ADR-018 §1,2): authenticate browser clients
		// via the cfgms_session HttpOnly+Secure+SameSite=Strict cookie. Credential precedence
		// (security B5.2): any header credential (Bearer or API key) or admin mTLS ALWAYS wins
		// — when a header credential is present the cookie is ignored entirely (not validated,
		// not renewed, no Set-Cookie emitted). This branch only fires when no header credential
		// is present, ensuring existing Bearer/API-key/mTLS clients are byte-identical.
		if s.webSessionManager != nil && !hasHeaderCredentials(r) {
			if cookie, cookieErr := r.Cookie("cfgms_session"); cookieErr == nil {
				webSess, webErr := s.webSessionManager.Validate(r.Context(), cookie.Value)
				if webErr != nil {
					switch {
					case errors.Is(webErr, session.ErrSessionRevoked):
						s.writeErrorResponse(w, http.StatusUnauthorized, "Session has been revoked", "SESSION_REVOKED")
					case errors.Is(webErr, session.ErrSessionExpired):
						s.writeErrorResponse(w, http.StatusUnauthorized, "Session has expired", "SESSION_EXPIRED")
					default:
						s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid session token", "INVALID_SESSION_TOKEN")
					}
					return
				}
				// Rolling renewal: refresh the cookie so the idle TTL resets on every
				// authenticated response (ADR-018 §1). When the session is already in the
				// grace window (prior token), Renew returns newToken == "" — do not
				// overwrite a Set-Cookie the client already received.
				// renewErr is intentionally soft-ignored for ALL error variants (including
				// ErrSessionRevoked) — the same pattern as the Bearer path above (line ~298).
				// If revocation races Validate→Renew within nanoseconds, the request still
				// proceeds; the next request will be rejected by Validate. If stricter
				// atomicity is needed, merge Validate and Renew into a single operation.
				_, newToken, renewErr := s.webSessionManager.Renew(r.Context(), cookie.Value)
				if renewErr == nil && newToken != "" {
					http.SetCookie(w, &http.Cookie{
						Name:     "cfgms_session",
						Value:    newToken,
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteStrictMode,
						Path:     "/",
					})
				}
				// Build Principal mirroring the Bearer session path (the sessionPrincipal block above).
				webPrincipal := &Principal{
					ID:        webSess.PrincipalID,
					Name:      "web-session:" + logging.SanitizeLogValue(webSess.PrincipalID),
					Assurance: session.AssuranceBasic,
					TenantID:  webSess.TenantID,
				}
				ctx := context.WithValue(r.Context(), principalContextKey, webPrincipal)
				ctx = context.WithValue(ctx, ctxkeys.UserIDKey, logging.SanitizeLogValue(webSess.PrincipalID))
				ctx = context.WithValue(ctx, ctxkeys.TenantID, webSess.TenantID)
				// Issue #2493: mark this request as cookie-authenticated so csrfMiddleware
				// can enforce the session-bound CSRF check on unsafe methods.
				ctx = context.WithValue(ctx, cookieAuthContextKey, true)
				ctx = context.WithValue(ctx, webSessionIDContextKey, webSess.ID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// API-key path.

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
			Assurance:   session.AssuranceMachine,
			Permissions: keyInfo.Permissions,
			TenantID:    keyInfo.TenantID,
		}

		// Add key info and principal to request context
		ctx := context.WithValue(r.Context(), apiKeyContextKey, keyInfo)
		ctx = context.WithValue(ctx, principalContextKey, principal)
		ctx = context.WithValue(ctx, ctxkeys.UserIDKey, keyInfo.ID)
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
// Human-authenticated principals (Assurance >= AssuranceBasic) short-circuit to ALLOW for any permission.
func (s *Server) requirePermission(resourceType, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip permission check if RBAC service is not available.
			// Relay principals are always enforced inline — scope isolation is their
			// entire security guarantee and must hold even without the RBAC audit path.
			if s.rbacService == nil {
				if _, isRelay := r.Context().Value(relayPrincipalKey).(*Principal); isRelay {
					p, _ := r.Context().Value(principalContextKey).(*Principal)
					permID := s.buildPermissionID(resourceType, action)
					if !s.hasPermission(p, permID) {
						s.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS")
						return
					}
					next.ServeHTTP(w, r)
					return
				}
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

			userID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)
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

			// Assurance check (ADR-021 Decision 2): after confirming the principal
			// holds the permission, verify the assurance level meets the minimum for
			// this route. This replaces requireTier(TierMTLSOnly) entirely.
			if req, found := permissionAssurance[permissionID]; found && principal.Assurance < req.Min {
				decision := &AuthorizationDecision{
					Granted:      false,
					PermissionID: permissionID,
					Resource:     resource,
					Action:       action,
					Decision:     "DENY",
					Reason:       fmt.Sprintf("Insufficient assurance: %s < %s required for %s", principal.Assurance, req.Min, permissionID),
					CheckedAt:    time.Now(),
					SubjectID:    userID,
					TenantID:     tenantID,
				}
				s.auditAuthorizationDecision(r, decision)

				if principal.Assurance == session.AssuranceMachine {
					// API-key principals can never step up; send a plain 403.
					s.writeAuthorizationError(w, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS", decision)
					return
				}
				// All other callers (AssuranceBasic+) receive a step-up challenge (ADR-021 Decision 6).
				levelName := req.Min.String()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`CFGMS-StepUp realm="cfgms", required="%s"`, levelName))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(struct {
					Error             string `json:"error"`
					RequiredAssurance string `json:"required_assurance"`
				}{
					Error:             "step_up_required",
					RequiredAssurance: levelName,
				})
				return
			}

			// Tenant isolation check for API-key (machine-assurance) principals.
			s.mu.RLock()
			engine := s.isolationEngine
			s.mu.RUnlock()
			if engine != nil && principal.Assurance < session.AssuranceBasic && principal.TenantID != "" {
				targetTenant := s.extractTargetTenantFromRequest(r, resourceType)
				if targetTenant != "" && targetTenant != principal.TenantID {
					isoResp, isoErr := engine.ValidateTenantAccess(r.Context(), &tenantsecurity.TenantAccessRequest{
						SubjectID:       principal.ID,
						SubjectTenantID: principal.TenantID,
						TargetTenantID:  targetTenant,
						ResourceID:      resource,
						AccessLevel:     tenantsecurity.CrossTenantLevelRead,
					})
					if isoErr != nil || isoResp == nil || !isoResp.Granted {
						isoDecision := &AuthorizationDecision{
							Granted:      false,
							PermissionID: permissionID,
							Resource:     resource,
							Action:       action,
							Decision:     "DENY",
							Reason:       "Cross-tenant access denied by isolation engine",
							CheckedAt:    time.Now(),
							SubjectID:    userID,
							TenantID:     tenantID,
						}
						s.auditAuthorizationDecision(r, isoDecision)
						s.writeAuthorizationError(w, "Cross-tenant access denied", "CROSS_TENANT_ACCESS_DENIED", isoDecision)
						return
					}
				}
			}

			// Principal has required permission — grant access.
			reason := "API key has required permission: " + permissionID
			if principal.Assurance >= session.AssuranceBasic {
				reason = "principal assurance sufficient for full access"
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
				"assurance_sufficient", principal.Assurance >= session.AssuranceBasic,
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

	// H3: Include auth method and cert details in audit log. CertSerial is only
	// populated for mTLS principals (Assurance == AssuranceStrong), making it a
	// more precise discriminator than the general assurance level here.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal != nil && principal.CertSerial != "" {
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
// Human-authenticated principals (Assurance >= AssuranceBasic) short-circuit to true
// regardless of permissionID — they carry an empty Permissions list and rely on this
// bypass for every requirePermission check.
// C1: "*" is treated as a literal permission name — it will not match any real permissionID.
func (s *Server) hasPermission(principal *Principal, permissionID string) bool {
	if principal == nil {
		return false
	}
	if principal.Assurance >= session.AssuranceBasic {
		return true
	}
	for _, p := range principal.Permissions {
		if p == permissionID {
			return true
		}
	}
	return false
}

// csrfMiddleware enforces session-bound double-submit CSRF for unsafe HTTP methods on
// cookie-authenticated requests (ADR-018 §3, security A5.3). Must run after
// authenticationMiddleware so the cookie-auth context key is set.
//
//   - Safe methods (GET, HEAD) are always exempt.
//   - Requests authenticated via Bearer token, API key, or mTLS are exempt (no cookie).
//   - Cookie-authenticated requests for POST/PUT/PATCH/DELETE must supply X-CSRF-Token
//     matching the server-side per-session token (constant-time compare).
//
// This is the only middleware that enforces CSRF for the api subrouter. The
// login and logout endpoints on the base router enforce their own CSRF checks inline.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods are always exempt.
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer/API-key/mTLS requests are never CSRF-checked (security A5.2).
		if !isCookieAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Retrieve the session ID set by authenticationMiddleware on cookie-auth success.
		sessID, _ := r.Context().Value(webSessionIDContextKey).(string)
		csrfHeader := r.Header.Get(headerCSRFToken)
		stored, _ := s.csrfTokens.Load(sessID)
		storedStr, _ := stored.(string)
		if csrfHeader == "" || storedStr == "" || subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(storedStr)) != 1 {
			s.writeErrorResponse(w, http.StatusForbidden, "CSRF token mismatch", "CSRF_MISMATCH")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isCookieAuthenticated reports whether this request was authenticated via the
// cfgms_session HttpOnly cookie (set by authenticationMiddleware on cookie-auth success).
func isCookieAuthenticated(r *http.Request) bool {
	v, _ := r.Context().Value(cookieAuthContextKey).(bool)
	return v
}

// extractTargetTenantFromRequest returns the tenant being targeted by this request,
// used by the isolation engine to detect cross-tenant access. Resolution order:
//  1. targetTenantContextKey in context (set by tests or upstream middleware).
//  2. URL path variable "tenant_id".
//  3. URL path variable "id" when resourceType == "tenant".
//
// Returns "" when no explicit target tenant is present (caller treats as same-tenant).
func (s *Server) extractTargetTenantFromRequest(r *http.Request, resourceType string) string {
	if t, ok := r.Context().Value(targetTenantContextKey).(string); ok && t != "" {
		return t
	}
	vars := mux.Vars(r)
	if t := vars["tenant_id"]; t != "" {
		return t
	}
	if resourceType == "tenant" {
		if t := vars["id"]; t != "" {
			return t
		}
	}
	return ""
}
