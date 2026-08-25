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
	"net"
	"net/http"
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

	// presenceTokenHeader is the HTTP request header that carries a short-lived,
	// single-use presence token minted by POST /api/v1/webauthn/presence/finish.
	// RequireUserPresence-gated routes consume this token via requirePermission.
	// ADR-021 Decision 4: presence must be proven fresh per action, not per session.
	presenceTokenHeader = "X-Presence-Token"
)

// hashPresenceToken returns the hex-encoded SHA-256 digest of the raw token value.
// Presence tokens are stored by hash (not plaintext) so the sync.Map is safe to
// inspect under a debugger or profiler without revealing usable token material.
func hashPresenceToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Principal represents an authenticated entity — either an mTLS admin cert, an API key,
// a cfg-CLI Bearer session (ADR-014), or a web session cookie (ADR-018).
//
// Assurance is the identity assurance level (ADR-021 Decision 1). It governs auth-strength
// gating: Assurance >= AssuranceBasic covers the three human-authenticated paths (mTLS admin
// cert, cfg-CLI Bearer session, web session cookie); AssuranceMachine covers API-key principals.
//
// GlobalScope is a separate, orthogonal axis that controls tenant visibility (Issue #2787).
// It is true for principals that have cross-tenant (fleet-wide) read access and false for
// principals confined to their own tenant subtree. Today every human-authenticated principal
// has GlobalScope=true and every machine-authenticated principal has GlobalScope=false —
// these happen to correlate, but they model different questions. A future tenant-scoped web
// account type (Assurance=AssuranceBasic, GlobalScope=false) is confined by GlobalScope
// regardless of its assurance level; a strongly-authenticated but tenant-scoped service account
// (Assurance=AssuranceStrong, GlobalScope=false) would pass AssuranceStrong-gated routes but
// still be confined to its tenant. The two signals MUST NOT be collapsed back into one.
// See ADR-021 Context §"It is load-bearing on an unwritten assumption".
type Principal struct {
	ID           string
	Name         string
	Assurance    session.AssuranceLevel
	GlobalScope  bool      // true → cross-tenant visibility; false → confined to TenantID subtree
	LastProvenAt time.Time // time of last strong-factor proof; set by mTLS path (others: follow-on story)
	Permissions  []string
	TenantID     string
	// Cert-auth fields — non-empty only for mTLS principals (Assurance == AssuranceStrong, H3)
	CertSerial      string
	CertFingerprint string
	CertNotAfter    time.Time
	// AuthenticatorCount is the number of WebAuthn credentials registered for this principal's
	// web account. Set at Principal-build time for cookie-authenticated sessions only (Issue #2965).
	// Zero for mTLS/API-key principals. -1 indicates the account could not be loaded.
	// Confinement middleware and routing layers use this to distinguish "no passkeys" (0)
	// from "unknown" (-1) or "has passkeys" (>0) without a per-request store query.
	AuthenticatorCount int
	// RootScoped marks a principal as a root-scoped SaaS-operator (ADR-025 Amendment 1
	// A1.3), a distinct and narrower category than an unscoped superadmin. Both present
	// TenantID == "" — that field alone MUST NOT be read as root scope — but only a
	// RootScoped principal is subject to ADR-025 Decision 1's root<->MSP boundary
	// (isCallerAuthorizedForTenant in handlers_tenants.go). Set from an explicit signal
	// only: cert.HasRootScopeMarker for mTLS admin certs, Session.RootScoped for cfg-CLI
	// Bearer sessions. Always false for API-key, web-session, and relay principals.
	RootScoped bool
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
		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}

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

// securityHeadersMiddleware applies browser and intermediary hardening to every
// public response, including early authentication, rate-limit, and error paths.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			headers.Set("Cache-Control", "no-store")
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
		ID:          peerCert.Subject.CommonName,
		Name:        "mtls-admin:" + peerCert.Subject.CommonName,
		Assurance:   session.AssuranceStrong,
		GlobalScope: true,
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
		// RootScoped is read from an explicit certificate extension (ADR-025 Amendment 1
		// A1.3) — never inferred from TenantID being empty. Absent on every admin cert
		// issued before this marker existed, so existing deployments are unaffected.
		RootScoped: cert.HasRootScopeMarker(peerCert),
	}
}

// isWithinTenantScope reports whether resourceTenant is within callerTenant's
// authorized subtree. An empty callerTenant (mTLS admin with no tenant scope)
// has unrestricted access and always returns true.
func isWithinTenantScope(callerTenant, resourceTenant string) bool {
	if callerTenant == "" {
		return true
	}
	return resourceTenant == callerTenant ||
		strings.HasPrefix(resourceTenant, callerTenant+"/")
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
					// Pass source IP to Validate for IP-change detection (ADR-021 Decision 5).
					// SplitHostPort extracts just the host; errors are ignored (empty host → no detection).
					sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
					validateCtx := session.WithSourceIP(r.Context(), sourceIP)
					sess, err := s.sessionManager.Validate(validateCtx, bearerToken)
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
					_, newToken, renewErr := s.sessionManager.Renew(validateCtx, bearerToken)
					if renewErr == nil && newToken != "" {
						w.Header().Set("X-Session-Token", newToken)
					}
					// Build a Principal from session state. Assurance is read directly from
					// the session so that IP-change downgrades (ADR-021 Decision 5) and future
					// WebAuthn upgrades are reflected on every request rather than fixed at issuance.
					//
					// GlobalScope mirrors the session's actual scope (Issue #3194): unscoped sessions
					// (TenantID=="", matching an unscoped mTLS admin cert) receive cross-tenant
					// visibility; tenant-scoped sessions are confined to their subtree. Fail-closed:
					// explicit scope → GlobalScope=false, matching the web-session path's shape.
					globalScope := sess.TenantID == ""
					sessionPrincipal := &Principal{
						ID:           sess.PrincipalID,
						Name:         "session:" + logging.SanitizeLogValue(sess.PrincipalID),
						Assurance:    sess.Assurance,
						LastProvenAt: sess.LastProvenAt,
						GlobalScope:  globalScope,
						// TenantID mirrors the issuing admin cert; "" means no tenant scope
						// (same semantics as extractAdminPrincipal for mTLS admin certs).
						TenantID: sess.TenantID,
						// RootScoped mirrors the session's own explicit marker (ADR-025
						// Amendment 1 A1.3, set only by session.Manager.IssueRootScoped) —
						// never derived from TenantID or GlobalScope.
						RootScoped: sess.RootScoped,
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
				// Pass source IP to Validate for IP-change detection (ADR-021 Decision 5).
				webSourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				webValidateCtx := session.WithSourceIP(r.Context(), webSourceIP)
				webSess, webErr := s.webSessionManager.Validate(webValidateCtx, cookie.Value)
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
				_, newToken, renewErr := s.webSessionManager.Renew(webValidateCtx, cookie.Value)
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
				// Assurance and LastProvenAt are read from session state so that IP-change downgrades
				// and WebAuthn upgrades (Issue #2965) are reflected on every request (ADR-021 Decision 3/5).
				authCount := -1
				globalScope := false
				// Non-nil is the fail-closed default: an account that cannot be resolved
				// gets an empty grant set, never an unbounded one. nil is the
				// implicit-admin marker consumed by hasPermission, and is assigned
				// below only for an account that resolved AND carries an explicit
				// root-scope grant.
				permissions := []string{}
				if acct, err := s.getWebAccountByID(r.Context(), webSess.PrincipalID); err == nil && acct != nil {
					// Issue #3126: an administratively disabled account loses access
					// immediately, not at session expiry. The login gate in
					// handlePasskeyLoginFinish only blocks new sessions; without this
					// check a session issued before the disable keeps full API access
					// for up to the absolute session timeout (12h) — including the
					// implicit-admin grant below for a root-scope account, and the
					// ability to step up assurance. Revoke the session server-side
					// (best effort) so the rejection is durable, and answer with the
					// same 401 a revoked session gets: the response must not
					// distinguish "disabled" from "revoked".
					if acct.Disabled {
						s.csrfTokens.Delete(webSess.ID)
						if revokeErr := s.webSessionManager.Revoke(r.Context(), webSess.ID); revokeErr != nil {
							s.logger.Warn("Failed to revoke session of disabled web account",
								"session_id", logging.SanitizeLogValue(webSess.ID),
								"error", logging.SanitizeLogValue(revokeErr.Error()))
						}
						s.writeErrorResponse(w, http.StatusUnauthorized, "Session has been revoked", "SESSION_REVOKED")
						return
					}
					authCount = len(acct.Credentials)
					globalScope = acct.RootScope
					if acct.RootScope {
						// Root-scope web accounts are platform administrators: they hold
						// every permission, exactly as the mTLS-admin and CLI-session
						// principals do. This is not an authorization hole — permission
						// breadth and proof strength are separate layers, and this one
						// only decides breadth. requirePermission still applies
						// permissionAssurance immediately afterwards, so the 32
						// AssuranceStrong permissions still force a WebAuthn step-up from
						// this AssuranceBasic session, and the 6 RequireUserPresence ones
						// still demand a fresh single-use presence token. Enumerating all
						// 87 IDs per account instead would add no assurance gate that is
						// not already applied, and would silently strip an administrator
						// of any permission introduced after their account was created.
						permissions = nil
					} else {
						// Tenant-scoped web accounts are least-privilege operators: their
						// configured RBAC grants are enforced verbatim (Issue #2919).
						permissions = append(permissions, acct.Permissions...)
					}
				}
				webPrincipal := &Principal{
					ID:                 webSess.PrincipalID,
					Name:               "web-session:" + logging.SanitizeLogValue(webSess.PrincipalID),
					Assurance:          webSess.Assurance,
					LastProvenAt:       webSess.LastProvenAt,
					GlobalScope:        globalScope,
					Permissions:        permissions,
					TenantID:           webSess.TenantID,
					AuthenticatorCount: authCount,
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
				s.logger.Debug("Failed to load API key from store", "error", logging.SanitizeLogValue(err.Error()))
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
			GlobalScope: false,
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
		// SecretStore lookup path (tenant + key hash), not the credential itself.
		// Named "…Ref" so CodeQL's name-based sensitive-data heuristic does not
		// classify it as a cleartext credential source.
		credentialRef := fmt.Sprintf("%s/%s", tenantID, keyHash)
		secret, err := s.secretStore.GetSecret(ctx, credentialRef)
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

// tenantCrossingRemedyPermissions lists the ADR-025 Decision 2 endpoints whose handlers
// own the root-scoped decision themselves, so requirePermission's boundary check must not
// pre-empt them:
//
//   - tenant:crossing-break-glass is the remedy for lacking a crossing. Gating it on
//     already holding one would make the boundary unopenable — a root-scoped operator
//     could never obtain a first crossing, and ADR-025 Decision 2(b) would be dead code.
//   - tenant:crossing-grant refuses every root-scoped caller outright
//     (handlers_tenant_crossing.go, ROOT_SCOPED_CANNOT_GRANT) because a grant is the MSP's
//     consent, never the operator's self-dealing. That refusal is strictly stricter than a
//     crossing check, and a challenge here would advertise a remedy that does not unlock
//     the endpoint.
//
// tenant:crossing-list is deliberately absent: reading an MSP's crossing history is
// ordinary tenant-scoped data and its handler already applies authorizeTenantAccess.
var tenantCrossingRemedyPermissions = map[string]bool{
	"tenant:crossing-break-glass": true,
	"tenant:crossing-grant":       true,
}

// enrollmentConfinementMiddleware blocks cookie-authenticated web sessions whose
// principal has zero enrolled passkeys (AuthenticatorCount == 0) from all api routes.
//
// A zero-passkey session can ONLY redeem a first-passkey enrollment link; that redemption
// path is on the BASE router (/api/v1/web/passkey/enroll/begin|finish), not the api
// subrouter, so this middleware does not apply to it — by construction.
//
// mTLS admin and API-key principals are not cookie-authenticated (cookieAuthContextKey
// is false), so they pass through regardless of AuthenticatorCount. AuthenticatorCount==-1
// (account-load failure) is also blocked: fail-closed is safer than fail-open when the
// session's enrollable state cannot be determined.
//
// This middleware MUST run BEFORE requirePermission (added earlier in the chain) so
// that confinement is enforced even when the principal holds the required permission.
func (s *Server) enrollmentConfinementMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieAuth, _ := r.Context().Value(cookieAuthContextKey).(bool)
		if cookieAuth {
			principal, _ := r.Context().Value(principalContextKey).(*Principal)
			if principal != nil && principal.AuthenticatorCount <= 0 {
				// Zero or unknown authenticator count on a cookie-auth session.
				s.writeErrorResponse(w, http.StatusForbidden,
					"Account has no passkey enrolled — redeem your enrollment link first",
					"ENROLLMENT_REQUIRED")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requirePermission creates middleware that enforces specific permission requirements.
// Human administrator principals carry nil Permissions and are implicitly
// authorized; web accounts carry an explicit (possibly empty) permission slice.
func (s *Server) requirePermission(resourceType, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail closed when the authorization service was not wired. Relay
			// principals are the sole exception: their grant-derived permission
			// set is independently verified inline.
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
				s.logger.Error("RBAC service not available; denying request")
				s.writeErrorResponse(w, http.StatusServiceUnavailable,
					"Authorization service unavailable", "AUTHORIZATION_UNAVAILABLE")
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
			// resolveAssuranceRequirement composes the global floor with any per-tenant
			// overrides declared by ancestors of tenantID (root→leaf), taking the max
			// of all Min values and OR-ing RequireUserPresence (ADR-021, Issue #2839).
			assuranceReq, assuranceFound := s.resolveAssuranceRequirement(r.Context(), tenantID, permissionID)
			if assuranceFound && principal.Assurance < assuranceReq.Min {
				decision := &AuthorizationDecision{
					Granted:      false,
					PermissionID: permissionID,
					Resource:     resource,
					Action:       action,
					Decision:     "DENY",
					Reason:       fmt.Sprintf("Insufficient assurance: %s < %s required for %s", principal.Assurance, assuranceReq.Min, permissionID),
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
				levelName := assuranceReq.Min.String()
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

			// User-presence check (ADR-021 Decision 4): a fresh per-action WebAuthn assertion
			// is required for catastrophic permissions (RequireUserPresence: true in permissionAssurance).
			// This runs only after the assurance check above has confirmed the principal holds at least
			// req.Min assurance, so AssuranceMachine principals are already rejected above (they never
			// reach this branch). The presence token was minted by POST /api/v1/webauthn/presence/finish
			// and is passed in X-Presence-Token. It is single-use (LoadAndDelete) and short-lived
			// (presenceTokenTTL). Continuity / LastProvenAt alone is insufficient — a hijacked-but-
			// continuous session cannot fake a present human (ADR-021 Decision 4 threat model).
			if assuranceFound && assuranceReq.RequireUserPresence {
				levelName := assuranceReq.Min.String()

				presenceToken := r.Header.Get(presenceTokenHeader)
				if presenceToken == "" {
					// No presence token: step-up challenge including presence="required" (ADR-021 Decision 6).
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`CFGMS-StepUp realm="cfgms", required="%s", presence="required"`, levelName))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(struct {
						Error             string `json:"error"`
						RequiredAssurance string `json:"required_assurance"`
						PresenceRequired  bool   `json:"presence_required"`
					}{
						Error:             "step_up_required",
						RequiredAssurance: levelName,
						PresenceRequired:  true,
					})
					return
				}

				// Validate and atomically consume the token (single-use via LoadAndDelete).
				tokenHash := hashPresenceToken(presenceToken)
				raw, tokenFound := s.presenceTokens.LoadAndDelete(tokenHash)
				if !tokenFound {
					// Token not found (already used, never issued, or tampered).
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`CFGMS-StepUp realm="cfgms", required="%s", presence="required"`, levelName))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(struct {
						Error            string `json:"error"`
						PresenceRequired bool   `json:"presence_required"`
					}{
						Error:            "presence_token_invalid",
						PresenceRequired: true,
					})
					return
				}
				record, _ := raw.(*presenceTokenRecord)
				if record == nil || time.Now().After(record.expires) {
					// Expired token (already removed from map above).
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`CFGMS-StepUp realm="cfgms", required="%s", presence="required"`, levelName))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(struct {
						Error            string `json:"error"`
						PresenceRequired bool   `json:"presence_required"`
					}{
						Error:            "presence_token_expired",
						PresenceRequired: true,
					})
					return
				}
				// Bind the presence proof to the acting principal (ADR-021 Decision 4):
				// the token is only valid for the principal that ran the WebAuthn ceremony.
				// A proof performed by principal A must never satisfy the gate for principal
				// B's catastrophic action. The token was already consumed by LoadAndDelete,
				// so a mismatch cannot be retried with the same token.
				if record.principalID != principal.ID {
					s.logger.Warn("Presence token principal mismatch",
						"token_principal_id", logging.SanitizeLogValue(record.principalID),
						"request_principal_id", logging.SanitizeLogValue(principal.ID),
						"permission_id", permissionID,
					)
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`CFGMS-StepUp realm="cfgms", required="%s", presence="required"`, levelName))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(struct {
						Error            string `json:"error"`
						PresenceRequired bool   `json:"presence_required"`
					}{
						Error:            "presence_token_principal_mismatch",
						PresenceRequired: true,
					})
					return
				}
				s.logger.Debug("Presence token accepted",
					"principal_id", logging.SanitizeLogValue(principal.ID),
					"permission_id", permissionID,
				)
			}

			// ADR-025 Decision 1 root<->MSP boundary for root-scoped principals.
			//
			// This must sit outside the tenant-scoped block below: a RootScoped principal
			// presents GlobalScope == true and TenantID == "" (extractAdminPrincipal and
			// the Bearer/session path both keep the unscoped shape), so that block is
			// structurally unreachable for it. Enforcing the boundary only inside the
			// handlers that happen to call authorizeTenantAccess left every other
			// tenant-targeting route open — tenant:manage's suspend and config-source/test,
			// and the per-tenant refresh-policy and assurance-policy endpoints — letting a
			// root-scoped SaaS-operator suspend an MSP tenant or drive a config-source test
			// against that tenant's git credential with no active grant and no break-glass
			// record. Checking here covers every current and future tenant-targeting route
			// by construction rather than by handler-by-handler discipline.
			if principal.RootScoped && !tenantCrossingRemedyPermissions[permissionID] {
				if targetTenant := s.extractBoundaryTenantFromRequest(r, resourceType); targetTenant != "" {
					switch s.authorizeTenantAccess(r.Context(), principal, targetTenant) {
					case tenantAuthAllowed:
						// Root itself, or a tenant covered by an active crossing.
					case tenantAuthNeedsCrossing:
						s.auditAuthorizationDecision(r, &AuthorizationDecision{
							Granted:      false,
							PermissionID: permissionID,
							Resource:     resource,
							Action:       action,
							Decision:     "DENY",
							Reason:       "Root-scoped principal has no active tenant crossing for target tenant",
							CheckedAt:    time.Now(),
							SubjectID:    userID,
							TenantID:     tenantID,
						})
						// The tenant is real and inside root's own subtree, so a challenge
						// discloses nothing this caller cannot already learn, and it is the
						// only way a legitimate break-glass invocation learns its remedy
						// (ADR-025 Decision 3).
						s.writeTenantCrossingChallenge(w, targetTenant)
						return
					default:
						isoDecision := &AuthorizationDecision{
							Granted:      false,
							PermissionID: permissionID,
							Resource:     resource,
							Action:       action,
							Decision:     "DENY",
							Reason:       "Target tenant is outside the root-scoped principal's boundary",
							CheckedAt:    time.Now(),
							SubjectID:    userID,
							TenantID:     tenantID,
						}
						s.auditAuthorizationDecision(r, isoDecision)
						// Same existence-oracle stance as handleGetTenant/handleUpdateTenant:
						// a tenant outside root's subtree must not be distinguishable from one
						// that does not exist.
						if resourceType == "tenant" {
							s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
							return
						}
						s.writeAuthorizationError(w, "Cross-tenant access denied", "CROSS_TENANT_ACCESS_DENIED", isoDecision)
						return
					}
				}
			}

			// Tenant isolation check for tenant-scoped (non-global) principals.
			s.mu.RLock()
			engine := s.isolationEngine
			s.mu.RUnlock()
			if !principal.GlobalScope && principal.TenantID != "" {
				targetTenant := s.extractTargetTenantFromRequest(r, resourceType)
				// Real tenant IDs are flat, ParentID-linked tokens, never hierarchical
				// paths — string-prefix matching against them is dead code (the same
				// defect isCallerAuthorizedForTenant's doc comment describes for
				// isWithinTenantScope). Every other resource type still uses the
				// path-shaped prefix check, which is unaffected here.
				var inTargetScope bool
				if targetTenant == "" || targetTenant == principal.TenantID {
					inTargetScope = true
				} else if resourceType == "tenant" {
					inTargetScope = s.isCallerAuthorizedForTenant(r.Context(), principal, targetTenant)
				} else {
					inTargetScope = strings.HasPrefix(targetTenant, principal.TenantID+"/")
				}
				if !inTargetScope {
					isoDecision := &AuthorizationDecision{
						Granted:      false,
						PermissionID: permissionID,
						Resource:     resource,
						Action:       action,
						Decision:     "DENY",
						Reason:       "Target tenant is outside principal tenant subtree",
						CheckedAt:    time.Now(),
						SubjectID:    userID,
						TenantID:     tenantID,
					}
					s.auditAuthorizationDecision(r, isoDecision)
					// tenant:read, tenant:update and tenant:manage (suspend, config-source/test)
					// all resolve a single tenant by ID and must return an identical 404 for
					// "doesn't exist" and "exists but out of my subtree" (ADR-025 existence-oracle
					// prevention, Issue #3125; extended to tenant:manage by Issue #3181) — a 403
					// here would let a caller distinguish the two cases via status code alone,
					// before ever reaching the handler's own isCallerAuthorizedForTenant check.
					if resourceType == "tenant" && (action == "read" || action == "update" || action == "manage") {
						s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
						return
					}
					s.writeAuthorizationError(w, "Cross-tenant access denied", "CROSS_TENANT_ACCESS_DENIED", isoDecision)
					return
				}
				if engine != nil && targetTenant != "" && targetTenant != principal.TenantID {
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
//
// A nil Permissions slice is the explicit implicit-admin marker, carried by the three
// platform-administrator principals: mTLS admin certs, CLI Bearer sessions, and
// root-scope web accounts. Every other principal carries a non-nil slice — including
// an empty one — and is held to it verbatim: tenant-scoped web accounts, API keys,
// relay principals, and any web account that failed to resolve.
//
// This decides permission BREADTH only, never proof strength. requirePermission
// consults permissionAssurance immediately after this returns, so an implicit admin
// is still forced through a WebAuthn step-up for AssuranceStrong permissions and a
// fresh single-use presence token for RequireUserPresence ones. Widening breadth here
// cannot widen the assurance gate.
//
// nil and empty slices are near-indistinguishable in Go — len, range and append treat
// them alike, and append(nil) with zero elements yields nil — so the middleware
// assigns nil deliberately and never by omission. See
// TestWebSessionCookie_PrincipalNeverCarriesImplicitAdminMarker.
//
// C1: "*" is treated as a literal permission name — it will not match any real permissionID.
func (s *Server) hasPermission(principal *Principal, permissionID string) bool {
	if principal == nil {
		return false
	}
	if principal.Assurance >= session.AssuranceBasic && principal.Permissions == nil {
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

// extractBoundaryTenantFromRequest returns the tenant a request acts on for the ADR-025
// Decision 1 boundary check, extending extractTargetTenantFromRequest with the
// "tenant_path" path variable. The per-tenant refresh-policy and assurance-policy routes
// (routes_tenants.go) name their target tenant under that variable, so they resolve to ""
// through the isolation-engine extractor and were invisible to any middleware scope check.
//
// It is a separate function rather than a widening of extractTargetTenantFromRequest
// because the tenant-scoped block that consumes the latter answers a cross-tenant denial
// with 403 CROSS_TENANT_ACCESS_DENIED, whereas those two handlers already enforce the same
// boundary for tenant-scoped callers and answer with 404 to avoid disclosing that the
// tenant exists. Routing them through the 403 path would trade one isolation gap for an
// existence oracle.
func (s *Server) extractBoundaryTenantFromRequest(r *http.Request, resourceType string) string {
	if t := s.extractTargetTenantFromRequest(r, resourceType); t != "" {
		return t
	}
	return mux.Vars(r)["tenant_path"]
}

// resolveAssuranceRequirement composes the global permissionAssurance floor with any
// per-tenant overrides declared along the root→leaf path to tenantID (ADR-021, Issue #2839).
//
// Resolution rules:
//   - Min takes the maximum seen across [global floor, ancestor overrides, tenant override].
//   - RequireUserPresence is true if true anywhere in the chain (OR, never cleared).
//
// When assurancePolicyStore or tenantStore is nil, or tenantID is empty, the method
// returns the global floor unchanged — preserving today's exact behavior in unit tests
// that build a bare Server without these stores.
//
// GetTenantPath or GetPolicy errors are logged at Warn and cause a fall-back to the
// global floor: an override-resolution error must never turn a storage hiccup into a
// fleet-wide outage on every gated endpoint. Falling back to the global floor is safe
// because the floor is always the tightest guaranteed lower bound.
func (s *Server) resolveAssuranceRequirement(ctx context.Context, tenantID, permissionID string) (Requirement, bool) {
	floor, found := permissionAssurance[permissionID]
	if s.assurancePolicyStore == nil || s.tenantStore == nil || tenantID == "" {
		return floor, found
	}

	path, err := s.tenantStore.GetTenantPath(ctx, tenantID)
	if err != nil {
		s.logger.Warn("resolveAssuranceRequirement: failed to get tenant path; using global floor",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"permission_id", logging.SanitizeLogValue(permissionID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		return floor, found
	}

	result := floor
	for _, t := range path {
		policy, err := s.assurancePolicyStore.GetPolicy(ctx, t)
		if err != nil {
			s.logger.Warn("resolveAssuranceRequirement: failed to get assurance policy; using global floor",
				"tenant_id", logging.SanitizeLogValue(t),
				"permission_id", logging.SanitizeLogValue(permissionID),
				"error", logging.SanitizeLogValue(err.Error()),
			)
			return floor, found
		}
		for _, ov := range policy.Overrides {
			// overrideAppliesTo matches the exact ID and any pre-rename ID for the same
			// operation, so a stored override survives a permission-ID rename instead of
			// silently dropping the admin's raised bar (Issue #3574).
			if !overrideAppliesTo(ov.PermissionID, permissionID) {
				continue
			}
			found = true
			if ov.MinOverride != nil {
				if ovMin := session.AssuranceLevel(*ov.MinOverride); ovMin > result.Min {
					result.Min = ovMin
				}
			}
			if ov.RequireUserPresence {
				result.RequireUserPresence = true
			}
		}
	}
	return result, found
}
