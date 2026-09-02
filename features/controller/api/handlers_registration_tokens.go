// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TokenResponse represents a registration token in API responses.
// Token (full secret) is only populated by create and rotate responses.
// All other endpoints (list, get, revoke) set TokenPrefix only.
// TokenID is a stable UUID, always set, safe to expose — it is NOT the secret.
type TokenResponse struct {
	TokenID       string  `json:"token_id,omitempty"`     // stable UUID — always set (Issue #2970)
	Token         string  `json:"token,omitempty"`        // full secret — create/rotate only
	TokenPrefix   string  `json:"token_prefix,omitempty"` // first 6 chars — always set
	TenantID      string  `json:"tenant_id"`
	ControllerURL string  `json:"controller_url"`
	Group         string  `json:"group,omitempty"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	Revoked       bool    `json:"revoked"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
}

// TokenListResponse represents a list of tokens
type TokenListResponse struct {
	Tokens []TokenResponse `json:"tokens"`
	Total  int             `json:"total"`
}

// rotateTokenRequest is the optional request body for the rotate endpoint.
type rotateTokenRequest struct {
	Group string `json:"group,omitempty"`
}

// createTokenRequestWithSingleUseCheck detects the legacy single_use field.
type createTokenRequestWithSingleUseCheck struct {
	registration.TokenCreateRequest
	SingleUse *bool `json:"single_use,omitempty"`
}

// handleCreateRegistrationToken handles POST /api/v1/registration/tokens
func (s *Server) handleCreateRegistrationToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body; detect removed single_use field.
	var req createTokenRequestWithSingleUseCheck
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to parse token create request", "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SingleUse != nil {
		http.Error(w, "single_use is not supported by this token format; newly issued tokens are short-lived by default", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.TenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}
	if req.ControllerURL == "" {
		http.Error(w, "controller_url is required", http.StatusBadRequest)
		return
	}

	// Tenant subtree enforcement: scoped callers may only create tokens for tenants
	// within their own subtree. Unscoped (mTLS admin) callers have no restriction.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := req.TenantID == callerTenant || strings.HasPrefix(req.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "forbidden: target tenant is outside caller's tenant subtree", http.StatusForbidden)
			return
		}
	}

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Create token using registration package
	token, err := registration.CreateToken(&req.TokenCreateRequest)
	if err != nil {
		s.logger.Error("Failed to create registration token", "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Save token to store
	if err := s.registrationTokenStore.SaveToken(r.Context(), token); err != nil {
		s.logger.Error("Failed to save registration token", "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to save token", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Created registration token",
		"token_prefix", token.Token[:min(len(token.Token), 6)],
		"tenant_id", logging.SanitizeLogValue(token.TenantID))
	s.emitTokenManagementAudit(r, "registration_token.created",
		token.Token[:min(len(token.Token), 6)], token.ID, token.TenantID)

	// Return full token response — create is the one-time mint window where the secret is disclosed.
	resp := tokenToResponse(token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode token response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleListRegistrationTokens handles GET /api/v1/registration/tokens
func (s *Server) handleListRegistrationTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Tenant scoping: scoped callers always see only their own tenant (query param is ignored).
	// Unscoped (mTLS admin) callers may supply ?tenant_id= to narrow the result.
	callerTenant := s.callerTenantID(r)
	tenantID := callerTenant
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}

	// List tokens
	tokens, err := s.registrationTokenStore.ListTokens(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to list registration tokens", "error", err)
		http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
		return
	}

	// Convert to redacted response format — list callers never receive the full secret.
	resp := TokenListResponse{
		Tokens: make([]TokenResponse, 0, len(tokens)),
		Total:  len(tokens),
	}
	for _, token := range tokens {
		resp.Tokens = append(resp.Tokens, tokenToResponseRedacted(token))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode tokens response", "error", err)
	}
}

// handleGetRegistrationToken handles GET /api/v1/registration/tokens/{token}
func (s *Server) handleGetRegistrationToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Get token from path
	vars := mux.Vars(r)
	tokenStr := vars["token"]
	if tokenStr == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	// Get token from store
	token, err := s.registrationTokenStore.GetToken(r.Context(), tokenStr)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to get registration token", "error", err)
		http.Error(w, "Failed to get token", http.StatusInternalServerError)
		return
	}

	// Tenant subtree enforcement: scoped callers may not read tokens from other tenants.
	// 404 (not 403) avoids existence disclosure across tenant boundaries.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := token.TenantID == callerTenant || strings.HasPrefix(token.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
	}

	// Return redacted response — get callers never receive the full secret.
	resp := tokenToResponseRedacted(token)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode token response", "error", err)
	}
}

// handleDeleteRegistrationToken handles DELETE /api/v1/registration/tokens/{token}
func (s *Server) handleDeleteRegistrationToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Get token from path
	vars := mux.Vars(r)
	tokenStr := vars["token"]
	if tokenStr == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	// Look up the token first for tenant scope enforcement and audit.
	// Try exact match first (mTLS admin with full token), then UUID lookup (web UI).
	token, err := s.registrationTokenStore.GetToken(r.Context(), tokenStr)
	if err != nil && strings.Contains(err.Error(), "not found") {
		token, err = s.registrationTokenStore.GetTokenByID(r.Context(), tokenStr)
	}
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to get registration token for delete", "error", err)
		http.Error(w, "Failed to delete token", http.StatusInternalServerError)
		return
	}

	// Tenant subtree enforcement: scoped callers may not delete tokens from other tenants.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := token.TenantID == callerTenant || strings.HasPrefix(token.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
	}

	// Delete token from store. Always use token.Token (the full secret string) as the
	// store key, not tokenStr which may be a UUID from a web UI caller.
	if err := s.registrationTokenStore.DeleteToken(r.Context(), token.Token); err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to delete registration token", "error", err)
		http.Error(w, "Failed to delete token", http.StatusInternalServerError)
		return
	}

	// SanitizeLogValue wraps strings.ReplaceAll so CodeQL's ReplaceSanitizer clears the taint.
	// Use token.Token for the prefix — tokenStr may be a UUID from a web UI caller.
	tokenPrefix := logging.SanitizeLogValue(token.Token[:min(len(token.Token), 6)])
	s.logger.Info("Deleted registration token", "token_prefix", tokenPrefix)
	s.emitTokenManagementAudit(r, "registration_token.deleted", tokenPrefix, token.ID, token.TenantID)

	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeRegistrationToken handles POST /api/v1/registration/tokens/{token}/revoke
func (s *Server) handleRevokeRegistrationToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Get token from path
	vars := mux.Vars(r)
	tokenStr := vars["token"]
	if tokenStr == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	// Get token from store.
	// Try exact match first (mTLS admin with full token), then UUID lookup (web UI).
	token, err := s.registrationTokenStore.GetToken(r.Context(), tokenStr)
	if err != nil && strings.Contains(err.Error(), "not found") {
		token, err = s.registrationTokenStore.GetTokenByID(r.Context(), tokenStr)
	}
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to get registration token", "error", err)
		http.Error(w, "Failed to get token", http.StatusInternalServerError)
		return
	}

	// Tenant subtree enforcement: scoped callers may not revoke tokens from other tenants.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := token.TenantID == callerTenant || strings.HasPrefix(token.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
	}

	// Revoke the token
	token.Revoke()

	// Update token in store
	if err := s.registrationTokenStore.UpdateToken(r.Context(), token); err != nil {
		s.logger.Error("Failed to revoke registration token", "error", err)
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	// SanitizeLogValue wraps strings.ReplaceAll so CodeQL's ReplaceSanitizer clears the taint.
	// Use token.Token for the prefix — tokenStr may be a UUID from a web UI caller.
	tokenPrefix := logging.SanitizeLogValue(token.Token[:min(len(token.Token), 6)])
	s.logger.Info("Revoked registration token", "token_prefix", tokenPrefix)
	s.emitTokenManagementAudit(r, "registration_token.revoked", tokenPrefix, token.ID, token.TenantID)

	// Return redacted response — revoke callers do not receive the raw secret.
	resp := tokenToResponseRedacted(token)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode token response", "error", err)
	}
}

// handleRotateRegistrationToken handles POST /api/v1/registration/tokens/{tenant_id}/rotate
func (s *Server) handleRotateRegistrationToken(w http.ResponseWriter, r *http.Request) {
	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Get tenant_id from path
	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]
	if tenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	// Tenant subtree enforcement: scoped callers may only rotate tokens for tenants
	// within their own subtree.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := tenantID == callerTenant || strings.HasPrefix(tenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "forbidden: target tenant is outside caller's tenant subtree", http.StatusForbidden)
			return
		}
	}

	// Parse optional request body for group filter
	var req rotateTokenRequest
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Rotate token atomically
	newToken, err := s.registrationTokenStore.RotateToken(r.Context(), tenantID, req.Group)
	if err != nil {
		if strings.Contains(err.Error(), "no active tokens found") {
			http.Error(w, "No active tokens found for the specified tenant/group", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to rotate registration token",
			"error", logging.SanitizeLogValue(err.Error()),
			"tenant_id", logging.SanitizeLogValue(tenantID))
		http.Error(w, "Failed to rotate token", http.StatusInternalServerError)
		return
	}

	tokenPrefix := newToken.Token[:min(len(newToken.Token), 6)]
	s.logger.Info("Rotated registration token",
		"token_prefix", tokenPrefix,
		"tenant_id", logging.SanitizeLogValue(tenantID))
	s.emitTokenManagementAudit(r, "registration_token.rotated", tokenPrefix, newToken.ID, tenantID)

	// Return full token response — rotate is a mint window where the new secret is disclosed once.
	resp := tokenToResponse(newToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode rotate token response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// tokenToResponse converts a registration.Token to TokenResponse including the full secret.
// Use ONLY for create and rotate responses where the secret must be returned once.
func tokenToResponse(token *registration.Token) TokenResponse {
	resp := TokenResponse{
		TokenID:       token.ID,
		Token:         token.Token,
		TokenPrefix:   business.RegistrationTokenDisplayPrefix(token.Token),
		TenantID:      token.TenantID,
		ControllerURL: token.ControllerURL,
		Group:         token.Group,
		CreatedAt:     token.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Revoked:       token.Revoked,
	}

	if token.ExpiresAt != nil {
		exp := token.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
		resp.ExpiresAt = &exp
	}

	if token.RevokedAt != nil {
		revoked := token.RevokedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.RevokedAt = &revoked
	}

	return resp
}

// tokenToResponseRedacted converts a registration.Token to TokenResponse WITHOUT the full secret.
// Use for list, get, and revoke responses — callers must never see the raw token outside of
// the create/rotate mint window.
func tokenToResponseRedacted(token *registration.Token) TokenResponse {
	resp := tokenToResponse(token)
	resp.Token = "" // never expose the secret in list/get/revoke responses
	return resp
}

// emitTokenManagementAudit records an audit event for a token management action
// (create, rotate, revoke, delete). It is a no-op when auditManager is nil.
// tokenID is the stable UUID (registration.Token.ID) — never the secret — recorded
// as the resource name so the audit trail can be correlated to a token by ID.
func (s *Server) emitTokenManagementAudit(r *http.Request, action, tokenPrefix, tokenID, tenantID string) {
	if s.auditManager == nil {
		return
	}
	auditTenantID := tenantID
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	b := audit.NewEventBuilder().
		Tenant(auditTenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, business.AuditUserTypeHuman).
		Resource("registration_token", tokenPrefix, tokenID).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh)
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit token management audit event",
			"error", err, "action", action)
	}
}
