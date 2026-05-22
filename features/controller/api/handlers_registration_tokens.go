// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
)

// TokenResponse represents a registration token in API responses
type TokenResponse struct {
	Token         string  `json:"token"`
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

// createTokenRequestWithSingleUseCheck wraps TokenCreateRequest to detect the removed
// single_use field and return 400 if a caller still sends it.
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
		s.logger.Warn("Failed to parse token create request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SingleUse != nil {
		http.Error(w, "single_use is no longer supported; tokens are perennial by default", http.StatusBadRequest)
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

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Create token using registration package
	token, err := registration.CreateToken(&req.TokenCreateRequest)
	if err != nil {
		s.logger.Error("Failed to create registration token", "error", err)
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Save token to store
	if err := s.registrationTokenStore.SaveToken(r.Context(), token); err != nil {
		s.logger.Error("Failed to save registration token", "error", err)
		http.Error(w, "Failed to save token", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Created registration token",
		"token_prefix", token.Token[:min(len(token.Token), 6)],
		"tenant_id", logging.SanitizeLogValue(token.TenantID))

	// Return token response
	resp := tokenToResponse(token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode token response", "error", err)
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

	// Get tenant_id from query parameter (optional filter)
	tenantID := r.URL.Query().Get("tenant_id")

	// List tokens
	tokens, err := s.registrationTokenStore.ListTokens(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to list registration tokens", "error", err)
		http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
		return
	}

	// Convert to response format
	resp := TokenListResponse{
		Tokens: make([]TokenResponse, 0, len(tokens)),
		Total:  len(tokens),
	}
	for _, token := range tokens {
		resp.Tokens = append(resp.Tokens, tokenToResponse(token))
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

	// Return token response
	resp := tokenToResponse(token)
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

	// Delete token from store
	if err := s.registrationTokenStore.DeleteToken(r.Context(), tokenStr); err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to delete registration token", "error", err)
		http.Error(w, "Failed to delete token", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Deleted registration token", "token_prefix", tokenStr[:min(len(tokenStr), 6)])

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

	// Revoke the token
	token.Revoke()

	// Update token in store
	if err := s.registrationTokenStore.UpdateToken(r.Context(), token); err != nil {
		s.logger.Error("Failed to revoke registration token", "error", err)
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Revoked registration token", "token_prefix", tokenStr[:min(len(tokenStr), 6)])

	// Return updated token
	resp := tokenToResponse(token)
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

	s.logger.Info("Rotated registration token",
		"token_prefix", newToken.Token[:min(len(newToken.Token), 6)],
		"tenant_id", logging.SanitizeLogValue(tenantID))

	resp := tokenToResponse(newToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode rotate token response", "error", err)
	}
}

// tokenToResponse converts a registration.Token to TokenResponse
func tokenToResponse(token *registration.Token) TokenResponse {
	resp := TokenResponse{
		Token:         token.Token,
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
