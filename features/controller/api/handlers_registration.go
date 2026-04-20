// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// RegistrationRequest represents the steward registration request
type RegistrationRequest struct {
	Token string `json:"token"`
}

// RegistrationResponse represents the steward registration response
type RegistrationResponse struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	Group            string `json:"group"`
	ControllerURL    string `json:"controller_url"`
	TransportAddress string `json:"transport_address"`

	// Certificate information (optional for alpha, required for production mTLS)
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`

	// Controller's server certificate (public key) for configuration signature verification
	// Stewards use this to verify configs signed by this controller
	// In HA clusters, stewards collect and trust certs from all controllers they connect to
	ServerCert string `json:"server_cert,omitempty"`

	// Story #377: Dedicated config signing certificate (separated architecture)
	// When present, stewards should use this for config signature verification instead of ServerCert
	// In unified mode, this is empty and ServerCert is used for both
	SigningCert string `json:"signing_cert,omitempty"`

	// Issue #422: Quarantined indicates the steward has been quarantined by the approval workflow.
	// Quarantined stewards receive certificates but are restricted to baseline configuration
	// (no secrets, no scripts) until an administrator promotes them.
	Quarantined bool `json:"quarantined,omitempty"`
}

// handleRegister handles steward registration via REST API
// POST /api/v1/register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Only allow POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to parse registration request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate token format
	if req.Token == "" {
		http.Error(w, "Registration token is required", http.StatusBadRequest)
		return
	}

	// H-AUTH-4: Reduce token prefix to 6 chars to prevent brute force (security audit finding)
	s.logger.Info("Processing steward registration request", "token_prefix", req.Token[:min(len(req.Token), 6)])

	// Check if registration token store is available
	if s.registrationTokenStore == nil {
		s.logger.Error("Registration token store not available")
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Retrieve token metadata (tenant, group, controller URL) for building the response
	token, err := s.registrationTokenStore.GetToken(r.Context(), req.Token)
	if err != nil {
		s.logger.Warn("Invalid registration token", "error", err)
		http.Error(w, "Invalid or expired registration token", http.StatusUnauthorized)
		return
	}

	// Check if token is revoked
	if token.Revoked {
		s.logger.Warn("Attempted use of revoked token", "token", req.Token)
		http.Error(w, "Registration token has been revoked", http.StatusUnauthorized)
		return
	}

	// Check if token is expired
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		s.logger.Warn("Attempted use of expired token", "token", req.Token, "expired_at", token.ExpiresAt)
		http.Error(w, "Registration token has expired", http.StatusUnauthorized)
		return
	}

	// Generate steward ID before the atomic claim so it is recorded inside ConsumeToken
	stewardID := fmt.Sprintf("steward-%d", time.Now().UnixNano())

	// Atomically claim the token. For single-use tokens this is the TOCTOU gate:
	// if two goroutines both pass GetToken and the revoke/expire checks, only the
	// first ConsumeToken caller wins; the second gets ErrTokenAlreadyUsed.
	if err := s.registrationTokenStore.ConsumeToken(r.Context(), req.Token, stewardID); err != nil {
		if errors.Is(err, business.ErrTokenAlreadyUsed) {
			s.logger.Warn("Single-use token already consumed",
				"token_prefix", req.Token[:min(len(req.Token), 6)])
			http.Error(w, "Registration token has already been used", http.StatusConflict)
			return
		}
		s.logger.Error("Failed to consume registration token", "error", err)
		http.Error(w, "Registration service error", http.StatusInternalServerError)
		return
	}

	// Issue #422: Run registration approval hook after token consumption.
	// The token is consumed before the hook runs, preventing a second attempt while
	// the hook is evaluating. Hook errors are non-fatal: we log and fall back to approve
	// so transient failures do not block legitimate registrations.
	quarantined := false
	{
		input := RegistrationInput{
			Token:    token,
			SourceIP: extractSourceIP(r),
		}
		decision, reason, hookErr := s.approvalHook.Evaluate(r.Context(), input)
		if hookErr != nil {
			s.logger.Warn("Registration approval hook error, defaulting to approve",
				"error", hookErr,
				"tenant_id", token.TenantID)
		} else {
			switch decision {
			case DecisionReject:
				s.logger.Warn("Registration rejected by approval workflow",
					"tenant_id", token.TenantID,
					"reason", logging.SanitizeLogValue(reason))
				http.Error(w, "Registration rejected", http.StatusForbidden)
				return
			case DecisionQuarantine:
				quarantined = true
				s.logger.Info("Registration quarantined by approval workflow",
					"tenant_id", token.TenantID)
			}
		}
	}

	s.logger.Info("Steward registered successfully",
		"steward_id", stewardID,
		"tenant_id", token.TenantID,
		"group", token.Group)

	// Build response with connection details
	resp := RegistrationResponse{
		StewardID:        stewardID,
		TenantID:         token.TenantID,
		Group:            token.Group,
		ControllerURL:    token.ControllerURL,
		TransportAddress: s.getTransportAddress(),
	}

	// Story #294 Phase 3: Generate client certificates for mTLS (REQUIRED)
	// Certificate generation is mandatory - mTLS required for production security
	if s.certManager == nil {
		s.logger.Error("Certificate manager not initialized", "steward_id", stewardID)
		http.Error(w, "Server misconfiguration: Certificate manager unavailable", http.StatusInternalServerError)
		return
	}

	// Generate client certificate for steward
	validityDays := 365 // Default validity
	if s.cfg.Certificate != nil && s.cfg.Certificate.ClientCertValidityDays > 0 {
		validityDays = s.cfg.Certificate.ClientCertValidityDays
	}

	clientCert, err := s.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   stewardID,
		Organization: "CFGMS Stewards",
		ClientID:     stewardID,
		ValidityDays: validityDays,
	})
	if err != nil {
		s.logger.Error("Failed to generate client certificate", "error", err, "steward_id", stewardID)
		http.Error(w, "Failed to generate client certificate", http.StatusInternalServerError)
		return
	}

	// Get CA certificate (required for certificate chain validation)
	caCert, err := s.certManager.GetCACertificate()
	if err != nil || len(caCert) == 0 {
		s.logger.Error("Failed to get CA certificate", "error", err, "steward_id", stewardID)
		http.Error(w, "CA certificate unavailable", http.StatusInternalServerError)
		return
	}

	// Get server certificate (public key) for configuration signature verification
	// Stewards need this to verify configs signed by this controller
	// CRITICAL (Story #378): Must use THE EXACT SAME certificate that the signer uses
	// We use the signerCertSerial that was stored during signer creation to ensure they match
	var serverCert []byte
	if s.certManager != nil && s.signerCertSerial != "" {
		// Use THE SAME cert serial that the signer uses (from server startup)
		// This guarantees signature verification will work
		certPEM, _, err := s.certManager.ExportCertificate(s.signerCertSerial, false)
		if err == nil && len(certPEM) > 0 {
			serverCert = certPEM
			s.logger.Info("Providing signer certificate to steward for signature verification",
				"steward_id", stewardID,
				"cert_serial", s.signerCertSerial)
		} else {
			s.logger.Warn("Failed to export signer certificate from cert manager",
				"error", err, "steward_id", stewardID, "cert_serial", s.signerCertSerial)
		}
	} else if s.signerCertSerial == "" {
		s.logger.Warn("Signer certificate serial not available (signer may not be initialized)",
			"steward_id", stewardID)
	} else {
		s.logger.Warn("Certificate manager unavailable, cannot provide server cert for signature verification",
			"steward_id", stewardID)
	}

	// Return certificates in response (ALWAYS - required for mTLS)
	resp.ClientCert = string(clientCert.CertificatePEM)
	resp.ClientKey = string(clientCert.PrivateKeyPEM)
	resp.CACert = string(caCert)
	resp.ServerCert = string(serverCert) // For config signature verification (backward compat)

	// Story #377: In separated mode, also provide the dedicated signing certificate
	// Stewards should prefer SigningCert for config verification when present
	if s.cfg.Certificate != nil && s.cfg.Certificate.IsSeparatedArchitecture() && s.certManager != nil {
		signingCertPEM, err := s.certManager.GetSigningCertificate()
		if err == nil && len(signingCertPEM) > 0 {
			resp.SigningCert = string(signingCertPEM)
			// Also set ServerCert to signing cert for backward compatibility with older stewards
			resp.ServerCert = string(signingCertPEM)
			s.logger.Info("Providing dedicated signing certificate to steward",
				"steward_id", stewardID)
		} else {
			s.logger.Warn("Failed to get signing certificate for registration response",
				"error", err, "steward_id", stewardID)
		}
	}

	s.logger.Info("Generated client certificate for steward",
		"steward_id", stewardID,
		"validity_days", validityDays)

	// Issue #422: Set quarantine flag on the response so the steward knows its status.
	if quarantined {
		resp.Quarantined = true
	}

	// Store registered steward in memory for API queries
	initialStatus := "registered" // Initial status before first heartbeat
	if quarantined {
		initialStatus = "quarantined"
	}
	s.mu.Lock()
	s.registeredStewards[stewardID] = &RegisteredSteward{
		StewardID:        stewardID,
		TenantID:         token.TenantID,
		Group:            token.Group,
		RegisteredAt:     time.Now(),
		Status:           initialStatus,
		TransportAddress: resp.TransportAddress,
	}
	s.mu.Unlock()

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode registration response", "error", err)
	}
}

// getTransportAddress returns the unified transport address for steward connections.
// This is a host:port string (e.g., "controller:4433"); the transport provider handles protocol details.
func (s *Server) getTransportAddress() string {
	addr := "localhost:4433" // Default transport address
	if s.cfg.Transport != nil && s.cfg.Transport.ListenAddr != "" {
		addr = s.cfg.Transport.ListenAddr
	}

	// Replace 0.0.0.0 with external hostname if configured (Docker/test mode)
	return replaceBindAddress(addr)
}

// replaceBindAddress replaces 0.0.0.0 bind addresses with external hostname
// This is needed for Docker/test environments where the controller binds to 0.0.0.0
// but stewards need a real hostname to connect to
func replaceBindAddress(addr string) string {
	// Check if address starts with 0.0.0.0
	if !strings.HasPrefix(addr, "0.0.0.0:") {
		return addr
	}

	// Get external hostname from environment (Docker/test mode)
	externalHostname := os.Getenv("CFGMS_EXTERNAL_HOSTNAME")
	if externalHostname == "" {
		// Default to localhost if not specified
		externalHostname = "localhost"
	}

	// Replace 0.0.0.0 with external hostname
	port := strings.TrimPrefix(addr, "0.0.0.0:")
	return externalHostname + ":" + port
}

// extractSourceIP returns the source IP from the HTTP request.
// It prefers X-Forwarded-For (first entry) when present, falling back to RemoteAddr.
func extractSourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first address (client IP before any proxies)
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// RemoteAddr is "host:port"; strip the port
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
