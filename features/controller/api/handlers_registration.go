// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
)

// RegistrationRequest represents the steward registration request
type RegistrationRequest struct {
	Token string `json:"token"`
}

// RegistrationResponse represents the steward registration response
type RegistrationResponse struct {
	StewardID     string `json:"steward_id"`
	TenantID      string `json:"tenant_id"`
	Group         string `json:"group"`
	ControllerURL string `json:"controller_url"`
	MQTTBroker    string `json:"mqtt_broker"`
	QUICAddress   string `json:"quic_address"`

	// Certificate information (optional for alpha, required for production mTLS)
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
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

	// Validate token
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

	// Check if single-use token was already used
	if token.SingleUse && token.UsedAt != nil {
		s.logger.Warn("Attempted reuse of single-use token", "token", req.Token, "used_at", token.UsedAt, "used_by", token.UsedBy)
		http.Error(w, "Registration token has already been used", http.StatusUnauthorized)
		return
	}

	// Generate steward ID
	stewardID := fmt.Sprintf("steward-%d", time.Now().UnixNano())

	// Mark token as used if it's single-use
	if token.SingleUse {
		token.UsedAt = timePtr(time.Now())
		token.UsedBy = stewardID
		if err := s.registrationTokenStore.SaveToken(r.Context(), token); err != nil {
			s.logger.Error("Failed to mark token as used", "error", err)
			// Continue anyway - registration should succeed
		}
	}

	s.logger.Info("Steward registered successfully",
		"steward_id", stewardID,
		"tenant_id", token.TenantID,
		"group", token.Group)

	// Build response with connection details
	resp := RegistrationResponse{
		StewardID:     stewardID,
		TenantID:      token.TenantID,
		Group:         token.Group,
		ControllerURL: token.ControllerURL,
		MQTTBroker:    s.getMQTTBrokerURL(), // Story #294 Phase 3: Return proper MQTT broker URL
		QUICAddress:   s.getQUICAddress(),
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

	// Return certificates in response (ALWAYS - required for mTLS)
	resp.ClientCert = string(clientCert.CertificatePEM)
	resp.ClientKey = string(clientCert.PrivateKeyPEM)
	resp.CACert = string(caCert)

	s.logger.Info("Generated client certificate for steward",
		"steward_id", stewardID,
		"validity_days", validityDays)

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode registration response", "error", err)
	}
}

// getQUICAddress returns the QUIC server address for steward connections
func (s *Server) getQUICAddress() string {
	if s.cfg.QUIC != nil && s.cfg.QUIC.Enabled {
		return s.cfg.QUIC.ListenAddr
	}
	return "localhost:4433" // Default QUIC address
}

// getMQTTBrokerURL returns the MQTT broker URL for steward connections
// Story #294 Phase 3: Return proper MQTT URL with ssl:// or tcp:// protocol
func (s *Server) getMQTTBrokerURL() string {
	if s.cfg.MQTT == nil || !s.cfg.MQTT.Enabled {
		return "tcp://localhost:1883" // Default MQTT address
	}

	// Determine protocol based on TLS configuration
	protocol := "tcp"
	if s.cfg.MQTT.EnableTLS {
		protocol = "ssl"
	}

	return fmt.Sprintf("%s://%s", protocol, s.cfg.MQTT.ListenAddr)
}

// Helper function to create a time pointer
func timePtr(t time.Time) *time.Time {
	return &t
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
