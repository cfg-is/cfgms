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

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// RegistrationRequest represents the steward registration request
type RegistrationRequest struct {
	Token string `json:"token"`
}

// RegistrationResponse represents the steward registration response for an approved registration.
type RegistrationResponse struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	Group            string `json:"group"`
	ControllerURL    string `json:"controller_url"`
	TransportAddress string `json:"transport_address"`

	// Certificate information (required for production mTLS)
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
}

// RegistrationPendingResponse is returned with HTTP 202 when a registration is quarantined
// pending operator approval. It contains no certificate fields — cert issuance is gated on
// the approval decision (Issue #1693).
type RegistrationPendingResponse struct {
	PendingID string `json:"pending_id"`
	StewardID string `json:"steward_id"`
	TenantID  string `json:"tenant_id"`
	Group     string `json:"group"`
	Status    string `json:"status"`
}

// PendingRegistration represents a quarantined steward awaiting admin approval.
type PendingRegistration struct {
	PendingID    string    `json:"pending_id"`
	StewardID    string    `json:"steward_id"`
	TenantID     string    `json:"tenant_id"`
	SourceIP     string    `json:"source_ip"`
	RegisteredAt time.Time `json:"registered_at"`
}

// denyRegistrationRequest is the optional request body for the deny endpoint.
type denyRegistrationRequest struct {
	Reason string `json:"reason,omitempty"`
}

// handleListPendingRegistrations handles GET /api/v1/registration/pending.
// Returns all quarantined stewards awaiting operator approval.
func (s *Server) handleListPendingRegistrations(w http.ResponseWriter, r *http.Request) {
	var pending []PendingRegistration
	s.registrationQueue.Range(func(_, value interface{}) bool {
		if pr, ok := value.(PendingRegistration); ok {
			pending = append(pending, pr)
		}
		return true
	})
	if pending == nil {
		pending = []PendingRegistration{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(pending); err != nil {
		s.logger.Error("Failed to encode pending registrations", "error", err)
	}
}

// handleApproveRegistration handles POST /api/v1/registration/{id}/approve.
// Promotes a quarantined steward to registered status.
func (s *Server) handleApproveRegistration(w http.ResponseWriter, r *http.Request) {
	stewardID := mux.Vars(r)["id"]
	if _, ok := s.registrationQueue.Load(stewardID); !ok {
		http.Error(w, "steward not found in pending queue", http.StatusNotFound)
		return
	}
	if err := s.controllerService.UpdateStewardStatus(stewardID, "registered"); err != nil {
		s.logger.Error("Failed to update steward status", "steward_id", stewardID, "error", err)
		http.Error(w, "Failed to update steward status", http.StatusInternalServerError)
		return
	}
	s.registrationQueue.Delete(stewardID)
	s.logger.Info("Steward registration approved", "steward_id", stewardID)
	w.WriteHeader(http.StatusOK)
}

// handleDenyRegistration handles POST /api/v1/registration/{id}/deny.
// Removes a quarantined steward from the pending queue without promoting it.
func (s *Server) handleDenyRegistration(w http.ResponseWriter, r *http.Request) {
	stewardID := mux.Vars(r)["id"]
	if _, ok := s.registrationQueue.Load(stewardID); !ok {
		http.Error(w, "steward not found in pending queue", http.StatusNotFound)
		return
	}
	var req denyRegistrationRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.registrationQueue.Delete(stewardID)
	s.logger.Info("Steward registration denied",
		"steward_id", stewardID,
		"reason", logging.SanitizeLogValue(req.Reason))
	w.WriteHeader(http.StatusOK)
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

	s.logger.Info("Processing steward registration request", "token_prefix", logging.RedactedID(req.Token))

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
		// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
		s.emitRegistrationAudit(r.Context(), req.Token, "unknown", "unknown",
			business.AuditEventSecurityEvent, "registration_rejected",
			business.AuditResultFailure, business.AuditSeverityCritical, nil)
		http.Error(w, "Invalid or expired registration token", http.StatusUnauthorized)
		return
	}

	// Check if token is revoked
	if token.Revoked {
		s.logger.Warn("Attempted use of revoked token", "token_prefix", logging.RedactedID(req.Token))
		// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
		s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, "unknown",
			business.AuditEventSecurityEvent, "registration_rejected",
			business.AuditResultFailure, business.AuditSeverityCritical, nil)
		http.Error(w, "Registration token has been revoked", http.StatusUnauthorized)
		return
	}

	// Check if token is expired
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		s.logger.Warn("Attempted use of expired token", "token_prefix", logging.RedactedID(req.Token), "expired_at", token.ExpiresAt)
		// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
		s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, "unknown",
			business.AuditEventSecurityEvent, "registration_rejected",
			business.AuditResultFailure, business.AuditSeverityCritical, nil)
		http.Error(w, "Registration token has expired", http.StatusUnauthorized)
		return
	}

	stewardID := fmt.Sprintf("steward-%d", time.Now().UnixNano())

	// Perennial tokens survive registration; log the use for auditability.
	s.logger.Info("Token used for registration",
		"token_prefix", logging.RedactedID(req.Token),
		"tenant_id", token.TenantID,
		"steward_id", stewardID)

	// Issue #422: Run registration approval hook.
	// Hook errors are non-fatal: we log and fall back to approve so transient failures
	// do not block legitimate registrations.
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
				// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
				s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, stewardID,
					business.AuditEventSecurityEvent, "registration_rejected",
					business.AuditResultDenied, business.AuditSeverityCritical, nil)
				http.Error(w, "Registration rejected", http.StatusForbidden)
				return
			case DecisionQuarantine:
				// Issue #1693: quarantine returns 202 with no cert — cert issuance is gated on approval.
				pendingID := fmt.Sprintf("pending-%d", time.Now().UnixNano())
				s.logger.Info("Registration quarantined by approval workflow",
					"tenant_id", token.TenantID,
					"pending_id", pendingID)
				// A registry write failure is non-fatal; the steward will re-appear on re-registration.
				if err := s.controllerService.RegisterSteward(stewardID, token.TenantID, s.getTransportAddress(), "quarantined"); err != nil {
					s.logger.Error("Failed to register quarantined steward in controller service",
						"steward_id", stewardID, "error", err)
				} else {
					s.registrationQueue.Store(stewardID, PendingRegistration{
						PendingID:    pendingID,
						StewardID:    stewardID,
						TenantID:     token.TenantID,
						SourceIP:     extractSourceIP(r),
						RegisteredAt: time.Now().UTC(),
					})
				}
				// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
				s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, stewardID,
					business.AuditEventAuthentication, "registration_quarantined",
					business.AuditResultSuccess, business.AuditSeverityHigh,
					map[string]interface{}{"quarantined": true})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				if err := json.NewEncoder(w).Encode(RegistrationPendingResponse{
					PendingID: pendingID,
					StewardID: stewardID,
					TenantID:  token.TenantID,
					Group:     token.Group,
					Status:    "pending",
				}); err != nil {
					s.logger.Error("Failed to encode pending registration response", "error", err)
				}
				return
			}
		}
	}

	// Approve path: generate mTLS certificates and return the full registration response.
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

	// A registry write failure is non-fatal: the steward already has valid certificates and
	// will re-appear in the registry on its first heartbeat. Blocking the response here would
	// leave the steward with credentials it cannot use and no way to recover without re-registering.
	if err := s.controllerService.RegisterSteward(stewardID, token.TenantID, resp.TransportAddress, "registered"); err != nil {
		s.logger.Error("Failed to register steward in controller service",
			"steward_id", stewardID, "error", err)
	}

	// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
	s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, stewardID,
		business.AuditEventAuthentication, "steward_registered",
		business.AuditResultSuccess, business.AuditSeverityHigh, nil)

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

// emitRegistrationAudit records a registration audit event. It is a no-op when auditManager is nil.
// Errors are logged at Warn and do not affect the caller's control flow.
func (s *Server) emitRegistrationAudit(
	ctx context.Context,
	tokenStr, tenantID, stewardID string,
	eventType business.AuditEventType,
	action string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	tokenPrefix := logging.RedactedID(tokenStr)
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(eventType).
		Action(action).
		User(stewardID, business.AuditUserTypeSystem).
		Resource("steward", stewardID, "").
		Result(result).
		Severity(severity).
		Detail("token_prefix", tokenPrefix)
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit registration audit event", "error", err, "action", action)
	}
}
