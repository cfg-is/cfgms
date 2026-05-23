// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	ServerCert string `json:"server_cert,omitempty"`

	// Story #377: Dedicated config signing certificate (separated architecture)
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

// PendingRegistration represents a quarantined steward awaiting admin approval in list responses.
type PendingRegistration struct {
	PendingID    string    `json:"pending_id"`
	StewardID    string    `json:"steward_id"`
	TenantID     string    `json:"tenant_id"`
	SourceIP     string    `json:"source_ip"`
	RegisteredAt time.Time `json:"registered_at"`
}

// RegistrationStatusResponse is returned by GET /api/v1/registration/status/{pending_id}.
// For terminal-approved (claimed) entries it includes the full cert bundle; other states
// include only Status.
type RegistrationStatusResponse struct {
	Status string `json:"status"`

	// Populated only when status transitions from "approved" to "claimed":
	StewardID        string `json:"steward_id,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	Group            string `json:"group,omitempty"`
	ControllerURL    string `json:"controller_url,omitempty"`
	TransportAddress string `json:"transport_address,omitempty"`
	ClientCert       string `json:"client_cert,omitempty"`
	ClientKey        string `json:"client_key,omitempty"`
	CACert           string `json:"ca_cert,omitempty"`
	ServerCert       string `json:"server_cert,omitempty"`
	SigningCert      string `json:"signing_cert,omitempty"`
}

// denyRegistrationRequest is the optional request body for the deny endpoint.
type denyRegistrationRequest struct {
	Reason string `json:"reason,omitempty"`
}

// handleListPendingRegistrations handles GET /api/v1/registration/pending.
// Returns all quarantined stewards awaiting operator approval.
func (s *Server) handleListPendingRegistrations(w http.ResponseWriter, r *http.Request) {
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	entries, err := s.pendingStore.ListPending(r.Context(), "")
	if err != nil {
		s.logger.Error("Failed to list pending registrations", "error", err)
		http.Error(w, "Failed to list pending registrations", http.StatusInternalServerError)
		return
	}

	pending := make([]PendingRegistration, 0, len(entries))
	for _, e := range entries {
		pending = append(pending, PendingRegistration{
			PendingID:    e.PendingID,
			StewardID:    e.StewardID,
			TenantID:     e.TenantID,
			SourceIP:     e.SourceIP,
			RegisteredAt: e.RegisteredAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(pending); err != nil {
		s.logger.Error("Failed to encode pending registrations", "error", err)
	}
}

// handleApproveRegistration handles POST /api/v1/registration/{id}/approve.
// Marks the pending entry as approved; no cert is generated here (generate-on-claim).
func (s *Server) handleApproveRegistration(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["id"]
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.pendingStore.GetPendingByID(r.Context(), pendingID); err != nil {
		if err == business.ErrPendingRegistrationNotFound {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to look up pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "Failed to look up pending registration", http.StatusInternalServerError)
		return
	}
	if err := s.pendingStore.UpdateStatus(r.Context(), pendingID, business.PendingRegistrationStatusApproved); err != nil {
		s.logger.Error("Failed to approve pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to approve registration", http.StatusInternalServerError)
		return
	}
	s.logger.Info("Steward registration approved (awaiting claim)", "pending_id", logging.SanitizeLogValue(pendingID))
	w.WriteHeader(http.StatusOK)
}

// handleDenyRegistration handles POST /api/v1/registration/{id}/deny.
// Marks the pending entry as denied; no certs are issued.
func (s *Server) handleDenyRegistration(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["id"]
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.pendingStore.GetPendingByID(r.Context(), pendingID); err != nil {
		if err == business.ErrPendingRegistrationNotFound {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to look up pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "Failed to look up pending registration", http.StatusInternalServerError)
		return
	}
	var req denyRegistrationRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.pendingStore.UpdateStatus(r.Context(), pendingID, business.PendingRegistrationStatusDenied); err != nil {
		s.logger.Error("Failed to deny pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to deny registration", http.StatusInternalServerError)
		return
	}
	s.logger.Info("Steward registration denied",
		"pending_id", logging.SanitizeLogValue(pendingID),
		"reason", logging.SanitizeLogValue(req.Reason))
	w.WriteHeader(http.StatusOK)
}

// handleRegistrationStatus handles GET /api/v1/registration/status/{pending_id}.
// Auth: Bearer <regToken> header; token must belong to the same tenant as the pending entry.
// State machine: pending→200 status, approved→claim+cert+200, claimed→410, denied/expired→200 status.
func (s *Server) handleRegistrationStatus(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["pending_id"]

	if s.pendingStore == nil || s.registrationTokenStore == nil {
		http.Error(w, "registration service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Extract Bearer token from Authorization header.
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Authorization: Bearer <token> required", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate the registration token.
	token, err := s.registrationTokenStore.GetToken(r.Context(), tokenStr)
	if err != nil {
		http.Error(w, "Invalid or expired registration token", http.StatusUnauthorized)
		return
	}
	if !token.IsValid() {
		http.Error(w, "Registration token is revoked or expired", http.StatusUnauthorized)
		return
	}

	// Retrieve the pending entry.
	entry, err := s.pendingStore.GetPendingByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRegistrationNotFound {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to retrieve pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "Failed to retrieve pending registration", http.StatusInternalServerError)
		return
	}

	// Tenant isolation: a token from a different tenant cannot observe this entry.
	if entry.TenantID != token.TenantID {
		http.Error(w, "forbidden: token tenant does not match pending entry tenant", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch entry.Status {
	case business.PendingRegistrationStatusPending:
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: "pending"})

	case business.PendingRegistrationStatusApproved:
		// Generate-on-claim: persist "claimed" + claimed_at BEFORE generating the cert so
		// a restart between this step and the response cannot yield a second cert.
		// The UPDATE has AND status = 'approved', so a concurrent poll racing this one
		// will get RowsAffected = 0 (returned as ErrPendingRegistrationNotFound), which
		// we surface as 410 Gone rather than 500, preventing double cert issuance.
		if err := s.pendingStore.UpdateStatus(r.Context(), pendingID, business.PendingRegistrationStatusClaimed); err != nil {
			if err == business.ErrPendingRegistrationNotFound {
				// Already claimed by a concurrent poll.
				w.WriteHeader(http.StatusGone)
				return
			}
			s.logger.Error("Failed to mark pending entry as claimed", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
			http.Error(w, "Failed to claim registration", http.StatusInternalServerError)
			return
		}
		resp, err := s.buildClaimResponse(r.Context(), entry)
		if err != nil {
			s.logger.Error("Failed to generate cert for claimed registration",
				"pending_id", logging.SanitizeLogValue(pendingID), "steward_id", logging.SanitizeLogValue(entry.StewardID), "error", err)
			// Entry is already "claimed" — steward must re-register if cert was not received.
			http.Error(w, "Failed to generate client certificate", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("Failed to encode registration status response", "error", err)
		}

	case business.PendingRegistrationStatusClaimed:
		w.WriteHeader(http.StatusGone)

	case business.PendingRegistrationStatusDenied:
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: "denied"})

	case business.PendingRegistrationStatusExpired:
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: "expired"})

	default:
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: entry.Status})
	}
}

// buildClaimResponse generates the cert and builds the RegistrationStatusResponse.
// Mirrors the approved path in handleRegister (lines ~286–365).
func (s *Server) buildClaimResponse(ctx context.Context, entry *business.PendingRegistrationEntry) (*RegistrationStatusResponse, error) {
	if s.certManager == nil {
		return nil, fmt.Errorf("certificate manager not initialized")
	}

	// Re-fetch the token to obtain Group and ControllerURL.
	tok, err := s.registrationTokenStore.GetToken(ctx, entry.TokenStr)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token for claim: %w", err)
	}

	validityDays := 365
	if s.cfg.Certificate != nil && s.cfg.Certificate.ClientCertValidityDays > 0 {
		validityDays = s.cfg.Certificate.ClientCertValidityDays
	}

	clientCert, err := s.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   entry.StewardID,
		Organization: "CFGMS Stewards",
		ClientID:     entry.StewardID,
		ValidityDays: validityDays,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %w", err)
	}

	caCert, err := s.certManager.GetCACertificate()
	if err != nil || len(caCert) == 0 {
		return nil, fmt.Errorf("CA certificate unavailable: %w", err)
	}

	var serverCert []byte
	if s.signerCertSerial != "" {
		certPEM, _, err := s.certManager.ExportCertificate(s.signerCertSerial, false)
		if err == nil && len(certPEM) > 0 {
			serverCert = certPEM
		}
	}

	resp := &RegistrationStatusResponse{
		Status:           business.PendingRegistrationStatusClaimed,
		StewardID:        entry.StewardID,
		TenantID:         entry.TenantID,
		Group:            tok.Group,
		ControllerURL:    tok.ControllerURL,
		TransportAddress: s.getTransportAddress(),
		ClientCert:       string(clientCert.CertificatePEM),
		ClientKey:        string(clientCert.PrivateKeyPEM),
		CACert:           string(caCert),
		ServerCert:       string(serverCert),
	}

	if s.cfg.Certificate != nil && s.cfg.Certificate.IsSeparatedArchitecture() {
		signingCertPEM, err := s.certManager.GetSigningCertificate()
		if err == nil && len(signingCertPEM) > 0 {
			resp.SigningCert = string(signingCertPEM)
			resp.ServerCert = string(signingCertPEM)
		}
	}

	// Promote steward to registered in the fleet registry.
	if err := s.controllerService.UpdateStewardStatus(entry.StewardID, "registered"); err != nil {
		s.logger.Warn("Failed to update steward status to registered after claim",
			"steward_id", entry.StewardID, "error", err)
	}

	s.logger.Info("Generated client certificate for claimed registration",
		"pending_id", entry.PendingID,
		"steward_id", entry.StewardID,
		"validity_days", validityDays)

	return resp, nil
}

// approveAllResponse is the JSON body returned by approve-all and approve-by-cidr.
type approveAllResponse struct {
	Approved int `json:"approved"`
}

// approveByCIDRRequest is the request body for POST /api/v1/registration/approve-by-cidr.
type approveByCIDRRequest struct {
	CIDR string `json:"cidr"`
}

// handleApproveAllRegistrations handles POST /api/v1/registration/approve-all.
// Approves every entry currently in "pending" status and returns the count.
// Idempotent: entries already approved/claimed/denied are skipped without error.
func (s *Server) handleApproveAllRegistrations(w http.ResponseWriter, r *http.Request) {
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	entries, err := s.pendingStore.ListPending(r.Context(), "")
	if err != nil {
		s.logger.Error("Failed to list pending registrations for approve-all", "error", err)
		http.Error(w, "Failed to list pending registrations", http.StatusInternalServerError)
		return
	}

	approved := 0
	for _, e := range entries {
		if e.Status != business.PendingRegistrationStatusPending {
			continue
		}
		if err := s.pendingStore.UpdateStatus(r.Context(), e.PendingID, business.PendingRegistrationStatusApproved); err != nil {
			s.logger.Error("Failed to approve pending registration in bulk",
				"pending_id", logging.SanitizeLogValue(e.PendingID), "error", err)
			continue
		}
		approved++
	}

	s.logger.Info("Bulk approve-all completed", "approved", approved)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveAllResponse{Approved: approved}); err != nil {
		s.logger.Error("Failed to encode approve-all response", "error", err)
	}
}

// handleApproveByCIDR handles POST /api/v1/registration/approve-by-cidr.
// Filters pending entries by source IP containment in the given CIDR (evaluated in Go,
// not delegated to storage) and approves matching entries. Returns the count approved.
func (s *Server) handleApproveByCIDR(w http.ResponseWriter, r *http.Request) {
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}

	var req approveByCIDRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
		http.Error(w, "cidr is required", http.StatusBadRequest)
		return
	}

	_, ipNet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		http.Error(w, "invalid CIDR", http.StatusBadRequest)
		return
	}

	entries, err := s.pendingStore.ListPending(r.Context(), "")
	if err != nil {
		s.logger.Error("Failed to list pending registrations for approve-by-cidr", "error", err)
		http.Error(w, "Failed to list pending registrations", http.StatusInternalServerError)
		return
	}

	approved := 0
	for _, e := range entries {
		if e.Status != business.PendingRegistrationStatusPending {
			continue
		}
		ip := net.ParseIP(e.SourceIP)
		if ip == nil || !ipNet.Contains(ip) {
			continue
		}
		if err := s.pendingStore.UpdateStatus(r.Context(), e.PendingID, business.PendingRegistrationStatusApproved); err != nil {
			s.logger.Error("Failed to approve pending registration in CIDR bulk",
				"pending_id", logging.SanitizeLogValue(e.PendingID), "error", err)
			continue
		}
		approved++
	}

	s.logger.Info("CIDR bulk approve completed",
		"cidr", logging.SanitizeLogValue(req.CIDR), "approved", approved)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveAllResponse{Approved: approved}); err != nil {
		s.logger.Error("Failed to encode approve-by-cidr response", "error", err)
	}
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
			SourceIP: extractSourceIP(r, s.trustedProxies),
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
				// Issue #1696: store the pending entry durably instead of in-memory sync.Map.
				pendingID := fmt.Sprintf("pending-%d", time.Now().UnixNano())
				s.logger.Info("Registration quarantined by approval workflow",
					"tenant_id", token.TenantID,
					"pending_id", pendingID)

				if err := s.controllerService.RegisterSteward(stewardID, token.TenantID, s.getTransportAddress(), "quarantined"); err != nil {
					s.logger.Error("Failed to register quarantined steward in controller service",
						"steward_id", stewardID, "error", err)
				}

				if s.pendingStore != nil {
					pendingEntry := &business.PendingRegistrationEntry{
						PendingID:    pendingID,
						StewardID:    stewardID,
						TenantID:     token.TenantID,
						TokenStr:     req.Token,
						SourceIP:     extractSourceIP(r, s.trustedProxies),
						RegisteredAt: time.Now().UTC(),
						ExpiresAt:    time.Now().UTC().Add(5 * 24 * time.Hour),
						Status:       business.PendingRegistrationStatusPending,
					}
					if err := s.pendingStore.AddPending(r.Context(), pendingEntry); err != nil {
						s.logger.Error("Failed to persist pending registration",
							"pending_id", pendingID, "steward_id", stewardID, "error", err)
					}
				} else {
					s.logger.Warn("Pending store not available; registration queue is not durable",
						"pending_id", pendingID)
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
	var serverCert []byte
	if s.certManager != nil && s.signerCertSerial != "" {
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
	if s.cfg.Certificate != nil && s.cfg.Certificate.IsSeparatedArchitecture() && s.certManager != nil {
		signingCertPEM, err := s.certManager.GetSigningCertificate()
		if err == nil && len(signingCertPEM) > 0 {
			resp.SigningCert = string(signingCertPEM)
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
func (s *Server) getTransportAddress() string {
	addr := "localhost:4433" // Default transport address
	if s.cfg.Transport != nil && s.cfg.Transport.ListenAddr != "" {
		addr = s.cfg.Transport.ListenAddr
	}
	return replaceBindAddress(addr)
}

// replaceBindAddress replaces 0.0.0.0 bind addresses with external hostname
func replaceBindAddress(addr string) string {
	if !strings.HasPrefix(addr, "0.0.0.0:") {
		return addr
	}
	externalHostname := os.Getenv("CFGMS_EXTERNAL_HOSTNAME")
	if externalHostname == "" {
		externalHostname = "localhost"
	}
	port := strings.TrimPrefix(addr, "0.0.0.0:")
	return externalHostname + ":" + port
}

// extractSourceIP returns the source IP from the HTTP request.
// It honors X-Forwarded-For only when the TCP peer (r.RemoteAddr) is within
// trustedProxies. When trustedProxies is empty or the peer is not in the list,
// the TCP peer address is always used — XFF is untrusted and ignored.
func extractSourceIP(r *http.Request, trustedProxies []net.IPNet) string {
	peerHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerHost = host
	}

	if len(trustedProxies) > 0 {
		peerIP := net.ParseIP(peerHost)
		if peerIP != nil {
			for i := range trustedProxies {
				if trustedProxies[i].Contains(peerIP) {
					if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
						if idx := strings.Index(xff, ","); idx != -1 {
							return strings.TrimSpace(xff[:idx])
						}
						return strings.TrimSpace(xff)
					}
					break
				}
			}
		}
	}

	return peerHost
}

// emitRegistrationAudit records a registration audit event. It is a no-op when auditManager is nil.
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
