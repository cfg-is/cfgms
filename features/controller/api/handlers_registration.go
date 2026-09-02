// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// Device identity fields (Issue #2095, ADR-010 §1): stable across mTLS cert rotations.
	DeviceID           string `json:"device_id,omitempty"`            // 64-char lowercase hex SHA-256 of Ed25519 public key
	IdentityKeyPub     string `json:"identity_key_pub,omitempty"`     // base64-encoded Ed25519 public key (32 bytes)
	KeyProtectionLevel string `json:"key_protection_level,omitempty"` // "file" or "tpm"

	// Best-effort identity hints seeded into initial DNA so the controller is not
	// blind to connected stewards before their first DNA sync (Issue #2640).
	// Registration succeeds even when these fields are absent.
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
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

	// IssuerChain is the PEM-concatenated chain from ClientCert's direct issuer up
	// to (but not including) CACert (Issue #3778). Empty when the controller's cert
	// manager is backed by a root-only CA (self-hosted default); populated when it
	// is backed by an imported regional intermediate.
	IssuerChain string `json:"issuer_chain,omitempty"`

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
	IssuerChain      string `json:"issuer_chain,omitempty"`
	ServerCert       string `json:"server_cert,omitempty"`
	SigningCert      string `json:"signing_cert,omitempty"`
}

// denyRegistrationRequest is the optional request body for the deny endpoint.
type denyRegistrationRequest struct {
	Reason string `json:"reason,omitempty"`
}

// handleListPendingRegistrations handles GET /api/v1/registration/pending.
// Returns all quarantined stewards awaiting operator approval.
// Scoped callers (API-key principals) see only their own tenant's entries; unscoped
// (mTLS admin, callerTenant == "") retain global visibility.
func (s *Server) handleListPendingRegistrations(w http.ResponseWriter, r *http.Request) {
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	callerTenant := s.callerTenantID(r)
	entries, err := s.pendingStore.ListPending(r.Context(), callerTenant)
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
// Returns 404 when the entry's tenant is outside the caller's subtree (no existence disclosure).
func (s *Server) handleApproveRegistration(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["id"]
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	entry, err := s.pendingStore.GetPendingByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRegistrationNotFound {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to look up pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to look up pending registration", http.StatusInternalServerError)
		return
	}
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := entry.TenantID == callerTenant || strings.HasPrefix(entry.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
	}
	if err := s.pendingStore.UpdateStatus(r.Context(), pendingID, business.PendingRegistrationStatusApproved); err != nil {
		s.logger.Error("Failed to approve pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to approve registration", http.StatusInternalServerError)
		return
	}
	s.logger.Info("Steward registration approved (awaiting claim)", "pending_id", logging.SanitizeLogValue(pendingID))
	s.emitRegistrationManagementAudit(r, "registration.approved",
		map[string]interface{}{"pending_id": pendingID, "tenant_id": entry.TenantID})
	w.WriteHeader(http.StatusOK)
}

// handleDenyRegistration handles POST /api/v1/registration/{id}/deny.
// Marks the pending entry as denied; no certs are issued.
// Returns 404 when the entry's tenant is outside the caller's subtree (no existence disclosure).
func (s *Server) handleDenyRegistration(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["id"]
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	entry, err := s.pendingStore.GetPendingByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRegistrationNotFound {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to look up pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to look up pending registration", http.StatusInternalServerError)
		return
	}
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := entry.TenantID == callerTenant || strings.HasPrefix(entry.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
	}
	// The deny reason is optional, so an absent body is not an error. A body that
	// is present but malformed is: the reason ends up in the audit record, and
	// dropping it silently would lose it with no diagnostic trace.
	var req denyRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.logger.Warn("Rejected malformed deny-registration body",
			"pending_id", logging.SanitizeLogValue(pendingID),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := s.pendingStore.UpdateStatus(r.Context(), pendingID, business.PendingRegistrationStatusDenied); err != nil {
		s.logger.Error("Failed to deny pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to deny registration", http.StatusInternalServerError)
		return
	}
	s.logger.Info("Steward registration denied",
		"pending_id", logging.SanitizeLogValue(pendingID),
		"reason", logging.SanitizeLogValue(req.Reason))
	s.emitRegistrationManagementAudit(r, "registration.denied",
		map[string]interface{}{"pending_id": pendingID, "tenant_id": entry.TenantID, "reason": req.Reason})
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

	// Retrieve the pending entry.
	entry, err := s.pendingStore.GetPendingByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRegistrationNotFound {
			http.Error(w, "pending registration not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to retrieve pending registration", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "Failed to retrieve pending registration", http.StatusInternalServerError)
		return
	}

	// Bind the bearer token to this exact pending entry without persisting the
	// bearer secret. Accept the raw comparison only for pre-migration rows.
	tokenLookupKey := business.RegistrationTokenLookupKey(tokenStr)
	if entry.TokenStr != tokenLookupKey && entry.TokenStr != tokenStr {
		http.Error(w, "forbidden: token does not match pending entry", http.StatusForbidden)
		return
	}
	if !token.IsValid() {
		http.Error(w, "Registration token is revoked or expired", http.StatusUnauthorized)
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
		// #nosec G117 -- this status-only instance leaves ClientKey empty; no
		// credential is serialized on the pending branch.
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: "pending"})

	case business.PendingRegistrationStatusApproved:
		// Issue #3471: the story excluded this handler as read-only; that exclusion
		// does not hold for this branch, which is the second half of enrollment —
		// it transitions the entry to "claimed" and mints a client certificate.
		// Gate the claim, not the whole endpoint: status polling stays available on
		// a non-authoritative controller, but no fleet trust is granted from one.
		// The steward retries the poll, so a 503 here is recoverable and the entry
		// stays "approved" for the authoritative controller to serve.
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
		resp, err := s.buildClaimResponse(r.Context(), entry, tokenStr)
		if err != nil {
			if errors.Is(err, errClaimDeviceIDConflict) || errors.Is(err, errClaimStewardIDConflict) {
				// The entry stays "claimed": the colliding enrollment is burned
				// rather than left retryable, and no certificate was minted.
				http.Error(w, "device_id already registered in this tenant", http.StatusConflict)
				return
			}
			s.logger.Error("Failed to generate cert for claimed registration",
				"pending_id", logging.SanitizeLogValue(pendingID), "steward_id", logging.SanitizeLogValue(entry.StewardID), "error", logging.SanitizeLogValue(err.Error()))
			// Entry is already "claimed" — steward must re-register if cert was not received.
			http.Error(w, "Failed to generate client certificate", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		// #nosec G117 -- this authenticated, tenant-bound, atomically one-time
		// claim response is the intended TLS delivery channel for the new key.
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("Failed to encode registration status response", "error", logging.SanitizeLogValue(err.Error()))
		}

	case business.PendingRegistrationStatusClaimed:
		w.WriteHeader(http.StatusGone)

	case business.PendingRegistrationStatusDenied:
		// #nosec G117 -- this status-only instance leaves ClientKey empty.
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: "denied"})

	case business.PendingRegistrationStatusExpired:
		// #nosec G117 -- this status-only instance leaves ClientKey empty.
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: "expired"})

	default:
		// #nosec G117 -- this status-only instance leaves ClientKey empty.
		_ = json.NewEncoder(w).Encode(RegistrationStatusResponse{Status: entry.Status})
	}
}

// errClaimDeviceIDConflict is returned by buildClaimResponse when the claimed
// pending entry asserts a device_id already held by a different steward in the
// same tenant. Surfaced as HTTP 409 by handleRegistrationStatus.
var errClaimDeviceIDConflict = errors.New("device_id already registered in this tenant")

// errClaimStewardIDConflict is returned by buildClaimResponse when the pending
// entry's StewardID is already held by a different device — a steward ID
// collision. Surfaced as HTTP 409 by handleRegistrationStatus.
var errClaimStewardIDConflict = errors.New("steward ID already claimed by a different device")

// generateStewardID returns a collision-resistant steward identifier.
// The ID embeds the given timestamp for readability and 8 cryptographically random
// bytes (64 bits of entropy) so that concurrent registrations on any platform —
// including Windows, where the wall clock has substantially coarser granularity than
// Linux — cannot share an ID regardless of timer resolution.
func generateStewardID(now time.Time) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate steward ID: %w", err)
	}
	return fmt.Sprintf("steward-%d-%s", now.UnixNano(), hex.EncodeToString(b)), nil
}

// buildClaimResponse generates the cert and builds the RegistrationStatusResponse.
// Mirrors the approved path in handleRegister (lines ~286–365).
func (s *Server) buildClaimResponse(ctx context.Context, entry *business.PendingRegistrationEntry, tokenStr string) (*RegistrationStatusResponse, error) {
	if s.certManager == nil {
		return nil, fmt.Errorf("certificate manager not initialized")
	}

	// Tenant-scoped duplicate-device_id guard for the quarantine→approve→claim
	// route (ADR-010 §1). handleRegister gates its direct-approval write with the
	// same lookup, but that check cannot cover this route: no StewardRecord exists
	// at register time, so two enrollments asserting one device_id both pass it and
	// both reach a write here. Their pending IDs differ — pendingRegistrationID
	// hashes the token together with the device identity — and neither the
	// non-unique device_id index nor RegisterSteward (which reports only a primary
	// key collision) rejects the second record. Two records sharing a device_id
	// break GetStewardByDeviceID, the single lookup feeding the revocation gate in
	// handlers_registration_refresh.go: a record still in "registered" state
	// alongside a revoked sibling lets the revoked holder pass that gate. Run the
	// check before the certificate is minted so a colliding claim gets no
	// credential either.
	if s.stewardStore != nil && entry.DeviceID != "" {
		existing, lookupErr := s.stewardStore.GetStewardByDeviceID(ctx, entry.DeviceID)
		if lookupErr == nil && existing != nil &&
			existing.TenantID == entry.TenantID && existing.ID != entry.StewardID {
			s.logger.Warn("Duplicate DeviceID at registration claim within tenant",
				"pending_id", logging.SanitizeLogValue(entry.PendingID),
				"steward_id", logging.SanitizeLogValue(entry.StewardID),
				"device_id", logging.SanitizeLogValue(entry.DeviceID),
				"tenant_id", logging.SanitizeLogValue(entry.TenantID))
			// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
			s.emitRegistrationAudit(ctx, tokenStr, entry.TenantID, entry.StewardID,
				business.AuditEventSecurityEvent, "registration_rejected",
				business.AuditResultDenied, business.AuditSeverityCritical,
				map[string]interface{}{"rejection_reason": "duplicate device_id in tenant"})
			return nil, errClaimDeviceIDConflict
		}
	}

	// Durably record the steward in the fleet store at enrollment — before any
	// gRPC check-in (Issue #3403). A steward in this state is fully described
	// (identity, tenant, enrollment timestamp) and distinguishable from a steward
	// that has connected (status: "active") or gone silent (status: "lost").
	//
	// This write is deliberately ordered BEFORE the certificate is minted. The
	// lookup above is check-then-act and two concurrent claims asserting one
	// device_id can both pass it; only the unique index on (tenant_id, device_id)
	// decides a winner. Writing first means the loser is rejected while it still
	// has no credential — minting first would hand out a certificate and then
	// discard it, leaving an issued cert with no steward record behind it.
	//
	// ErrStewardAlreadyExists is benign: the same steward was written twice by a
	// concurrent poll of one pending entry. ErrStewardDeviceIDConflict is not — it
	// is a different steward holding this device_id, and it fails the claim.
	if s.stewardStore != nil {
		now := time.Now().UTC()
		storeErr := s.stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID:                 entry.StewardID,
			TenantID:           entry.TenantID,
			Hostname:           entry.Hostname,
			Platform:           entry.Platform,
			Status:             business.StewardStatusRegistered,
			RegisteredAt:       entry.RegisteredAt,
			LastSeen:           now,
			DeviceID:           entry.DeviceID,
			IdentityKeyPub:     entry.IdentityKeyPub,
			KeyProtectionLevel: entry.KeyProtectionLevel,
		})
		switch {
		case errors.Is(storeErr, business.ErrStewardDeviceIDConflict):
			s.logger.Warn("Duplicate DeviceID rejected by unique index at registration claim",
				"pending_id", logging.SanitizeLogValue(entry.PendingID),
				"steward_id", logging.SanitizeLogValue(entry.StewardID),
				"device_id", logging.SanitizeLogValue(entry.DeviceID),
				"tenant_id", logging.SanitizeLogValue(entry.TenantID))
			// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
			s.emitRegistrationAudit(ctx, tokenStr, entry.TenantID, entry.StewardID,
				business.AuditEventSecurityEvent, "registration_rejected",
				business.AuditResultDenied, business.AuditSeverityCritical,
				map[string]interface{}{"rejection_reason": "duplicate device_id in tenant"})
			return nil, errClaimDeviceIDConflict
		case errors.Is(storeErr, business.ErrStewardAlreadyExists):
			// A concurrent claim poll or retry wrote this record first. This is benign
			// when the same device re-claims its own approved entry. However, if two
			// registrations were assigned the same StewardID (steward ID collision) the
			// existing record belongs to a different device — refuse the claim so no
			// second certificate is issued. Key on DeviceID: the same steward re-claiming
			// has the same DeviceID; a colliding registration has a different one.
			if entry.DeviceID != "" {
				if existing, getErr := s.stewardStore.GetSteward(ctx, entry.StewardID); getErr == nil &&
					existing != nil && existing.DeviceID != entry.DeviceID {
					s.logger.Warn("Steward ID collision: existing record holds a different device",
						"steward_id", logging.SanitizeLogValue(entry.StewardID),
						"pending_device_id", logging.SanitizeLogValue(entry.DeviceID))
					// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
					s.emitRegistrationAudit(ctx, tokenStr, entry.TenantID, entry.StewardID,
						business.AuditEventSecurityEvent, "registration_rejected",
						business.AuditResultDenied, business.AuditSeverityCritical,
						map[string]interface{}{"rejection_reason": "steward ID collision"})
					return nil, errClaimStewardIDConflict
				}
			}
		case storeErr != nil:
			s.logger.Error("Failed to persist steward record to fleet store at enrollment",
				"steward_id", logging.SanitizeLogValue(entry.StewardID),
				"error", logging.SanitizeLogValue(storeErr.Error()))
		}
	}

	// Re-fetch the token to obtain Group and ControllerURL.
	tok, err := s.registrationTokenStore.GetToken(ctx, tokenStr)
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
		certPEM, _, err := s.certManager.ExportCertificate(s.signerCertSerial, false, false)
		if err == nil && len(certPEM) > 0 {
			serverCert = certPEM
		}
	}

	transportAddr, err := s.getTransportAddress()
	if err != nil {
		return nil, fmt.Errorf("transport address unavailable: %w", err)
	}

	resp := &RegistrationStatusResponse{
		Status:           business.PendingRegistrationStatusClaimed,
		StewardID:        entry.StewardID,
		TenantID:         entry.TenantID,
		Group:            tok.Group,
		ControllerURL:    tok.ControllerURL,
		TransportAddress: transportAddr,
		ClientCert:       string(clientCert.CertificatePEM),
		ClientKey:        string(clientCert.PrivateKeyPEM),
		CACert:           string(caCert),
		IssuerChain:      string(clientCert.IssuerChainPEM),
		ServerCert:       string(serverCert),
	}

	// Always provide the dedicated signing certificate (separated architecture is mandatory)
	if s.certManager != nil {
		if signingCertPEM, sigErr := s.certManager.GetSigningCertificate(); sigErr == nil && len(signingCertPEM) > 0 {
			resp.SigningCert = string(signingCertPEM)
			resp.ServerCert = string(signingCertPEM)
		}
	}

	// Promote steward to registered in the fleet registry and persist the status
	// to durable DNA storage so LoadFromStorage warm-loads it after a restart
	// (Issue #3403).
	if err := s.controllerService.UpdateStewardStatusDurable(entry.StewardID, entry.TenantID, "registered"); err != nil {
		s.logger.Warn("Failed to update steward status to registered after claim",
			"steward_id", logging.SanitizeLogValue(entry.StewardID), "error", logging.SanitizeLogValue(err.Error()))
	}

	s.logger.Info("Generated client certificate for claimed registration",
		"pending_id", logging.SanitizeLogValue(entry.PendingID),
		"steward_id", logging.SanitizeLogValue(entry.StewardID),
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
// Scoped callers approve only within their own tenant subtree.
func (s *Server) handleApproveAllRegistrations(w http.ResponseWriter, r *http.Request) {
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}
	callerTenant := s.callerTenantID(r)
	entries, err := s.pendingStore.ListPending(r.Context(), callerTenant)
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
	s.emitRegistrationManagementAudit(r, "registration.approve_all",
		map[string]interface{}{"approved_count": approved})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveAllResponse{Approved: approved}); err != nil {
		s.logger.Error("Failed to encode approve-all response", "error", err)
	}
}

// handleApproveByCIDR handles POST /api/v1/registration/approve-by-cidr.
// Filters pending entries by source IP containment in the given CIDR (evaluated in Go,
// not delegated to storage) and approves matching entries. Returns the count approved.
// Scoped callers approve only within their own tenant subtree.
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

	callerTenant := s.callerTenantID(r)
	entries, err := s.pendingStore.ListPending(r.Context(), callerTenant)
	if err != nil {
		s.logger.Error("Failed to list pending registrations for approve-by-cidr", "error", logging.SanitizeLogValue(err.Error()))
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
				"pending_id", logging.SanitizeLogValue(e.PendingID), "error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		approved++
	}

	s.logger.Info("CIDR bulk approve completed",
		"cidr", logging.SanitizeLogValue(req.CIDR), "approved", approved)
	s.emitRegistrationManagementAudit(r, "registration.approve_by_cidr",
		map[string]interface{}{"cidr": req.CIDR, "approved_count": approved})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveAllResponse{Approved: approved}); err != nil {
		s.logger.Error("Failed to encode approve-by-cidr response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// approveByCIDRPreviewResponse is returned by GET /api/v1/registration/approve-by-cidr/preview.
type approveByCIDRPreviewResponse struct {
	Count      int      `json:"count"`
	PendingIDs []string `json:"pending_ids"`
	SourceIPs  []string `json:"source_ips"`
}

// handleApproveByCIDRPreview handles GET /api/v1/registration/approve-by-cidr/preview.
// Returns a dry-run preview of pending entries whose source IP falls in the given CIDR,
// without mutating any state. Requires the ?cidr= query parameter.
// Scoped callers see only their own tenant subtree.
// The caller must show this preview to the operator before the mutating POST is allowed.
func (s *Server) handleApproveByCIDRPreview(w http.ResponseWriter, r *http.Request) {
	if s.pendingStore == nil {
		http.Error(w, "registration store unavailable", http.StatusServiceUnavailable)
		return
	}

	cidr := r.URL.Query().Get("cidr")
	if cidr == "" {
		http.Error(w, "cidr query parameter is required", http.StatusBadRequest)
		return
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		http.Error(w, "invalid CIDR", http.StatusBadRequest)
		return
	}

	callerTenant := s.callerTenantID(r)
	entries, err := s.pendingStore.ListPending(r.Context(), callerTenant)
	if err != nil {
		s.logger.Error("Failed to list pending registrations for approve-by-cidr preview", "error", err)
		http.Error(w, "Failed to list pending registrations", http.StatusInternalServerError)
		return
	}

	pendingIDs := make([]string, 0)
	sourceIPs := make([]string, 0)
	for _, e := range entries {
		if e.Status != business.PendingRegistrationStatusPending {
			continue
		}
		ip := net.ParseIP(e.SourceIP)
		if ip == nil || !ipNet.Contains(ip) {
			continue
		}
		pendingIDs = append(pendingIDs, e.PendingID)
		sourceIPs = append(sourceIPs, e.SourceIP)
	}

	s.logger.Info("CIDR bulk approve preview",
		"cidr", logging.SanitizeLogValue(cidr), "matched", len(pendingIDs))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(approveByCIDRPreviewResponse{
		Count:      len(pendingIDs),
		PendingIDs: pendingIDs,
		SourceIPs:  sourceIPs,
	}); err != nil {
		s.logger.Error("Failed to encode approve-by-cidr preview response", "error", err)
	}
}

// isValidDeviceID returns true if id is exactly 64 lowercase hex characters.
// The DeviceID is the SHA-256 fingerprint of the steward's Ed25519 identity key (ADR-010 §1).
func isValidDeviceID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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
		s.logger.Warn("Failed to parse registration request", "error", logging.SanitizeLogValue(err.Error()))
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
		s.logger.Warn("Invalid registration token", "error", logging.SanitizeLogValue(err.Error()))
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

	stewardID, idErr := generateStewardID(time.Now())
	if idErr != nil {
		s.logger.Error("Failed to generate steward ID", "error", logging.SanitizeLogValue(idErr.Error()))
		http.Error(w, "Registration service unavailable", http.StatusInternalServerError)
		return
	}

	// Build initial DNA attributes from best-effort identity hints (Issue #2640).
	// Hostname and OS are optional; registration succeeds when absent.
	var initialAttrs map[string]string
	if req.Hostname != "" || req.OS != "" {
		initialAttrs = make(map[string]string)
		if req.Hostname != "" {
			initialAttrs["hostname"] = req.Hostname
		}
		if req.OS != "" {
			initialAttrs["os"] = req.OS
		}
	}

	// Log token use without exposing the bearer value.
	s.logger.Info("Token used for registration",
		"token_prefix", logging.RedactedID(req.Token),
		"tenant_id", token.TenantID,
		"steward_id", stewardID)

	// Validate device identity fields (Issue #2095, ADR-010 §1).
	if !isValidDeviceID(req.DeviceID) {
		http.Error(w, "device_id is required and must be a 64-character lowercase hex string", http.StatusBadRequest)
		return
	}
	identityKeyBytes, keyErr := base64.StdEncoding.DecodeString(req.IdentityKeyPub)
	if keyErr != nil || len(identityKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "identity_key_pub is required and must be a base64-encoded 32-byte Ed25519 public key", http.StatusBadRequest)
		return
	}
	claimID := registrationClaimID(req.DeviceID, identityKeyBytes)

	// Reject duplicate DeviceID within the same tenant. Cross-tenant collision is allowed —
	// each tenant namespace is independent (matching the tenant-isolation pattern at line ~221).
	if s.stewardStore != nil {
		if existing, lookupErr := s.stewardStore.GetStewardByDeviceID(r.Context(), req.DeviceID); lookupErr == nil && existing.TenantID == token.TenantID {
			s.logger.Warn("Duplicate DeviceID registration attempt within tenant",
				"device_id", logging.SanitizeLogValue(req.DeviceID),
				"tenant_id", logging.SanitizeLogValue(token.TenantID))
			http.Error(w, "device_id already registered in this tenant", http.StatusConflict)
			return
		}
	}

	// Issue #422: Run registration approval hook.
	// Hook failures must not grant unrestricted access. Quarantine keeps certificate
	// issuance behind an explicit operator decision while preserving a recoverable
	// path for a legitimate steward when the admission service is unavailable.
	{
		input := RegistrationInput{
			Token:    token,
			SourceIP: extractSourceIP(r, s.trustedProxies),
		}
		decision, reason, hookErr := s.approvalHook.Evaluate(r.Context(), input)
		if hookErr != nil {
			s.logger.Warn("Registration approval hook error, quarantining",
				"error", hookErr,
				"tenant_id", token.TenantID)
			decision = DecisionQuarantine
			reason = "admission service unavailable"
		}
		switch decision {
		case DecisionReject:
			// The reason originates in an approval workflow, which reaches
			// modules and external APIs, so it is untrusted text of the
			// controller's own making. It belongs in the durable audit record —
			// access-controlled and attributable — not in the application log,
			// which is the broader-exposure surface. The log records only that a
			// bounded reason exists, so an operator knows where to look.
			s.logger.Warn("Registration rejected by approval workflow",
				"tenant_id", token.TenantID,
				"has_reason", reason != "")
			// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
			s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, stewardID,
				business.AuditEventSecurityEvent, "registration_rejected",
				business.AuditResultDenied, business.AuditSeverityCritical,
				map[string]interface{}{"rejection_reason": reason})
			http.Error(w, "Registration rejected", http.StatusForbidden)
			return
		case DecisionQuarantine:
			// Issue #1693: quarantine returns 202 with no cert — cert issuance is gated on approval.
			// Issue #1696: store the pending entry durably instead of in-memory sync.Map.
			if s.pendingStore == nil {
				s.logger.Error("Cannot quarantine registration without durable pending store",
					"tenant_id", token.TenantID)
				http.Error(w, "Registration admission service unavailable", http.StatusServiceUnavailable)
				return
			}

			quarantineTransportAddr, taErr := s.getTransportAddress()
			if taErr != nil {
				s.logger.Error("Transport address not configured; steward cannot reconnect after approval",
					"steward_id", stewardID, "error", taErr)
				http.Error(w, "Server misconfiguration: transport address not configured", http.StatusInternalServerError)
				return
			}

			created, claimErr := s.registrationTokenStore.ClaimToken(r.Context(), req.Token, claimID)
			if claimErr != nil {
				s.logger.Error("Failed to atomically claim registration token", "error", logging.SanitizeLogValue(claimErr.Error()))
				http.Error(w, "Registration service unavailable", http.StatusServiceUnavailable)
				return
			}

			// The pending ID is derived from the token and the device identity
			// rather than from the clock, so a retrying device can be handed back
			// its own entry. A perennial token quarantines many devices at once,
			// so a by-token lookup here could return a different device's entry.
			pendingID := pendingRegistrationID(req.Token, claimID)
			if !created {
				existing, existingErr := s.pendingStore.GetPendingByID(r.Context(), pendingID)
				if existingErr == nil && existing != nil &&
					(existing.Status == business.PendingRegistrationStatusPending ||
						existing.Status == business.PendingRegistrationStatusApproved) {
					s.writePendingRegistrationResponse(w, existing, token.Group)
					return
				}
				http.Error(w, "Registration token claim is already in progress or completed", http.StatusConflict)
				return
			}

			pendingEntry := &business.PendingRegistrationEntry{
				PendingID:          pendingID,
				StewardID:          stewardID,
				TenantID:           token.TenantID,
				TokenStr:           req.Token,
				SourceIP:           extractSourceIP(r, s.trustedProxies),
				RegisteredAt:       time.Now().UTC(),
				ExpiresAt:          time.Now().UTC().Add(5 * 24 * time.Hour),
				Status:             business.PendingRegistrationStatusPending,
				DeviceID:           req.DeviceID,
				IdentityKeyPub:     identityKeyBytes,
				KeyProtectionLevel: req.KeyProtectionLevel,
				Hostname:           req.Hostname,
				Platform:           req.OS,
			}
			if err := s.pendingStore.AddPending(r.Context(), pendingEntry); err != nil {
				if releaseErr := s.registrationTokenStore.ReleaseTokenClaim(r.Context(), req.Token, claimID); releaseErr != nil {
					s.logger.Error("Failed to release registration token claim after pending-store failure",
						"pending_id", pendingID, "error", logging.SanitizeLogValue(releaseErr.Error()))
				}
				s.logger.Error("Failed to persist pending registration",
					"pending_id", pendingID, "steward_id", stewardID, "error", logging.SanitizeLogValue(err.Error()))
				http.Error(w, "Registration admission service unavailable", http.StatusServiceUnavailable)
				return
			}

			s.logger.Info("Registration quarantined by approval workflow",
				"tenant_id", token.TenantID,
				"pending_id", pendingID)
			if err := s.controllerService.RegisterStewardWithAttributes(stewardID, token.TenantID, quarantineTransportAddr, "quarantined", initialAttrs); err != nil {
				s.logger.Error("Failed to register quarantined steward in controller service",
					"steward_id", stewardID, "error", logging.SanitizeLogValue(err.Error()))
			}

			// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
			s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, stewardID,
				business.AuditEventAuthentication, "registration_quarantined",
				business.AuditResultSuccess, business.AuditSeverityHigh,
				map[string]interface{}{"quarantined": true, "reason": reason})
			s.writePendingRegistrationResponse(w, pendingEntry, token.Group)
			return
		}
	}

	// Build response with connection details
	approveTransportAddr, taErr := s.getTransportAddress()
	if taErr != nil {
		s.logger.Error("Transport address not configured; steward cannot connect after registration",
			"steward_id", stewardID, "error", taErr)
		http.Error(w, "Server misconfiguration: transport address not configured", http.StatusInternalServerError)
		return
	}
	resp := RegistrationResponse{
		StewardID:        stewardID,
		TenantID:         token.TenantID,
		Group:            token.Group,
		ControllerURL:    token.ControllerURL,
		TransportAddress: approveTransportAddr,
	}

	// Story #294 Phase 3: Generate client certificates for mTLS (REQUIRED)
	// Certificate generation is mandatory - mTLS required for production security
	if s.certManager == nil {
		s.logger.Error("Certificate manager not initialized", "steward_id", stewardID)
		http.Error(w, "Server misconfiguration: Certificate manager unavailable", http.StatusInternalServerError)
		return
	}

	// Resolve every fallible prerequisite before claiming the token. Failures up
	// to this point are safe for the steward to retry.
	validityDays := 365 // Default validity
	if s.cfg.Certificate != nil && s.cfg.Certificate.ClientCertValidityDays > 0 {
		validityDays = s.cfg.Certificate.ClientCertValidityDays
	}

	// Get CA certificate (required for certificate chain validation)
	caCert, err := s.certManager.GetCACertificate()
	if err != nil || len(caCert) == 0 {
		s.logger.Error("Failed to get CA certificate", "error", logging.SanitizeLogValue(err.Error()), "steward_id", stewardID)
		http.Error(w, "CA certificate unavailable", http.StatusInternalServerError)
		return
	}

	// Get server certificate (public key) for configuration signature verification
	var serverCert []byte
	if s.certManager != nil && s.signerCertSerial != "" {
		certPEM, _, err := s.certManager.ExportCertificate(s.signerCertSerial, false, false)
		if err == nil && len(certPEM) > 0 {
			serverCert = certPEM
			s.logger.Info("Providing signer certificate to steward for signature verification",
				"steward_id", stewardID,
				"cert_serial", s.signerCertSerial)
		} else {
			s.logger.Warn("Failed to export signer certificate from cert manager",
				"error", logging.SanitizeLogValue(err.Error()), "steward_id", stewardID, "cert_serial", s.signerCertSerial)
		}
	} else if s.signerCertSerial == "" {
		s.logger.Warn("Signer certificate serial not available (signer may not be initialized)",
			"steward_id", stewardID)
	} else {
		s.logger.Warn("Certificate manager unavailable, cannot provide server cert for signature verification",
			"steward_id", stewardID)
	}

	// This is the REST issuance boundary. For a given device identity exactly one
	// caller can create the durable claim, even across controller processes, so a
	// concurrent retry cannot obtain a second private key/certificate. The token
	// itself stays valid for the rest of the fleet (Issue #1690).
	created, claimErr := s.registrationTokenStore.ClaimToken(r.Context(), req.Token, claimID)
	if claimErr != nil {
		s.logger.Error("Failed to atomically claim registration token", "error", logging.SanitizeLogValue(claimErr.Error()))
		http.Error(w, "Registration service unavailable", http.StatusServiceUnavailable)
		return
	}
	if !created {
		http.Error(w, "Registration token claim is already in progress or completed", http.StatusConflict)
		return
	}

	clientCert, err := s.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   stewardID,
		Organization: "CFGMS Stewards",
		ClientID:     stewardID,
		ValidityDays: validityDays,
	})
	if err != nil {
		if releaseErr := s.registrationTokenStore.ReleaseTokenClaim(r.Context(), req.Token, claimID); releaseErr != nil {
			s.logger.Error("Failed to release registration token claim after certificate failure",
				"steward_id", stewardID, "error", logging.SanitizeLogValue(releaseErr.Error()))
		}
		s.logger.Error("Failed to generate client certificate", "error", logging.SanitizeLogValue(err.Error()), "steward_id", stewardID)
		http.Error(w, "Failed to generate client certificate", http.StatusInternalServerError)
		return
	}

	// Return certificates in response (ALWAYS - required for mTLS)
	resp.ClientCert = string(clientCert.CertificatePEM)
	resp.ClientKey = string(clientCert.PrivateKeyPEM)
	resp.CACert = string(caCert)
	resp.IssuerChain = string(clientCert.IssuerChainPEM)
	resp.ServerCert = string(serverCert) // For config signature verification (backward compat)

	// Always provide the dedicated signing certificate (separated architecture is mandatory)
	if s.certManager != nil {
		signingCertPEM, sigErr := s.certManager.GetSigningCertificate()
		if sigErr == nil && len(signingCertPEM) > 0 {
			resp.SigningCert = string(signingCertPEM)
			resp.ServerCert = string(signingCertPEM)
			s.logger.Info("Providing dedicated signing certificate to steward",
				"steward_id", stewardID)
		} else {
			s.logger.Warn("Failed to get signing certificate for registration response",
				"error", sigErr, "steward_id", stewardID)
		}
	}

	s.logger.Info("Generated client certificate for steward",
		"steward_id", stewardID,
		"validity_days", validityDays)
	s.logger.Info("Steward registered successfully",
		"steward_id", stewardID,
		"tenant_id", token.TenantID,
		"group", token.Group)

	if err := s.controllerService.RegisterStewardWithAttributes(stewardID, token.TenantID, resp.TransportAddress, "registered", initialAttrs); err != nil {
		s.logger.Error("Failed to register steward in controller service",
			"steward_id", stewardID, "error", logging.SanitizeLogValue(err.Error()))
	}

	// Persist device identity to the durable StewardStore so the S3b PoP verification
	// gate (registration-refresh) has a stored public key to verify against (Issue #2095).
	// Without this write, record.IdentityKeyPub is empty and refresh verification is impossible.
	if s.stewardStore != nil {
		now := time.Now().UTC()
		if storeErr := s.stewardStore.RegisterSteward(r.Context(), &business.StewardRecord{
			ID:                 stewardID,
			TenantID:           token.TenantID,
			Status:             business.StewardStatusRegistered,
			RegisteredAt:       now,
			LastSeen:           now,
			DeviceID:           req.DeviceID,
			IdentityKeyPub:     identityKeyBytes,
			KeyProtectionLevel: req.KeyProtectionLevel,
		}); storeErr != nil {
			s.logger.Error("Failed to persist device identity to steward store",
				"steward_id", stewardID,
				"device_id", logging.SanitizeLogValue(req.DeviceID),
				"error", logging.SanitizeLogValue(storeErr.Error()))
		}
	}

	// emitRegistrationAudit calls logging.RedactedID internally; raw token is not stored
	s.emitRegistrationAudit(r.Context(), req.Token, token.TenantID, stewardID,
		business.AuditEventAuthentication, "steward_registered",
		business.AuditResultSuccess, business.AuditSeverityLow, nil)

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// #nosec G117 -- successful authenticated registration intentionally returns
	// the freshly issued client key once over the required TLS endpoint.
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode registration response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// registrationClaimID binds a REST claim to the stable device identity without
// storing either the device identifier or public key in the token-claim table.
func registrationClaimID(deviceID string, identityKey []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(deviceID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(identityKey)
	return hex.EncodeToString(h.Sum(nil))
}

// pendingRegistrationID derives a quarantine entry's identifier from the token
// and the claiming device, so the same device retrying the same token addresses
// the same entry and a second device on that token gets its own. Neither the
// bearer token nor the device identity is recoverable from the result.
func pendingRegistrationID(tokenStr, claimID string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(business.RegistrationTokenLookupKey(tokenStr)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(claimID))
	return "pending-" + hex.EncodeToString(h.Sum(nil))
}

func (s *Server) writePendingRegistrationResponse(w http.ResponseWriter, entry *business.PendingRegistrationEntry, group string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(RegistrationPendingResponse{
		PendingID: entry.PendingID,
		StewardID: entry.StewardID,
		TenantID:  entry.TenantID,
		Group:     group,
		Status:    entry.Status,
	}); err != nil {
		s.logger.Error("Failed to encode pending registration response", "error", err)
	}
}

// getTransportAddress returns the unified transport address for steward connections.
// Returns an error if ListenAddr binds 0.0.0.0 and neither transport.external_address
// nor CFGMS_EXTERNAL_HOSTNAME is configured.
func (s *Server) getTransportAddress() (string, error) {
	addr := "localhost:4433"
	if s.cfg.Transport != nil && s.cfg.Transport.ListenAddr != "" {
		addr = s.cfg.Transport.ListenAddr
	}

	// Resolve the external address: config file takes precedence over env var.
	externalAddress := ""
	if s.cfg.Transport != nil {
		externalAddress = s.cfg.Transport.ExternalAddress
	}
	if externalAddress == "" {
		externalAddress = os.Getenv("CFGMS_EXTERNAL_HOSTNAME")
	}

	return replaceBindAddress(addr, externalAddress)
}

// replaceBindAddress substitutes the 0.0.0.0 wildcard with the resolved external address.
// Returns an error when addr starts with "0.0.0.0:" and externalAddress is empty.
func replaceBindAddress(addr, externalAddress string) (string, error) {
	if !strings.HasPrefix(addr, "0.0.0.0:") {
		return addr, nil
	}
	if externalAddress == "" {
		return "", fmt.Errorf("transport.listen_addr binds 0.0.0.0 but no external address is configured; set transport.external_address in controller.cfg or CFGMS_EXTERNAL_HOSTNAME env var")
	}
	port := strings.TrimPrefix(addr, "0.0.0.0:")
	return externalAddress + ":" + port, nil
}

// extractSourceIP returns the source IP from the HTTP request.
// It honors X-Forwarded-For only when the TCP peer (r.RemoteAddr) is within
// trustedProxies. The chain is evaluated from right to left so a client-supplied
// leftmost value cannot bypass source controls when a trusted proxy appends the
// real upstream address. When trustedProxies is empty, the peer is untrusted, or
// the chain is malformed, the TCP peer address is used.
func extractSourceIP(r *http.Request, trustedProxies []net.IPNet) string {
	peerHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerHost = host
	}

	peerIP := net.ParseIP(peerHost)
	if peerIP == nil || !isTrustedProxyIP(peerIP, trustedProxies) {
		return peerHost
	}

	xffValues := r.Header.Values("X-Forwarded-For")
	if len(xffValues) == 0 {
		return peerHost
	}
	xff := strings.Join(xffValues, ",")
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := net.ParseIP(strings.TrimSpace(hops[i]))
		if hop == nil {
			return peerHost
		}
		if !isTrustedProxyIP(hop, trustedProxies) {
			return hop.String()
		}
	}

	// Every forwarded hop is trusted. The leftmost entry is the originating
	// trusted peer and remains the most specific available source identity.
	return net.ParseIP(strings.TrimSpace(hops[0])).String()
}

func isTrustedProxyIP(ip net.IP, trustedProxies []net.IPNet) bool {
	for i := range trustedProxies {
		if trustedProxies[i].Contains(ip) {
			return true
		}
	}
	return false
}

// emitRegistrationManagementAudit records an audit event for a registration management action
// (approve, deny, approve-all, approve-by-cidr). It is a no-op when auditManager is nil.
func (s *Server) emitRegistrationManagementAudit(r *http.Request, action string, extras map[string]interface{}) {
	if s.auditManager == nil {
		return
	}
	callerTenant := s.callerTenantID(r)
	tenantID := callerTenant
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, business.AuditUserTypeHuman).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh)
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit registration management audit event",
			"error", err, "action", action)
	}
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
