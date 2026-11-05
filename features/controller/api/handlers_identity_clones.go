// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Audit actions written by the operator identity-clone verbs, and read by the
// clone list (ADR-034 §5).
const (
	auditActionCredentialsRotated = "steward_credentials_rotated"
	auditActionIdentityMoved      = "steward_identity_moved"

	// Detection events written by sibling stories; the list reads them back.
	auditActionIdentityConflictDetected = "steward_identity_conflict_detected"
	auditActionProvenanceDivergence     = "steward_provenance_divergence"

	// identityCloneAuditLimit bounds the detection events read for one list.
	identityCloneAuditLimit = 5000
)

// identityCloneQueuedCopy is a pending registration that reported being a copy
// of a steward ID.
type identityCloneQueuedCopy struct {
	PendingID    string    `json:"pending_id"`
	Hostname     string    `json:"hostname"`
	SourceIP     string    `json:"source_ip"`
	RegisteredAt time.Time `json:"registered_at"`

	// Set only for a copy admitted locked after declaring broken trust (ADR-034).
	// Everything after CloneReason is the steward's own claim or the token it
	// presented, not verified evidence: an operator confirms it out of band.
	CloneReason   string     `json:"clone_reason,omitempty"`
	CopyStewardID string     `json:"copy_steward_id,omitempty"`
	TokenLabel    string     `json:"token_label,omitempty"`
	OldLastSeen   *time.Time `json:"old_last_seen,omitempty"`
	ClaimVerified *bool      `json:"claim_verified,omitempty"`
}

// identityCloneEntry is the evidence for one steward ID with a detected copy.
// Provenance field names are listed, never their values.
type identityCloneEntry struct {
	StewardID        string                    `json:"steward_id"`
	TenantID         string                    `json:"tenant_id"`
	FirstDetected    *time.Time                `json:"first_detected,omitempty"`
	LastDetected     *time.Time                `json:"last_detected,omitempty"`
	DetectionCount   int                       `json:"detection_count"`
	ExistingPeer     string                    `json:"existing_peer,omitempty"`
	OtherPeer        string                    `json:"other_peer,omitempty"`
	Serials          []string                  `json:"serials,omitempty"`
	DivergentFields  []string                  `json:"divergent_fields,omitempty"`
	QueuedCopies     []identityCloneQueuedCopy `json:"queued_copies"`
	lastConflictTime time.Time
}

// identityCloneListResponse is the body of GET /api/v1/stewards/identity-clones.
type identityCloneListResponse struct {
	Clones []*identityCloneEntry `json:"clones"`
}

// auditStringSlice reads a string list out of an audit detail value, which is a
// []string when freshly built and a []interface{} after a storage round trip.
func auditStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func auditString(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}

func addUnique(list []string, vals ...string) []string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		found := false
		for _, e := range list {
			if e == v {
				found = true
				break
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}

// handleListIdentityClones handles GET /api/v1/stewards/identity-clones.
// It joins the detection audit events with the queued pending registrations
// that carry a CloneOf, scoped to the caller's tenants. No new storage.
func (s *Server) handleListIdentityClones(w http.ResponseWriter, r *http.Request) {
	tenantFilter, ok := s.tenantListFilterForScope(r)
	if !ok {
		s.writeErrorResponse(w, http.StatusForbidden, "Tenant scope unavailable", "TENANT_SCOPE_UNAVAILABLE")
		return
	}
	if s.stewardStore == nil || s.pendingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
		return
	}
	allowed := s.tenantAccessFilter(r, "GET /api/v1/stewards/identity-clones")
	ctx := r.Context()
	byID := make(map[string]*identityCloneEntry)

	entryFor := func(stewardID, tenantID string) *identityCloneEntry {
		e, ok := byID[stewardID]
		if !ok {
			e = &identityCloneEntry{StewardID: stewardID, TenantID: tenantID, QueuedCopies: []identityCloneQueuedCopy{}}
			byID[stewardID] = e
		}
		return e
	}

	// Detection evidence. The steward record is the authority for the tenant,
	// not the audit entry, which may have fallen back to a system tenant.
	if s.auditManager != nil {
		entries, err := s.auditManager.QueryEntries(ctx, &business.AuditFilter{
			Actions: []string{auditActionIdentityConflictDetected, auditActionProvenanceDivergence},
			Limit:   identityCloneAuditLimit,
			SortBy:  "timestamp",
			Order:   "asc",
		})
		if err != nil {
			s.logger.Error("identity clones: audit query failed", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read detection events", "INTERNAL_ERROR")
			return
		}
		recordTenant := make(map[string]string)
		for _, ae := range entries {
			stewardID := ae.ResourceID
			if stewardID == "" {
				stewardID = auditString(ae.Details, "steward_id")
			}
			if stewardID == "" {
				continue
			}
			tenantID, known := recordTenant[stewardID]
			if !known {
				rec, err := s.stewardStore.GetSteward(ctx, stewardID)
				if err == nil && rec != nil {
					tenantID = rec.TenantID
				}
				recordTenant[stewardID] = tenantID
			}
			if tenantID == "" || !allowed(tenantID) {
				continue
			}
			e := entryFor(stewardID, tenantID)
			ts := ae.Timestamp.UTC()
			e.noteDetection(ts)
			switch ae.Action {
			case auditActionIdentityConflictDetected:
				e.Serials = addUnique(e.Serials, auditString(ae.Details, "existing_serial"), auditString(ae.Details, "new_serial"))
				if !ts.Before(e.lastConflictTime) {
					e.lastConflictTime = ts
					e.ExistingPeer = auditString(ae.Details, "existing_addr")
					e.OtherPeer = auditString(ae.Details, "new_addr")
				}
				e.DivergentFields = addUnique(e.DivergentFields, auditStringSlice(ae.Details["provenance_divergent_keys"])...)
			case auditActionProvenanceDivergence:
				e.DivergentFields = addUnique(e.DivergentFields, auditStringSlice(ae.Details["divergent_keys"])...)
			}
		}
	}

	// Queued copies: pending registrations that named this steward as CloneOf.
	pending, err := s.pendingStore.ListPending(ctx, tenantFilter)
	if err != nil {
		s.logger.Error("identity clones: pending list failed", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list pending registrations", "INTERNAL_ERROR")
		return
	}
	for _, p := range pending {
		if p.CloneOf == "" || !allowed(p.TenantID) {
			continue
		}
		e := entryFor(p.CloneOf, p.TenantID)
		e.QueuedCopies = append(e.QueuedCopies, s.queuedCopyFor(ctx, p))
	}

	resp := identityCloneListResponse{Clones: make([]*identityCloneEntry, 0, len(byID))}
	for _, e := range byID {
		sort.Strings(e.Serials)
		sort.Strings(e.DivergentFields)
		resp.Clones = append(resp.Clones, e)
	}
	sort.Slice(resp.Clones, func(i, j int) bool { return resp.Clones[i].StewardID < resp.Clones[j].StewardID })
	s.writeSuccessResponse(w, resp)
}

// noteDetection counts one detection event at ts and widens the first/last
// detection window to include it.
func (e *identityCloneEntry) noteDetection(ts time.Time) {
	if e.FirstDetected == nil || ts.Before(*e.FirstDetected) {
		t := ts
		e.FirstDetected = &t
	}
	if e.LastDetected == nil || ts.After(*e.LastDetected) {
		t := ts
		e.LastDetected = &t
	}
	e.DetectionCount++
}

// queuedCopyFor builds the queued-copy evidence for a pending entry that names
// an old identity, with the locked-admission claim evidence when it was admitted
// locked.
func (s *Server) queuedCopyFor(ctx context.Context, p *business.PendingRegistrationEntry) identityCloneQueuedCopy {
	c := identityCloneQueuedCopy{
		PendingID:    p.PendingID,
		Hostname:     p.Hostname,
		SourceIP:     p.SourceIP,
		RegisteredAt: p.RegisteredAt.UTC(),
	}
	if s.isLockedAdmission(ctx, p) {
		s.addLockedCopyEvidence(ctx, &c, p)
	}
	return c
}

// addLockedCopyEvidence marks a queued copy as admitted locked and attaches the
// unverified claim evidence: the token's label and when the named old record was
// last seen.
func (s *Server) addLockedCopyEvidence(ctx context.Context, c *identityCloneQueuedCopy, p *business.PendingRegistrationEntry) {
	unverified := false
	c.CloneReason = cloneReasonBrokenTrust
	c.CopyStewardID = p.StewardID
	c.ClaimVerified = &unverified
	if old, err := s.stewardStore.GetSteward(ctx, p.CloneOf); err == nil && old != nil {
		seen := old.LastSeen
		if old.LastHeartbeatAt.After(seen) {
			seen = old.LastHeartbeatAt
		}
		if !seen.IsZero() {
			t := seen.UTC()
			c.OldLastSeen = &t
		}
	}
	if s.registrationTokenStore != nil {
		if tokens, err := s.registrationTokenStore.ListTokens(ctx, p.TenantID); err == nil {
			for _, t := range tokens {
				if business.RegistrationTokenLookupKey(t.Token) == p.TokenStr {
					c.TokenLabel = t.Label
					break
				}
			}
		}
	}
}

// operatorStewardRecord resolves the steward for an operator identity verb: it
// validates the ID, requires the stores and cert manager, and answers 404 for a
// missing steward or one outside the caller's tenant scope. On false the
// response has been written.
func (s *Server) operatorStewardRecord(w http.ResponseWriter, r *http.Request, route string) (*business.StewardRecord, bool) {
	record, ok := s.operatorStewardLookup(w, r, route)
	if !ok {
		return nil, false
	}
	switch record.Status {
	case business.StewardStatusRevoked, business.StewardStatusDeregistered,
		// tampered is not a valid source for rotate-credentials or identity move:
		// only an operator restore or ban ends it.
		business.StewardStatusTampered:
		s.writeErrorResponse(w, http.StatusConflict, "Steward is "+string(record.Status), "STEWARD_NOT_ACTIVE")
		return nil, false
	}
	return record, true
}

// operatorStewardLookup is operatorStewardRecord without the status check: it
// answers 404 for a missing steward or one outside the caller's tenant scope and
// leaves the status decision to the verb.
func (s *Server) operatorStewardLookup(w http.ResponseWriter, r *http.Request, route string) (*business.StewardRecord, bool) {
	stewardID := mux.Vars(r)["id"]
	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return nil, false
	}
	if s.stewardStore == nil || s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
		return nil, false
	}
	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		if errors.Is(err, business.ErrStewardNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return nil, false
		}
		s.logger.Error("identity verb: steward lookup failed",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up steward", "INTERNAL_ERROR")
		return nil, false
	}
	if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), record.TenantID, route); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		}
		return nil, false
	}
	return record, true
}

// revokeStewardSerials revokes every client-certificate serial issued for
// stewardID and returns them. A revocation reaches the control plane through the
// admission gate (checkPeerRevocation), including the periodic re-check of open
// streams.
func revokeStewardSerials(mgr *cert.Manager, stewardID string) ([]string, error) {
	infos, err := mgr.GetCertificateByCommonName(stewardID)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	serials := make([]string, 0, len(infos))
	for _, info := range infos {
		if info.Type != cert.CertificateTypeClient || info.SerialNumber == "" {
			continue
		}
		if err := mgr.Revoke(info.SerialNumber); err != nil {
			return serials, fmt.Errorf("revoke serial %s: %w", info.SerialNumber, err)
		}
		serials = append(serials, info.SerialNumber)
	}
	sort.Strings(serials)
	return serials, nil
}

func (s *Server) emitIdentityOperatorAudit(ctx context.Context, r *http.Request, action string, record *business.StewardRecord, extras map[string]interface{}) {
	s.emitOperatorAuditResult(ctx, r, action, business.AuditResultSuccess, record, extras)
}

// emitOperatorAuditResult writes a high-severity security audit event naming the
// acting principal, with the given result (a refused verb is recorded as denied).
func (s *Server) emitOperatorAuditResult(ctx context.Context, r *http.Request, action string, result business.AuditResult, record *business.StewardRecord, extras map[string]interface{}) {
	if s.auditManager == nil {
		return
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	b := audit.NewEventBuilder().
		Tenant(record.TenantID).
		Type(business.AuditEventSecurityEvent).
		Action(action).
		User(principalID, business.AuditUserTypeHuman).
		Resource("steward", record.ID, "").
		Result(result).
		Severity(business.AuditSeverityHigh).
		Detail("steward_id", record.ID)
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit identity operator audit event",
			"action", action, "error", logging.SanitizeLogValue(err.Error()))
	}
}

// rotateCredentialsResponse is the body of POST /stewards/{id}/credentials/rotate.
type rotateCredentialsResponse struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials"`
	NextStep       string   `json:"next_step"`
}

// handleRotateCredentials handles POST /api/v1/stewards/{id}/credentials/rotate
// (ADR-034 §5 removal): revoke every client-certificate serial issued for the
// steward and archive the record, so the next refresh is queued for approval
// whatever the refresh policy says.
func (s *Server) handleRotateCredentials(w http.ResponseWriter, r *http.Request) {
	record, ok := s.operatorStewardRecord(w, r, "POST /api/v1/stewards/{id}/credentials/rotate")
	if !ok {
		return
	}
	serials, err := revokeStewardSerials(s.certManager, record.ID)
	if err != nil {
		s.logger.Error("rotate credentials: revocation failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke certificates; retry", "INTERNAL_ERROR")
		return
	}
	if _, err := s.stewardStore.TransitionStewardStatus(r.Context(), record.ID, business.StewardStatusArchived,
		business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost,
		business.StewardStatusDormant, business.StewardStatusArchived); err != nil {
		s.logger.Error("rotate credentials: archive failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Certificates revoked but the record could not be archived; retry", "INTERNAL_ERROR")
		return
	}
	if s.controllerService != nil {
		if err := s.controllerService.UpdateStewardStatus(record.ID, string(business.StewardStatusArchived)); err != nil {
			s.logger.Debug("rotate credentials: in-memory status update skipped",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	s.emitIdentityOperatorAudit(r.Context(), r, auditActionCredentialsRotated, record, map[string]interface{}{
		"revoked_serials": serials,
		"previous_status": string(record.Status),
	})
	s.logger.Info("Steward credentials rotated",
		"steward_id", logging.SanitizeLogValue(record.ID), "revoked_serials", len(serials))
	s.writeSuccessResponse(w, rotateCredentialsResponse{
		ID:             record.ID,
		Status:         string(business.StewardStatusArchived),
		RevokedSerials: serials,
		NextStep:       "The approved machine will re-admit with its device key; complete the rotation with `cfg refresh approve` after checking that machine.",
	})
}

// moveIdentityRequest is the body of POST /stewards/{id}/identity/move.
type moveIdentityRequest struct {
	PendingID string `json:"pending_id"`

	// ConfirmLive acknowledges linking a locked copy to an old record that has
	// heartbeated within linkLiveWindow: the machine holding it may be the
	// legitimate one.
	ConfirmLive bool `json:"confirm_live,omitempty"`
}

// moveIdentityResponse is the body of POST /stewards/{id}/identity/move.
type moveIdentityResponse struct {
	ID             string   `json:"id"`
	PendingID      string   `json:"pending_id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials"`
	NextStep       string   `json:"next_step"`

	// Set when the move linked a locked copy back to its old identity.
	CopyStewardID string `json:"copy_steward_id,omitempty"`
}

// handleMoveIdentity handles POST /api/v1/stewards/{id}/identity/move
// (ADR-034 §5 move): the machine that kept the identity is the wrong one, so the
// steward record is rebound to the queued copy's device identity, the queued
// entry is pointed at the original steward ID and approved (the ordinary claim
// then signs the certificate under that ID), and the previous serials are
// revoked. Nothing else moves an identity.
func (s *Server) handleMoveIdentity(w http.ResponseWriter, r *http.Request) {
	// A tampered record is a valid source only when the queued entry is a locked
	// copy being linked back to it; that is decided once the entry is loaded.
	record, ok := s.operatorStewardLookup(w, r, "POST /api/v1/stewards/{id}/identity/move")
	if !ok {
		return
	}
	if record.Status == business.StewardStatusRevoked || record.Status == business.StewardStatusDeregistered {
		s.writeErrorResponse(w, http.StatusConflict, "Steward is "+string(record.Status), "STEWARD_NOT_ACTIVE")
		return
	}
	if s.pendingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Registration store unavailable", "SERVICE_UNAVAILABLE")
		return
	}
	var req moveIdentityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.PendingID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "pending_id is required", "INVALID_REQUEST")
		return
	}
	ctx := r.Context()
	entry, ok := s.loadMoveEntry(w, r, record, req.PendingID)
	if !ok {
		return
	}
	if s.tryLinkLockedCopy(w, r, record, entry, req.ConfirmLive) {
		return
	}
	if !s.ordinaryMoveAllowed(w, record, entry) {
		return
	}

	// (a) Rebind the record. A device_id conflict changes nothing.
	oldDeviceID, oldKey, oldLevel, oldAlg := record.DeviceID, record.IdentityKeyPub, record.KeyProtectionLevel, record.KeyAlgorithm
	if err := s.stewardStore.RebindStewardIdentity(ctx, record.ID, entry.DeviceID, entry.IdentityKeyPub, entry.KeyProtectionLevel, entry.KeyAlgorithm); err != nil {
		if errors.Is(err, business.ErrStewardDeviceIDConflict) {
			s.writeErrorResponse(w, http.StatusConflict, "Device identity is held by another steward in this tenant", "DEVICE_ID_CONFLICT")
			return
		}
		s.logger.Error("move identity: rebind failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to move identity", "INTERNAL_ERROR")
		return
	}

	// (b) Point the queued entry at the original ID and approve it.
	stepErr := s.pendingStore.ReassignPendingSteward(ctx, entry.PendingID, record.ID)
	if stepErr == nil {
		stepErr = s.pendingStore.UpdateStatus(ctx, entry.PendingID, business.PendingRegistrationStatusApproved)
	}
	if stepErr != nil {
		// Put the record back so the original machine keeps its identity.
		if rbErr := s.stewardStore.RebindStewardIdentity(ctx, record.ID, oldDeviceID, oldKey, oldLevel, oldAlg); rbErr != nil {
			s.logger.Error("move identity: rollback of rebind failed",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(rbErr.Error()))
		}
		if errors.Is(stepErr, business.ErrPendingRegistrationNotFound) {
			s.writeErrorResponse(w, http.StatusConflict, "Queued copy was modified concurrently; reload and retry", "PENDING_CONFLICT")
			return
		}
		s.logger.Error("move identity: approving queued copy failed",
			"pending_id", logging.SanitizeLogValue(entry.PendingID), "error", logging.SanitizeLogValue(stepErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to move identity", "INTERNAL_ERROR")
		return
	}

	// (c) Revoke every serial issued so far. The queued machine's certificate is
	// signed at claim, after this point, so it is not affected.
	serials, err := revokeStewardSerials(s.certManager, record.ID)
	if err != nil {
		s.logger.Error("move identity: revocation failed after move",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Identity moved but old certificates could not all be revoked; run rotate-credentials to finish", "INTERNAL_ERROR")
		return
	}
	s.emitIdentityOperatorAudit(ctx, r, auditActionIdentityMoved, record, map[string]interface{}{
		"pending_id":      entry.PendingID,
		"old_device_id":   oldDeviceID,
		"new_device_id":   entry.DeviceID,
		"revoked_serials": serials,
	})
	s.logger.Info("Steward identity moved",
		"steward_id", logging.SanitizeLogValue(record.ID),
		"pending_id", logging.SanitizeLogValue(entry.PendingID), "revoked_serials", len(serials))
	s.writeSuccessResponse(w, moveIdentityResponse{
		ID:             record.ID,
		PendingID:      entry.PendingID,
		Status:         string(business.PendingRegistrationStatusApproved),
		RevokedSerials: serials,
		NextStep:       "The queued machine claims its approved registration under the original steward ID on its next poll; the previous machine's certificates are revoked.",
	})
}

// loadMoveEntry loads the queued entry an identity move names. An entry in
// another tenant, or one that does not name record as its CloneOf, is reported
// as not found so one tenant cannot probe another tenant's queue. On false the
// response has been written.
func (s *Server) loadMoveEntry(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, pendingID string) (*business.PendingRegistrationEntry, bool) {
	entry, err := s.pendingStore.GetPendingByID(r.Context(), pendingID)
	if err != nil && !errors.Is(err, business.ErrPendingRegistrationNotFound) {
		s.logger.Error("move identity: pending lookup failed",
			"pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up pending registration", "INTERNAL_ERROR")
		return nil, false
	}
	if err != nil || entry.TenantID != record.TenantID || entry.CloneOf != record.ID {
		s.writeErrorResponse(w, http.StatusNotFound, "Queued copy not found for this steward", "PENDING_NOT_FOUND")
		return nil, false
	}
	return entry, true
}

// tryLinkLockedCopy links entry back to record when entry is a locked copy of
// it, and reports whether it handled the request (including a lookup failure,
// answered 500). On false the request is an ordinary move.
func (s *Server) tryLinkLockedCopy(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, entry *business.PendingRegistrationEntry, confirmLive bool) bool {
	lk, locked, err := s.lockedLinkTarget(r.Context(), record, entry)
	if err != nil {
		s.logger.Error("move identity: copy lookup failed",
			"pending_id", logging.SanitizeLogValue(entry.PendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up queued copy", "INTERNAL_ERROR")
		return true
	}
	if !locked {
		return false
	}
	s.linkLockedCopy(w, r, record, entry, lk, confirmLive)
	return true
}

// ordinaryMoveAllowed checks the source record and queued entry of an ordinary
// (not locked-copy) move. On false the response has been written.
func (s *Server) ordinaryMoveAllowed(w http.ResponseWriter, record *business.StewardRecord, entry *business.PendingRegistrationEntry) bool {
	// tampered is not a valid source for an ordinary move: only an operator
	// restore or ban ends it.
	if record.Status == business.StewardStatusTampered {
		s.writeErrorResponse(w, http.StatusConflict, "Steward is "+string(record.Status), "STEWARD_NOT_ACTIVE")
		return false
	}
	if entry.Status != business.PendingRegistrationStatusPending {
		s.writeErrorResponse(w, http.StatusConflict, "Queued copy is no longer pending", "PENDING_NOT_PENDING")
		return false
	}
	return s.queuedCopyHasIdentity(w, entry)
}

// queuedCopyHasIdentity answers 400 when the queued entry carries no device
// identity to rebind to, and reports whether it has one.
func (s *Server) queuedCopyHasIdentity(w http.ResponseWriter, entry *business.PendingRegistrationEntry) bool {
	if entry.DeviceID == "" || len(entry.IdentityKeyPub) == 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, "Queued copy carries no device identity", "INVALID_REQUEST")
		return false
	}
	return true
}

const (
	// linkLiveWindow is how recent the old record's last heartbeat must be for
	// linking a locked copy to it to need confirm_live.
	linkLiveWindow = 10 * time.Minute

	auditActionLinkStep    = "steward_identity_link_step"
	auditActionLinkFailed  = "steward_identity_link_failed"
	auditActionLinkRefused = "steward_identity_link_refused"
)

// Names of the link steps, reported in a failure response and in the audit trail.
const (
	linkStepRetireCopy    = "retire_copy"
	linkStepRebindOld     = "rebind_old_identity"
	linkStepRevokeOld     = "revoke_old_credentials"
	linkStepApprovePend   = "approve_pending"
	linkStepSupersedePend = "supersede_pending"
)

// lockedLink describes a queued entry that belongs to a copy admitted locked.
type lockedLink struct {
	copyID string // the copy's steward ID; empty when the entry already points at the old ID
	// copyRetired is set when the copy is already deregistered, or the entry
	// already names the old ID: an earlier attempt got past the retire step.
	copyRetired bool
}

// lockedLinkTarget decides whether entry is a locked copy of record. The entry
// is one when it was admitted locked: its steward record exists in the old
// record's tenant and is tampered (or deregistered by an earlier link attempt),
// or an earlier attempt already pointed it at the old ID.
func (s *Server) lockedLinkTarget(ctx context.Context, record *business.StewardRecord, entry *business.PendingRegistrationEntry) (lockedLink, bool, error) {
	if entry.Status != business.PendingRegistrationStatusPending && entry.Status != business.PendingRegistrationStatusApproved {
		return lockedLink{}, false, nil
	}
	if entry.StewardID == record.ID {
		return lockedLink{copyRetired: true}, s.stoppedLink(ctx, record, entry), nil
	}
	copyRec, err := s.stewardStore.GetSteward(ctx, entry.StewardID)
	if err != nil {
		if errors.Is(err, business.ErrStewardNotFound) {
			return lockedLink{}, false, nil
		}
		return lockedLink{}, false, err
	}
	lk, ok := lockedLinkForCopy(record, copyRec)
	return lk, ok, nil
}

// stoppedLink reports whether an entry already on the old ID is a link that
// stopped part-way: still pending, or approved with a recorded link approval. An
// ordinary move leaves an approved entry in the same shape and must stay refused.
func (s *Server) stoppedLink(ctx context.Context, record *business.StewardRecord, entry *business.PendingRegistrationEntry) bool {
	return entry.Status == business.PendingRegistrationStatusPending || s.linkApprovalAudited(ctx, record, entry.PendingID)
}

// lockedLinkForCopy classifies the entry's steward record: tampered is a locked
// copy, deregistered one an earlier attempt already retired.
func lockedLinkForCopy(record, copyRec *business.StewardRecord) (lockedLink, bool) {
	if copyRec == nil || copyRec.TenantID != record.TenantID {
		return lockedLink{}, false
	}
	switch copyRec.Status {
	case business.StewardStatusTampered:
		return lockedLink{copyID: copyRec.ID}, true
	case business.StewardStatusDeregistered:
		return lockedLink{copyID: copyRec.ID, copyRetired: true}, true
	}
	return lockedLink{}, false
}

// linkLockedCopy links a locked copy back to its old identity (ADR-034): the
// copy is retired and its credential revoked, the old record is rebound to the
// copy's device identity, the old ID's own credentials are revoked, and the queued
// entry is pointed at the old ID and approved, then superseded so it can never be
// claimed (the endpoint returns through the refresh flow). The old record keeps
// its status.
//
// The steps are ordered so no window leaves two live credentials for one
// identity, and a failure up to the approval leaves the old record as it was.
// Every step is idempotent, so a retry completes a link that stopped part-way.
func (s *Server) linkLockedCopy(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, entry *business.PendingRegistrationEntry, lk lockedLink, confirmLive bool) {
	// An earlier attempt that approved the entry but failed to supersede it only
	// has the supersede step left.
	supersedeOnly := entry.Status == business.PendingRegistrationStatusApproved &&
		entry.StewardID == record.ID && record.DeviceID == entry.DeviceID
	live, ok := s.linkPreconditions(w, r, record, entry, lk, supersedeOnly, confirmLive)
	if !ok {
		return
	}
	l := &linkRun{s: s, w: w, r: r, ctx: r.Context(), record: record, entry: entry, lk: lk, confirmed: live && confirmLive}

	var serials []string
	if !supersedeOnly {
		if serials, ok = l.relinkIdentity(); !ok {
			return
		}
	}
	// (5) The approved entry is never claimed: supersede it so it cannot be.
	if !l.supersedePending() {
		return
	}
	l.finish(serials)
}

// linkPreconditions checks that entry can be linked and, when the old record
// heartbeated within linkLiveWindow, that the operator confirmed it. It returns
// whether the old record is live. On false the response has been written.
func (s *Server) linkPreconditions(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, entry *business.PendingRegistrationEntry,
	lk lockedLink, supersedeOnly, confirmLive bool) (live bool, ok bool) {
	if entry.Status != business.PendingRegistrationStatusPending && !supersedeOnly {
		s.writeErrorResponse(w, http.StatusConflict, "Queued copy is no longer pending", "PENDING_NOT_PENDING")
		return false, false
	}
	if !s.queuedCopyHasIdentity(w, entry) {
		return false, false
	}
	live = !supersedeOnly && !record.LastHeartbeatAt.IsZero() && time.Since(record.LastHeartbeatAt) <= linkLiveWindow
	if live && !confirmLive {
		s.emitOperatorAuditResult(r.Context(), r, auditActionLinkRefused, business.AuditResultDenied, record, map[string]interface{}{
			"pending_id": entry.PendingID, "copy_steward_id": lk.copyID, "reason": "confirm_live_required",
		})
		s.writeErrorResponse(w, http.StatusConflict,
			"The old record heartbeated within the last 10 minutes, so the machine holding it may be the legitimate one; repeat the request with confirm_live to link anyway",
			"CONFIRM_LIVE_REQUIRED")
		return false, false
	}
	return live, true
}

// linkRun carries one link of a locked copy through its steps; each step audits
// itself on success and, on failure, rolls back what it must, audits the failed
// step and writes the response.
type linkRun struct {
	s         *Server
	w         http.ResponseWriter
	r         *http.Request
	ctx       context.Context
	record    *business.StewardRecord
	entry     *business.PendingRegistrationEntry
	lk        lockedLink
	confirmed bool // the old record was live and the operator confirmed it
}

// step audits a completed link step.
func (l *linkRun) step(name string, extras map[string]interface{}) {
	d := map[string]interface{}{
		"step":            name,
		"confirm_live":    l.confirmed,
		"pending_id":      l.entry.PendingID,
		"copy_steward_id": l.lk.copyID,
	}
	for k, v := range extras {
		d[k] = v
	}
	l.s.emitIdentityOperatorAudit(l.ctx, l.r, auditActionLinkStep, l.record, d)
}

// fail runs rollback (when set), audits the failed step and answers status.
func (l *linkRun) fail(status int, code, name string, err error, rollback func()) {
	if rollback != nil {
		rollback()
	}
	l.s.logger.Error("link locked copy: step failed",
		"steward_id", logging.SanitizeLogValue(l.record.ID), "step", name, "error", logging.SanitizeLogValue(err.Error()))
	l.s.emitOperatorAuditResult(l.ctx, l.r, auditActionLinkFailed, business.AuditResultFailure, l.record, map[string]interface{}{
		"pending_id": l.entry.PendingID, "copy_steward_id": l.lk.copyID, "step": name,
	})
	l.s.writeErrorResponse(l.w, status, "Link failed at step "+name+"; retry to complete the link", code)
}

// relinkIdentity runs steps (1) to (4) and returns the old ID's revoked serials.
func (l *linkRun) relinkIdentity() ([]string, bool) {
	if !l.retireCopy() {
		return nil, false
	}
	rollbackRebind, ok := l.rebindOld()
	if !ok {
		return nil, false
	}
	// (3) The old ID's own credentials end before anything can return under it.
	serials, err := revokeStewardSerials(l.s.certManager, l.record.ID)
	if err != nil {
		l.fail(http.StatusInternalServerError, "LINK_STEP_FAILED", linkStepRevokeOld, err, rollbackRebind)
		return nil, false
	}
	l.step(linkStepRevokeOld, map[string]interface{}{"revoked_serials": serials})
	if !l.approvePending(rollbackRebind) {
		return nil, false
	}
	return serials, true
}

// retireCopy is step (1): the copy's credential dies first, then its record,
// which frees its device_id for the old record.
func (l *linkRun) retireCopy() bool {
	if l.lk.copyID == "" {
		return true
	}
	copySerials, err := revokeStewardSerials(l.s.certManager, l.lk.copyID)
	if err != nil {
		l.fail(http.StatusInternalServerError, "LINK_STEP_FAILED", linkStepRetireCopy, err, nil)
		return false
	}
	if !l.lk.copyRetired && !l.deregisterCopy() {
		return false
	}
	if l.s.controllerService != nil {
		if uErr := l.s.controllerService.UpdateStewardStatus(l.lk.copyID, string(business.StewardStatusDeregistered)); uErr != nil {
			l.s.logger.Debug("link: in-memory status update skipped",
				"steward_id", logging.SanitizeLogValue(l.lk.copyID), "error", logging.SanitizeLogValue(uErr.Error()))
		}
	}
	l.s.evictStewardStream(l.lk.copyID)
	l.step(linkStepRetireCopy, map[string]interface{}{"revoked_serials": copySerials})
	return true
}

// deregisterCopy moves the copy's record from tampered to deregistered; a copy
// that is no longer tampered is a conflict.
func (l *linkRun) deregisterCopy() bool {
	transitioned, err := l.s.stewardStore.TransitionStewardStatus(l.ctx, l.lk.copyID, business.StewardStatusDeregistered, business.StewardStatusTampered)
	if err != nil {
		l.fail(http.StatusInternalServerError, "LINK_STEP_FAILED", linkStepRetireCopy, err, nil)
		return false
	}
	if !transitioned {
		l.fail(http.StatusConflict, "LINK_COPY_CHANGED", linkStepRetireCopy, errors.New("copy is no longer locked"), nil)
		return false
	}
	return true
}

// rebindOld is step (2): rebind the old record to the copy's device identity. It
// returns the rollback that restores the old record's previous identity.
func (l *linkRun) rebindOld() (func(), bool) {
	record, entry := l.record, l.entry
	oldDeviceID, oldKey, oldLevel, oldAlg := record.DeviceID, record.IdentityKeyPub, record.KeyProtectionLevel, record.KeyAlgorithm
	if record.DeviceID != entry.DeviceID || !bytes.Equal(record.IdentityKeyPub, entry.IdentityKeyPub) {
		if err := l.s.stewardStore.RebindStewardIdentity(l.ctx, record.ID, entry.DeviceID, entry.IdentityKeyPub, entry.KeyProtectionLevel, entry.KeyAlgorithm); err != nil {
			status, code := http.StatusInternalServerError, "LINK_STEP_FAILED"
			if errors.Is(err, business.ErrStewardDeviceIDConflict) {
				status, code = http.StatusConflict, "DEVICE_ID_CONFLICT"
			}
			l.fail(status, code, linkStepRebindOld, err, nil)
			return nil, false
		}
	}
	l.step(linkStepRebindOld, map[string]interface{}{"old_device_id": oldDeviceID, "new_device_id": entry.DeviceID})
	return func() {
		if rbErr := l.s.stewardStore.RebindStewardIdentity(l.ctx, record.ID, oldDeviceID, oldKey, oldLevel, oldAlg); rbErr != nil {
			l.s.logger.Error("link locked copy: rollback of rebind failed",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(rbErr.Error()))
		}
	}, true
}

// approvePending is step (4): point the entry at the old ID and approve it. A
// failure undoes the reassignment and the rebind.
func (l *linkRun) approvePending(rollbackRebind func()) bool {
	reassigned := false
	var err error
	if l.entry.StewardID != l.record.ID {
		if err = l.s.pendingStore.ReassignPendingSteward(l.ctx, l.entry.PendingID, l.record.ID); err == nil {
			reassigned = true
		}
	}
	if err == nil {
		err = l.s.pendingStore.UpdateStatus(l.ctx, l.entry.PendingID, business.PendingRegistrationStatusApproved)
	}
	if err == nil {
		l.step(linkStepApprovePend, nil)
		return true
	}
	status, code := http.StatusInternalServerError, "LINK_STEP_FAILED"
	if errors.Is(err, business.ErrPendingRegistrationNotFound) {
		status, code = http.StatusConflict, "PENDING_CONFLICT"
	}
	l.fail(status, code, linkStepApprovePend, err, func() {
		if reassigned {
			l.undoReassign()
		}
		rollbackRebind()
	})
	return false
}

// undoReassign points the entry back at the copy's steward ID.
func (l *linkRun) undoReassign() {
	if l.lk.copyID == "" {
		return
	}
	if err := l.s.pendingStore.ReassignPendingSteward(l.ctx, l.entry.PendingID, l.lk.copyID); err != nil {
		l.s.logger.Error("link locked copy: rollback of reassignment failed",
			"pending_id", logging.SanitizeLogValue(l.entry.PendingID), "error", logging.SanitizeLogValue(err.Error()))
	}
}

// supersedePending is step (5): the approved entry is superseded so it can never
// be claimed.
func (l *linkRun) supersedePending() bool {
	if err := l.s.pendingStore.UpdateStatus(l.ctx, l.entry.PendingID, business.PendingRegistrationStatusDenied); err != nil {
		l.fail(http.StatusInternalServerError, "LINK_STEP_FAILED", linkStepSupersedePend, err, nil)
		return false
	}
	l.step(linkStepSupersedePend, nil)
	return true
}

// finish audits the completed link and answers with its outcome.
func (l *linkRun) finish(serials []string) {
	record, entry := l.record, l.entry
	l.s.emitIdentityOperatorAudit(l.ctx, l.r, auditActionIdentityMoved, record, map[string]interface{}{
		"pending_id":      entry.PendingID,
		"copy_steward_id": l.lk.copyID,
		"new_device_id":   entry.DeviceID,
		"revoked_serials": serials,
		"linked":          true,
		"confirm_live":    l.confirmed,
	})
	l.s.logger.Info("Locked copy linked to its old identity",
		"steward_id", logging.SanitizeLogValue(record.ID), "pending_id", logging.SanitizeLogValue(entry.PendingID))
	l.s.writeSuccessResponse(l.w, moveIdentityResponse{
		ID:             record.ID,
		PendingID:      entry.PendingID,
		Status:         "linked",
		RevokedSerials: serials,
		CopyStewardID:  l.lk.copyID,
		NextStep:       "The locked copy is retired. The endpoint returns under the original steward ID through its refresh; the original record keeps its current status until it is restored.",
	})
}

// lockedCopyNamingOldID returns the pending entry of a locked copy that names an
// old identity, or nil when record is not such a copy.
func (s *Server) lockedCopyNamingOldID(ctx context.Context, record *business.StewardRecord) (*business.PendingRegistrationEntry, error) {
	if s.pendingStore == nil {
		return nil, nil
	}
	pending, err := s.pendingStore.ListPending(ctx, record.TenantID)
	if err != nil {
		return nil, err
	}
	for _, p := range pending {
		if p.StewardID == record.ID && p.CloneOf != "" {
			return p, nil
		}
	}
	return nil, nil
}

// linkApprovalAudited reports whether a link approved pendingID for record, from
// the audit trail of the link steps.
func (s *Server) linkApprovalAudited(ctx context.Context, record *business.StewardRecord, pendingID string) bool {
	if s.auditManager == nil {
		return false
	}
	entries, err := s.auditManager.QueryEntries(ctx, &business.AuditFilter{
		Actions:     []string{auditActionLinkStep},
		ResourceIDs: []string{record.ID},
		Limit:       identityCloneAuditLimit,
	})
	if err != nil {
		return false
	}
	for _, e := range entries {
		if auditString(e.Details, "step") == linkStepApprovePend && auditString(e.Details, "pending_id") == pendingID {
			return true
		}
	}
	return false
}
