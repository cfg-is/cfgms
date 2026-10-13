// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
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
			if e.FirstDetected == nil || ts.Before(*e.FirstDetected) {
				t := ts
				e.FirstDetected = &t
			}
			if e.LastDetected == nil || ts.After(*e.LastDetected) {
				t := ts
				e.LastDetected = &t
			}
			e.DetectionCount++
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
		e.QueuedCopies = append(e.QueuedCopies, identityCloneQueuedCopy{
			PendingID:    p.PendingID,
			Hostname:     p.Hostname,
			SourceIP:     p.SourceIP,
			RegisteredAt: p.RegisteredAt.UTC(),
		})
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

// operatorStewardRecord resolves the steward for an operator identity verb: it
// validates the ID, requires the stores and cert manager, and answers 404 for a
// missing steward or one outside the caller's tenant scope. On false the
// response has been written.
func (s *Server) operatorStewardRecord(w http.ResponseWriter, r *http.Request, route string) (*business.StewardRecord, bool) {
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
	switch record.Status {
	case business.StewardStatusRevoked, business.StewardStatusDeregistered:
		s.writeErrorResponse(w, http.StatusConflict, "Steward is "+string(record.Status), "STEWARD_NOT_ACTIVE")
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
		Result(business.AuditResultSuccess).
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
}

// moveIdentityResponse is the body of POST /stewards/{id}/identity/move.
type moveIdentityResponse struct {
	ID             string   `json:"id"`
	PendingID      string   `json:"pending_id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials"`
	NextStep       string   `json:"next_step"`
}

// handleMoveIdentity handles POST /api/v1/stewards/{id}/identity/move
// (ADR-034 §5 move): the machine that kept the identity is the wrong one, so the
// steward record is rebound to the queued copy's device identity, the queued
// entry is pointed at the original steward ID and approved (the ordinary claim
// then signs the certificate under that ID), and the previous serials are
// revoked. Nothing else moves an identity.
func (s *Server) handleMoveIdentity(w http.ResponseWriter, r *http.Request) {
	record, ok := s.operatorStewardRecord(w, r, "POST /api/v1/stewards/{id}/identity/move")
	if !ok {
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
	notFound := func() {
		s.writeErrorResponse(w, http.StatusNotFound, "Queued copy not found for this steward", "PENDING_NOT_FOUND")
	}
	entry, err := s.pendingStore.GetPendingByID(ctx, req.PendingID)
	if err != nil {
		if errors.Is(err, business.ErrPendingRegistrationNotFound) {
			notFound()
			return
		}
		s.logger.Error("move identity: pending lookup failed",
			"pending_id", logging.SanitizeLogValue(req.PendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up pending registration", "INTERNAL_ERROR")
		return
	}
	// Same tenant and an explicit CloneOf: anything else is reported as not found
	// so one tenant cannot probe another tenant's queue.
	if entry.TenantID != record.TenantID || entry.CloneOf != record.ID {
		notFound()
		return
	}
	if entry.Status != business.PendingRegistrationStatusPending {
		s.writeErrorResponse(w, http.StatusConflict, "Queued copy is no longer pending", "PENDING_NOT_PENDING")
		return
	}
	if entry.DeviceID == "" || len(entry.IdentityKeyPub) == 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, "Queued copy carries no device identity", "INVALID_REQUEST")
		return
	}

	// (a) Rebind the record. A device_id conflict changes nothing.
	oldDeviceID, oldKey, oldLevel := record.DeviceID, record.IdentityKeyPub, record.KeyProtectionLevel
	if err := s.stewardStore.RebindStewardIdentity(ctx, record.ID, entry.DeviceID, entry.IdentityKeyPub, entry.KeyProtectionLevel); err != nil {
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
		if rbErr := s.stewardStore.RebindStewardIdentity(ctx, record.ID, oldDeviceID, oldKey, oldLevel); rbErr != nil {
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
