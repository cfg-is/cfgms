// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SetCasesStore wires the cockpit case store (Issue #3605). When nil (default),
// the /api/v1/cases handlers return 503. Call after New() but before Start().
func (s *Server) SetCasesStore(store business.CaseStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.casesStore = store
}

// CasesStore returns the wired case store, or nil when unwired. Exposed so
// controller startup wiring can be regression-tested (Issue #3605).
func (s *Server) CasesStore() business.CaseStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.casesStore
}

// caseInCallerSubtree reports whether a case's tenant falls within the caller's
// tenant subtree. An empty callerTenant means the caller has global scope and
// all cases are visible. Mirrors the subtree check used by ip-trust and
// registration-token handlers.
func caseInCallerSubtree(caseTenantID, callerTenant string) bool {
	if callerTenant == "" {
		return true
	}
	return caseTenantID == callerTenant || strings.HasPrefix(caseTenantID, callerTenant+"/")
}

// createCaseRequest is the JSON body for POST /api/v1/cases.
type createCaseRequest struct {
	TenantID string          `json:"tenant_id"`
	Ticket   caseTicketInput `json:"ticket"`
}

// updateCaseRequest is the JSON body for PUT /api/v1/cases/{id}.
type updateCaseRequest struct {
	Status string          `json:"status"`
	Ticket caseTicketInput `json:"ticket"`
}

// caseTicketInput is the per-field ticket shape accepted on writes.
type caseTicketInput struct {
	Title    caseTicketFieldInput `json:"title"`
	Client   caseTicketFieldInput `json:"client"`
	Contact  caseTicketFieldInput `json:"contact"`
	Priority caseTicketFieldInput `json:"priority"`
	Category caseTicketFieldInput `json:"category"`
}

// caseTicketFieldInput carries value and source for a single ticket field.
type caseTicketFieldInput struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// parseCaseStatus maps a client-supplied status string onto a business.CaseStatus,
// reporting false for anything outside the persisted set. Neither case store
// constrains the column (both schemas declare `status TEXT NOT NULL` with no CHECK),
// so an unchecked cast would let a caller park a case in a status that
// status-based filtering and closure semantics cannot reason about.
func parseCaseStatus(s string) (business.CaseStatus, bool) {
	switch business.CaseStatus(s) {
	case business.CaseStatusOpen:
		return business.CaseStatusOpen, true
	case business.CaseStatusClosed:
		return business.CaseStatusClosed, true
	default:
		return "", false
	}
}

// parseTicketFieldSource maps a client-supplied source string onto a
// business.TicketFieldSource, reporting false for anything outside the five
// declared provenance values. Per-field provenance is load-bearing in the
// cockpit UI (ADR-022 §8), so a forged source is a correctness defect, not a
// cosmetic one.
func parseTicketFieldSource(s string) (business.TicketFieldSource, bool) {
	switch business.TicketFieldSource(s) {
	case business.TicketFieldSourceEmail:
		return business.TicketFieldSourceEmail, true
	case business.TicketFieldSourceCallerID:
		return business.TicketFieldSourceCallerID, true
	case business.TicketFieldSourcePSA:
		return business.TicketFieldSourcePSA, true
	case business.TicketFieldSourceOperator:
		return business.TicketFieldSourceOperator, true
	case business.TicketFieldSourceInferred:
		return business.TicketFieldSourceInferred, true
	default:
		return "", false
	}
}

// validateTicketInput rejects any ticket field carrying a source outside the five
// TicketFieldSource constants. An omitted source is not an error: it defaults to
// operator in ticketFieldFromInput, since this API surface is operator-driven.
func validateTicketInput(t caseTicketInput) error {
	fields := []struct {
		name  string
		input caseTicketFieldInput
	}{
		{"title", t.Title},
		{"client", t.Client},
		{"contact", t.Contact},
		{"priority", t.Priority},
		{"category", t.Category},
	}
	for _, f := range fields {
		if f.input.Source == "" {
			continue
		}
		if _, ok := parseTicketFieldSource(f.input.Source); !ok {
			return fmt.Errorf(
				"ticket.%s.source must be one of: email, caller-id, psa, operator, inferred", f.name)
		}
	}
	return nil
}

// handleCreateCase handles POST /api/v1/cases.
// Creates a case in the caller's tenant, rejecting a supplied tenant_id outside
// the caller's subtree.
func (s *Server) handleCreateCase(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}

	var req createCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateTicketInput(req.Ticket); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_TICKET_FIELD_SOURCE")
		return
	}

	callerTenant := callerTenantSubtree(r)
	// Validate the supplied tenant_id: must be within the caller's subtree.
	// If not supplied, default to the caller's own tenant.
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = callerTenant
	}
	if !caseInCallerSubtree(tenantID, callerTenant) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"tenant_id is outside caller's tenant subtree", "TENANT_OUTSIDE_SUBTREE")
		return
	}
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"tenant_id is required for global-scope callers", "TENANT_ID_REQUIRED")
		return
	}

	now := time.Now().UTC()
	c := &business.Case{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		Status:    business.CaseStatusOpen,
		Ticket:    ticketFromInput(req.Ticket),
		Pins:      []*business.Pin{},
		Content:   []*business.ContentEntry{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.casesStore.CreateCase(r.Context(), c); err != nil {
		s.logger.Error("handleCreateCase: store failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to create case", http.StatusInternalServerError)
		return
	}

	s.writeResponse(w, http.StatusCreated, caseToResponse(c))
}

// handleListCases handles GET /api/v1/cases.
// Returns only cases within the caller's tenant subtree. Tenant filtering is
// applied in this handler — requirePermission only checks permission, not tenant
// scope (ADR-022 §7).
func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}

	callerTenant := callerTenantSubtree(r)
	if callerTenant == "" {
		// Global-scope callers: no tenant to filter by. ListCases requires a
		// non-empty tenant ID. Return empty list — global admins do not have a
		// home tenant and cockpit cases are always tenant-anchored.
		s.writeResponse(w, http.StatusOK, []caseResponse{})
		return
	}

	cases, err := s.casesStore.ListCases(r.Context(), callerTenant)
	if err != nil {
		s.logger.Error("handleListCases: store failed",
			"tenant_id", logging.SanitizeLogValue(callerTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to list cases", http.StatusInternalServerError)
		return
	}
	if cases == nil {
		cases = []*business.Case{}
	}

	resp := make([]caseResponse, 0, len(cases))
	for _, c := range cases {
		resp = append(resp, caseToResponse(c))
	}
	s.writeResponse(w, http.StatusOK, resp)
}

// handleGetCase handles GET /api/v1/cases/{id}.
// Returns 404 for both a nonexistent id and an id belonging to another tenant —
// indistinguishable responses (existence-oracle prevention, ADR-022 §7).
// Response embeds the case's current pin list.
func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "case id is required", http.StatusBadRequest)
		return
	}

	c, err := s.casesStore.GetCase(r.Context(), id)
	if err != nil {
		if errors.Is(err, business.ErrCaseNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleGetCase: store failed",
			"case_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to get case", http.StatusInternalServerError)
		return
	}

	// Cross-tenant check: same 404 as not-found (existence-oracle prevention).
	callerTenant := callerTenantSubtree(r)
	if !caseInCallerSubtree(c.TenantID, callerTenant) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	s.writeResponse(w, http.StatusOK, caseToResponse(c))
}

// handleUpdateCase handles PUT /api/v1/cases/{id}.
// Applies the same cross-tenant check as GET before allowing an update.
func (s *Server) handleUpdateCase(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "case id is required", http.StatusBadRequest)
		return
	}

	// Fetch first to apply cross-tenant check before parsing body.
	existing, err := s.casesStore.GetCase(r.Context(), id)
	if err != nil {
		if errors.Is(err, business.ErrCaseNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleUpdateCase: get failed",
			"case_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to get case", http.StatusInternalServerError)
		return
	}

	callerTenant := callerTenantSubtree(r)
	if !caseInCallerSubtree(existing.TenantID, callerTenant) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var req updateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Status != "" {
		status, ok := parseCaseStatus(req.Status)
		if !ok {
			s.writeErrorResponse(w, http.StatusBadRequest,
				"status must be one of: open, closed", "INVALID_STATUS")
			return
		}
		existing.Status = status
	}
	if err := validateTicketInput(req.Ticket); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_TICKET_FIELD_SOURCE")
		return
	}
	existing.Ticket = ticketFromInput(req.Ticket)
	existing.UpdatedAt = time.Now().UTC()

	// Issue #3895: CAS on the version read alongside GetCase above, mirroring
	// persistAccountCAS. Two concurrent updates racing this handler both read
	// the same starting version; the first write to land advances it, and the
	// second's CAS then loses (ok=false, no error) rather than silently
	// overwriting the first caller's change.
	newVersion, ok, err := s.casesStore.UpdateCaseCAS(r.Context(), existing, existing.Version)
	if err != nil {
		s.logger.Error("handleUpdateCase: store failed",
			"case_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to update case", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "case was modified concurrently; reload and retry", http.StatusConflict)
		return
	}
	existing.Version = newVersion

	s.writeResponse(w, http.StatusOK, caseToResponse(existing))
}

// loadCallerCase retrieves a case by ID and verifies it falls within the
// caller's tenant subtree. Writes the appropriate HTTP error and returns nil
// when access is denied, so callers should return immediately on nil.
func (s *Server) loadCallerCase(w http.ResponseWriter, r *http.Request, id string) *business.Case {
	c, err := s.casesStore.GetCase(r.Context(), id)
	if err != nil {
		if errors.Is(err, business.ErrCaseNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return nil
		}
		s.logger.Error("loadCallerCase: store failed",
			"case_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to get case", http.StatusInternalServerError)
		return nil
	}
	if !caseInCallerSubtree(c.TenantID, callerTenantSubtree(r)) {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return c
}

// addPinRequest is the JSON body for POST /api/v1/cases/{id}/pins.
type addPinRequest struct {
	Kind               string    `json:"kind"`
	EID                string    `json:"eid,omitempty"`
	EdgeType           string    `json:"edge_type,omitempty"`
	FromEID            string    `json:"from_eid,omitempty"`
	ToEID              string    `json:"to_eid,omitempty"`
	ObservationVersion string    `json:"observation_version,omitempty"`
	DriftRecord        string    `json:"drift_record,omitempty"`
	Subject            string    `json:"subject,omitempty"`
	TimeRangeStart     time.Time `json:"time_range_start,omitempty"`
	TimeRangeEnd       time.Time `json:"time_range_end,omitempty"`
	Annotation         string    `json:"annotation,omitempty"`
}

// buildPinRef validates addPinRequest and returns the corresponding PinRef.
// For entity-referencing kinds (eid, edge-identity, subject-time-range) it
// calls verifyEntityAccess against caseTenantID — the case's own tenant ceiling,
// not the caller's ambient tenant (binding PO constraint, ADR-022 §7). Returns
// (ref, true) on success; writes the HTTP error and returns false on failure.
func (s *Server) buildPinRef(w http.ResponseWriter, r *http.Request, req addPinRequest, caseTenantID string) (business.PinRef, bool) {
	switch business.PinRefKind(req.Kind) {

	case business.PinRefKindEID:
		if req.EID == "" {
			http.Error(w, "eid is required for kind 'eid'", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		eid, err := egtypes.ParseEID(req.EID)
		if err != nil {
			http.Error(w, "invalid eid", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		if s.egProvider == nil {
			http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
			return business.PinRef{}, false
		}
		ok, accessErr := s.verifyEntityAccess(r.Context(), eid, caseTenantID)
		if accessErr != nil {
			s.logger.Error("handleAddPin: eid access check failed",
				"error", logging.SanitizeLogValue(accessErr.Error()))
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return business.PinRef{}, false
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return business.PinRef{}, false
		}
		return business.PinRef{Kind: business.PinRefKindEID, EID: eid.String()}, true

	case business.PinRefKindEdgeIdentity:
		if req.FromEID == "" || req.ToEID == "" {
			http.Error(w, "from_eid and to_eid are required for kind 'edge-identity'", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		// edge_type is the first field of the three-field edge subject and is
		// concatenated below, so it gets the same treatment as the endpoints:
		// non-empty, delimiter-free, and a taxonomy kind. Without this an
		// operator could smuggle extra '|'-separated fields into the stored
		// identity and shift the field boundaries a three-way split recovers,
		// naming endpoints that never passed the tenant check (ADR-022 §2/§4).
		if err := validateAssertedEdgeType(req.EdgeType); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return business.PinRef{}, false
		}
		fromEID, err := egtypes.ParseEID(req.FromEID)
		if err != nil || strings.Contains(fromEID.String(), edgeSubjectDelimiter) {
			http.Error(w, "invalid from_eid", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		toEID, err := egtypes.ParseEID(req.ToEID)
		if err != nil || strings.Contains(toEID.String(), edgeSubjectDelimiter) {
			http.Error(w, "invalid to_eid", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		if s.egProvider == nil {
			http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
			return business.PinRef{}, false
		}
		// Both endpoints must resolve within the case's tenant subtree (ADR-022 §7).
		ok, accessErr := s.verifyEntityAccess(r.Context(), fromEID, caseTenantID)
		if accessErr != nil {
			s.logger.Error("handleAddPin: from_eid access check failed",
				"error", logging.SanitizeLogValue(accessErr.Error()))
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return business.PinRef{}, false
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return business.PinRef{}, false
		}
		ok, accessErr = s.verifyEntityAccess(r.Context(), toEID, caseTenantID)
		if accessErr != nil {
			s.logger.Error("handleAddPin: to_eid access check failed",
				"error", logging.SanitizeLogValue(accessErr.Error()))
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return business.PinRef{}, false
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return business.PinRef{}, false
		}
		edgeIdentity := req.EdgeType + edgeSubjectDelimiter + fromEID.String() + edgeSubjectDelimiter + toEID.String()
		return business.PinRef{Kind: business.PinRefKindEdgeIdentity, EdgeIdentity: edgeIdentity}, true

	case business.PinRefKindObservationVersion:
		if req.ObservationVersion == "" {
			http.Error(w, "observation_version is required for kind 'observation-version'", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		return business.PinRef{Kind: business.PinRefKindObservationVersion, ObservationVersion: req.ObservationVersion}, true

	case business.PinRefKindDriftRecord:
		if req.DriftRecord == "" {
			http.Error(w, "drift_record is required for kind 'drift-record'", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		return business.PinRef{Kind: business.PinRefKindDriftRecord, DriftRecord: req.DriftRecord}, true

	case business.PinRefKindSubjectTimeRange:
		if req.Subject == "" {
			http.Error(w, "subject is required for kind 'subject-time-range'", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		if req.TimeRangeStart.IsZero() || req.TimeRangeEnd.IsZero() {
			http.Error(w, "time_range_start and time_range_end are required for kind 'subject-time-range'", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		subjectEID, err := egtypes.ParseEID(req.Subject)
		if err != nil {
			http.Error(w, "invalid subject eid", http.StatusBadRequest)
			return business.PinRef{}, false
		}
		if s.egProvider == nil {
			http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
			return business.PinRef{}, false
		}
		ok, accessErr := s.verifyEntityAccess(r.Context(), subjectEID, caseTenantID)
		if accessErr != nil {
			s.logger.Error("handleAddPin: subject access check failed",
				"error", logging.SanitizeLogValue(accessErr.Error()))
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return business.PinRef{}, false
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return business.PinRef{}, false
		}
		return business.PinRef{
			Kind:           business.PinRefKindSubjectTimeRange,
			Subject:        subjectEID.String(),
			TimeRangeStart: req.TimeRangeStart,
			TimeRangeEnd:   req.TimeRangeEnd,
		}, true

	default:
		if req.Kind == "" {
			http.Error(w, "kind is required", http.StatusBadRequest)
		} else {
			http.Error(w, "kind must be one of: eid, edge-identity, observation-version, drift-record, subject-time-range", http.StatusBadRequest)
		}
		return business.PinRef{}, false
	}
}

// handleAddPin handles POST /api/v1/cases/{id}/pins.
// Adds a pin whose graph reference must resolve within the case's own tenant
// subtree — checked against the case's TenantID, not the caller's ambient
// tenant (binding PO constraint).
func (s *Server) handleAddPin(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "case id is required", http.StatusBadRequest)
		return
	}

	c := s.loadCallerCase(w, r, id)
	if c == nil {
		return
	}

	var req addPinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ref, ok := s.buildPinRef(w, r, req, c.TenantID)
	if !ok {
		return
	}

	callerID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)
	if callerID == "" {
		callerID = "unknown"
	}

	pin := &business.Pin{
		ID:         uuid.New().String(),
		CaseID:     c.ID,
		Ref:        ref,
		Annotation: req.Annotation,
		Author:     callerID,
		PinnedAt:   time.Now().UTC(),
	}

	if err := s.casesStore.AddPin(r.Context(), c.ID, pin); err != nil {
		s.logger.Error("handleAddPin: store failed",
			"case_id", logging.SanitizeLogValue(c.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to add pin", http.StatusInternalServerError)
		return
	}

	s.writeResponse(w, http.StatusCreated, pinToResponse(pin))
}

// handleRemovePin handles DELETE /api/v1/cases/{id}/pins/{pin_id}.
// Removes a pin from a case, gated by the same case-tenant check used for add.
func (s *Server) handleRemovePin(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	pinID := vars["pin_id"]
	if id == "" {
		http.Error(w, "case id is required", http.StatusBadRequest)
		return
	}
	if pinID == "" {
		http.Error(w, "pin id is required", http.StatusBadRequest)
		return
	}

	c := s.loadCallerCase(w, r, id)
	if c == nil {
		return
	}

	if err := s.casesStore.RemovePin(r.Context(), c.ID, pinID); err != nil {
		if errors.Is(err, business.ErrPinNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleRemovePin: store failed",
			"case_id", logging.SanitizeLogValue(c.ID),
			"pin_id", logging.SanitizeLogValue(pinID),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to remove pin", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── JSON response types ────────────────────────────────────────────────────

// caseResponse is the JSON shape returned by GetCase, ListCases, CreateCase, UpdateCase.
type caseResponse struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Status    string            `json:"status"`
	Ticket    ticketResponse    `json:"ticket"`
	Pins      []pinResponse     `json:"pins"`
	Content   []contentResponse `json:"content"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ticketResponse is the per-field ticket shape in responses.
type ticketResponse struct {
	Title    ticketFieldResponse `json:"title"`
	Client   ticketFieldResponse `json:"client"`
	Contact  ticketFieldResponse `json:"contact"`
	Priority ticketFieldResponse `json:"priority"`
	Category ticketFieldResponse `json:"category"`
}

// ticketFieldResponse is a single provenanced ticket field in responses.
type ticketFieldResponse struct {
	Value  string `json:"value"`
	Source string `json:"source"`
	Filled bool   `json:"filled"`
}

// pinResponse is the JSON shape for a single Pin.
type pinResponse struct {
	ID         string         `json:"id"`
	CaseID     string         `json:"case_id"`
	Ref        pinRefResponse `json:"ref"`
	Annotation string         `json:"annotation"`
	Author     string         `json:"author"`
	PinnedAt   time.Time      `json:"pinned_at"`
}

// pinRefResponse is the JSON shape for a PinRef.
type pinRefResponse struct {
	Kind               string    `json:"kind"`
	EID                string    `json:"eid,omitempty"`
	EdgeIdentity       string    `json:"edge_identity,omitempty"`
	ObservationVersion string    `json:"observation_version,omitempty"`
	DriftRecord        string    `json:"drift_record,omitempty"`
	Subject            string    `json:"subject,omitempty"`
	TimeRangeStart     time.Time `json:"time_range_start,omitempty"`
	TimeRangeEnd       time.Time `json:"time_range_end,omitempty"`
}

// contentResponse is the JSON shape for a ContentEntry.
type contentResponse struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Kind      string    `json:"kind"`
	Body      string    `json:"body"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

// caseToResponse converts a business.Case to its JSON response shape.
func caseToResponse(c *business.Case) caseResponse {
	pins := make([]pinResponse, 0, len(c.Pins))
	for _, p := range c.Pins {
		pins = append(pins, pinToResponse(p))
	}
	content := make([]contentResponse, 0, len(c.Content))
	for _, e := range c.Content {
		content = append(content, contentEntryToResponse(e))
	}
	return caseResponse{
		ID:        c.ID,
		TenantID:  c.TenantID,
		Status:    string(c.Status),
		Ticket:    ticketToResponse(c.Ticket),
		Pins:      pins,
		Content:   content,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

// ticketToResponse converts a business.Ticket to its response shape.
func ticketToResponse(t business.Ticket) ticketResponse {
	return ticketResponse{
		Title:    ticketFieldToResponse(t.Title),
		Client:   ticketFieldToResponse(t.Client),
		Contact:  ticketFieldToResponse(t.Contact),
		Priority: ticketFieldToResponse(t.Priority),
		Category: ticketFieldToResponse(t.Category),
	}
}

// ticketFieldToResponse converts a business.TicketField to its response shape.
func ticketFieldToResponse(f business.TicketField) ticketFieldResponse {
	return ticketFieldResponse{
		Value:  f.Value,
		Source: string(f.Source),
		Filled: f.Filled,
	}
}

// ticketFromInput converts a caseTicketInput to a business.Ticket.
func ticketFromInput(t caseTicketInput) business.Ticket {
	return business.Ticket{
		Title:    ticketFieldFromInput(t.Title),
		Client:   ticketFieldFromInput(t.Client),
		Contact:  ticketFieldFromInput(t.Contact),
		Priority: ticketFieldFromInput(t.Priority),
		Category: ticketFieldFromInput(t.Category),
	}
}

// ticketFieldFromInput converts a caseTicketFieldInput to a business.TicketField.
// The source is only ever one of the five declared constants: callers validate the
// request with validateTicketInput first, and an omitted source on a supplied value
// resolves to operator. An absent value yields an unfilled field with no provenance.
func ticketFieldFromInput(f caseTicketFieldInput) business.TicketField {
	if f.Value == "" {
		return business.TicketField{}
	}
	source, ok := parseTicketFieldSource(f.Source)
	if !ok {
		source = business.TicketFieldSourceOperator
	}
	return business.TicketField{
		Value:  f.Value,
		Source: source,
		Filled: true,
	}
}

// pinToResponse converts a business.Pin to its response shape.
func pinToResponse(p *business.Pin) pinResponse {
	if p == nil {
		return pinResponse{}
	}
	return pinResponse{
		ID:         p.ID,
		CaseID:     p.CaseID,
		Ref:        pinRefToResponse(p.Ref),
		Annotation: p.Annotation,
		Author:     p.Author,
		PinnedAt:   p.PinnedAt,
	}
}

// pinRefToResponse converts a business.PinRef to its response shape.
func pinRefToResponse(ref business.PinRef) pinRefResponse {
	return pinRefResponse{
		Kind:               string(ref.Kind),
		EID:                ref.EID,
		EdgeIdentity:       ref.EdgeIdentity,
		ObservationVersion: ref.ObservationVersion,
		DriftRecord:        ref.DriftRecord,
		Subject:            ref.Subject,
		TimeRangeStart:     ref.TimeRangeStart,
		TimeRangeEnd:       ref.TimeRangeEnd,
	}
}

// contentEntryToResponse converts a business.ContentEntry to its response shape.
func contentEntryToResponse(e *business.ContentEntry) contentResponse {
	if e == nil {
		return contentResponse{}
	}
	return contentResponse{
		ID:        e.ID,
		CaseID:    e.CaseID,
		Kind:      string(e.Kind),
		Body:      e.Body,
		Author:    e.Author,
		CreatedAt: e.CreatedAt,
	}
}
