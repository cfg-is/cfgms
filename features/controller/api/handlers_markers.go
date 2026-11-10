// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// markerActionPrefix prefixes the audit action of every marker row. Rollout and
	// upgrade markers are written under the same prefix by the rollout service.
	markerActionPrefix = "marker_"
	// markerControllerStart is the audit action recorded at controller startup; it is
	// listed as a marker beside the marker_* rows.
	markerControllerStart = "controller_start"

	markerMaxBodyBytes = 4 << 10
	markerMaxNoteLen   = 256
	markerMaxKindLen   = 32
	// markerMaxResults bounds one list response; when more rows match, the newest are kept.
	markerMaxResults = 1000
)

// markerWriteKinds are the kinds a caller may record through POST. Other marker kinds
// (rollout, upgrade) come from server-side writers.
var markerWriteKinds = map[string]bool{
	"deploy":      true,
	"rollback":    true,
	"chaos_start": true,
	"chaos_end":   true,
}

var (
	// markerRevisionPattern accepts a hex commit id (7 to 64 digits) or a semantic version.
	markerRevisionPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{7,64}|v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$`)
	markerKindPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

const markerMaxRevisionLen = 64

type markerCreateRequest struct {
	Kind     string `json:"kind"`
	Revision string `json:"revision"`
	Note     string `json:"note,omitempty"`
}

// markerResponse is one marker. Resource is a marker or rollout id, never a tenant path.
type markerResponse struct {
	ID        string    `json:"id,omitempty"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Revision  string    `json:"revision"`
	Principal string    `json:"principal"`
	Resource  string    `json:"resource"`
	Note      string    `json:"note,omitempty"`
}

type markerListResponse struct {
	Markers []markerResponse `json:"markers"`
}

// handleCreateMarker handles POST /api/v1/monitoring/markers on the private metrics
// listener. It records a deploy, rollback or chaos marker as an audit event under the
// system tenant (action marker_<kind>), with the caller and revision in the details.
func (s *Server) handleCreateMarker(w http.ResponseWriter, r *http.Request) {
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Marker store unavailable", "MARKERS_UNAVAILABLE")
		return
	}

	req, ok := s.decodeMarkerRequest(w, r)
	if !ok {
		return
	}
	if msg, code := validateMarkerRequest(req); code != "" {
		s.writeErrorResponse(w, http.StatusBadRequest, msg, code)
		return
	}

	principalID, userType := markerCaller(r)
	id := uuid.New().String()
	now := time.Now().UTC()
	if err := s.auditManager.RecordEvent(r.Context(), newMarkerEvent(req, id, principalID, userType)); err != nil {
		s.logger.Error("Failed to record marker",
			"kind", logging.SanitizeLogValue(req.Kind),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record marker", "INTERNAL_ERROR")
		return
	}

	s.writeResponse(w, http.StatusCreated, markerResponse{
		ID:        id,
		Time:      now,
		Kind:      req.Kind,
		Revision:  req.Revision,
		Principal: principalID,
		Resource:  id,
		Note:      req.Note,
	})
}

// decodeMarkerRequest reads the size-bounded JSON body, rejecting unknown fields and
// trailing data. It writes the error response and reports false on failure.
func (s *Server) decodeMarkerRequest(w http.ResponseWriter, r *http.Request) (markerCreateRequest, bool) {
	var req markerCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, markerMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeMarkerBodyError(w, err)
		return req, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.writeMarkerBodyError(w, err)
		return req, false
	}
	return req, true
}

// validateMarkerRequest returns the error message and code for an invalid request, or an
// empty code when the request is valid.
func validateMarkerRequest(req markerCreateRequest) (msg, code string) {
	switch {
	case !markerWriteKinds[req.Kind]:
		return "kind must be one of deploy, rollback, chaos_start, chaos_end", "INVALID_KIND"
	case len(req.Revision) > markerMaxRevisionLen || !markerRevisionPattern.MatchString(req.Revision):
		return "revision must be a hex commit id or a semantic version of at most 64 characters", "INVALID_REVISION"
	case len(req.Note) > markerMaxNoteLen || strings.ContainsFunc(req.Note, unicode.IsControl):
		return "note is too long or contains control characters", "INVALID_NOTE"
	}
	return "", ""
}

// markerCaller returns the audit identity of the authenticated caller.
func markerCaller(r *http.Request) (string, business.AuditUserType) {
	principalID, userType := "unknown", business.AuditUserTypeHuman
	p, _ := r.Context().Value(principalContextKey).(*Principal)
	if p == nil {
		return principalID, userType
	}
	if p.ID != "" {
		principalID = p.ID
	}
	if p.Channel == AuthChannelAPIKey {
		userType = business.AuditUserTypeAPI
	}
	return principalID, userType
}

func newMarkerEvent(req markerCreateRequest, id, principalID string, userType business.AuditUserType) *audit.AuditEventBuilder {
	event := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSystemEvent).
		Action(markerActionPrefix+req.Kind).
		User(principalID, userType).
		Resource("marker", id, "").
		Detail("principal", principalID).
		Detail("revision", req.Revision).
		Severity(business.AuditSeverityLow)
	if req.Note != "" {
		event.Detail("note", req.Note)
	}
	return event
}

func (s *Server) writeMarkerBodyError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		s.writeErrorResponse(w, http.StatusRequestEntityTooLarge, "Request body too large", "REQUEST_TOO_LARGE")
		return
	}
	s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
}

// handleListMarkers handles GET /api/v1/monitoring/markers?since=&until=&kind=. It reads
// system-tenant audit rows only and returns, oldest first, the marker_* rows and the
// controller_start rows.
func (s *Server) handleListMarkers(w http.ResponseWriter, r *http.Request) {
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Marker store unavailable", "MARKERS_UNAVAILABLE")
		return
	}

	filter, msg, code := markerListFilter(r.URL.Query())
	if code != "" {
		s.writeErrorResponse(w, http.StatusBadRequest, msg, code)
		return
	}

	entries, err := s.auditManager.QueryEntries(r.Context(), filter)
	if err != nil {
		s.logger.Error("Failed to query markers",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve markers", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, markerListResponse{Markers: markersFromEntries(entries)})
}

// markerListFilter builds the system-tenant audit filter for a list request, or returns
// the error message and code for an invalid query.
func markerListFilter(q url.Values) (filter *business.AuditFilter, msg, code string) {
	kind := q.Get("kind")
	if kind != "" && (len(kind) > markerMaxKindLen || !markerKindPattern.MatchString(kind)) {
		return nil, "kind must be lowercase letters, digits and underscores", "INVALID_KIND"
	}
	tr, msg, code := markerTimeRange(q)
	if code != "" {
		return nil, msg, code
	}

	filter = &business.AuditFilter{
		TenantID: audit.SystemTenantID,
		Order:    "asc",
		SortBy:   "timestamp",
	}
	if tr.Start != nil || tr.End != nil {
		filter.TimeRange = &tr
	}
	// The store matches actions exactly, so a marker_* prefix match is applied when the
	// entries are mapped. A kind narrows the query to the one action.
	if kind == markerControllerStart {
		filter.Actions = []string{markerControllerStart}
	} else if kind != "" {
		filter.Actions = []string{markerActionPrefix + kind}
	}
	return filter, "", ""
}

// markerTimeRange parses the optional since and until RFC 3339 query parameters.
func markerTimeRange(q url.Values) (business.TimeRange, string, string) {
	var tr business.TimeRange
	for _, p := range []struct {
		name string
		dst  **time.Time
	}{{"since", &tr.Start}, {"until", &tr.End}} {
		raw := q.Get(p.name)
		if raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return tr, p.name + " must be an RFC 3339 timestamp", "INVALID_TIME"
		}
		t = t.UTC()
		*p.dst = &t
	}
	if tr.Start != nil && tr.End != nil && tr.End.Before(*tr.Start) {
		return tr, "until must not be before since", "INVALID_TIME"
	}
	return tr, "", ""
}

// markersFromEntries maps audit rows to markers, oldest first, keeping the newest
// markerMaxResults when more match.
func markersFromEntries(entries []*business.AuditEntry) []markerResponse {
	markers := make([]markerResponse, 0, len(entries))
	for _, e := range entries {
		// Defence in depth: only system-tenant rows are ever listed.
		if e == nil || e.TenantID != audit.SystemTenantID {
			continue
		}
		if m, ok := markerFromEntry(e); ok {
			markers = append(markers, m)
		}
	}
	sort.SliceStable(markers, func(i, j int) bool { return markers[i].Time.Before(markers[j].Time) })
	if len(markers) > markerMaxResults {
		markers = markers[len(markers)-markerMaxResults:]
	}
	return markers
}

// markerFromEntry maps an audit row to a marker, or reports false for a row that is not one.
func markerFromEntry(e *business.AuditEntry) (markerResponse, bool) {
	var kind string
	switch {
	case e.Action == markerControllerStart:
		kind = markerControllerStart
	case strings.HasPrefix(e.Action, markerActionPrefix) && len(e.Action) > len(markerActionPrefix):
		kind = strings.TrimPrefix(e.Action, markerActionPrefix)
	default:
		return markerResponse{}, false
	}
	revision, _ := e.Details["revision"].(string)
	principal, _ := e.Details["principal"].(string)
	if principal == "" {
		principal = e.UserID
	}
	note, _ := e.Details["note"].(string)
	return markerResponse{
		Time:      e.Timestamp.UTC(),
		Kind:      kind,
		Revision:  revision,
		Principal: principal,
		Resource:  e.ResourceID,
		Note:      note,
	}, true
}
