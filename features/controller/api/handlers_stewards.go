// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	loggingInterfaces "github.com/cfgis/cfgms/pkg/logging/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Regex pattern for validating identifiers (prevents log injection)
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// tenantPathRegex validates a tenant path: flat IDs (e.g. "corp") and slash-separated
// hierarchical paths (e.g. "msp-a/client-1"). Each component matches identifierRegex.
var tenantPathRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`)

// stewardPageMaxLimit caps the limit query parameter on GET /api/v1/stewards (Issue #2489).
const stewardPageMaxLimit = 500

// StewardListPage is the paginated envelope returned by handleListStewards when
// the limit/offset query parameters are present. Total is the post-filter,
// pre-slice steward count so clients can compute page counts.
type StewardListPage struct {
	Stewards []StewardInfo `json:"stewards"`
	Total    int           `json:"total"`
	Limit    int           `json:"limit"`
	Offset   int           `json:"offset"`
}

// parseStewardPagination parses the optional limit/offset query parameters for
// GET /api/v1/stewards. Rules (pinned by Issue #2489):
//   - limit must be an integer in 1..stewardPageMaxLimit
//   - offset must be an integer >= 0
//   - limit present without offset implies offset=0
//   - offset present without limit is rejected (ambiguous page size)
//   - neither present => paginated=false (existing full-list behavior)
//
// Error messages reference the offending parameter NAME only — never the raw
// client-supplied value (no information disclosure in error responses).
func parseStewardPagination(q url.Values) (limit, offset int, paginated bool, err error) {
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")

	if limitStr == "" && offsetStr == "" {
		return 0, 0, false, nil
	}
	if limitStr == "" {
		return 0, 0, false, fmt.Errorf("offset requires limit to be set")
	}

	limit, convErr := strconv.Atoi(limitStr)
	if convErr != nil || limit < 1 || limit > stewardPageMaxLimit {
		return 0, 0, false, fmt.Errorf("limit must be an integer between 1 and %d", stewardPageMaxLimit)
	}

	if offsetStr != "" {
		offset, convErr = strconv.Atoi(offsetStr)
		if convErr != nil || offset < 0 {
			return 0, 0, false, fmt.Errorf("offset must be a non-negative integer")
		}
	}

	return limit, offset, true, nil
}

// paginateStewards sorts stewards by ID and slices the requested page window.
// The ID sort exists solely to make pagination deterministic — pages must be
// stable across requests even though the underlying sources iterate maps in
// random order. User-facing sort is explicitly out of scope (Issue #2489).
func paginateStewards(stewards []StewardInfo, limit, offset int) StewardListPage {
	sort.Slice(stewards, func(i, j int) bool { return stewards[i].ID < stewards[j].ID })
	total := len(stewards)
	start := min(offset, total)
	end := min(start+limit, total)
	return StewardListPage{
		Stewards: stewards[start:end],
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
}

// handleListStewards handles GET /api/v1/stewards
// Supports optional query parameters for filtered search: os, platform, arch, status, hostname,
// tag (repeatable). TenantID is always taken from the authenticated context, never from query params.
//
// Optional pagination (Issue #2489): limit (1..500) and offset (>=0) select a page
// over a deterministic steward-ID-sorted order and switch the response payload to
// a StewardListPage envelope with total = post-filter, pre-slice count. Pagination
// applies on both the filtered and unfiltered code paths. When both params are
// absent, the existing full-list payload is returned unchanged (backward
// compatibility for cfg and existing clients).
func (s *Server) handleListStewards(w http.ResponseWriter, r *http.Request) {
	// Extract tenant from authenticated context (same pattern as handleUpdateStewardConfig).
	tenantID := callerTenantFilter(r.Context()) //architecture:allow-root-scope -- builds the query filter only; visibility of the results is decided by readScope below

	// A root caller subject to the ADR-025 boundary lists only root-tenant and
	// crossing-covered stewards; the rest are silently omitted (A2.5), so the
	// pagination total counts visible rows only (Issue #4715).
	readScope := s.tenantReadScope(r, "GET /api/v1/stewards")
	defer readScope.LogSummary()

	// Selector-based search path: when ?q=<selector> is present, parse the
	// expression and apply tenant-scope enforcement identical to handleResolveSelector
	// (handlers_fleet.go:51-64). The existing ?os, ?platform, ?arch, ?status, ?tag,
	// ?hostname params are unaffected — they remain active on the non-q path.
	if q := r.URL.Query().Get("q"); q != "" {
		s.listStewardsBySelector(w, r, q, tenantID, readScope)
		return
	}

	// Build a filter from query params and authenticated tenant scope.
	filter, err := buildFleetFilter(r, tenantID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_FILTER")
		return
	}
	s.scopeFilterToTenantSubtree(r.Context(), &filter, tenantID)

	// Parse optional pagination params. Rejected values are logged sanitized;
	// the error body names the offending param, never the raw client value.
	limit, offset, paginated, ok := s.parseStewardListPagination(w, r)
	if !ok {
		return
	}

	// When a filter is specified, use FleetQuery for filtered results (connected stewards only).
	if !isEmptyFilter(filter) {
		results, err := s.fleetQuery.Search(r.Context(), filter)
		if err != nil {
			s.logger.Error("Fleet query failed", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
			return
		}
		stewardList := s.readableStewardInfos(r.Context(), readScope, results)
		s.writeStewardList(w, stewardList, paginated, limit, offset,
			"Listed stewards (filtered)", "Listed stewards (filtered, paginated)")
		return
	}

	stewardList := s.unfilteredStewardList(r, tenantID, readScope)
	s.writeStewardList(w, stewardList, paginated, limit, offset,
		"Listed stewards", "Listed stewards (paginated)")
}

// listStewardsBySelector serves the ?q=<selector> path of handleListStewards.
func (s *Server) listStewardsBySelector(w http.ResponseWriter, r *http.Request, q, tenantID string, readScope *tenantReadScope) {
	s.logger.Debug("Steward list selector search",
		"q", logging.SanitizeLogValue(q))
	selectorFilter, ok := s.selectorListFilter(w, r, q, tenantID)
	if !ok {
		return
	}

	limit, offset, paginated, ok := s.parseStewardListPagination(w, r)
	if !ok {
		return
	}

	results, searchErr := s.fleetQuery.Search(r.Context(), selectorFilter)
	if searchErr != nil {
		s.logger.Error("Fleet query failed", "error", searchErr)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}
	stewardList := s.readableStewardInfos(r.Context(), readScope, results)
	qForLog := logging.SanitizeLogValue(q)
	if paginated {
		page := paginateStewards(stewardList, limit, offset)
		s.logger.Info("Listed stewards (selector, paginated)",
			"q", qForLog, "count", len(page.Stewards), "total", page.Total)
		s.writeSuccessResponse(w, page)
		return
	}
	s.logger.Info("Listed stewards (selector)",
		"q", qForLog, "count", len(stewardList))
	s.writeSuccessResponse(w, stewardList)
}

// selectorListFilter parses the ?q= selector and enforces the caller's tenant
// subtree on it — identical to handleResolveSelector (same grammar, same
// boundary, same 403 CROSS_TENANT response code). On failure it has written the
// error response and ok is false.
func (s *Server) selectorListFilter(w http.ResponseWriter, r *http.Request, q, tenantID string) (fleet.Filter, bool) {
	selectorFilter, parsedTenantPath, parseErr := selector.Parse(q)
	if parseErr != nil {
		s.logger.Info("Invalid selector expression in steward list",
			"q", logging.SanitizeLogValue(q), "error", logging.SanitizeLogValue(parseErr.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid selector expression", "INVALID_SELECTOR")
		return fleet.Filter{}, false
	}
	if parsedTenantPath == "" {
		if tenantID != "" {
			s.scopeFilterToTenantSubtree(r.Context(), &selectorFilter, tenantID)
		}
		return selectorFilter, true
	}
	if tenantID != "" && !selectorPathWithinCaller(tenantID, parsedTenantPath) {
		s.logger.Info("Selector tenant outside caller subtree",
			"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
			"caller_tenant", logging.SanitizeLogValue(tenantID))
		s.writeErrorResponse(w, http.StatusForbidden,
			"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
		return fleet.Filter{}, false
	}
	selectorFilter.TenantSubtree = parsedTenantPath
	return selectorFilter, true
}

// parseStewardListPagination parses the optional limit/offset params of the
// steward list. A rejected value is logged sanitized and answered 400
// INVALID_PAGINATION (the body names the param, never the raw client value); ok
// is then false.
func (s *Server) parseStewardListPagination(w http.ResponseWriter, r *http.Request) (limit, offset int, paginated, ok bool) {
	limit, offset, paginated, err := parseStewardPagination(r.URL.Query())
	if err != nil {
		s.logger.Warn("Rejected steward list pagination params",
			"limit", logging.SanitizeLogValue(r.URL.Query().Get("limit")),
			"offset", logging.SanitizeLogValue(r.URL.Query().Get("offset")),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_PAGINATION")
		return 0, 0, false, false
	}
	return limit, offset, paginated, true
}

// readableStewardInfos narrows fleet search results to those the caller's read
// scope allows, builds their API view and attaches tags and health reasons.
func (s *Server) readableStewardInfos(ctx context.Context, readScope *tenantReadScope, results []fleet.StewardResult) []StewardInfo {
	results, _ = splitReadableResults(readScope, results)
	stewardList := make([]StewardInfo, 0, len(results))
	for _, res := range results {
		stewardList = append(stewardList, fleetResultInfo(res))
	}
	s.attachStewardTags(ctx, stewardList)
	return stewardList
}

// fleetResultInfo builds the API view of one fleet search result.
func fleetResultInfo(res fleet.StewardResult) StewardInfo {
	info := StewardInfo{
		ID:       res.ID,
		TenantID: res.TenantID,
		Status:   res.Status,
		LastSeen: res.LastHeartbeat,
		Version:  res.DNAAttributes["steward.version"],
	}
	if len(res.DNAAttributes) > 0 {
		attrs := filteredDNAAttrs(res.DNAAttributes)
		if res.TenantID != "" {
			attrs["tenant"] = res.TenantID
		}
		info.DNA = &DNAInfo{
			Hostname:     res.Hostname,
			OS:           res.OS,
			Architecture: res.Architecture,
			Attributes:   attrs,
		}
	}
	return info
}

// writeStewardList writes the steward list, as a StewardListPage envelope when
// the request was paginated and as the bare list otherwise. msg and pagedMsg are
// the info log lines for the two shapes.
func (s *Server) writeStewardList(w http.ResponseWriter, stewardList []StewardInfo, paginated bool, limit, offset int, msg, pagedMsg string) {
	if paginated {
		page := paginateStewards(stewardList, limit, offset)
		s.logger.Info(pagedMsg, "count", len(page.Stewards), "total", page.Total)
		s.writeSuccessResponse(w, page)
		return
	}
	s.logger.Info(msg, "count", len(stewardList))
	s.writeSuccessResponse(w, stewardList)
}

// unfilteredStewardList builds the no-filter steward list: every steward the
// caller may read, including registered-but-not-connected ones.
// Deregistered stewards are excluded by default; pass ?include_deregistered=true to restore them.
// Hidden and quarantined stewards are excluded by default (Issue #2918).
func (s *Server) unfilteredStewardList(r *http.Request, tenantID string, readScope *tenantReadScope) []StewardInfo {
	visibility := stewardListVisibility{
		includeDeregistered: r.URL.Query().Get("include_deregistered") == "true",
		includeQuarantined:  r.URL.Query().Get("include_quarantined") == "true",
		includeHidden:       r.URL.Query().Get("include_hidden") == "true",
	}
	stewards := s.controllerService.ListFleetStewards(r.Context())

	// The in-process map only holds stewards THIS node handled, so on a cluster
	// it is a fraction of the fleet. Start from the durable store — authoritative
	// for existence cluster-wide — and let the local entries below overlay it
	// with live DNA/metrics for the stewards actually attached here (Issue #3480).
	durable, _ := s.fleetRecords(r.Context(), tenantID)
	seen := make(map[string]bool, len(stewards))

	stewardList := make([]StewardInfo, 0, len(stewards))

	for _, steward := range stewards {
		// A tenant-scoped caller must not see other tenants' stewards. The
		// node-local map is unscoped, so this filter applies to it too.
		if !readScope.Allows(steward.TenantID) {
			continue
		}
		seen[steward.ID] = true
		status := listedStewardStatus(steward.Status, durable[steward.ID])
		if visibility.excludes(steward.Status, status, steward.Hidden) {
			continue
		}
		stewardList = append(stewardList, localStewardInfo(steward, status))
	}

	stewardList = appendPeerStewards(stewardList, durable, seen, readScope, visibility)
	s.attachStewardTags(r.Context(), stewardList)
	return stewardList
}

// appendPeerStewards adds stewards this node has never handled — the ones
// attached to peer nodes. They carry their durable facts and deliberately no
// liveness fields: this node has no heartbeat from them and must not invent one
// (Issue #3480). durable is nil when the store is unavailable, which adds
// nothing.
func appendPeerStewards(stewardList []StewardInfo, durable map[string]*business.StewardRecord, seen map[string]bool, readScope *tenantReadScope, visibility stewardListVisibility) []StewardInfo {
	for id, rec := range durable {
		if seen[id] || !readScope.Allows(rec.TenantID) {
			continue
		}
		if visibility.excludes(string(rec.Status), string(rec.Status), rec.Hidden) {
			continue
		}
		stewardList = append(stewardList, StewardInfo{
			ID:       rec.ID,
			TenantID: rec.TenantID,
			Version:  rec.Version,
			Status:   string(rec.Status),
			LastSeen: rec.LastSeen,
			Hidden:   rec.Hidden,
		})
	}
	return stewardList
}

// stewardListVisibility holds the include_* query flags of the unfiltered
// steward list. Deregistered, hidden and quarantined stewards are excluded by
// default (Issue #2918).
type stewardListVisibility struct {
	includeDeregistered bool
	includeQuarantined  bool
	includeHidden       bool
}

// excludes reports whether a row is left out of the list. recordStatus is the
// row's own status (deregistration is judged on it); status is the listed
// status. Only quarantined is excluded by status: tampered stays in the default
// list, and hidden is orthogonal to status except that a tampered steward is
// never concealed.
func (v stewardListVisibility) excludes(recordStatus, status string, hidden bool) bool {
	switch {
	case !v.includeDeregistered && recordStatus == string(business.StewardStatusDeregistered):
		return true
	case !v.includeQuarantined && status == "quarantined":
		return true
	case !v.includeHidden && hidden && status != string(business.StewardStatusTampered):
		return true
	default:
		return false
	}
}

// listedStewardStatus returns the status to list for a node-local entry. The
// durable record is authoritative for tampered: a peer node may have recorded
// the alarm after this node's entry was last refreshed.
func listedStewardStatus(localStatus string, rec *business.StewardRecord) string {
	if rec != nil && rec.Status == business.StewardStatusTampered {
		return string(business.StewardStatusTampered)
	}
	return localStatus
}

// localStewardInfo builds the API view of a steward this node handled, with its
// live liveness, clock offset, metrics and DNA, listed with status.
func localStewardInfo(steward *service.StewardInfo, status string) StewardInfo {
	info := StewardInfo{
		ID:          steward.ID,
		TenantID:    steward.TenantID,
		Version:     steward.Version,
		Status:      status,
		LastSeen:    steward.LastHeartbeat,
		ConnectedAt: steward.LastHeartbeat,
		Metrics:     steward.Metrics,
		Hidden:      steward.Hidden,
	}
	if steward.ClockOffsetKnown {
		ms := steward.ClockOffset.Milliseconds()
		info.ClockOffsetMs = &ms
	}
	if steward.DNA == nil {
		return info
	}
	attrs := filteredDNAAttrs(service.FlattenDNAFragments(steward.DNA.Fragments))
	if steward.TenantID != "" {
		merged := make(map[string]string, len(attrs)+1)
		for k, v := range attrs {
			merged[k] = v
		}
		merged["tenant"] = steward.TenantID
		attrs = merged
	}
	info.DNA = &DNAInfo{
		Hostname:     attrs["hostname"],
		OS:           attrs["os"],
		Architecture: attrs["arch"],
		Attributes:   attrs,
	}
	return info
}

// applyDurableRecord copies the facts only the durable record carries (key
// protection and health reasons) onto the API view. A nil record leaves it
// unchanged.
func applyDurableRecord(info *StewardInfo, rec *business.StewardRecord) {
	if rec == nil {
		return
	}
	info.KeyProtectionLevel = rec.KeyProtectionLevel
	info.KeyAlgorithm = effectiveKeyAlgorithm(rec.KeyAlgorithm)
	info.HealthReasons = healthReasonsFromRecord(rec)
}

// attachStewardTags populates Tags (and, from the durable store, health
// reasons) on each already-tenant-scoped list row with a
// single batch read of the tag store, avoiding one request per row (Issue #4595).
// Tags are looked up only for rows in the list, so a scoped caller never sees tags
// for stewards outside its visible set. A missing or failing store leaves Tags
// empty rather than failing the list.
func (s *Server) attachStewardTags(ctx context.Context, list []StewardInfo) {
	s.attachHealthReasons(ctx, list)
	s.attachTamperCodes(ctx, list)
	s.mu.RLock()
	ts := s.tagStore
	s.mu.RUnlock()
	if ts == nil || len(list) == 0 {
		return
	}
	all, err := ts.GetAll(ctx)
	if err != nil {
		s.logger.Warn("Failed to read steward tags for list",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for i := range list {
		if tags := all[list[i].ID]; len(tags) > 0 {
			list[i].Tags = tags
		}
	}
}

// buildFleetFilter constructs a fleet.Filter from HTTP query parameters.
// tenantID comes from the authenticated context, not from query params, to prevent
// cross-tenant enumeration. Recognized params: os, platform, arch, status, hostname,
// tag (repeatable).
//
// Validation rules:
//   - status must be "online", "offline", "any", or empty
//   - string fields are capped at 253 characters (max DNS hostname length)
func buildFleetFilter(r *http.Request, tenantID string) (fleet.Filter, error) {
	const maxFieldLen = 253
	q := r.URL.Query()

	status := q.Get("status")
	if status != "" && status != "online" && status != "offline" && status != "any" &&
		status != string(business.StewardStatusTampered) {
		return fleet.Filter{}, fmt.Errorf("invalid status %q: must be online, offline, tampered, or any", status)
	}

	os := q.Get("os")
	platform := q.Get("platform")
	arch := q.Get("arch")
	hostname := q.Get("hostname")

	for name, val := range map[string]string{"os": os, "platform": platform, "arch": arch, "hostname": hostname} {
		if len(val) > maxFieldLen {
			return fleet.Filter{}, fmt.Errorf("filter field %q exceeds maximum length of %d", name, maxFieldLen)
		}
	}

	return fleet.Filter{
		TenantSubtree: tenantID, // Issue #2919: subtree-aware scope replaces exact TenantID match
		OS:            os,
		Platform:      platform,
		Architecture:  arch,
		Status:        status,
		Hostname:      hostname,
		Tags:          q["tag"],
	}, nil
}

// isEmptyFilter reports whether a filter has no criteria set.
func isEmptyFilter(f fleet.Filter) bool {
	return f.TenantID == "" &&
		f.TenantSubtree == "" && // Issue #2919: must check subtree too
		f.OS == "" &&
		f.Platform == "" &&
		f.Architecture == "" &&
		f.Status == "" &&
		f.Hostname == "" &&
		len(f.Tags) == 0 &&
		len(f.DNAAttributes) == 0
}

// handleGetSteward handles GET /api/v1/stewards/{id}
func (s *Server) handleGetSteward(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Get steward from controller service using GetStewardInfo
	stewardInfo, exists := s.controllerService.GetStewardInfo(stewardID)
	if !exists {
		// Not attached to THIS node. In a cluster that says nothing about whether
		// the steward exists — the in-process map only holds what this node
		// handled — so fall back to the durable store before declaring 404
		// (Issue #3480). Liveness below correctly reports "disconnected": the
		// registry is per-node and this steward is attached elsewhere.
		if rec := s.durableStewardRecord(r.Context(), stewardID); rec != nil {
			s.writeStewardFromDurableRecord(w, r, rec)
			return
		}
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	// Cross-tenant read: a tenant-scoped caller is confined to its subtree (404), and a
	// root caller subject to the ADR-025 boundary needs a crossing for a client
	// tenant's steward (Issue #4715).
	if !s.authorizeRecordRead(w, r, stewardInfo.TenantID, "GET /api/v1/stewards/{id}", func() {
		s.logger.Info("Cross-tenant steward get refused",
			"steward_tenant", logging.SanitizeLogValue(stewardInfo.TenantID))
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
	}) {
		return
	}

	activeSessions, connectionState := s.stewardConnectionState(stewardID)

	apiStewardInfo := StewardInfo{
		ID:              stewardInfo.ID,
		TenantID:        stewardInfo.TenantID,
		Status:          stewardInfo.Status,
		LastSeen:        stewardInfo.LastHeartbeat,
		Version:         stewardInfo.Version,
		Metrics:         stewardInfo.Metrics,
		ActiveSessions:  activeSessions,
		ConnectionState: connectionState,
	}
	if stewardInfo.ClockOffsetKnown {
		ms := stewardInfo.ClockOffset.Milliseconds()
		apiStewardInfo.ClockOffsetMs = &ms
	}

	// Key protection comes from the durable record, which the in-memory
	// attachment does not carry. Read after the tenant check above.
	durableRec := s.durableStewardRecord(r.Context(), stewardID)
	applyDurableRecord(&apiStewardInfo, durableRec)
	apiStewardInfo.Status = listedStewardStatus(apiStewardInfo.Status, durableRec)
	s.attachTamperCodesTo(r.Context(), &apiStewardInfo)

	// Include DNA information if available
	if stewardInfo.DNA != nil {
		apiStewardInfo.DNA = DNAFromProto(stewardInfo.DNA)
		if apiStewardInfo.DNA != nil {
			attrs := filteredDNAAttrs(apiStewardInfo.DNA.Attributes)
			if stewardInfo.TenantID != "" {
				attrs["tenant"] = stewardInfo.TenantID
			}
			apiStewardInfo.DNA.Attributes = attrs
		}
	}

	s.writeSuccessResponse(w, apiStewardInfo)
}

// stewardConnectionState reports whether the steward holds a session on this
// node's registry: (1, "connected") when it does, (0, "disconnected") otherwise
// or when no registry is wired. The registry is per-node.
func (s *Server) stewardConnectionState(stewardID string) (int, string) {
	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg == nil {
		return 0, "disconnected"
	}
	if _, ok := reg.Get(stewardID); ok {
		return 1, "connected"
	}
	return 0, "disconnected"
}

// dnaAttributeDenylist contains glob-style patterns (case-insensitive substring match)
// for attribute keys that must never be returned via ?attribute=<key>. 404 is returned
// rather than 403 to avoid disclosing whether a sensitive attribute exists.
var dnaAttributeDenylist = []string{"token", "secret", "password", "credential", "api_key"}

// dnaAttributeMaxLen is the maximum accepted length for the ?attribute= query parameter.
const dnaAttributeMaxLen = 128

// isDNAAttributeDenylisted reports whether key matches any denylist pattern (case-insensitive).
// Returns the matched pattern for logging, or "" when not matched.
func isDNAAttributeDenylisted(key string) string {
	lower := strings.ToLower(key)
	for _, pattern := range dnaAttributeDenylist {
		if strings.Contains(lower, pattern) {
			return pattern
		}
	}
	return ""
}

// filteredDNAAttrs copies src, dropping any key that matches dnaAttributeDenylist.
// Issue #4335: the denylist was previously applied only on the single ?attribute=<key>
// lookup path (handleGetStewardDNA); the list and get responses below copied every DNA
// attribute unfiltered, including sensitive ones like tokens and credentials.
func filteredDNAAttrs(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		if isDNAAttributeDenylisted(k) != "" {
			continue
		}
		out[k] = v
	}
	return out
}

// handleGetStewardDNA handles GET /api/v1/stewards/{id}/dna
// Optional query parameter: ?attribute=<key> returns a single attribute value.
func (s *Server) handleGetStewardDNA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Containment resolves through ParentID ancestry, so "msp-ab" never matches "msp-a";
	// a root caller subject to the ADR-025 boundary needs a crossing (Issue #4715).
	if !s.authorizeStewardRead(w, r, stewardID, "GET /api/v1/stewards/{id}/dna") {
		return
	}

	// Create gRPC request
	req := &controller.StewardRequest{
		StewardId: stewardID,
	}

	// Call gRPC service
	dnaResp, err := s.controllerService.GetStewardDNA(r.Context(), req)
	if err != nil {
		s.logger.Error("Failed to get steward DNA", "steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get steward DNA", "INTERNAL_ERROR")
		return
	}

	// Convert to API response
	dnaInfo := DNAFromProto(dnaResp)
	if dnaInfo == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "DNA not found for steward", "DNA_NOT_FOUND")
		return
	}

	// Handle optional ?attribute=<key> filter.
	attrKey := r.URL.Query().Get("attribute")
	if attrKey != "" {
		if len(attrKey) > dnaAttributeMaxLen {
			s.writeErrorResponse(w, http.StatusBadRequest, "attribute key too long", "ATTRIBUTE_KEY_TOO_LONG")
			return
		}
		if matched := isDNAAttributeDenylisted(attrKey); matched != "" {
			s.logger.Info("attribute key matches denylist; returning 404", "matched_pattern", logging.SanitizeLogValue(matched))
			s.writeErrorResponse(w, http.StatusNotFound, "attribute not found", "DNA_ATTRIBUTE_REDACTED")
			return
		}
		val, ok := dnaInfo.Attributes[attrKey]
		if !ok {
			s.logger.Info("DNA attribute not found", "steward_id", stewardIDForLog, "attribute", logging.SanitizeLogValue(attrKey))
			s.writeErrorResponse(w, http.StatusNotFound, "attribute not found", "DNA_ATTRIBUTE_NOT_FOUND")
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"value": val})
		return
	}

	// The bulk dump must honour the same denylist as the single-key lookup above,
	// otherwise omitting ?attribute= returns every sensitive value the narrow path
	// refuses (Issue #4335).
	dnaInfo.Attributes = filteredDNAAttrs(dnaInfo.Attributes)

	s.writeSuccessResponse(w, dnaInfo)
}

// authorizeStewardScope resolves stewardID's owning tenant (durable-store fallback,
// matching handleGetSteward) and authorizes it against the caller's ctxkeys.TenantScope
// (Issue #4335). On any failure — steward not found, or found but outside the caller's
// scope — it writes the same 404 STEWARD_NOT_FOUND response and returns false, so a
// caller cannot use response shape to distinguish "does not exist" from "exists in
// another tenant".
func (s *Server) authorizeStewardScope(w http.ResponseWriter, r *http.Request, stewardID, route string) bool {
	stewardTenant, exists := "", false
	if info, ok := s.controllerService.GetStewardInfo(stewardID); ok {
		stewardTenant, exists = info.TenantID, true
	} else if rec := s.durableStewardRecord(r.Context(), stewardID); rec != nil {
		stewardTenant, exists = rec.TenantID, true
	}
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return false
	}

	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, stewardTenant, route); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, stewardTenant) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		}
		return false
	}
	return true
}

// authorizeStewardRead decides a by-ID read of a steward-keyed resource. It
// resolves the steward's owning tenant (live registry, then the durable store)
// and applies the shared read decision (Issue #4715): a root caller subject to the
// ADR-025 boundary with no crossing for that tenant gets the crossing challenge,
// and every other refusal — including a steward known nowhere — is the 404
// STEWARD_NOT_FOUND, so response shape is no existence oracle.
func (s *Server) authorizeStewardRead(w http.ResponseWriter, r *http.Request, stewardID, route string) bool {
	_, ok := s.authorizeStewardReadTenant(w, r, stewardID, route)
	return ok
}

// authorizeStewardReadTenant is authorizeStewardRead returning the steward's
// owning tenant for handlers that need it after the decision.
func (s *Server) authorizeStewardReadTenant(w http.ResponseWriter, r *http.Request, stewardID, route string) (string, bool) {
	stewardTenant, exists := "", false
	if info, ok := s.controllerService.GetStewardInfo(stewardID); ok {
		stewardTenant, exists = info.TenantID, true
	} else if rec := s.durableStewardRecord(r.Context(), stewardID); rec != nil {
		stewardTenant, exists = rec.TenantID, true
	}
	notFound := func() { s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND") }
	if !exists {
		notFound()
		return "", false
	}
	if !s.authorizeRecordRead(w, r, stewardTenant, route, notFound) {
		return "", false
	}
	return stewardTenant, true
}

// authorizeStewardScopeLenient resolves stewardID's owning tenant the same way
// handleUpdateStewardConfig does — falling back to the caller's own tenant (never
// denying outright) when the steward is not known anywhere, since config and
// script-history endpoints keyed by steward ID can legitimately be queried before a
// steward first connects — and authorizes it against the caller's ctxkeys.TenantScope
// (Issue #4335). Unlike authorizeStewardScope, this never 404s solely because the
// steward is unknown: an unknown steward resolves to the caller's own tenant, which
// is always self-authorized, leaving the downstream lookup to decide not-found on
// its own terms.
//
// Ownership is resolved from the live registry first and from the durable store
// second, exactly as authorizeStewardScope does. The durable fallback is what keeps
// the gate a gate: the connection registry is per-node (Issue #3480), so a steward
// owned by another tenant that is merely offline or attached to a peer controller is
// absent from GetStewardInfo, and without the fallback it would resolve to the
// caller's own tenant and self-authorize. The durable store answers nothing for a
// genuinely unregistered steward, so the intended leniency is preserved.
func (s *Server) authorizeStewardScopeLenient(w http.ResponseWriter, r *http.Request, stewardID, route string) bool {
	_, ok := s.authorizeStewardTenantLenient(w, r, stewardID, route)
	return ok
}

// authorizeStewardTenantLenient is authorizeStewardScopeLenient returning the
// tenant it authorized — the tenant the steward's config is stored under. A
// steward known nowhere resolves to the caller's own tenant (the root tenant for a
// root caller, Issue #4665); a caller with no tenant at all is refused rather than
// given a substitute tenant (Issue #4543).
func (s *Server) authorizeStewardTenantLenient(w http.ResponseWriter, r *http.Request, stewardID, route string) (string, bool) {
	tenantID, known := s.stewardOwnerTenant(r.Context(), stewardID)
	if !known {
		own, ok := callerOwnTenant(r.Context())
		if !ok {
			s.writeErrorResponse(w, http.StatusForbidden, "No tenant scope", "NO_TENANT_SCOPE")
			return "", false
		}
		tenantID = own
	}

	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, tenantID, route); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, tenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		}
		return "", false
	}
	return tenantID, true
}

// stewardOwnerTenant is the tenant that owns stewardID, from the live registry
// first and the durable store second (see authorizeStewardScopeLenient for why
// both). ok is false for a steward known to neither.
func (s *Server) stewardOwnerTenant(ctx context.Context, stewardID string) (string, bool) {
	if info, ok := s.controllerService.GetStewardInfo(stewardID); ok && info.TenantID != "" {
		return info.TenantID, true
	}
	if rec := s.durableStewardRecord(ctx, stewardID); rec != nil && rec.TenantID != "" {
		return rec.TenantID, true
	}
	return "", false
}

// handleGetStewardConfig handles GET /api/v1/stewards/{id}/config
func (s *Server) handleGetStewardConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	if !s.authorizeStewardScopeLenient(w, r, stewardID, "GET /api/v1/stewards/{id}/config") {
		return
	}

	// Get modules filter from query params
	modules := r.URL.Query()["modules"]

	// Create gRPC request
	req := &controller.ConfigRequest{
		StewardId: stewardID,
		Modules:   modules,
	}

	// Call gRPC service. Threading r.Context() (not context.Background()) lets
	// GetConfiguration's own cross-tenant guard (Issue #1572) see the caller's
	// tenant — defense-in-depth alongside authorizeStewardScopeLenient above,
	// and load-bearing for any future caller of this service method that does
	// not go through that handler-level check (Issue #4346).
	configResp, err := s.configService.GetConfiguration(r.Context(), req)
	if err != nil {
		s.logger.Error("Failed to get steward configuration", "steward_id", stewardIDForLog, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get configuration", "INTERNAL_ERROR")
		return
	}

	// Check response status
	if configResp.Status.Code != 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, configResp.Status.Message, "CONFIG_ERROR")
		return
	}

	// Convert protobuf config to map for HTTP response
	protoConfig := configResp.Config.Config
	if protoConfig == nil {
		s.logger.Error("Configuration is nil")
		s.writeErrorResponse(w, http.StatusInternalServerError, "Configuration is nil", "INTERNAL_ERROR")
		return
	}

	// Convert protobuf to Go struct
	goConfig, err := stewardtypes.FromProto(protoConfig)
	if err != nil {
		s.logger.Error("Failed to convert protobuf to Go struct", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to convert configuration", "CONVERSION_ERROR")
		return
	}

	// Marshal Go struct to JSON for response
	jsonBytes, err := json.Marshal(goConfig)
	if err != nil {
		s.logger.Error("Failed to marshal configuration to JSON", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to marshal configuration", "MARSHAL_ERROR")
		return
	}

	// Parse into map for response
	var config map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &config); err != nil {
		s.logger.Error("Failed to parse configuration JSON", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to parse configuration", "PARSE_ERROR")
		return
	}

	// Create response
	configInfo := ConfigurationInfo{
		StewardID: stewardID,
		Version:   configResp.Version,
		Config:    config,
		UpdatedAt: time.Now().UTC(),
	}

	s.writeSuccessResponse(w, configInfo)
}

// handleUpdateStewardConfig handles PUT /api/v1/stewards/{id}/config
func (s *Server) handleUpdateStewardConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)
	if !identifierRegex.MatchString(stewardID) {
		s.logger.Warn("Invalid steward ID format in config update request")
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	// Resolve the tenant the config is stored under. This endpoint targets a
	// specific steward, so the config must be stored under THAT steward's
	// tenant — not the caller's. Using the caller's tenant would store the
	// config where neither the save=deploy fanout nor the steward's own sync
	// can find it. The caller's own tenant is used only when the steward is not
	// yet known (Issue #1572).
	//
	// Tenant-subtree authorization (Issue #3792) is checked before the body is
	// even read, so a caller with no authority over the target tenant learns
	// nothing about the request beyond a 404 — not even whether the body is
	// well-formed. 404 rather than 403 avoids disclosing that a steward exists in
	// a tenant outside the caller's authority. This is the most powerful write
	// class in the API, so a root caller subject to the ADR-025 boundary must hold
	// a crossing for the steward's tenant exactly as on any other tenant-targeting
	// route (Issue #4337).
	tenantID, ok := s.authorizeStewardTenantLenient(w, r, stewardID, "PUT /api/v1/stewards/{id}/config")
	if !ok {
		return
	}

	tenantIDForLog := logging.SanitizeLogValue(tenantID)

	config, ok := s.decodeStewardConfigBody(w, r, stewardIDForLog)
	if !ok {
		return
	}

	if !s.validateConfigResourceNames(w, &config, stewardIDForLog) {
		return
	}

	s.logger.Info("Configuration upload request received",
		"steward_id", stewardIDForLog,
		"tenant_id", tenantIDForLog,
		"resource_count", len(config.Resources))

	if !s.resolveConfigRequiredModules(w, r, &config, stewardIDForLog, tenantIDForLog) {
		return
	}

	// Store configuration using V2 durable config service
	if !s.storeStewardConfig(w, r, tenantID, stewardID, &config, stewardIDForLog, tenantIDForLog) {
		return
	}

	s.logger.Info("Configuration stored successfully",
		"steward_id", stewardIDForLog,
		"tenant_id", tenantIDForLog)

	// Issue #3757 (ADR-031 Decision 2): "status: stored responses that imply
	// more than storage are replaced by responses that reference the trackable
	// delivery record." Record a durable outbox row for this steward-directed
	// write and attempt immediate delivery via the same node-local fan-out path
	// handleConfigPush uses, so the response can point the caller at something
	// they can watch land instead of a bare "stored".
	resp := map[string]any{
		"steward_id": stewardID,
		"tenant_id":  tenantID,
		"message":    "Configuration stored successfully",
	}
	s.recordConfigUpdateDelivery(r, stewardID, tenantID, stewardIDForLog, resp)
	if _, ok := resp["command_id"]; !ok {
		// No commandStore configured, or the delivery row failed to persist —
		// fall back to a plain storage acknowledgement rather than claiming a
		// trackable record that does not exist.
		resp["status"] = "stored"
	}

	s.writeSuccessResponse(w, resp)
}

// decodeStewardConfigBody reads the request body into a StewardConfig.
// Supports both JSON (legacy) and YAML (production .cfg format), selected by
// Content-Type. On failure the response has been written and ok is false.
func (s *Server) decodeStewardConfigBody(w http.ResponseWriter, r *http.Request, stewardIDForLog string) (stewardtypes.StewardConfig, bool) {
	var config stewardtypes.StewardConfig
	contentType := r.Header.Get("Content-Type")

	// Read body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Failed to read request body", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body", "READ_ERROR")
		return config, false
	}

	// Parse based on Content-Type
	if strings.Contains(contentType, "yaml") || strings.Contains(contentType, "x-yaml") {
		// YAML format (production .cfg files)
		if err := yaml.Unmarshal(bodyBytes, &config); err != nil {
			s.logger.Error("Failed to decode config YAML", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid YAML body", "INVALID_YAML")
			return config, false
		}
		s.logger.Info("Received configuration in YAML format", "steward_id", stewardIDForLog, "resources", len(config.Resources))
		return config, true
	}
	// JSON format (legacy/backward compatibility)
	if err := json.Unmarshal(bodyBytes, &config); err != nil {
		s.logger.Error("Failed to decode config JSON", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_YAML")
		return config, false
	}
	s.logger.Info("Received configuration in JSON format", "steward_id", stewardIDForLog, "resources", len(config.Resources))
	return config, true
}

// validateConfigResourceNames validates resource names at the handler boundary
// before any storage-side effect. An invalid name (e.g. containing a dot like
// "docker.io") is a client input error, not a storage fault: reject it with 400
// VALIDATION_ERROR here rather than letting it reach SetConfiguration and
// surface as a generic 500 STORAGE_ERROR. The offending name is
// config-derived and therefore safe to echo back to the caller so the
// client can self-diagnose without server logs. (Issue #2482)
func (s *Server) validateConfigResourceNames(w http.ResponseWriter, config *stewardtypes.StewardConfig, stewardIDForLog string) bool {
	for i, resource := range config.Resources {
		if !identifierRegex.MatchString(resource.Name) {
			s.logger.Warn("Invalid resource name in config upload",
				"steward_id", stewardIDForLog,
				"resource_index", i,
				"resource_name", logging.SanitizeLogValue(resource.Name))
			s.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("Invalid resource name %q: must contain only alphanumeric characters, hyphens, and underscores", resource.Name),
				"VALIDATION_ERROR")
			return false
		}
	}
	return true
}

// resolveConfigRequiredModules resolves required_modules: against the controller
// module cache before the configuration is stored (Issue #1884). When the module
// subsystem is wired, any declared module that is not cached + approved must
// block the deployment. Dependencies are nil-tolerant so deployments without the
// module subsystem (and tests that exercise unrelated paths) continue to
// function unchanged.
func (s *Server) resolveConfigRequiredModules(w http.ResponseWriter, r *http.Request, config *stewardtypes.StewardConfig, stewardIDForLog, tenantIDForLog string) bool {
	s.mu.RLock()
	cacheLister := s.moduleCacheLister
	bundleResolver := s.moduleBundleResolver
	bundleApprover := s.moduleBundleApprover
	trustStore := s.moduleTrustStore
	s.mu.RUnlock()
	if len(config.RequiredModules) == 0 ||
		cacheLister == nil || bundleResolver == nil ||
		bundleApprover == nil || trustStore == nil {
		return true
	}
	if err := resolution.ResolveCfgRequiredModules(
		r.Context(),
		config.RequiredModules,
		cacheLister,
		bundleResolver,
		bundleApprover,
		trustStore,
	); err != nil {
		s.logger.Warn("cfg deployment blocked by required_modules resolution",
			"steward_id", stewardIDForLog,
			"tenant_id", tenantIDForLog,
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusUnprocessableEntity, err.Error(), "REQUIRED_MODULE_NOT_APPROVED")
		return false
	}
	return true
}

// storeStewardConfig persists the configuration through the config service. A
// validation failure is a 400 VALIDATION_ERROR; any other failure is a 500
// STORAGE_ERROR. On failure the response has been written and ok is false.
func (s *Server) storeStewardConfig(w http.ResponseWriter, r *http.Request, tenantID, stewardID string, config *stewardtypes.StewardConfig, stewardIDForLog, tenantIDForLog string) bool {
	err := s.configService.SetConfiguration(r.Context(), tenantID, stewardID, config)
	if err == nil {
		return true
	}
	var ve *service.ValidationFailedError
	if errors.As(err, &ve) {
		s.logger.Warn("Configuration validation failed",
			"steward_id", stewardIDForLog,
			"tenant_id", tenantIDForLog,
			"error_count", len(ve.Errors))
		s.writeErrorResponse(w, http.StatusBadRequest, ve.Error(), "VALIDATION_ERROR")
		return false
	}
	s.logger.Error("Failed to store configuration",
		"steward_id", stewardIDForLog,
		"tenant_id", tenantIDForLog,
		"error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store configuration", "STORAGE_ERROR")
	return false
}

// recordConfigUpdateDelivery records a durable sync_config outbox row for a
// stored config update and attempts delivery, adding command_id and
// delivery_status to resp. It leaves resp untouched when no command store is
// configured or the row fails to persist.
func (s *Server) recordConfigUpdateDelivery(r *http.Request, stewardID, tenantID, stewardIDForLog string, resp map[string]any) {
	if s.commandStore == nil {
		return
	}
	var issuedBy string
	if principal, ok := r.Context().Value(principalContextKey).(*Principal); ok && principal != nil {
		issuedBy = principal.ID
	}
	rec := &business.CommandRecord{
		ID:             fmt.Sprintf("cfg-update-%s-%d", stewardID, time.Now().UnixNano()),
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      stewardID,
		TenantID:       tenantID,
		IssuedAt:       time.Now().UTC(),
		IssuedBy:       issuedBy,
		DeliveryStatus: business.DeliveryStatusPending,
	}
	if err := s.commandStore.CreateCommandRecord(r.Context(), rec); err != nil {
		s.logger.Warn("Failed to durably record config update delivery",
			"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	resp["command_id"] = rec.ID
	resp["delivery_status"] = string(s.deliverConfigUpdate(r.Context(), rec, stewardID, stewardIDForLog))
}

// deliverConfigUpdate triggers the config sync for a recorded config update and
// returns the delivery status written back to the record: delivered on success,
// otherwise the record's initial (pending) status.
func (s *Server) deliverConfigUpdate(ctx context.Context, rec *business.CommandRecord, stewardID, stewardIDForLog string) business.DeliveryStatus {
	if s.commandPublisher == nil {
		return rec.DeliveryStatus
	}
	if pubErr := s.commandPublisher.TriggerConfigSyncWithID(ctx, rec.ID, stewardID); pubErr != nil {
		s.logger.Warn("Failed to trigger config sync after config update",
			"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(pubErr.Error()))
		if updErr := s.commandStore.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusPending, logging.SanitizeLogValue(pubErr.Error())); updErr != nil {
			s.logger.Warn("Failed to record delivery attempt failure",
				"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(updErr.Error()))
		}
		return rec.DeliveryStatus
	}
	if updErr := s.commandStore.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusDelivered, ""); updErr != nil {
		s.logger.Warn("Failed to record delivered status",
			"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(updErr.Error()))
		return rec.DeliveryStatus
	}
	return business.DeliveryStatusDelivered
}

// handleValidateConfig handles POST /api/v1/stewards/{id}/config/validate
func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	tenantID, ok := s.authorizeStewardTenantLenient(w, r, stewardID, "POST /api/v1/stewards/{id}/config/validate")
	if !ok {
		return
	}

	// Parse request body
	var validationReq ConfigValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&validationReq); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Convert config to JSON bytes
	configBytes, err := json.Marshal(validationReq.Config)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid configuration format", "INVALID_CONFIG")
		return
	}

	// Create gRPC request
	req := &controller.ConfigValidationRequest{
		Config:  configBytes,
		Version: validationReq.Version,
	}

	// Call gRPC service
	validationResp, err := s.configService.ValidateConfig(context.WithValue(r.Context(), ctxkeys.TenantID, tenantID), req)
	if err != nil {
		s.logger.Error("Failed to validate configuration", "steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to validate configuration", "INTERNAL_ERROR")
		return
	}

	// Convert validation errors
	var validationErrors []ValidationError
	for _, err := range validationResp.Errors {
		validationErrors = append(validationErrors, ValidationErrorFromProto(err))
	}

	// Create response
	result := ConfigValidationResult{
		Valid:    validationResp.Status.Code == 0,
		Errors:   validationErrors,
		Metadata: validationResp.Metadata,
	}

	s.writeSuccessResponse(w, result)
}

// handleStewardAuthRefresh handles POST /api/v1/stewards/{id}/auth/refresh.
// It is a no-op surface that validates the steward exists and acknowledges the
// refresh request. No token or credential state is modified (mTLS is the sole
// auth mechanism; this endpoint exists for HA test instrumentation only).
func (s *Server) handleStewardAuthRefresh(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	idForLog := logging.SanitizeLogValue(id)

	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	if !s.authorizeStewardScope(w, r, id, "POST /api/v1/stewards/{id}/auth/refresh") {
		return
	}

	s.logger.Info("Auth refresh requested", "steward_id", idForLog)
	s.respondJSON(w, http.StatusOK, map[string]string{"steward_id": id, "status": "refresh_requested"})
}

// handleDeleteStewardConfig handles DELETE /api/v1/stewards/{id}/config
func (s *Server) handleDeleteStewardConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	// The config lives under the steward's own tenant (Issue #1572), which the
	// caller must be authorized for (Issue #4665).
	tenantID, ok := s.authorizeStewardTenantLenient(w, r, stewardID, "DELETE /api/v1/stewards/{id}/config")
	if !ok {
		return
	}

	err := s.configService.DeleteConfiguration(r.Context(), tenantID, stewardID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.logger.Debug("Configuration not found for deletion", "steward_id", stewardIDForLog)
			s.writeErrorResponse(w, http.StatusNotFound, "Configuration not found", "CONFIG_NOT_FOUND")
		} else {
			s.logger.Error("Failed to delete configuration", "steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete configuration", "INTERNAL_ERROR")
		}
		return
	}

	s.logger.Info("Configuration deleted", "steward_id", stewardIDForLog)
	w.WriteHeader(http.StatusNoContent)
}

// handleDecommissionSteward handles DELETE /api/v1/stewards/{id}.
// Tombstones the steward's durable record (status: deregistered), updates the in-memory
// registry, and drops any active QUIC/gRPC session. The record is retained for audit.
// Requires an admin mTLS certificate (TierMTLSOnly gate). Issue #2408.
func (s *Server) handleDecommissionSteward(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	if s.stewardStore == nil {
		s.logger.Error("decommission failed: steward store not configured",
			"steward_id", logging.SanitizeLogValue(stewardID))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
		return
	}

	callerTenant := callerTenantFilter(r.Context())

	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		if !errors.Is(err, business.ErrStewardNotFound) {
			s.logger.Error("decommission failed: store lookup error",
				"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up steward", "INTERNAL_ERROR")
			return
		}
		// Fallback: steward registered via gRPC path exists only in the in-memory
		// registry but not in the durable store (Issue #2929 root cause).
		memInfo, memExists := s.controllerService.GetStewardInfo(stewardID)
		if !memExists {
			// Not in either store — genuinely unknown steward.
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
		// Cross-tenant scope check using the in-memory record's TenantID (fallback path).
		// 404 instead of 403 to avoid existence disclosure across tenant boundaries.
		if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), memInfo.TenantID, "DELETE /api/v1/stewards/{id}"); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, memInfo.TenantID) {
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			}
			return
		}
		// Backfill a durable record before tombstoning — must succeed before any in-memory
		// updates (mirrors the "durable write must succeed first" invariant). Populate at
		// minimum ID and TenantID; the store stamps RegisteredAt/LastSeen/Status itself.
		backfill := &business.StewardRecord{
			ID:       stewardID,
			TenantID: memInfo.TenantID,
		}
		if backfillErr := s.stewardStore.RegisterSteward(r.Context(), backfill); backfillErr != nil && !errors.Is(backfillErr, business.ErrStewardAlreadyExists) {
			s.logger.Error("decommission failed: backfill registration error",
				"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(backfillErr.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decommission steward", "INTERNAL_ERROR")
			return
		}
	} else {
		// Cross-tenant scope check using the durable record's TenantID as the authoritative
		// source; a root caller subject to the ADR-025 boundary needs a crossing for a
		// steward in a tenant below root (Issue #4665).
		if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), record.TenantID, "DELETE /api/v1/stewards/{id}"); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
				// 404 instead of 403 to avoid existence disclosure across tenant boundaries.
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			}
			return
		}
	}

	// Tombstone in durable storage — authoritative; must succeed before in-memory updates.
	if err := s.stewardStore.DeregisterSteward(r.Context(), stewardID); err != nil {
		s.logger.Error("decommission failed: store write error",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decommission steward", "INTERNAL_ERROR")
		return
	}

	// Update in-memory status — best-effort; durable storage already succeeded.
	if err := s.controllerService.UpdateStewardStatus(stewardID, string(business.StewardStatusDeregistered)); err != nil {
		s.logger.Warn("decommission: in-memory status update failed (non-fatal)",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
	}

	// Drop any active QUIC/gRPC connection.
	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg != nil {
		reg.Unregister(stewardID)
	}

	// Emit audit event.
	auditTenantID := callerTenant
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	s.emitDecommissionAudit(r.Context(), auditTenantID, principalID, stewardID)

	s.logger.Info("Steward decommissioned",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"principal_id", logging.SanitizeLogValue(principalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     stewardID,
		"status": string(business.StewardStatusDeregistered),
	})
}

// emitDecommissionAudit records a steward-decommission audit event. No-op when auditManager is nil.
func (s *Server) emitDecommissionAudit(ctx context.Context, tenantID, principalID, stewardID string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("steward.decommissioned").
		User(principalID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit decommission audit event",
			"error", err, "steward_id", logging.SanitizeLogValue(stewardID))
	}
}

// setVisibilityRequest is the JSON body for PATCH /api/v1/stewards/{id}/visibility.
type setVisibilityRequest struct {
	Hidden bool `json:"hidden"`
}

// handleSetStewardVisibility handles PATCH /api/v1/stewards/{id}/visibility.
// Reversibly hides or unhides a steward from the default fleet view.
// Requires steward:visibility permission at AssuranceBasic (Issue #2918).
func (s *Server) handleSetStewardVisibility(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	if s.stewardStore == nil {
		s.logger.Error("visibility update failed: steward store not configured",
			"steward_id", logging.SanitizeLogValue(stewardID))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
		return
	}

	var req setVisibilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	callerTenant := callerTenantFilter(r.Context())

	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		if errors.Is(err, business.ErrStewardNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
		s.logger.Error("visibility update failed: store lookup error",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up steward", "INTERNAL_ERROR")
		return
	}

	// Tenant-scope check: 404 instead of 403 to avoid existence disclosure across tenant boundaries.
	if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), record.TenantID, "PATCH /api/v1/stewards/{id}/visibility"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		}
		return
	}

	// Durable write first — hard-fail the request on error.
	if err := s.stewardStore.SetStewardHidden(r.Context(), stewardID, req.Hidden); err != nil {
		s.logger.Error("visibility update failed: durable write error",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update steward visibility", "INTERNAL_ERROR")
		return
	}

	// Best-effort in-memory update — log-and-continue on error.
	if err := s.controllerService.SetStewardHidden(stewardID, req.Hidden); err != nil {
		s.logger.Warn("visibility update: in-memory update failed (non-fatal)",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
	}

	// Emit audit event at Medium severity: concealment-capable but reversible (Issue #2918 security ruling).
	auditTenantID := callerTenant
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	s.emitVisibilityAudit(r.Context(), auditTenantID, principalID, stewardID, req.Hidden)

	// The logged state is selected through control flow rather than read off the
	// decoded request body: req is populated from the untrusted HTTP body, so any
	// field read of it is a taint source into the log sink. Branching to a literal
	// keeps request-controlled bytes out of the sink entirely.
	visibilityState := "visible"
	if req.Hidden {
		visibilityState = "hidden"
	}

	s.logger.Info("Steward visibility updated",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"visibility", visibilityState,
		"principal_id", logging.SanitizeLogValue(principalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     stewardID,
		"hidden": req.Hidden,
	})
}

// emitVisibilityAudit records a steward visibility-changed audit event.
// Severity: Medium — concealment-capable (drops device from default view) but reversible.
// No-op when auditManager is nil.
func (s *Server) emitVisibilityAudit(ctx context.Context, tenantID, principalID, stewardID string, hidden bool) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventDataModification).
		Action("steward.visibility_changed").
		User(principalID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Detail("hidden", hidden)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit visibility audit event",
			"error", logging.SanitizeLogValue(err.Error()), "steward_id", logging.SanitizeLogValue(stewardID))
	}
}

// Limits on the module list built from steward-supplied fragment authorities.
const (
	maxReportedModules = 64
	maxModuleNameLen   = 64
)

// nonModuleAuthorities are fragment authorities that identify a steward component
// rather than a module: host-fact gatherers and the osquery observer.
var nonModuleAuthorities = map[string]bool{"gatherer": true, "osquery": true}

// moduleNamesFromFragments returns the distinct, sorted authorities of the fragments
// that are owned by a module. Authority is steward-supplied and the host may be
// compromised, so each value is untrusted display data: blank values, values with
// control or format characters, and over-long values are dropped, and the list is capped.
func moduleNamesFromFragments(frags []*common.Fragment) []string {
	seen := make(map[string]struct{})
	for _, f := range frags {
		name := strings.TrimSpace(f.GetAuthority())
		if name == "" || len(name) > maxModuleNameLen || nonModuleAuthorities[name] {
			continue
		}
		// Control and format characters (bidi overrides, zero-width) could make a name
		// render as a different module in a terminal.
		if strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 || !utf8.ValidString(name) {
			continue
		}
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maxReportedModules {
		names = names[:maxReportedModules]
	}
	return names
}

// handleGetStewardModules handles GET /api/v1/stewards/{id}/modules.
// The list is the modules that own at least one resource on the steward, derived from
// the Authority of the stored DNA fragments (ADR-017). It returns 501 only when the
// steward has no DNA at all. The steward's fragment budget can truncate module
// fragments on very large hosts, in which case a module may be missing from the list.
func (s *Server) handleGetStewardModules(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	stewardInfo, exists := s.controllerService.GetStewardInfo(stewardID)
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	// The caller's tenant must equal or be a ParentID ancestor of the steward's tenant
	// (404 otherwise); a boundary-subject root caller needs a crossing (Issue #4715).
	if !s.authorizeRecordRead(w, r, stewardInfo.TenantID, "GET /api/v1/stewards/{id}/modules", func() {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
	}) {
		return
	}

	if stewardInfo.DNA == nil {
		s.logger.Info("Modules unavailable: steward has no DNA", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusNotImplemented,
			"steward has not reported DNA yet; module list unavailable",
			"MODULES_UNAVAILABLE")
		return
	}

	type moduleEntry struct {
		Name string `json:"name"`
	}
	names := moduleNamesFromFragments(stewardInfo.DNA.Fragments)
	modules := make([]moduleEntry, 0, len(names))
	for _, name := range names {
		modules = append(modules, moduleEntry{Name: name})
	}

	s.logger.Info("Fetched steward loaded modules", "steward_id", stewardIDForLog, "count", len(modules))
	s.writeSuccessResponse(w, map[string]interface{}{"modules": modules})
}

// stewardLogEvent is the per-event shape returned in the logs response.
type stewardLogEvent struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	Component     string                 `json:"component,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
}

// stewardLogRecord is one logical event in the logs response. Correlated
// detection+outcome pairs share a CorrelationID and are rolled into one record.
// A detection with no outcome in the query window carries PendingOutcome=true
// (the "monitor fired, convergence never completed" wedge signal from ADR-012 §2).
type stewardLogRecord struct {
	CorrelationID  string           `json:"correlation_id,omitempty"`
	Detection      *stewardLogEvent `json:"detection"`
	Outcome        *stewardLogEvent `json:"outcome,omitempty"`
	PendingOutcome bool             `json:"pending_outcome,omitempty"`
}

// handleGetStewardLogs handles GET /api/v1/stewards/{id}/logs.
// Reads from the dedicated steward-event LoggingManager via QueryTimeRange,
// scopes to the path steward by post-filtering on steward_id, rolls up
// correlated detection+outcome pairs, and gates on the caller's tenant.
func (s *Server) handleGetStewardLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	params, invalidMsg := parseStewardLogParams(r.URL.Query())
	if invalidMsg != "" {
		s.writeErrorResponse(w, http.StatusBadRequest, invalidMsg, "INVALID_PARAMETER")
		return
	}

	s.logger.Debug("Steward log pull request",
		"steward_id", stewardIDForLog,
		"tail", params.tail,
		"since", logging.SanitizeLogValue(params.since),
		"level", logging.SanitizeLogValue(params.level),
		"module", logging.SanitizeLogValue(params.module),
	)

	// Containment resolves through ParentID ancestry, so "msp-ab" never matches "msp-a";
	// a root caller subject to the ADR-025 boundary needs a crossing (Issue #4715).
	if !s.authorizeStewardRead(w, r, stewardID, "GET /api/v1/stewards/{id}/logs") {
		return
	}

	// Return empty events when the manager is not yet wired.
	s.mu.RLock()
	mgr := s.stewardEventLoggingManager
	s.mu.RUnlock()

	emptyEvents := []stewardLogRecord{}
	if mgr == nil {
		s.writeSuccessResponse(w, map[string]interface{}{"events": emptyEvents})
		return
	}

	entries, ok := s.flushAndQueryStewardLogs(w, r, mgr, params.timeRangeQuery(stewardID), stewardIDForLog)
	if !ok {
		return
	}

	// Defensive post-filter: the shared steward-event manager co-mingles all stewards;
	// the ACL gates endpoint access but does not scope the result set. Only entries
	// whose steward_id field exactly matches the path parameter are returned.
	filtered := make([]loggingInterfaces.LogEntry, 0, len(entries))
	for _, e := range entries {
		if sid, ok := e.Fields["steward_id"].(string); ok && sid == stewardID {
			filtered = append(filtered, e)
		}
	}

	records := rollupStewardLogsByCorrelationID(filtered)
	s.writeSuccessResponse(w, map[string]interface{}{"events": records})
}

// stewardLogParams is the validated query of GET /api/v1/stewards/{id}/logs.
type stewardLogParams struct {
	tail   int
	since  string
	level  string
	module string
}

// parseStewardLogParams validates the tail, since, level and module query
// parameters. A non-empty message names the first invalid parameter and is the
// 400 INVALID_PARAMETER response text.
func parseStewardLogParams(q url.Values) (stewardLogParams, string) {
	tail, ok := parseStewardLogTail(q.Get("tail"))
	if !ok {
		return stewardLogParams{}, "tail must be an integer between 1 and 1000"
	}

	// Validate since is a parseable Go duration.
	since := q.Get("since")
	if since != "" {
		if _, err := time.ParseDuration(since); err != nil {
			return stewardLogParams{}, "since must be a valid Go duration (e.g. 1h, 30m)"
		}
	}

	// Validate level is one of the four allowed values.
	level := q.Get("level")
	switch level {
	case "", "DEBUG", "INFO", "WARN", "ERROR":
	default:
		return stewardLogParams{}, "level must be DEBUG, INFO, WARN, or ERROR"
	}

	// Cap module at 128 characters.
	module := q.Get("module")
	if len(module) > 128 {
		return stewardLogParams{}, "module parameter exceeds maximum length of 128 characters"
	}

	return stewardLogParams{tail: tail, since: since, level: level, module: module}, ""
}

// parseStewardLogTail parses the tail parameter (default 100, max 1000); ok is
// false for a value that is not an integer in 1..1000.
func parseStewardLogTail(tailStr string) (int, bool) {
	if tailStr == "" {
		return 100, true
	}
	v, err := strconv.Atoi(tailStr)
	if err != nil || v < 1 || v > 1000 {
		return 0, false
	}
	return v, true
}

// timeRangeQuery maps the validated parameters onto a TimeRangeQuery scoped to
// stewardID.
func (p stewardLogParams) timeRangeQuery(stewardID string) loggingInterfaces.TimeRangeQuery {
	startTime := time.Now().Add(-24 * time.Hour) // default: last 24 hours
	if p.since != "" {
		d, _ := time.ParseDuration(p.since) // already validated by parseStewardLogParams
		startTime = time.Now().Add(-d)
	}

	filters := map[string]interface{}{
		"steward_id": stewardID,
	}
	if p.level != "" {
		filters["level"] = p.level
	}
	if p.module != "" {
		filters["component"] = p.module
	}

	return loggingInterfaces.TimeRangeQuery{
		StartTime: startTime,
		EndTime:   time.Now(),
		Filters:   filters,
		Limit:     p.tail,
	}
}

// flushAndQueryStewardLogs flushes the event manager and then runs query.
//
// Issue #4857: the manager batches and writes asynchronously, so entries the
// log-stream handler has accepted may still be buffered. Flush before reading
// so every accepted entry is visible to this query; a flush failure is
// reported like a query failure rather than serving a silently stale result.
// On failure the 500 QUERY_ERROR response has been written and ok is false.
func (s *Server) flushAndQueryStewardLogs(w http.ResponseWriter, r *http.Request, mgr *logging.LoggingManager, query loggingInterfaces.TimeRangeQuery, stewardIDForLog string) ([]loggingInterfaces.LogEntry, bool) {
	if flushErr := mgr.Flush(r.Context()); flushErr != nil {
		s.logger.Error("Failed to flush steward event log before query",
			"steward_id", stewardIDForLog,
			"error", logging.SanitizeLogValue(flushErr.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query event log", "QUERY_ERROR")
		return nil, false
	}

	entries, err := mgr.QueryTimeRange(r.Context(), query)
	if err != nil {
		s.logger.Error("Failed to query steward event log",
			"steward_id", stewardIDForLog,
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query event log", "QUERY_ERROR")
		return nil, false
	}
	return entries, true
}

// rollupStewardLogsByCorrelationID groups log entries by correlation_id.
// Entries without a correlation_id are standalone records. Correlated pairs
// are merged into one record (detection = earlier timestamp, outcome = later).
// A detection with no paired outcome is marked PendingOutcome=true.
func rollupStewardLogsByCorrelationID(entries []loggingInterfaces.LogEntry) []stewardLogRecord {
	var records []stewardLogRecord

	// Group entries by correlation_id. Entries with no correlation_id are
	// immediately emitted as standalone records, preserving source order.
	grouped := make(map[string][]loggingInterfaces.LogEntry)
	var corrOrder []string // tracks first-seen order for deterministic output
	seen := make(map[string]bool)

	for _, e := range entries {
		if e.CorrelationID == "" {
			records = append(records, stewardLogRecord{
				Detection: logEntryToStewardEvent(e),
			})
			continue
		}
		if !seen[e.CorrelationID] {
			corrOrder = append(corrOrder, e.CorrelationID)
			seen[e.CorrelationID] = true
		}
		grouped[e.CorrelationID] = append(grouped[e.CorrelationID], e)
	}

	for _, corrID := range corrOrder {
		events := grouped[corrID]
		// Sort by timestamp: earlier = detection, later = outcome.
		sort.Slice(events, func(i, j int) bool {
			return events[i].Timestamp.Before(events[j].Timestamp)
		})
		record := stewardLogRecord{
			CorrelationID: corrID,
			Detection:     logEntryToStewardEvent(events[0]),
		}
		if len(events) >= 2 {
			record.Outcome = logEntryToStewardEvent(events[1])
		} else {
			record.PendingOutcome = true
		}
		records = append(records, record)
	}

	return records
}

// logEntryToStewardEvent converts a LogEntry to the API response event shape.
func logEntryToStewardEvent(e loggingInterfaces.LogEntry) *stewardLogEvent {
	return &stewardLogEvent{
		Timestamp:     e.Timestamp,
		Level:         e.Level,
		Message:       e.Message,
		Component:     e.Component,
		CorrelationID: e.CorrelationID,
		Fields:        e.Fields,
	}
}

// moveStewardRequest is the JSON body for POST /api/v1/stewards/{id}/move.
type moveStewardRequest struct {
	NewTenantID string `json:"new_tenant_id"`
}

// allowedMoveSources is the set of statuses from which a steward may be moved.
// Revoked stewards are excluded: accepting a move would silently back-door re-entry
// into a new tenant without going through the registration-refresh approval flow.
var allowedMoveSources = map[string]bool{
	"registered":   true,
	"active":       true,
	"lost":         true,
	"archived":     true,
	"dormant":      true,
	"deregistered": true,
}

// handleMoveSteward handles POST /api/v1/stewards/{id}/move.
// Moves a steward to a different tenant: updates durable storage AND the live
// in-memory registry, and invalidates the per-tenant config cache for both the
// source and destination tenants. Registered in the Tier-3 (mTLS-only) endpoint
// class (Issue #2341).
func (s *Server) handleMoveSteward(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	newTenantID, ok := s.decodeMoveDestination(w, r)
	if !ok {
		return
	}

	record, ok := s.loadMoveSource(w, r, stewardID, stewardIDForLog)
	if !ok {
		return
	}

	// Extract the caller's principal and scope from context once so they are available
	// throughout authorization, audit, and the success path.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	mv := stewardMove{
		stewardID:      stewardID,
		oldTenantID:    record.TenantID,
		newTenantID:    newTenantID,
		principal:      principal,
		callerTenantID: callerTenantFilter(r.Context()),
	}

	if !s.authorizeStewardMove(w, r, mv) {
		return
	}

	// Self-move: destination equals current tenant — short-circuit with no state change.
	if mv.oldTenantID == mv.newTenantID {
		s.logger.Info("steward move skipped (self-move)",
			"steward_id", logging.SanitizeLogValue(mv.stewardID),
			"tenant_id", logging.SanitizeLogValue(mv.newTenantID),
		)
		s.writeSuccessResponse(w, mv.response("no_change"))
		return
	}

	if !s.checkMoveSourceStatus(w, record, stewardIDForLog) {
		return
	}
	if !s.checkMoveDestination(w, r, mv) {
		return
	}
	if !s.applyStewardMove(w, r, mv) {
		return
	}

	s.logger.Info("steward moved to new tenant",
		"steward_id", logging.SanitizeLogValue(mv.stewardID),
		"old_tenant_id", logging.SanitizeLogValue(mv.oldTenantID),
		"new_tenant_id", logging.SanitizeLogValue(mv.newTenantID),
	)

	s.emitMoveAudit(r, mv.stewardID, mv.oldTenantID, mv.newTenantID, mv.principal,
		business.AuditEventDataModification, "steward_move",
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{
			"decision":                "approved",
			"privileged_cross_tenant": mv.callerTenantID == "", //architecture:allow-root-scope -- audit detail, not an access decision
		})

	s.writeSuccessResponse(w, mv.response("moved"))
}

// stewardMove carries the identifiers of one steward move through the
// authorization, validation and apply steps of handleMoveSteward.
type stewardMove struct {
	stewardID, oldTenantID, newTenantID string
	principal                           *Principal
	callerTenantID                      string
}

// response is the success body of a move; status is "moved" or "no_change".
func (m stewardMove) response(status string) map[string]any {
	return map[string]any{
		"steward_id":      m.stewardID,
		"tenant_id":       m.newTenantID,
		"previous_tenant": m.oldTenantID,
		"status":          status,
	}
}

// decodeMoveDestination reads and validates new_tenant_id from the request
// body. On failure the 400 response has been written and ok is false.
func (s *Server) decodeMoveDestination(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req moveStewardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return "", false
	}

	newTenantID := req.NewTenantID
	if newTenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "new_tenant_id is required", "MISSING_TENANT_ID")
		return "", false
	}
	if !tenantPathRegex.MatchString(newTenantID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid tenant ID format", "INVALID_TENANT_ID")
		return "", false
	}
	return newTenantID, true
}

// loadMoveSource loads the steward to move: it must exist in durable storage.
// On failure the response has been written and ok is false.
func (s *Server) loadMoveSource(w http.ResponseWriter, r *http.Request, stewardID, stewardIDForLog string) (*business.StewardRecord, bool) {
	if s.stewardStore == nil {
		s.logger.Error("steward move failed: steward store not configured", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Steward store not configured", "INTERNAL_ERROR")
		return nil, false
	}

	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		s.logger.Info("steward not found for move", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return nil, false
	}
	return record, true
}

// authorizeStewardMove is the dual-admin authorization (Issue #2342). An
// explicitly root caller (callerTenantID == "") may move across tenants — the move
// is recorded as a privileged cross-tenant action — but both the source and the
// destination tenant must pass its tenant decision, so a root caller subject to the
// ADR-025 boundary needs a crossing for each tenant below root it touches (Issue
// #4665). A scoped admin must have scope that is an ancestor of (or equal to) BOTH
// source AND destination through ParentID ancestry: a sibling whose ID merely
// shares a prefix ("msp-ab" vs "msp-a") is not a descendant and is denied. On
// denial the audit event and response have been written and ok is false.
func (s *Server) authorizeStewardMove(w http.ResponseWriter, r *http.Request, mv stewardMove) bool {
	if mv.callerTenantID == "" { //architecture:allow-root-scope -- an explicitly root caller: both tenants pass tenantAccessForScope here
		return s.authorizeRootMove(w, r, mv)
	}
	return s.authorizeScopedMove(w, r, mv)
}

// authorizeRootMove applies the tenant decision of a root caller to both the
// source and the destination tenant of a move.
func (s *Server) authorizeRootMove(w http.ResponseWriter, r *http.Request, mv stewardMove) bool {
	for _, tenant := range []string{mv.oldTenantID, mv.newTenantID} {
		access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), tenant, "POST /api/v1/stewards/{id}/move")
		if access == tenantAuthAllowed {
			continue
		}
		reason := "tenant_outside_boundary"
		if access == tenantAuthNeedsCrossing {
			reason = "tenant_crossing_required"
		}
		s.emitMoveAudit(r, mv.stewardID, mv.oldTenantID, mv.newTenantID, mv.principal,
			business.AuditEventSecurityEvent, "steward_move",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{
				"decision": "denied",
				"reason":   reason,
			})
		if !s.writeTenantCrossingIfNeeded(w, access, tenant) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		}
		return false
	}
	return true
}

// authorizeScopedMove requires the source and destination of a move to be in
// the tenant-scoped caller's subtree.
func (s *Server) authorizeScopedMove(w http.ResponseWriter, r *http.Request, mv stewardMove) bool {
	sourceInScope := s.tenantSubtreeContains(r.Context(), mv.callerTenantID, mv.oldTenantID)
	destInScope := s.tenantSubtreeContains(r.Context(), mv.callerTenantID, mv.newTenantID)
	if sourceInScope && destInScope {
		return true
	}
	s.logger.Warn("steward move denied: scoped admin has insufficient scope",
		"steward_id", logging.SanitizeLogValue(mv.stewardID),
		"source_tenant", logging.SanitizeLogValue(mv.oldTenantID),
		"dest_tenant", logging.SanitizeLogValue(mv.newTenantID),
		"caller_scope", logging.SanitizeLogValue(mv.callerTenantID),
	)
	s.emitMoveAudit(r, mv.stewardID, mv.oldTenantID, mv.newTenantID, mv.principal,
		business.AuditEventSecurityEvent, "steward_move",
		business.AuditResultDenied, business.AuditSeverityCritical,
		map[string]interface{}{
			"decision":        "denied",
			"reason":          "insufficient_scope",
			"source_in_scope": sourceInScope,
			"dest_in_scope":   destInScope,
		})
	if !sourceInScope {
		// A steward outside the caller's subtree is indistinguishable from an
		// unknown one, as on every other per-steward route (no existence oracle).
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return false
	}
	s.writeErrorResponse(w, http.StatusForbidden, "Insufficient scope to move steward between these tenants", "INSUFFICIENT_SCOPE")
	return false
}

// checkMoveSourceStatus rejects a source steward whose status does not permit a
// move. Revoked stewards may not be moved (would back-door un-revoke). On
// rejection the 400 response has been written and ok is false.
func (s *Server) checkMoveSourceStatus(w http.ResponseWriter, record *business.StewardRecord, stewardIDForLog string) bool {
	if string(record.Status) == "revoked" {
		s.logger.Warn("steward move rejected: source status is revoked",
			"steward_id", stewardIDForLog,
		)
		s.writeErrorResponse(w, http.StatusBadRequest, "Revoked stewards cannot be moved", "STEWARD_REVOKED")
		return false
	}

	// Validate source status against the allowed set.
	if !allowedMoveSources[string(record.Status)] {
		s.logger.Warn("steward move rejected: source status not allowed",
			"steward_id", stewardIDForLog,
			"status", logging.SanitizeLogValue(string(record.Status)),
		)
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Steward status does not permit a move", "STEWARD_STATUS_INVALID")
		return false
	}
	return true
}

// checkMoveDestination requires the destination tenant to exist and be active.
// On rejection the response has been written and ok is false.
func (s *Server) checkMoveDestination(w http.ResponseWriter, r *http.Request, mv stewardMove) bool {
	if s.tenantManager == nil {
		s.logger.Error("steward move failed: tenant manager not configured", "steward_id", logging.SanitizeLogValue(mv.stewardID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Tenant manager not configured", "INTERNAL_ERROR")
		return false
	}

	destTenant, err := s.tenantManager.GetTenant(r.Context(), mv.newTenantID)
	if err != nil {
		s.logger.Info("destination tenant not found for steward move",
			"steward_id", logging.SanitizeLogValue(mv.stewardID),
			"new_tenant_id", logging.SanitizeLogValue(mv.newTenantID),
		)
		s.writeErrorResponse(w, http.StatusBadRequest, "Destination tenant not found", "TENANT_NOT_FOUND")
		return false
	}
	if destTenant.Status != "active" {
		s.logger.Warn("destination tenant is not active",
			"steward_id", logging.SanitizeLogValue(mv.stewardID),
			"new_tenant_id", logging.SanitizeLogValue(mv.newTenantID),
			"tenant_status", logging.SanitizeLogValue(string(destTenant.Status)),
		)
		s.writeErrorResponse(w, http.StatusBadRequest, "Destination tenant is not active", "TENANT_NOT_ACTIVE")
		return false
	}
	return true
}

// applyStewardMove performs the move: durable storage, the live registry and
// device-tenant mapping, and the per-tenant config caches. On failure the
// response has been written and ok is false.
func (s *Server) applyStewardMove(w http.ResponseWriter, r *http.Request, mv stewardMove) bool {
	// Update durable storage. Guarded by a compare-and-swap on oldTenantID — the
	// snapshot read via GetSteward above (Issue #3895): two concurrent moves
	// racing against the same stale snapshot must not both blindly overwrite
	// the tenant column. GetSteward above already confirmed the steward exists,
	// so a guard-loss error here means a concurrent move already changed its
	// tenant — a conflict, not a fresh not-found.
	if err := s.stewardStore.UpdateStewardTenant(r.Context(), mv.stewardID, mv.oldTenantID, mv.newTenantID); err != nil {
		if err == business.ErrStewardNotFound {
			s.logger.Info("steward move lost the compare-and-swap: tenant changed concurrently",
				"steward_id", logging.SanitizeLogValue(mv.stewardID),
				"expected_tenant_id", logging.SanitizeLogValue(mv.oldTenantID),
				"new_tenant_id", logging.SanitizeLogValue(mv.newTenantID),
			)
			s.writeErrorResponse(w, http.StatusConflict,
				"Steward was moved concurrently; reload and retry", "STEWARD_MOVE_CONFLICT")
			return false
		}
		s.logger.Error("steward move: failed to update durable store",
			"steward_id", logging.SanitizeLogValue(mv.stewardID),
			"new_tenant_id", logging.SanitizeLogValue(mv.newTenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update steward tenant", "INTERNAL_ERROR")
		return false
	}

	// Update the live in-memory registry and the durable device_tenant mapping that
	// tenant resolution reads on reconnect and restart (Issue #3324). A missing
	// registry entry is not an error — the steward may not be connected yet (e.g.
	// the controller just restarted) and the durable writes are authoritative. Any
	// other error means the device_tenant mapping still names the OLD tenant, so the
	// move would silently revert on the steward's next reconnect: fail the request.
	if regErr := s.controllerService.UpdateStewardTenant(mv.stewardID, mv.newTenantID); regErr != nil {
		if !errors.Is(regErr, service.ErrStewardNotInRegistry) {
			s.logger.Error("steward move: failed to persist device tenant mapping",
				"steward_id", logging.SanitizeLogValue(mv.stewardID),
				"new_tenant_id", logging.SanitizeLogValue(mv.newTenantID),
				"error", logging.SanitizeLogValue(regErr.Error()),
			)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update steward tenant", "INTERNAL_ERROR")
			return false
		}
		s.logger.Info("steward move: registry entry not present (steward not yet connected)",
			"steward_id", logging.SanitizeLogValue(mv.stewardID),
		)
	}

	// Invalidate per-tenant config cache for both source and destination so the
	// next config resolution uses the correct tenant path.
	s.tenantManager.InvalidateConfigCache(mv.oldTenantID)
	s.tenantManager.InvalidateConfigCache(mv.newTenantID)
	return true
}

// emitMoveAudit records a steward-move audit event. It is a no-op when auditManager is nil.
// Must be called before WriteHeader on every code path.
func (s *Server) emitMoveAudit(
	r *http.Request,
	stewardID, sourceTenantID, destTenantID string,
	principal *Principal,
	eventType business.AuditEventType,
	action string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	callerID := ""
	certSerial := ""
	certFingerprint := ""
	if principal != nil {
		callerID = principal.ID
		certSerial = principal.CertSerial
		certFingerprint = principal.CertFingerprint
	}

	b := audit.NewEventBuilder().
		Tenant(sourceTenantID).
		Type(eventType).
		Action(action).
		User(callerID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(result).
		Severity(severity).
		Request(s.getRequestID(r), r.Method, r.URL.Path, extractSourceIP(r, s.trustedProxies), r.Header.Get("User-Agent")).
		Changes(
			map[string]interface{}{"tenant_id": logging.SanitizeLogValue(sourceTenantID)},
			map[string]interface{}{"tenant_id": logging.SanitizeLogValue(destTenantID)},
			[]string{"tenant_id"},
		).
		Detail("steward_id", logging.SanitizeLogValue(stewardID)).
		Detail("source_tenant", logging.SanitizeLogValue(sourceTenantID)).
		Detail("dest_tenant", logging.SanitizeLogValue(destTenantID)).
		Detail("admin_cn", logging.SanitizeLogValue(callerID)).
		Detail("cert_serial", logging.SanitizeLogValue(certSerial)).
		Detail("cert_fingerprint", logging.SanitizeLogValue(certFingerprint))

	for k, v := range extras {
		b = b.Detail(k, v)
	}

	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit move audit event",
			"error", err,
			"steward_id", logging.SanitizeLogValue(stewardID),
		)
	}
}

// handleGetEffectiveConfig handles GET /api/v1/stewards/{id}/config/effective
func (s *Server) handleGetEffectiveConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// The config lives under the steward's own tenant (Issue #1572), which the
	// caller must be authorized for (Issue #4665).
	tenantID, ok := s.authorizeStewardTenantLenient(w, r, stewardID, "GET /api/v1/stewards/{id}/config/effective")
	if !ok {
		return
	}

	// Get effective configuration from the V2 configuration service (durable storage)
	effectiveConfig, err := s.configService.GetEffectiveConfiguration(r.Context(), tenantID, stewardID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.logger.Debug("No effective configuration found", "steward_id", stewardIDForLog)
			s.writeErrorResponse(w, http.StatusNotFound, "No effective configuration found for steward", "NOT_FOUND")
		} else {
			s.logger.Error("Failed to get effective configuration", "steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve effective configuration", "INTERNAL_ERROR")
		}
		return
	}

	s.logger.Info("Retrieved effective configuration", "steward_id", stewardIDForLog)
	s.writeSuccessResponse(w, effectiveConfig)
}
