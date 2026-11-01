// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DegradedHeartbeatAge is the heartbeat age beyond which an otherwise-active
// steward is counted as Degraded in the fleet health aggregate
// (GET /api/v1/fleet/health). An active steward whose last heartbeat arrived
// more than DegradedHeartbeatAge ago is experiencing connectivity issues and
// warrants attention. Mirrors the client-side STALE_AFTER_MS threshold
// (web/src/fleet/health.ts) so aggregate counts align with per-row health pills.
const DegradedHeartbeatAge = 5 * time.Minute

// FleetHealthResponse is the response payload for GET /api/v1/fleet/health.
// Hidden is always present (non-suppressible) regardless of include_hidden:
// an operator must always see that concealment is in effect (Issue #2918).
type FleetHealthResponse struct {
	// Tampered counts readable stewards that raised a tamper alarm, hidden ones
	// included: a tampered steward is never concealed. TamperedStewards lists them
	// and comes first so a consumer reads the highest-severity group before the rest.
	Tampered         int                    `json:"tampered"`
	TamperedStewards []FleetTamperedSteward `json:"tampered_stewards"`

	Healthy     int `json:"healthy"`
	Degraded    int `json:"degraded"`
	Unreachable int `json:"unreachable"`
	Hidden      int `json:"hidden"`

	// ReasonCounts counts readable, non-hidden stewards by health reason code
	// (a steward reporting a code is counted once for it). Always present, empty
	// when no steward reports a reason.
	ReasonCounts map[string]int `json:"reason_counts"`

	// WalledOff holds the anonymized aggregate of client-tenant stewards a root
	// caller subject to the ADR-025 boundary holds no crossing for (A6.1). It is
	// counts only, and is absent for every other caller and when nothing is
	// walled off. The four counters above cover only stewards the caller may read.
	WalledOff *FleetAnonymizedMetrics `json:"walled_off,omitempty"`
}

// FleetTamperedSteward is one tampered steward in the fleet health response.
type FleetTamperedSteward struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	TamperCodes []string `json:"tamper_codes,omitempty"`
}

// FleetAnonymizedMetrics is the Amendment 6 (A6.1) anonymized metric set: online
// and offline totals, operating-system platform mix and steward version mix. It
// has no field that can carry a host name or device identifier. Online counts
// active stewards and Offline counts lost ones, as in the billing rollup.
type FleetAnonymizedMetrics struct {
	Online   int            `json:"online"`
	Offline  int            `json:"offline"`
	Platform platformCounts `json:"platform"`
	Versions map[string]int `json:"versions"`
}

// add counts one steward into the anonymized set.
func (m *FleetAnonymizedMetrics) add(res fleet.StewardResult) {
	switch res.Status {
	case "active":
		m.Online++
	case "lost":
		m.Offline++
	}
	osName := strings.ToLower(res.OS)
	switch {
	case strings.Contains(osName, "windows"):
		m.Platform.Windows++
	case strings.Contains(osName, "linux"):
		m.Platform.Linux++
	case strings.Contains(osName, "darwin"), strings.Contains(osName, "macos"):
		m.Platform.Darwin++
	default:
		m.Platform.Other++
	}
	version := res.RunningVersion
	if version == "" {
		version = res.DNAAttributes["steward.version"]
	}
	if version == "" {
		version = unknownStewardVersion
	}
	if m.Versions == nil {
		m.Versions = make(map[string]int)
	}
	m.Versions[version]++
}

// splitReadableResults partitions search results into those the caller may read
// and the rest. A caller not subject to the ADR-025 boundary keeps every result:
// its tenant scoping is already in the query filter. A boundary-subject root
// caller keeps only root-tenant and crossing-covered rows (A2.5: a bulk read
// silently omits the others).
func splitReadableResults(scope *tenantReadScope, results []fleet.StewardResult) (readable, walledOff []fleet.StewardResult) {
	if !scope.boundarySubject() {
		return results, nil
	}
	readable = make([]fleet.StewardResult, 0, len(results))
	for _, res := range results {
		if scope.Allows(res.TenantID) {
			readable = append(readable, res)
		} else {
			walledOff = append(walledOff, res)
		}
	}
	scope.LogSummary()
	return readable, walledOff
}

// SelectorResolveRequest is the request body for POST /api/v1/fleet/resolve.
type SelectorResolveRequest struct {
	Selector string `json:"selector"`
}

// selectorResolveError carries the HTTP status/code/message a selector-resolution failure
// should produce. It lets resolveSelectorFilter be shared between handleResolveSelector and
// handleOperatorPayloadSignBegin (Issue #3695) while each handler keeps its own response
// envelope and success-path shaping.
type selectorResolveError struct {
	status  int
	message string
	code    string
}

// resolveSelectorFilter parses selectorExpr and enforces the caller's tenant subtree scope,
// returning a filter ready for fleetQuery.Search. An explicit tenant prefix in the selector
// must be at or below the caller's own node; an absent prefix defaults to the caller's entire
// subtree. Root-scoped callers (ctxkeys.TenantScope) are unrestricted.
//
// This is the sole tenant-scoping enforcement path for selector-driven target resolution —
// shared rather than duplicated so every caller (handleResolveSelector,
// handleOperatorPayloadSignBegin) enforces identical cross-tenant boundaries.
//
// Migrated to ctxkeys.TenantScope (Issue #4335): an unset scope is refused rather than
// silently treated as unrestricted the way a raw ctxkeys.TenantID=="" comparison would —
// that ambiguity is exactly what let a plumbing bug (a dropped context, or a wrong
// context key) resolve every selector fleet-wide instead of denying the request.
func (s *Server) resolveSelectorFilter(ctx context.Context, selectorExpr string) (fleet.Filter, *selectorResolveError) {
	if selectorExpr == "" {
		return fleet.Filter{}, &selectorResolveError{
			status: http.StatusBadRequest, code: "MISSING_SELECTOR",
			message: "selector is required: use 'all' to match all stewards",
		}
	}

	filter, parsedTenantPath, err := selector.Parse(selectorExpr)
	if err != nil {
		s.logger.Info("Invalid selector expression",
			"selector", logging.SanitizeLogValue(selectorExpr), "error", logging.SanitizeLogValue(err.Error()))
		return fleet.Filter{}, &selectorResolveError{
			status: http.StatusBadRequest, code: "INVALID_SELECTOR", message: err.Error(),
		}
	}

	scope, _ := ctx.Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	var tid string
	switch {
	case scope.IsRoot(): //architecture:allow-root-scope -- builds the query filter only; a read filters its results with splitReadableResults and an action applies authorizeFleetTargets
		// Unrestricted: tid stays "".
	case scope.IsTenant() && scope.Path() != "":
		tid = scope.Path()
	default:
		s.logger.Info("Selector resolution refused: caller tenant scope is unset")
		return fleet.Filter{}, &selectorResolveError{
			status: http.StatusForbidden, code: "FORBIDDEN",
			message: "tenant scope required",
		}
	}

	if parsedTenantPath != "" {
		if tid != "" && !selectorPathWithinCaller(tid, parsedTenantPath) {
			s.logger.Info("Selector tenant outside caller subtree",
				"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
				"caller_tenant", logging.SanitizeLogValue(tid))
			return fleet.Filter{}, &selectorResolveError{
				status: http.StatusForbidden, code: "CROSS_TENANT",
				message: "Target tenant is outside the caller's authorized subtree",
			}
		}
		filter.TenantSubtree = parsedTenantPath
	} else if tid != "" {
		s.scopeFilterToTenantSubtree(ctx, &filter, tid)
	}

	return filter, nil
}

// handleResolveSelector resolves a steward filter expression to a concrete steward set.
//
// POST /api/v1/fleet/resolve
// Body: {"selector": "name:es-hv0* os:linux tag:prod"}
//
// An empty or missing selector is rejected — use "all" to match all stewards.
// The expression is parsed by pkg/fleet/selector; unknown keys are a parse error.
func (s *Server) handleResolveSelector(w http.ResponseWriter, r *http.Request) {
	var req SelectorResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	filter, rerr := s.resolveSelectorFilter(r.Context(), req.Selector)
	if rerr != nil {
		s.writeErrorResponse(w, rerr.status, rerr.message, rerr.code)
		return
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}

	// A root caller subject to the ADR-025 boundary resolves only the stewards of
	// tenants it may read (Issue #4715).
	results, _ = splitReadableResults(s.tenantReadScope(r, "POST /api/v1/fleet/resolve"), results)

	stewardList := make([]StewardInfo, 0, len(results))
	for _, res := range results {
		info := StewardInfo{
			ID:       res.ID,
			TenantID: res.TenantID,
			Status:   res.Status,
			LastSeen: res.LastHeartbeat,
		}
		if len(res.DNAAttributes) > 0 {
			info.DNA = &DNAInfo{
				Hostname:     res.Hostname,
				OS:           res.OS,
				Architecture: res.Architecture,
				Attributes:   res.DNAAttributes,
				Fragments:    res.DNAFragments,
			}
		}
		stewardList = append(stewardList, info)
	}
	s.attachHealthReasons(r.Context(), stewardList)

	s.logger.Info("Resolved selector",
		"selector", logging.SanitizeLogValue(req.Selector), "count", len(stewardList))
	s.writeSuccessResponse(w, stewardList)
}

// handleFleetHealth handles GET /api/v1/fleet/health.
//
// Returns tenant-scoped counts of stewards by health classification:
//   - healthy:     status=="active" with a heartbeat within DegradedHeartbeatAge
//   - degraded:    status=="active" with a heartbeat older than DegradedHeartbeatAge
//   - unreachable: status=="lost"
//   - tampered:    status=="tampered", listed first with its tamper codes
//
// Other lifecycle states (registered, deregistered, archived, dormant, revoked)
// are not counted. Scoping includes the caller's full tenant subtree (the caller
// plus all descendant tenants), consistent with handleResolveSelector.
// Admin callers (empty TenantID) see the full fleet.
func (s *Server) handleFleetHealth(w http.ResponseWriter, r *http.Request) {
	tid := callerTenantFilter(r.Context())

	filter := fleet.Filter{}
	if tid != "" { //architecture:allow-root-scope -- builds the query filter only; the read filter is splitReadableResults below
		s.scopeFilterToTenantSubtree(r.Context(), &filter, tid)
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet health query failed", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}

	// Counters cover only stewards the caller may read. Client-tenant stewards a
	// boundary-subject root caller holds no crossing for contribute only the
	// anonymized A6.1 aggregate (Issue #4715).
	results, walledOff := splitReadableResults(s.tenantReadScope(r, "GET /api/v1/fleet/health"), results)

	now := time.Now()
	resp := FleetHealthResponse{ReasonCounts: map[string]int{}, TamperedStewards: []FleetTamperedSteward{}}
	reasonsByID := s.healthReasonCodesByID(r.Context())
	if len(walledOff) > 0 {
		resp.WalledOff = &FleetAnonymizedMetrics{Versions: map[string]int{}}
		for _, res := range walledOff {
			resp.WalledOff.add(res)
		}
	}
	tenantByTampered := resp.tally(results, reasonsByID, now)
	s.attachFleetTamperCodes(r.Context(), &resp, tenantByTampered)

	s.logger.Info("Fleet health query",
		"tenant_id", logging.SanitizeLogValue(tid),
		"tampered", resp.Tampered,
		"healthy", resp.Healthy,
		"degraded", resp.Degraded,
		"unreachable", resp.Unreachable,
		"hidden", resp.Hidden,
	)
	s.writeSuccessResponse(w, resp)
}

// tally counts readable stewards into the response and returns the tenant of
// each tampered steward, keyed by steward ID. A tampered steward is counted and
// listed whether or not it is hidden, and is not also counted as healthy,
// degraded or hidden.
func (r *FleetHealthResponse) tally(results []fleet.StewardResult, reasonsByID map[string]map[string]struct{}, now time.Time) map[string]string {
	tenantByTampered := make(map[string]string)
	for _, res := range results {
		if res.Status == string(business.StewardStatusTampered) {
			r.Tampered++
			r.TamperedStewards = append(r.TamperedStewards, FleetTamperedSteward{ID: res.ID, TenantID: res.TenantID})
			tenantByTampered[res.ID] = res.TenantID
			r.countReasons(reasonsByID[res.ID])
			continue
		}
		// Count hidden stewards in the caller's scope regardless of include_hidden
		// (non-suppressible: the operator must always see that concealment is in effect).
		if res.Hidden {
			r.Hidden++
			continue
		}
		r.countReasons(reasonsByID[res.ID])
		switch res.Status {
		case "active":
			if now.Sub(res.LastHeartbeat) <= DegradedHeartbeatAge {
				r.Healthy++
			} else {
				r.Degraded++
			}
		case "lost":
			r.Unreachable++
		}
	}
	return tenantByTampered
}

// attachFleetTamperCodes sorts the tampered stewards by ID and fills in each
// one's tamper codes from the latest alarm audit event.
func (s *Server) attachFleetTamperCodes(ctx context.Context, resp *FleetHealthResponse, tenantByTampered map[string]string) {
	sort.Slice(resp.TamperedStewards, func(i, j int) bool { return resp.TamperedStewards[i].ID < resp.TamperedStewards[j].ID })
	if len(tenantByTampered) == 0 {
		return
	}
	codes := s.tamperCodesFromAudit(ctx, tenantByTampered)
	for i := range resp.TamperedStewards {
		resp.TamperedStewards[i].TamperCodes = codes[resp.TamperedStewards[i].ID]
	}
}

// countReasons adds one to the count of each reason code a steward reports.
func (r *FleetHealthResponse) countReasons(codes map[string]struct{}) {
	for code := range codes {
		r.ReasonCounts[code]++
	}
}

// healthReasonCodesByID returns each steward's distinct reason codes from the
// durable store, for stewards that report any. Callers look up only stewards
// already filtered to the caller's read scope, so nothing here widens it. An
// absent or failing store yields an empty map.
func (s *Server) healthReasonCodesByID(ctx context.Context) map[string]map[string]struct{} {
	store := s.stewardStore
	if store == nil {
		return nil
	}
	records, err := store.ListStewards(ctx)
	if err != nil {
		s.logger.Warn("Failed to read steward health reasons for fleet health",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil
	}
	out := make(map[string]map[string]struct{})
	for _, rec := range records {
		if rec == nil || len(rec.HealthReasons) == 0 {
			continue
		}
		codes := make(map[string]struct{}, len(rec.HealthReasons))
		for _, r := range healthReasonsFromRecord(rec) {
			codes[r.Code] = struct{}{}
		}
		out[rec.ID] = codes
	}
	return out
}
