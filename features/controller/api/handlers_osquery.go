// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/fleet/selector"
	"github.com/cfgis/cfgms/features/controller/health"
	stewardosquery "github.com/cfgis/cfgms/features/controller/osquery"
	osquerymodule "github.com/cfgis/cfgms/features/modules/extended/osquery"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// stewardOsqueryDispatcher is the minimal interface satisfied by *osquery.OsqueryHandler.
// Defined here to keep the api package self-contained and to allow test doubles.
// The controller validates catalog_id and params against the catalog before any
// fan-out (Issue #5449), then passes the values through unchanged; the steward-side
// admission step (Issue #3566) re-validates and builds the SQL.
type stewardOsqueryDispatcher interface {
	QuerySteward(ctx context.Context, stewardID, catalogID string, params map[string]string) ([]*transportpb.OsqueryRow, error)
}

// osqueryQueryRequest is the JSON body for POST /api/v1/osquery/query.
type osqueryQueryRequest struct {
	CatalogID string            `json:"catalog_id"`
	Params    map[string]string `json:"params,omitempty"`
	Selector  string            `json:"selector"`
}

// Per-steward outcome values carried on the wire in osqueryStewardResult.Outcome
// (Epic #6439). These are distinct from the osqueryOutcome* set below, which is
// the request-level signal label (ok/partial/failed) of the live-query metrics.
const (
	osqueryResultAnswered     = "answered"      // the steward returned a result (rows may be empty)
	osqueryResultNotConnected = "not_connected" // no open query stream on this node; nothing was sent
	osqueryResultFailed       = "failed"        // any other dispatch error: refused, not sent, or ended in an error
)

// osqueryStewardResult is one steward's result within the aggregate response.
// Rows holds the answer of an answered steward; Error holds the sanitized error
// text of a not_connected or failed steward. Outcome is always one of the
// osqueryResult* values. LastSeen is set only on a not_connected result, from
// the fleet record's last heartbeat (see osqueryLastSeen).
type osqueryStewardResult struct {
	StewardID string              `json:"steward_id"`
	Rows      []map[string]string `json:"rows,omitempty"`
	Error     string              `json:"error,omitempty"`
	Outcome   string              `json:"outcome"`
	LastSeen  *time.Time          `json:"last_seen,omitempty"`
}

// osqueryQuerySummary states how complete the answer is: how many stewards the
// selector matched and how many of them ended in each outcome. QueriedAt is the
// UTC time the fan-out was dispatched.
type osqueryQuerySummary struct {
	Matched      int       `json:"matched"`
	Answered     int       `json:"answered"`
	NotConnected int       `json:"not_connected"`
	Failed       int       `json:"failed"`
	QueriedAt    time.Time `json:"queried_at"`
}

// osqueryQueryResponse is returned by POST /api/v1/osquery/query: a summary of
// the answer's completeness and one result per matched steward, in match order.
type osqueryQueryResponse struct {
	Summary osqueryQuerySummary    `json:"summary"`
	Results []osqueryStewardResult `json:"results"`
}

// handleOsqueryQuery handles POST /api/v1/osquery/query.
//
// Accepts a catalog query ID, optional typed parameters, and a fleet selector.
// Dispatches to each targeted steward via S7's (Issue #3566) QuerySteward method,
// and returns per-steward results with partial success on individual steward
// failures. Each result carries an outcome (answered, not_connected or failed),
// and the response carries a summary with the matched count, the count per
// outcome and the dispatch time. Every execution is audited.
func (s *Server) handleOsqueryQuery(w http.ResponseWriter, r *http.Request) {
	if s.osqueryDispatcher == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Osquery dispatch not configured", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := s.requireActingPrincipal(w, r)
	if !ok {
		return
	}

	req, ok := s.decodeOsqueryQueryRequest(w, r)
	if !ok {
		return
	}

	filter, ok := s.osqueryTargetFilter(w, r, req.Selector)
	if !ok {
		return
	}

	if s.fleetQuery == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet query not available", "SERVICE_UNAVAILABLE")
		return
	}

	stewards, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during osquery dispatch",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve fleet selector", "INTERNAL_ERROR")
		return
	}

	// A query runs on every matched steward: each one's tenant must pass the
	// caller's tenant decision, crossing included (Issue #4665).
	if !s.authorizeFleetTargets(w, r, stewards, "POST /api/v1/osquery/query") {
		return
	}

	stewardIDs := make([]string, 0, len(stewards))
	for _, sr := range stewards {
		stewardIDs = append(stewardIDs, sr.ID)
	}

	// Fan-out to all targeted stewards concurrently; collect partial results.
	dispatchStart := time.Now()
	results := s.fanOutOsqueryQuery(r.Context(), stewards, req)
	s.recordOsqueryQuerySignals(time.Since(dispatchStart), results)

	s.emitOsqueryAudit(r, principal.ID, req.CatalogID, stewardIDs)

	s.writeSuccessResponse(w, osqueryQueryResponse{
		Summary: summarizeOsqueryResults(results, dispatchStart),
		Results: results,
	})
}

// decodeOsqueryQueryRequest decodes the body of POST /api/v1/osquery/query and
// validates its catalog_id and params against the catalog. On false the error
// response has been written.
func (s *Server) decodeOsqueryQueryRequest(w http.ResponseWriter, r *http.Request) (osqueryQueryRequest, bool) {
	var req osqueryQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return osqueryQueryRequest{}, false
	}

	if req.CatalogID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "catalog_id is required", "MISSING_CATALOG_ID")
		return osqueryQueryRequest{}, false
	}

	entry, err := osquerymodule.LookupCatalogEntry(req.CatalogID)
	if err != nil {
		s.logger.Debug("Unknown osquery catalog id",
			"catalog_id", logging.SanitizeLogValue(req.CatalogID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Unknown catalog_id", "INVALID_CATALOG_ID")
		return osqueryQueryRequest{}, false
	}
	if err := osquerymodule.ValidateParams(entry, req.Params); err != nil {
		s.logger.Debug("Invalid osquery params",
			"catalog_id", logging.SanitizeLogValue(req.CatalogID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid params for catalog_id", "INVALID_PARAMS")
		return osqueryQueryRequest{}, false
	}
	return req, true
}

// osqueryTargetFilter parses the fleet selector of an osquery dispatch and enforces the
// caller's tenant authorization boundary on it. On false the response has been written.
func (s *Server) osqueryTargetFilter(w http.ResponseWriter, r *http.Request, selectorExpr string) (fleet.Filter, bool) {
	if selectorExpr == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "selector is required", "MISSING_SELECTOR")
		return fleet.Filter{}, false
	}

	filter, parsedTenantPath, err := selector.Parse(selectorExpr)
	if err != nil {
		s.logger.Debug("Invalid osquery selector",
			"selector", logging.SanitizeLogValue(selectorExpr),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid selector", "INVALID_SELECTOR")
		return fleet.Filter{}, false
	}

	// Enforce the tenant authz boundary. selector.Parse deliberately does not do
	// this — it returns the parsed tenant path and leaves the decision to the
	// caller. fleet.Filter{TenantSubtree: ""} is unrestricted, so an unset
	// TenantSubtree would fan a catalog query out across every tenant's stewards.
	// An explicit selector prefix must lie at or below the caller's own node;
	// an absent prefix defaults to the caller's entire subtree. Admin callers
	// (empty tenant ID, e.g. mTLS cert admins) remain unrestricted, matching
	// handleResolveSelector and handleDispatchUpgrade.
	callerTenantID := callerTenantFilter(r.Context())
	if parsedTenantPath != "" {
		if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), parsedTenantPath, "POST /api/v1/osquery/query"); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, parsedTenantPath) {
				s.logger.Info("Osquery selector tenant outside caller subtree",
					"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
					"caller_tenant", logging.SanitizeLogValue(callerTenantID))
				s.writeErrorResponse(w, http.StatusForbidden,
					"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
			}
			return fleet.Filter{}, false
		}
		filter.TenantSubtree = parsedTenantPath
	} else if callerTenantID != "" { //architecture:allow-root-scope -- selector narrowing for tenant callers; the matched stewards then pass authorizeFleetTargets
		s.scopeFilterToTenantSubtree(r.Context(), &filter, callerTenantID)
	}
	return filter, true
}

// fanOutOsqueryQuery queries every steward concurrently and returns one result per
// steward, in stewards order. A steward's failure is recorded in its own result.
func (s *Server) fanOutOsqueryQuery(ctx context.Context, stewards []fleet.StewardResult, req osqueryQueryRequest) []osqueryStewardResult {
	results := make([]osqueryStewardResult, len(stewards))
	var wg sync.WaitGroup
	for i, sr := range stewards {
		wg.Add(1)
		go func(idx int, sr fleet.StewardResult) {
			defer wg.Done()
			rows, dispErr := s.osqueryDispatcher.QuerySteward(ctx, sr.ID, req.CatalogID, req.Params)
			results[idx] = newOsqueryStewardResult(sr, rows, dispErr)
		}(i, sr)
	}
	wg.Wait()
	return results
}

// newOsqueryStewardResult classifies one steward's dispatch result. A nil error
// is answered; the controller's ErrStewardNotConnected sentinel (matched by
// identity, wrapped or not) is not_connected; every other error is failed. The
// sanitized error text is kept on both error outcomes.
func newOsqueryStewardResult(sr fleet.StewardResult, rows []*transportpb.OsqueryRow, dispErr error) osqueryStewardResult {
	res := osqueryStewardResult{StewardID: sr.ID}
	switch {
	case dispErr == nil:
		res.Rows = rowsToMaps(rows)
		res.Outcome = osqueryResultAnswered
	case errors.Is(dispErr, stewardosquery.ErrStewardNotConnected):
		res.Error = logging.SanitizeLogValue(dispErr.Error())
		res.Outcome = osqueryResultNotConnected
		res.LastSeen = osqueryLastSeen(sr.LastHeartbeat)
	default:
		res.Error = logging.SanitizeLogValue(dispErr.Error())
		res.Outcome = osqueryResultFailed
	}
	return res
}

// osqueryLastSeen returns the last_seen value of a not_connected result: the
// fleet record's last heartbeat in UTC. A zero heartbeat (the steward was never
// heard from) yields nil, so last_seen is omitted. This zero-time rule lives
// here alone so it can be changed in one place.
func osqueryLastSeen(lastHeartbeat time.Time) *time.Time {
	if lastHeartbeat.IsZero() {
		return nil
	}
	t := lastHeartbeat.UTC()
	return &t
}

// summarizeOsqueryResults counts the results by outcome. Every result lands in
// exactly one count, so answered + not_connected + failed == matched holds by
// construction; an unrecognised outcome counts as failed.
func summarizeOsqueryResults(results []osqueryStewardResult, queriedAt time.Time) osqueryQuerySummary {
	sum := osqueryQuerySummary{Matched: len(results), QueriedAt: queriedAt.UTC()}
	for _, res := range results {
		switch res.Outcome {
		case osqueryResultAnswered:
			sum.Answered++
		case osqueryResultNotConnected:
			sum.NotConnected++
		default:
			sum.Failed++
		}
	}
	return sum
}

// Live-query signals (Issue #6059). Every label value comes from the closed sets
// below; the catalog ID, query text and steward IDs never reach a label.
const (
	osqueryOutcomeOK      = "ok"      // every targeted steward answered
	osqueryOutcomePartial = "partial" // some, not all, answered
	osqueryOutcomeFailed  = "failed"  // no targeted steward answered

	osqueryStewardOK     = "steward_ok"
	osqueryStewardFailed = "steward_failed"
)

// osqueryQuerySignals holds the registered live-query metrics of one collector.
type osqueryQuerySignals struct {
	duration *health.Histogram
	queries  *health.Counter
	stewards *health.Counter
}

// osquerySignalsEntry registers the metrics for one signal registry exactly once.
type osquerySignalsEntry struct {
	once    sync.Once
	signals *osqueryQuerySignals
}

// osquerySignalsByRegistry maps a collector's signal registry to its live-query
// metrics. A registry rejects a second registration of the same name, so the
// handler registers lazily, once per registry.
var osquerySignalsByRegistry sync.Map // *health.SignalRegistry -> *osquerySignalsEntry

// osqueryQuerySignalsFor returns the live-query metrics registered on the
// health collector's registry, registering them on first use. It returns nil
// when there is no collector or registration failed.
func (s *Server) osqueryQuerySignalsFor() *osqueryQuerySignals {
	if s.healthCollector == nil {
		return nil
	}
	reg := s.healthCollector.Signals()
	if reg == nil {
		return nil
	}
	v, _ := osquerySignalsByRegistry.LoadOrStore(reg, &osquerySignalsEntry{})
	entry := v.(*osquerySignalsEntry)
	entry.once.Do(func() {
		sig, err := registerOsqueryQuerySignals(reg)
		if err != nil {
			s.logger.Warn("Failed to register osquery query signals",
				"error", logging.SanitizeLogValue(err.Error()))
			return
		}
		entry.signals = sig
	})
	return entry.signals
}

func registerOsqueryQuerySignals(reg *health.SignalRegistry) (*osqueryQuerySignals, error) {
	duration, err := reg.RegisterHistogram("cfgms_osquery_query_duration_seconds",
		"Duration of live fleet osquery fan-outs, from dispatch to the last steward response.",
		[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}, nil)
	if err != nil {
		return nil, err
	}
	queries, err := reg.RegisterCounter("cfgms_osquery_queries_total",
		"Live fleet osquery requests that reached dispatch, by outcome: ok (every steward answered), partial (some) or failed (none).",
		map[string][]string{"outcome": {osqueryOutcomeOK, osqueryOutcomePartial, osqueryOutcomeFailed}})
	if err != nil {
		return nil, err
	}
	stewards, err := reg.RegisterCounter("cfgms_osquery_steward_results_total",
		"Per-steward results of live fleet osquery requests: steward_ok or steward_failed.",
		map[string][]string{"result": {osqueryStewardOK, osqueryStewardFailed}})
	if err != nil {
		return nil, err
	}
	return &osqueryQuerySignals{duration: duration, queries: queries, stewards: stewards}, nil
}

// osqueryOutcome classifies a fan-out from its per-steward results. A request
// with no targeted steward has nothing that failed to answer and counts as ok.
func osqueryOutcome(ok, failed int) string {
	switch {
	case failed == 0:
		return osqueryOutcomeOK
	case ok == 0:
		return osqueryOutcomeFailed
	default:
		return osqueryOutcomePartial
	}
}

// recordOsqueryQuerySignals records the duration, outcome and per-steward result
// counts of a fan-out that reached dispatch. No-op when s.healthCollector is nil.
// A failed record is logged and dropped: a missing signal never fails the request.
func (s *Server) recordOsqueryQuerySignals(elapsed time.Duration, results []osqueryStewardResult) {
	sig := s.osqueryQuerySignalsFor()
	if sig == nil {
		return
	}
	var ok, failed int
	for _, res := range results {
		if res.Error != "" {
			failed++
		} else {
			ok++
		}
	}
	record := func(err error) {
		if err != nil {
			s.logger.Warn("Failed to record osquery query signal",
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
	record(sig.duration.Observe(elapsed.Seconds(), nil))
	record(sig.queries.Inc(map[string]string{"outcome": osqueryOutcome(ok, failed)}))
	if ok > 0 {
		record(sig.stewards.Add(float64(ok), map[string]string{"result": osqueryStewardOK}))
	}
	if failed > 0 {
		record(sig.stewards.Add(float64(failed), map[string]string{"result": osqueryStewardFailed}))
	}
}

// rowsToMaps converts a proto OsqueryRow slice to []map[string]string for JSON output.
func rowsToMaps(rows []*transportpb.OsqueryRow) []map[string]string {
	if len(rows) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		m := make(map[string]string, len(row.GetColumns()))
		for k, v := range row.GetColumns() {
			m[k] = v
		}
		out = append(out, m)
	}
	return out
}

// emitOsqueryAudit records an osquery dispatch audit event.
// stewardIDs is the list of targeted steward IDs. No-op when auditManager is nil.
//
// The query has already run on the endpoints when this is called, so the write
// must not depend on the client still being connected: it uses a context that
// keeps the request's values but is not cancelled with it, bounded by
// auditWriteTimeout so a stalled audit path cannot hold the goroutine open.
func (s *Server) emitOsqueryAudit(r *http.Request, actorID, catalogID string, stewardIDs []string) {
	if s.auditManager == nil {
		return
	}

	b := audit.NewEventBuilder().
		Tenant("root").
		Type(business.AuditEventSystemAccess).
		Action("osquery.query.dispatch").
		User(actorID, business.AuditUserTypeHuman).
		Resource("osquery_catalog", logging.SanitizeLogValue(catalogID), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Request(s.getRequestID(r), r.Method, r.URL.Path, extractSourceIP(r, s.trustedProxies), r.Header.Get("User-Agent")).
		Detail("catalog_id", logging.SanitizeLogValue(catalogID)).
		Detail("target_count", fmt.Sprintf("%d", len(stewardIDs)))

	for i, sid := range stewardIDs {
		if i >= 10 {
			// Cap per-steward detail entries to avoid unbounded audit record size.
			b = b.Detail("targets_truncated", "true")
			break
		}
		b = b.Detail(fmt.Sprintf("steward_%d", i), logging.SanitizeLogValue(sid))
	}

	ctx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit osquery audit event",
			"error", logging.SanitizeLogValue(err.Error()),
			"catalog_id", logging.SanitizeLogValue(catalogID))
	}
}

// handleOsqueryCatalog handles GET /api/v1/osquery/catalog: the catalog entry ids
// and parameter schemas, never the SQL text (Issue #5449).
func (s *Server) handleOsqueryCatalog(w http.ResponseWriter, _ *http.Request) {
	s.writeSuccessResponse(w, osquerymodule.ListCatalog())
}
