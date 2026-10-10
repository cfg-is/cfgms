// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"sort"

	"github.com/cfgis/cfgms/features/controller/fleet"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	"github.com/cfgis/cfgms/pkg/logging"
)

// reportsReadScope adapts the server's per-request tenantReadScope to the reports
// handler's reportapi.TenantReadScope, so reports make the same ADR-025 crossing
// decision every other root read makes (Issue #4720).
type reportsReadScope struct {
	s     *Server
	r     *http.Request
	scope *tenantReadScope
}

// reportsTenantReadScope is the reportapi.TenantReadScopeFunc the server injects
// into the reports handler.
func (s *Server) reportsTenantReadScope(r *http.Request, route string) reportapi.TenantReadScope {
	return &reportsReadScope{s: s, r: r, scope: s.tenantReadScope(r, route)}
}

// Unrestricted reports that the crossing boundary does not apply to the caller.
func (a *reportsReadScope) Unrestricted() bool { return !a.scope.boundarySubject() }

// Decide is the read decision for the tenant.
func (a *reportsReadScope) Decide(tenantID string) reportapi.ReadDecision {
	switch a.scope.decide(tenantID) {
	case tenantAuthAllowed:
		return reportapi.ReadAllowed
	case tenantAuthNeedsCrossing:
		return reportapi.ReadNeedsCrossing
	default:
		return reportapi.ReadDenied
	}
}

// ReadableTenants is the root tenant plus every crossing-covered tenant with its
// descendants, each confirmed readable by the same decision.
func (a *reportsReadScope) ReadableTenants() []string {
	ctx := a.r.Context()
	seen := make(map[string]struct{})
	if root := a.s.rootTenantID(ctx); root != "" {
		seen[root] = struct{}{}
	}
	for _, crossing := range a.scope.CrossingTenants() {
		for id := range a.s.tenantSubtreeIDs(ctx, crossing) {
			if a.scope.Allows(id) {
				seen[id] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// AnonymizedFleet is the A6.1 aggregate over the stewards of tenants the caller
// may not read. It is computed from the fleet records of the unreadable tenants
// only, as a separate pass from the readable rows, and holds only counts.
func (a *reportsReadScope) AnonymizedFleet() any {
	metrics := &FleetAnonymizedMetrics{Versions: map[string]int{}}
	if a.s.fleetQuery == nil {
		return metrics
	}
	results, err := a.s.fleetQuery.Search(a.r.Context(), fleet.Filter{})
	if err != nil {
		a.s.logger.Error("Anonymized fleet aggregate query failed",
			"error", logging.SanitizeLogValue(err.Error()))
		return metrics
	}
	_, walledOff := splitReadableResults(a.scope, results)
	for _, res := range walledOff {
		metrics.add(res)
	}
	return metrics
}

// WriteCrossingChallenge answers with the ADR-025 crossing challenge.
func (a *reportsReadScope) WriteCrossingChallenge(w http.ResponseWriter, tenantID string) {
	writeTenantCrossingChallenge(w, tenantID)
}
