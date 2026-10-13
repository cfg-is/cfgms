// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rootReadClass says how a GET route under /api/v1 treats a boundary-subject root
// caller (ADR-025 Amendment 8). The set is closed.
type rootReadClass string

const (
	// rootReadCrossing: the read decision applies. A client tenant's records need an
	// active crossing; without one a list omits them and a by-ID read is challenged.
	rootReadCrossing rootReadClass = "crossing"
	// rootReadTenantPathGate: the tenant is a path variable, decided by
	// requirePermission's boundary gate or authorizeTenantAccess.
	rootReadTenantPathGate rootReadClass = "tenant-path-gate"
	// rootReadOwnScope: returns only the caller's own records.
	rootReadOwnScope rootReadClass = "own-scope"
	// rootReadPlatform: ADR-025 Decision 4 platform and security signal, always visible.
	rootReadPlatform rootReadClass = "platform"
	// rootReadAggregate: an Amendment 6 anonymized metric, always visible.
	rootReadAggregate rootReadClass = "aggregate"
	// rootReadSharedReference: reference data with no owning tenant.
	rootReadSharedReference rootReadClass = "shared-reference"
)

// rootReadEntry classifies one route. Reason is required for the classes that put
// data in front of a root caller with no crossing (platform, aggregate and
// shared-reference).
type rootReadEntry struct {
	Class  rootReadClass
	Reason string
}

// rootReadClassification is the closed classification of every GET route under
// /api/v1, keyed by path template (Issue #4722). Growing the platform and aggregate
// sets widens what root reads with no crossing, which is a founder decision
// (ADR-025 A8.3): rootReadAlwaysVisible pins them so the change shows in review.
//
// A new GET route fails TestEveryGETRouteHasRootReadClassification until it has an
// entry here; a crossing entry must also be answerable by the no-leak sweep
// (rootReadSweepRoutes in root_read_sweep_test.go).
var rootReadClassification = map[string]rootReadEntry{
	"/api/v1/accounts":                                               {rootReadCrossing, ""},
	"/api/v1/accounts/{username}":                                    {rootReadCrossing, ""},
	"/api/v1/accounts/{username}/certs":                              {rootReadCrossing, ""},
	"/api/v1/accounts/{username}/webauthn/credentials":               {rootReadCrossing, ""},
	"/api/v1/api-keys":                                               {rootReadCrossing, ""},
	"/api/v1/api-keys/{id}":                                          {rootReadCrossing, ""},
	"/api/v1/audit/entries":                                          {rootReadCrossing, ""},
	"/api/v1/billing/report":                                         {rootReadAggregate, "per-MSP counts with clients under opaque labels only (A6.1, A6.2)"},
	"/api/v1/cases":                                                  {rootReadCrossing, ""},
	"/api/v1/cases/{id}":                                             {rootReadCrossing, ""},
	"/api/v1/cases/{id}/watch":                                       {rootReadCrossing, ""},
	"/api/v1/certificates":                                           {rootReadCrossing, ""},
	"/api/v1/certificates/revocation-manifest":                       {rootReadPlatform, "signed fleet-wide revoked-serial manifest with no tenant attribution (recorded in handlers_revocation_manifest.go for PO confirmation)"},
	"/api/v1/certificates/signing/migration":                         {rootReadPlatform, "fleet-wide signing-certificate migration progress, counts only (Decision 4: system and platform logs and metrics)"},
	"/api/v1/certificates/{serial}":                                  {rootReadCrossing, ""},
	"/api/v1/cli-login/{id}":                                         {rootReadOwnScope, ""},
	"/api/v1/cli-presence/{id}":                                      {rootReadOwnScope, ""},
	"/api/v1/clusters":                                               {rootReadCrossing, ""},
	"/api/v1/clusters/{name}":                                        {rootReadCrossing, ""},
	"/api/v1/clusters/{name}/reconciliation":                         {rootReadCrossing, ""},
	"/api/v1/commands/{id}":                                          {rootReadCrossing, ""},
	"/api/v1/compliance/summary":                                     {rootReadCrossing, ""},
	"/api/v1/compliance/tenants/{id:.+}/devices":                     {rootReadTenantPathGate, ""},
	"/api/v1/config/push/{id}":                                       {rootReadCrossing, ""},
	"/api/v1/configs":                                                {rootReadCrossing, ""},
	"/api/v1/configs/{id}/deployments":                               {rootReadCrossing, ""},
	"/api/v1/credential-requests":                                    {rootReadCrossing, ""},
	"/api/v1/credential-requests/orphaned":                           {rootReadCrossing, ""},
	"/api/v1/entities":                                               {rootReadCrossing, ""},
	"/api/v1/entities/drifted":                                       {rootReadCrossing, ""},
	"/api/v1/entities/timeline":                                      {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}":                                      {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}/desired-state":                        {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}/diff":                                 {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}/drift":                                {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}/edges":                                {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}/history":                              {rootReadCrossing, ""},
	"/api/v1/entities/{eid:.+}/neighborhood":                         {rootReadCrossing, ""},
	"/api/v1/fleet/health":                                           {rootReadAggregate, "fleet counts with client-tenant stewards folded into anonymized metrics"},
	"/api/v1/ha/cluster":                                             {rootReadPlatform, "controller cluster membership (Decision 4: system and platform logs and metrics)"},
	"/api/v1/ha/leader":                                              {rootReadPlatform, "controller cluster leader (Decision 4: system and platform logs and metrics)"},
	"/api/v1/ha/nodes":                                               {rootReadPlatform, "controller cluster nodes (Decision 4: system and platform logs and metrics)"},
	"/api/v1/ha/status":                                              {rootReadPlatform, "controller cluster status (Decision 4: system and platform logs and metrics)"},
	"/api/v1/health/alerts":                                          {rootReadPlatform, "controller platform alerts (Decision 4: system and platform logs and metrics)"},
	"/api/v1/health/alerts/history":                                  {rootReadPlatform, "controller platform alert history (Decision 4: system and platform logs and metrics)"},
	"/api/v1/health/detailed":                                        {rootReadPlatform, "controller component health (Decision 4: system and platform logs and metrics)"},
	"/api/v1/health/trace/{request_id}":                              {rootReadPlatform, "controller request trace (Decision 4: system and platform logs and metrics)"},
	"/api/v1/health/traces":                                          {rootReadPlatform, "controller request traces (Decision 4: system and platform logs and metrics)"},
	"/api/v1/hyperv/profiles":                                        {rootReadCrossing, ""},
	"/api/v1/hyperv/profiles/{name}":                                 {rootReadCrossing, ""},
	"/api/v1/installer/artifacts":                                    {rootReadCrossing, ""},
	"/api/v1/installer/artifacts/{platform}/{arch}":                  {rootReadCrossing, ""},
	"/api/v1/installer/steward-binaries/{version}/{platform}/{arch}": {rootReadSharedReference, "steward binaries are published to the fleet-wide namespace"},
	"/api/v1/jobs":                                                   {rootReadCrossing, ""},
	"/api/v1/jobs/{id}":                                              {rootReadCrossing, ""},
	"/api/v1/modules":                                                {rootReadSharedReference, "module catalogue is one fleet-wide approval decision with no owning tenant"},
	"/api/v1/modules/approvals":                                      {rootReadSharedReference, "module approvals are one fleet-wide decision with no owning tenant"},
	"/api/v1/monitoring/anomalies":                                   {rootReadPlatform, "controller anomaly signals (Decision 4: abuse and resource-exhaustion signals)"},
	"/api/v1/monitoring/components/{component}/health":               {rootReadPlatform, "controller component health (Decision 4: system and platform logs and metrics)"},
	"/api/v1/monitoring/config":                                      {rootReadPlatform, "controller monitoring configuration (Decision 4: system and platform logs and metrics)"},
	"/api/v1/monitoring/health":                                      {rootReadPlatform, "controller system health (Decision 4: system and platform logs and metrics)"},
	"/api/v1/notifications/email":                                    {rootReadSharedReference, "email delivery is one controller-wide capability with no owning tenant"},
	"/api/v1/rbac/permissions":                                       {rootReadSharedReference, "permission definitions are shared reference data with no owning tenant"},
	"/api/v1/rbac/permissions/{id}":                                  {rootReadSharedReference, "permission definitions are shared reference data with no owning tenant"},
	"/api/v1/rbac/roles":                                             {rootReadCrossing, ""},
	"/api/v1/rbac/roles/{id}":                                        {rootReadCrossing, ""},
	"/api/v1/rbac/subjects/{id}/roles":                               {rootReadCrossing, ""},
	"/api/v1/registration/approve-by-cidr/preview":                   {rootReadCrossing, ""},
	"/api/v1/registration/ip-trust":                                  {rootReadCrossing, ""},
	"/api/v1/registration/pending":                                   {rootReadCrossing, ""},
	"/api/v1/registration/tokens":                                    {rootReadCrossing, ""},
	"/api/v1/registration/tokens/{token}":                            {rootReadCrossing, ""},
	"/api/v1/reports/compliance/status":                              {rootReadCrossing, ""},
	"/api/v1/reports/dashboard/alerts":                               {rootReadCrossing, ""},
	"/api/v1/reports/dashboard/overview":                             {rootReadAggregate, "anonymized fleet metrics for client tenants (A6.1)"},
	"/api/v1/reports/dashboard/trends":                               {rootReadAggregate, "anonymized fleet metrics for client tenants (A6.1)"},
	"/api/v1/reports/drift/summary":                                  {rootReadCrossing, ""},
	"/api/v1/reports/templates":                                      {rootReadSharedReference, "report templates are shared reference data with no owning tenant"},
	"/api/v1/reports/templates/{template}":                           {rootReadSharedReference, "report templates are shared reference data with no owning tenant"},
	"/api/v1/roles":                                                  {rootReadCrossing, ""},
	"/api/v1/roles/{name}":                                           {rootReadCrossing, ""},
	"/api/v1/rollback/history":                                       {rootReadCrossing, ""},
	"/api/v1/rollback/points":                                        {rootReadCrossing, ""},
	"/api/v1/rollback/{rollback_id}/status":                          {rootReadCrossing, ""},
	"/api/v1/rollout/{rollout_id}":                                   {rootReadCrossing, ""},
	"/api/v1/runs":                                                   {rootReadCrossing, ""},
	"/api/v1/runs/{run_id}":                                          {rootReadCrossing, ""},
	"/api/v1/runs/{run_id}/jobs":                                     {rootReadCrossing, ""},
	"/api/v1/scripts":                                                {rootReadSharedReference, "script library items carry no tenant (shared reference data)"},
	"/api/v1/scripts/{id}":                                           {rootReadSharedReference, "script library items carry no tenant (shared reference data)"},
	"/api/v1/sessions":                                               {rootReadCrossing, ""},
	"/api/v1/stewards":                                               {rootReadCrossing, ""},
	"/api/v1/stewards/connections/all":                               {rootReadCrossing, ""},
	"/api/v1/stewards/identity-clones":                               {rootReadCrossing, ""},
	"/api/v1/stewards/refresh/pending":                               {rootReadCrossing, ""},
	"/api/v1/stewards/upgrade/{upgrade_id}":                          {rootReadCrossing, ""},
	"/api/v1/stewards/{id}":                                          {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/compliance":                               {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/compliance/report":                        {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/config":                                   {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/config/effective":                         {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/connection":                               {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/dna":                                      {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/logs":                                     {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/modules":                                  {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/pending-deliveries":                       {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/reboot-window":                            {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/scripts/executions":                       {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/scripts/executions/{execution_id}":        {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/scripts/metrics":                          {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/scripts/status":                           {rootReadCrossing, ""},
	"/api/v1/stewards/{id}/tags":                                     {rootReadCrossing, ""},
	"/api/v1/telemetry/ws/{id}":                                      {rootReadCrossing, ""},
	"/api/v1/tenant-crossings/active":                                {rootReadPlatform, "crossing meta-log feed (A8.3 item 3.2); client tenant names are withheld from root"},
	"/api/v1/tenants":                                                {rootReadCrossing, ""},
	"/api/v1/tenants/{id}":                                           {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{id}/access-grants":                             {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{id}/admin-contacts":                            {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{id}/m365-connection":                           {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{id}/billing-report":                            {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{id}/delete":                                    {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{tenant_id}/reboot-window":                      {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{tenant_path:.+}/assurance-policy":              {rootReadTenantPathGate, ""},
	"/api/v1/tenants/{tenant_path:.+}/refresh-policy":                {rootReadTenantPathGate, ""},
	"/api/v1/terminal/ws/{steward_id}":                               {rootReadCrossing, ""},
	"/api/v1/triggers":                                               {rootReadCrossing, ""},
	"/api/v1/triggers/health":                                        {rootReadPlatform, "trigger subsystem liveness, no tenant data (Decision 4: system and platform logs and metrics)"},
	"/api/v1/triggers/{id}":                                          {rootReadCrossing, ""},
	"/api/v1/triggers/{id}/executions":                               {rootReadCrossing, ""},
	"/api/v1/workflows":                                              {rootReadCrossing, ""},
	"/api/v1/workflows/approvals":                                    {rootReadCrossing, ""},
	"/api/v1/workflows/{id}":                                         {rootReadCrossing, ""},
	"/api/v1/workflows/{id}/executions":                              {rootReadCrossing, ""},
	"/api/v1/workflows/{id}/executions/{exec_id}":                    {rootReadCrossing, ""},
}

// rootReadAlwaysVisible pins the routes classified platform or aggregate: the
// always-visible set of ADR-025 A8.3 is closed, and growing it is a founder decision.
// Changing this list in a pull request is the visible, reviewable act that decision
// requires.
var rootReadAlwaysVisible = []string{
	"/api/v1/billing/report",
	"/api/v1/certificates/revocation-manifest",
	"/api/v1/certificates/signing/migration",
	"/api/v1/fleet/health",
	"/api/v1/ha/cluster",
	"/api/v1/ha/leader",
	"/api/v1/ha/nodes",
	"/api/v1/ha/status",
	"/api/v1/health/alerts",
	"/api/v1/health/alerts/history",
	"/api/v1/health/detailed",
	"/api/v1/health/trace/{request_id}",
	"/api/v1/health/traces",
	"/api/v1/monitoring/anomalies",
	"/api/v1/monitoring/components/{component}/health",
	"/api/v1/monitoring/config",
	"/api/v1/monitoring/health",
	"/api/v1/reports/dashboard/overview",
	"/api/v1/reports/dashboard/trends",
	"/api/v1/tenant-crossings/active",
	"/api/v1/triggers/health",
}

// crossingClassRoutes returns the path templates classified crossing, sorted.
func crossingClassRoutes(t *testing.T) []string {
	t.Helper()
	var routes []string
	for path, entry := range rootReadClassification {
		if entry.Class == rootReadCrossing {
			routes = append(routes, path)
		}
	}
	sort.Strings(routes)
	require.NotEmpty(t, routes)
	return routes
}

// getRoutePaths walks the real router and returns the path template of every GET
// route under /api/v1, with the optional subsystems that register routes of their
// own wired.
func getRoutePaths(t *testing.T) []string {
	t.Helper()
	server := setupRouteTestServer(t)
	registerOptionalRouteSubsystems(t, server, newTestEntityGraphProvider(t))

	seen := map[string]bool{}
	err := server.router.Walk(func(route *mux.Route, _ *mux.Router, ancestors []*mux.Route) error {
		path, pathErr := route.GetPathTemplate()
		if pathErr != nil {
			return nil
		}
		methods, methodErr := route.GetMethods()
		if methodErr != nil {
			return nil
		}
		underAPI := false
		for _, ancestor := range ancestors {
			if prefix, prefixErr := ancestor.GetPathTemplate(); prefixErr == nil && prefix == "/api/v1" {
				underAPI = true
			}
		}
		for _, method := range methods {
			if method == "GET" && underAPI {
				seen[path] = true
			}
		}
		return nil
	})
	require.NoError(t, err)
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// TestEveryGETRouteHasRootReadClassification walks the real router and requires every
// authenticated GET route to carry a class from the closed set (Issue #4722): a route
// no one classified cannot reach root unnoticed, and an entry for a route that no
// longer exists is removed.
func TestEveryGETRouteHasRootReadClassification(t *testing.T) {
	paths := getRoutePaths(t)
	require.NotEmpty(t, paths)

	routed := map[string]bool{}
	var unclassified []string
	for _, p := range paths {
		routed[p] = true
		if _, ok := rootReadClassification[p]; !ok {
			unclassified = append(unclassified, p)
		}
	}
	assert.Empty(t, unclassified, "GET routes without a rootReadClassification entry")

	var stale []string
	for p := range rootReadClassification {
		if !routed[p] {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale, "rootReadClassification entries for routes the router does not serve")
}

// rootReadEntryValid reports whether an entry has a class from the closed set and,
// for the classes visible to root with no crossing (platform, aggregate and
// shared-reference), a one-line reason.
func rootReadEntryValid(e rootReadEntry) bool {
	switch e.Class {
	case rootReadCrossing, rootReadTenantPathGate, rootReadOwnScope:
		return true
	case rootReadPlatform, rootReadAggregate, rootReadSharedReference:
		return strings.TrimSpace(e.Reason) != "" && !strings.Contains(e.Reason, "\n")
	default:
		return false
	}
}

// TestRootReadClassificationEntriesAreValid requires every entry to be valid.
func TestRootReadClassificationEntriesAreValid(t *testing.T) {
	for path, entry := range rootReadClassification {
		assert.Truef(t, rootReadEntryValid(entry), "%s: class %q is unknown, or a %s entry has no one-line reason", path, entry.Class, entry.Class)
	}
}

// TestRootReadClassificationValidatorRejects proves the validity check fails an
// unknown class and a missing reason, rather than passing vacuously.
func TestRootReadClassificationValidatorRejects(t *testing.T) {
	assert.False(t, rootReadEntryValid(rootReadEntry{Class: "everything"}))
	assert.False(t, rootReadEntryValid(rootReadEntry{Class: rootReadPlatform}))
	assert.False(t, rootReadEntryValid(rootReadEntry{Class: rootReadAggregate}))
	assert.False(t, rootReadEntryValid(rootReadEntry{Class: rootReadSharedReference}))
	assert.True(t, rootReadEntryValid(rootReadEntry{Class: rootReadPlatform, Reason: "r"}))
	assert.True(t, rootReadEntryValid(rootReadEntry{Class: rootReadCrossing}))
}

// TestRootReadAlwaysVisibleIsPinned asserts the exact platform and aggregate routes.
func TestRootReadAlwaysVisibleIsPinned(t *testing.T) {
	var got []string
	for path, entry := range rootReadClassification {
		if entry.Class == rootReadPlatform || entry.Class == rootReadAggregate {
			got = append(got, path)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), rootReadAlwaysVisible...)
	sort.Strings(want)
	assert.Equal(t, want, got,
		"the always-visible set (platform and aggregate) changed: growing it is a founder decision (ADR-025 A8.3)")
}
