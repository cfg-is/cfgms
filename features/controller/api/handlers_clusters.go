// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ClusterInfo is the per-cluster shape returned by the cluster read endpoints.
type ClusterInfo struct {
	Name       string            `json:"name"`
	Members    []string          `json:"members"`
	RoleOwners map[string]string `json:"role_owners,omitempty"`
}

// ClusterReconciliationResponse is returned by GET /api/v1/clusters/{name}/reconciliation.
type ClusterReconciliationResponse struct {
	ClusterName string                            `json:"cluster_name"`
	Resources   []ClusterResourceStatus           `json:"resources"`
	Alerts      []health.Alert                    `json:"alerts,omitempty"`
	Components  map[string]health.ComponentHealth `json:"components,omitempty"`
}

// ClusterResourceStatus is the per-role entry in a reconciliation response.
type ClusterResourceStatus struct {
	RoleName       string                         `json:"role_name"`
	Status         clusterregistry.ResourceStatus `json:"status"`
	OwnerID        string                         `json:"owner_id,omitempty"`
	AllOwnerClaims []string                       `json:"all_owner_claims,omitempty"`
}

// stewardsToFleetData converts the controller service's StewardInfo slice to the
// fleet.StewardData slice required by clusterregistry.BuildRegistry. It mirrors
// controllerServiceAdapter.GetAllStewards (server.go:375-397) but returns only
// the stewards whose TenantID is in scope for callerTenant.
//
// Two views of the same scoped snapshot are returned:
//   - the fragment-only fleet.StewardData slice clusterregistry.BuildRegistry parses.
//   - hostnameOwners: node hostname → steward ID, which handleClusterReconciliation
//     needs because cluster role owners are expressed as node hostnames, not steward
//     IDs (see dnaHostname).
//
// Both are built from one GetAllStewards() call so the registry and the liveness
// index can never disagree about which stewards exist.
//
// Access rules:
//   - callerTenant == "" → admin mTLS principal; all tenants are in scope.
//   - callerTenant == steward.TenantID → exact match; in scope.
//   - strings.HasPrefix(steward.TenantID, callerTenant+"/") → caller is a hierarchical
//     ancestor of the steward's tenant; in scope.
func (s *Server) stewardsInTenantScope(callerTenant string) ([]fleet.StewardData, map[string]string) {
	infos := s.controllerService.GetAllStewards()
	result := make([]fleet.StewardData, 0, len(infos))
	hostnameOwners := make(map[string]string, len(infos))
	// hostnameClaims records which steward currently holds each hostname entry so a
	// second steward publishing the same hostname resolves deterministically instead
	// of by GetAllStewards iteration order: the most recent heartbeat wins, ties
	// broken by the lexicographically smaller steward ID.
	type hostnameClaim struct {
		stewardID string
		heartbeat time.Time
	}
	hostnameClaims := make(map[string]hostnameClaim, len(infos))
	for _, info := range infos {
		if callerTenant != "" {
			sameTenant := info.TenantID == callerTenant
			ancestorTenant := strings.HasPrefix(info.TenantID, callerTenant+"/")
			if !sameTenant && !ancestorTenant {
				continue
			}
		}
		var frags []*commonpb.Fragment
		if info.DNA != nil {
			// Fragments carry cluster:<name> membership and resource_owner state
			// (ADR-017); clusterregistry.BuildRegistry parses them, so dropping
			// them here would make every cluster invisible to the read endpoints.
			frags = info.DNA.Fragments
		}
		result = append(result, fleet.StewardData{
			ID:            info.ID,
			TenantID:      info.TenantID,
			Status:        info.Status,
			LastHeartbeat: info.LastHeartbeat,
			DNAFragments:  frags,
		})

		hostname := dnaHostname(info.DNA)
		if hostname == "" {
			continue
		}
		prev, claimed := hostnameClaims[hostname]
		wins := !claimed ||
			info.LastHeartbeat.After(prev.heartbeat) ||
			(info.LastHeartbeat.Equal(prev.heartbeat) && info.ID < prev.stewardID)
		if wins {
			hostnameClaims[hostname] = hostnameClaim{stewardID: info.ID, heartbeat: info.LastHeartbeat}
			hostnameOwners[hostname] = info.ID
		}
	}
	return result, hostnameOwners
}

// dnaHostname returns the node hostname a steward published in its DNA, or ""
// when the steward has published none.
//
// This is the value cluster role owners are expressed in: the hyperv module emits
// ClusterStatus.RoleOwners as role → owner *node name*
// (features/modules/hyperv/cluster.go), and clusterregistry copies that value into
// ClusterEntry.RoleOwners verbatim — so resolving owner liveness requires a
// hostname → steward mapping.
//
// No ADR-017 fragment carries hostname: features/steward/dna/fragments.go's
// hostFactFragmentSpecs cover host:cpu, host:memory, host:os and host:bios only,
// none of which include the hostname key. The flat attribute is therefore the only
// controller-side source of a steward's hostname, and this function is the single
// place the cluster read endpoints read it from — the one line to change when epic
// #2911 gives hostname a fragment home.
func dnaHostname(dna *commonpb.DNA) string {
	if dna == nil {
		return ""
	}
	return dna.Attributes["hostname"]
}

// handleListClusters handles GET /api/v1/clusters.
//
// Returns all clusters visible to the authenticated caller, derived on demand
// from the cluster:<name> ADR-017 fragments in each steward's already-durable
// DNA.Fragments. The result is eventually consistent — it reflects whatever
// DNA was last published by the steward's DNARefreshLoop (default 30 min).
//
// Tenant scoping mirrors handleListStewards: the caller's tenant from the
// authenticated context limits which stewards' DNA is scanned. An admin mTLS
// principal (empty TenantID) has no scope restriction.
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	stewards, _ := s.stewardsInTenantScope(callerTenant)
	reg := clusterregistry.BuildRegistry(stewards)

	clusters := make([]ClusterInfo, 0, len(reg.Clusters()))
	for name, entry := range reg.Clusters() {
		members := make([]string, len(entry.Members))
		copy(members, entry.Members)
		clusters = append(clusters, ClusterInfo{
			Name:       name,
			Members:    members,
			RoleOwners: entry.RoleOwners,
		})
	}
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })

	s.logger.Info("Listed clusters", "count", len(clusters))
	s.writeSuccessResponse(w, clusters)
}

// handleGetCluster handles GET /api/v1/clusters/{name}.
//
// Returns the cluster entry for the named cluster, or 404 when the cluster is
// not found or all its member stewards are outside the caller's tenant scope.
// 404 (not 403) is used for cross-tenant misses to avoid disclosing cluster
// existence across tenant boundaries — mirrors handleGetStewardDNA's pattern.
func (s *Server) handleGetCluster(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clusterName := vars["name"]
	clusterNameForLog := logging.SanitizeLogValue(clusterName)

	if clusterName == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Cluster name is required", "MISSING_CLUSTER_NAME")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	stewards, _ := s.stewardsInTenantScope(callerTenant)
	reg := clusterregistry.BuildRegistry(stewards)

	entry := reg.Cluster(clusterName)
	if entry == nil {
		// 404 not 403: avoids disclosing whether the cluster exists in another tenant.
		s.writeErrorResponse(w, http.StatusNotFound, "Cluster not found", "CLUSTER_NOT_FOUND")
		return
	}

	members := make([]string, len(entry.Members))
	copy(members, entry.Members)

	s.logger.Info("Fetched cluster",
		"cluster_name", clusterNameForLog,
		"member_count", len(members))
	s.writeSuccessResponse(w, ClusterInfo{
		Name:       entry.Name,
		Members:    members,
		RoleOwners: entry.RoleOwners,
	})
}

// handleClusterReconciliation handles GET /api/v1/clusters/{name}/reconciliation.
//
// Returns the reconciliation status for each declared clustered resource in the
// named cluster. The declared set is sourced from the cluster-policies config
// stored under the caller's tenant (via InheritanceResolver's cluster-policies
// namespace). The actual set is derived from steward DNA fragments via
// clusterregistry.BuildRegistry.
//
// Four outcomes are possible per resource (Issue #2704):
//   - present-with-live-owner: resource exists in the registry, owner is live.
//   - declared-but-missing: resource declared in config but absent from registry
//     (create-coverage gap — a non-owner's compliant-by-delegation is unsafe).
//   - orphan-dead-owner: resource has a registry entry, but the owner steward's
//     heartbeat exceeds the DeadOwnerStaleThreshold (60 s).
//   - split-brain: multiple cluster members report different owner values for
//     the same role (>1 claimed owner).
//
// Returns 404 when the cluster does not exist or is outside the caller's tenant
// scope (same 404-not-403 pattern as handleGetCluster).
func (s *Server) handleClusterReconciliation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clusterName := vars["name"]
	clusterNameForLog := logging.SanitizeLogValue(clusterName)

	if clusterName == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Cluster name is required", "MISSING_CLUSTER_NAME")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	stewards, hostnameOwners := s.stewardsInTenantScope(callerTenant)
	reg := clusterregistry.BuildRegistry(stewards)

	if reg.Cluster(clusterName) == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Cluster not found", "CLUSTER_NOT_FOUND")
		return
	}

	// Build the declared-resource set from the cluster-policies config
	// (same namespace the InheritanceResolver uses in applyClusterConfiguration).
	declared := s.clusterDeclaredResources(r.Context(), callerTenant, clusterName)

	// Build a liveness checker over steward IDs and the published node hostnames
	// that stewardsInTenantScope indexed. The owner value in resource_owner.<role>
	// is the cluster node hostname (e.g. "CFG-70-02") for every module that reports
	// clustered roles, so the hostname path is the production path — without it
	// every live clustered role would resolve as a dead owner.
	//
	// The controller-assigned steward ID is matched first: it is authoritative
	// identity, so a steward-published hostname can never shadow another steward's ID.
	stewardIDIdx := make(map[string]fleet.StewardData, len(stewards))
	for _, sd := range stewards {
		stewardIDIdx[sd.ID] = sd
	}
	isOwnerLive := func(ownerID string) bool {
		sd, found := stewardIDIdx[ownerID]
		if !found {
			if id, ok := hostnameOwners[ownerID]; ok {
				sd, found = stewardIDIdx[id]
			}
		}
		if !found {
			return false // unknown owner — cannot confirm liveness → treat as dead
		}
		return time.Since(sd.LastHeartbeat) <= clusterregistry.DeadOwnerStaleThreshold
	}

	results := clusterregistry.Reconcile(declared, reg, stewards, isOwnerLive)

	// Shape results into the response, generating health.Alert and
	// health.ComponentHealth entries for each non-healthy status.
	resources := make([]ClusterResourceStatus, 0, len(results))
	var alerts []health.Alert
	components := make(map[string]health.ComponentHealth)

	for _, res := range results {
		rs := ClusterResourceStatus{
			RoleName:       res.RoleName,
			Status:         res.Status,
			OwnerID:        res.OwnerID,
			AllOwnerClaims: res.AllOwnerClaims,
		}
		resources = append(resources, rs)

		componentKey := clusterName + "/" + res.RoleName
		switch res.Status {
		case clusterregistry.StatusPresentLiveOwner:
			components[componentKey] = health.ComponentHealth{
				Name:    componentKey,
				Status:  "healthy",
				Message: "owner is live",
			}

		case clusterregistry.StatusDeclaredMissing:
			alert := health.Alert{
				ID:          componentKey + "/declared-but-missing",
				Severity:    health.SeverityCritical,
				Title:       "Cluster role not created",
				Description: "Role " + res.RoleName + " declared in cluster-policies for cluster " + clusterName + " but has no owner in the registry (create-coverage gap).",
				MetricType:  health.MetricTypeApplication,
				MetricName:  "cluster_role_missing",
				Status:      "active",
			}
			alerts = append(alerts, alert)
			components[componentKey] = health.ComponentHealth{
				Name:    componentKey,
				Status:  "unhealthy",
				Message: "declared but not created",
			}

		case clusterregistry.StatusOrphanDeadOwner:
			alert := health.Alert{
				ID:          componentKey + "/orphan-dead-owner",
				Severity:    health.SeverityWarning,
				Title:       "Cluster role owner offline",
				Description: "Role " + res.RoleName + " in cluster " + clusterName + " is registered but its owner (" + res.OwnerID + ") has a stale heartbeat — compliant-by-delegation is not safe.",
				MetricType:  health.MetricTypeApplication,
				MetricName:  "cluster_role_dead_owner",
				Status:      "active",
			}
			alerts = append(alerts, alert)
			components[componentKey] = health.ComponentHealth{
				Name:    componentKey,
				Status:  "degraded",
				Message: "owner offline: " + res.OwnerID,
			}

		case clusterregistry.StatusSplitBrain:
			alert := health.Alert{
				ID:          componentKey + "/split-brain",
				Severity:    health.SeverityCritical,
				Title:       "Cluster role split-brain",
				Description: "Role " + res.RoleName + " in cluster " + clusterName + " has multiple owners claiming it — split-brain detected.",
				MetricType:  health.MetricTypeApplication,
				MetricName:  "cluster_role_split_brain",
				Status:      "active",
			}
			alerts = append(alerts, alert)
			components[componentKey] = health.ComponentHealth{
				Name:    componentKey,
				Status:  "unhealthy",
				Message: "split-brain: multiple owners",
			}
		}
	}

	resp := ClusterReconciliationResponse{
		ClusterName: clusterName,
		Resources:   resources,
		Alerts:      alerts,
		Components:  components,
	}

	s.logger.Info("Reconciled cluster",
		"cluster_name", clusterNameForLog,
		"resource_count", len(results),
		"alert_count", len(alerts))
	s.writeSuccessResponse(w, resp)
}

// clusterDeclaredResources returns the DeclaredResource list for the given cluster
// by reading the cluster-policies/<clusterName> config document from storage. When
// the document does not exist or configService is unavailable, returns an empty
// slice (no create-coverage gaps can be detected, but dead-owner and split-brain
// detection still work from the DNA-derived registry).
func (s *Server) clusterDeclaredResources(ctx context.Context, tenantID, clusterName string) []clusterregistry.DeclaredResource {
	if s.configService == nil {
		return nil
	}
	resources, err := s.configService.GetClusterDeclaredResources(ctx, tenantID, clusterName)
	if err != nil {
		s.logger.Warn("Failed to load cluster-policies config; create-coverage detection disabled",
			"cluster_name", logging.SanitizeLogValue(clusterName),
			"error", err.Error())
		return nil
	}
	if len(resources) == 0 {
		return nil
	}
	declared := make([]clusterregistry.DeclaredResource, 0, len(resources))
	for _, r := range resources {
		if r.Name != "" {
			declared = append(declared, clusterregistry.DeclaredResource{
				ClusterName: clusterName,
				RoleName:    r.Name,
			})
		}
	}
	return declared
}
