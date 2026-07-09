// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ClusterInfo is the per-cluster shape returned by the cluster read endpoints.
type ClusterInfo struct {
	Name       string            `json:"name"`
	Members    []string          `json:"members"`
	RoleOwners map[string]string `json:"role_owners,omitempty"`
}

// stewardsToFleetData converts the controller service's StewardInfo slice to the
// fleet.StewardData slice required by clusterregistry.BuildRegistry. It mirrors
// controllerServiceAdapter.GetAllStewards (server.go:375-397) but returns only
// the stewards whose TenantID is in scope for callerTenant.
//
// Access rules:
//   - callerTenant == "" → admin mTLS principal; all tenants are in scope.
//   - callerTenant == steward.TenantID → exact match; in scope.
//   - strings.HasPrefix(steward.TenantID, callerTenant+"/") → caller is a hierarchical
//     ancestor of the steward's tenant; in scope.
func (s *Server) stewardsInTenantScope(callerTenant string) []fleet.StewardData {
	infos := s.controllerService.GetAllStewards()
	result := make([]fleet.StewardData, 0, len(infos))
	for _, info := range infos {
		if callerTenant != "" {
			sameTenant := info.TenantID == callerTenant
			ancestorTenant := strings.HasPrefix(info.TenantID, callerTenant+"/")
			if !sameTenant && !ancestorTenant {
				continue
			}
		}
		var attrs map[string]string
		if info.DNA != nil {
			attrs = info.DNA.Attributes
		}
		result = append(result, fleet.StewardData{
			ID:            info.ID,
			TenantID:      info.TenantID,
			Status:        info.Status,
			LastHeartbeat: info.LastHeartbeat,
			DNAAttributes: attrs,
		})
	}
	return result
}

// handleListClusters handles GET /api/v1/clusters.
//
// Returns all clusters visible to the authenticated caller, derived on demand
// from cluster:<name>.* DNA attributes in each steward's already-durable
// DNA.Attributes. The result is eventually consistent — it reflects whatever
// DNA was last published by the steward's DNARefreshLoop (default 30 min).
//
// Tenant scoping mirrors handleListStewards: the caller's tenant from the
// authenticated context limits which stewards' DNA is scanned. An admin mTLS
// principal (empty TenantID) has no scope restriction.
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	reg := clusterregistry.BuildRegistry(s.stewardsInTenantScope(callerTenant))

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

	reg := clusterregistry.BuildRegistry(s.stewardsInTenantScope(callerTenant))

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
