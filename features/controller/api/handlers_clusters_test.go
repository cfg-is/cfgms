// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/health"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// seedClusterSteward registers a steward and sets its DNA to carry the given flat
// attributes plus the given ADR-017 fragments. Cluster membership and role ownership
// live in cluster:<name> fragments (Issue #2908) — dnaAttrs carries only host facts
// such as "hostname", which the reconciliation handler uses for owner liveness.
func seedClusterSteward(t *testing.T, server *Server, id, tenantID string, dnaAttrs map[string]string, frags ...*commonpb.Fragment) {
	t.Helper()
	require.NoError(t, server.controllerService.RegisterSteward(id, tenantID, "addr", "active"))
	ok := server.controllerService.SetStewardDNA(id, &commonpb.DNA{
		Id:         id,
		Attributes: dnaAttrs,
		Fragments:  frags,
	})
	require.True(t, ok, "SetStewardDNA must return true for a registered steward")
}

// clusterFragment builds a cluster:<name> DNA fragment carrying the given
// resource_owner role→owner map. Construction goes through sdna.NewFragment — the
// same production path the steward's monitor bridge uses — so these fixtures decode
// through the real clusterregistry parse path with no hand-rolled bytes.
func clusterFragment(t *testing.T, clusterName string, owners map[string]string) *commonpb.Fragment {
	t.Helper()
	frag, err := sdna.NewFragment("cluster:"+clusterName, "hyperv", sdna.MapState{
		"name":           clusterName,
		"resource_owner": owners,
	})
	require.NoError(t, err)
	return frag
}

// withClusterTenant returns a copy of req with callerTenant injected via ctxkeys.TenantID,
// mirroring what authenticationMiddleware does for API-key callers.
func withClusterTenant(req *http.Request, callerTenant string) *http.Request {
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, callerTenant)
	return req.WithContext(ctx)
}

// TestHandleListClusters_HappyPath verifies the list endpoint returns all clusters
// when called by a root admin (no tenant restriction).
func TestHandleListClusters_HappyPath(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-a", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"}))
	seedClusterSteward(t, server, "steward-b", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	// No tenant in context → root admin scope (sees everything).
	rec := httptest.NewRecorder()
	server.handleListClusters(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []ClusterInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "cfg-lab", resp.Data[0].Name)
	assert.Len(t, resp.Data[0].Members, 2)
	assert.Contains(t, resp.Data[0].Members, "steward-a")
	assert.Contains(t, resp.Data[0].Members, "steward-b")
	assert.Equal(t, map[string]string{"csv": "CFG-70-02"}, resp.Data[0].RoleOwners)
}

// TestHandleListClusters_TenantIsolation is the required AC test. A scoped caller
// must only see clusters whose member stewards belong to the caller's tenant.
func TestHandleListClusters_TenantIsolation(t *testing.T) {
	server := setupTestServer(t)

	// Steward in tenant-a has cluster cfg-lab.
	seedClusterSteward(t, server, "steward-a", "tenant-a", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "node-a"}))
	// Steward in tenant-b has cluster cfg-prod.
	seedClusterSteward(t, server, "steward-b", "tenant-b", nil,
		clusterFragment(t, "cfg-prod", map[string]string{"cno": "node-b"}))

	// Caller scoped to tenant-a: must only see cfg-lab, not cfg-prod.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	req = withClusterTenant(req, "tenant-a")
	rec := httptest.NewRecorder()
	server.handleListClusters(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []ClusterInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1, "tenant-a caller must only see tenant-a clusters")
	assert.Equal(t, "cfg-lab", resp.Data[0].Name)
}

// TestHandleListClusters_AncestorTenantSeesDescendants verifies hierarchical ancestor
// access: a caller at root/msp-a can see clusters from root/msp-a/client-1.
func TestHandleListClusters_AncestorTenantSeesDescendants(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-child", "root/msp-a/client-1", nil,
		clusterFragment(t, "cfg-lab", nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	req = withClusterTenant(req, "root/msp-a")
	rec := httptest.NewRecorder()
	server.handleListClusters(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []ClusterInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "cfg-lab", resp.Data[0].Name)
}

// TestHandleListClusters_EmptyResult verifies 200 with empty slice when no clusters exist.
func TestHandleListClusters_EmptyResult(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	rec := httptest.NewRecorder()
	server.handleListClusters(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []ClusterInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.Data)
}

// TestHandleGetCluster_HappyPath verifies the detail endpoint returns the correct cluster.
func TestHandleGetCluster_HappyPath(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-a", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{
			"csv": "CFG-70-02",
			"cno": "CFG-AB-02",
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	rec := httptest.NewRecorder()
	server.handleGetCluster(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "cfg-lab", resp.Data.Name)
	assert.Equal(t, []string{"steward-a"}, resp.Data.Members)
	assert.Equal(t, map[string]string{"csv": "CFG-70-02", "cno": "CFG-AB-02"}, resp.Data.RoleOwners)
}

// TestHandleGetCluster_NotFound is the required AC test.
// 404 for unknown cluster name; 404 (not 403) for a cluster outside the caller's tenant.
func TestHandleGetCluster_NotFound(t *testing.T) {
	server := setupTestServer(t)

	// A cluster that exists but belongs to tenant-b.
	seedClusterSteward(t, server, "steward-b", "tenant-b", nil,
		clusterFragment(t, "cfg-prod", nil))

	t.Run("unknown cluster name returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/no-such-cluster", nil)
		req = withVars(req, map[string]string{"name": "no-such-cluster"})
		rec := httptest.NewRecorder()
		server.handleGetCluster(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("cluster outside caller tenant returns 404 not 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-prod", nil)
		req = withVars(req, map[string]string{"name": "cfg-prod"})
		req = withClusterTenant(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleGetCluster(rec, req)
		// 404 not 403 — avoids disclosing cluster existence across tenant boundaries.
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestHandleGetCluster_MissingName verifies 400 when the {name} path variable is empty.
func TestHandleGetCluster_MissingName(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/", nil)
	req = withVars(req, map[string]string{"name": ""})
	rec := httptest.NewRecorder()
	server.handleGetCluster(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Cluster reconciliation handler tests (Issue #2704) ---

// seedClusterPoliciesConfig stores a cluster-policies YAML document in the test
// server's config store, declaring the given role names as required clustered
// resources. This simulates an admin having pushed a cluster-policies config for
// the cluster.
func seedClusterPoliciesConfig(t *testing.T, server *Server, tenantID, clusterName string, roleNames ...string) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("resources:\n")
	for _, name := range roleNames {
		sb.WriteString("  - name: " + name + "\n    module: file\n")
	}
	require.NoError(t, server.configService.GetConfigStore().StoreConfig(
		context.Background(),
		&cfgconfig.ConfigEntry{
			Key: &cfgconfig.ConfigKey{
				TenantID:  tenantID,
				Namespace: "cluster-policies",
				Name:      clusterName,
			},
			Data:   []byte(sb.String()),
			Format: cfgconfig.ConfigFormatYAML,
		},
	))
}

// TestHandleClusterReconciliation_PresentWithLiveOwner is the required AC test:
// a declared resource with a registry entry and a live owner returns
// present-with-live-owner with no alerts.
func TestHandleClusterReconciliation_PresentWithLiveOwner(t *testing.T) {
	server := setupTestServer(t)

	// Production shape: the owner value is the cluster NODE HOSTNAME (the hyperv
	// module emits RoleOwners as node names), and the owning steward publishes that
	// hostname in its DNA. The handler must resolve hostname → steward → heartbeat.
	seedClusterSteward(t, server, "steward-a", "default",
		map[string]string{"hostname": "CFG-70-02"},
		clusterFragment(t, "cfg-lab", map[string]string{"vm1": "CFG-70-02"}))
	seedClusterPoliciesConfig(t, server, "default", "cfg-lab", "vm1")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Resources, 1)
	r := resp.Data.Resources[0]
	assert.Equal(t, "vm1", r.RoleName)
	assert.Equal(t, clusterregistry.StatusPresentLiveOwner, r.Status)
	assert.Equal(t, "CFG-70-02", r.OwnerID)
	assert.Empty(t, r.AllOwnerClaims)
	assert.Empty(t, resp.Data.Alerts, "no alerts for a healthy cluster resource")
}

// TestHandleClusterReconciliation_LiveOwnerByStewardID verifies the second
// resolution path: an owner value that is already a steward ID resolves directly,
// without needing a hostname claim.
func TestHandleClusterReconciliation_LiveOwnerByStewardID(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-a", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"vm1": "steward-a"}))
	seedClusterPoliciesConfig(t, server, "default", "cfg-lab", "vm1")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Resources, 1)
	assert.Equal(t, clusterregistry.StatusPresentLiveOwner, resp.Data.Resources[0].Status)
	assert.Empty(t, resp.Data.Alerts)
}

// TestHandleClusterReconciliation_HostnameOwnerNotDeadOwner is the regression test
// for the hostname-liveness path (Issue #3323 review finding): a healthy cluster
// whose role owners are node hostnames must not raise cluster_role_dead_owner
// alerts. Without a hostname source, every live clustered role resolves as an
// orphan-dead-owner and drowns genuine dead-owner signal.
func TestHandleClusterReconciliation_HostnameOwnerNotDeadOwner(t *testing.T) {
	server := setupTestServer(t)

	// Two-node cluster, both nodes live, both roles owned by node hostnames.
	seedClusterSteward(t, server, "steward-a", "default",
		map[string]string{"hostname": "CFG-70-01"},
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-01", "cno": "CFG-70-01"}))
	seedClusterSteward(t, server, "steward-b", "default",
		map[string]string{"hostname": "CFG-70-02"},
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-01", "cno": "CFG-70-01"}))
	seedClusterPoliciesConfig(t, server, "default", "cfg-lab", "csv", "cno")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Resources, 2)
	for _, r := range resp.Data.Resources {
		assert.Equal(t, clusterregistry.StatusPresentLiveOwner, r.Status,
			"role %s owned by a live node hostname must not be orphan-dead-owner", r.RoleName)
	}
	assert.Empty(t, resp.Data.Alerts, "a healthy hostname-owned cluster must raise no alerts")
}

// TestHandleClusterReconciliation_DeclaredButMissing is the required AC test:
// a declared resource that has no registry entry → declared-but-missing (create-
// coverage gap), and a critical alert is emitted.
func TestHandleClusterReconciliation_DeclaredButMissing(t *testing.T) {
	server := setupTestServer(t)

	// Cluster member exists but has not published resource_owner.vm2.
	seedClusterSteward(t, server, "steward-a", "default", nil,
		clusterFragment(t, "cfg-lab", nil))
	seedClusterPoliciesConfig(t, server, "default", "cfg-lab", "vm2")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Resources, 1)
	r := resp.Data.Resources[0]
	assert.Equal(t, "vm2", r.RoleName)
	assert.Equal(t, clusterregistry.StatusDeclaredMissing, r.Status)
	assert.Empty(t, r.OwnerID, "declared-but-missing must not report an owner")
	require.Len(t, resp.Data.Alerts, 1, "one critical alert for a create-coverage gap")
	assert.Equal(t, health.SeverityCritical, resp.Data.Alerts[0].Severity)
	assert.Equal(t, "cluster_role_missing", resp.Data.Alerts[0].MetricName)
}

// TestHandleClusterReconciliation_DeadOwner is the required AC test:
// a registry entry whose owner steward has a heartbeat older than
// DeadOwnerStaleThreshold (60 s) → orphan-dead-owner, warning alert.
func TestHandleClusterReconciliation_DeadOwner(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-a", "default",
		map[string]string{"hostname": "CFG-70-02"},
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"}))
	// Backdate the heartbeat past DeadOwnerStaleThreshold (60 s).
	ok := server.controllerService.RecordHeartbeat("steward-a", "", time.Now().Add(-2*time.Minute))
	require.True(t, ok, "RecordHeartbeat must find the registered steward")

	seedClusterPoliciesConfig(t, server, "default", "cfg-lab", "csv")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Resources, 1)
	r := resp.Data.Resources[0]
	assert.Equal(t, "csv", r.RoleName)
	assert.Equal(t, clusterregistry.StatusOrphanDeadOwner, r.Status)
	assert.Equal(t, "CFG-70-02", r.OwnerID)
	require.Len(t, resp.Data.Alerts, 1, "one warning alert for a dead owner")
	assert.Equal(t, health.SeverityWarning, resp.Data.Alerts[0].Severity)
	assert.Equal(t, "cluster_role_dead_owner", resp.Data.Alerts[0].MetricName)
}

// TestHandleClusterReconciliation_SplitBrain is the required AC test:
// two cluster members reporting different owner values for the same role →
// split-brain status, critical alert, AllOwnerClaims populated.
func TestHandleClusterReconciliation_SplitBrain(t *testing.T) {
	server := setupTestServer(t)

	// Both stewards claim to own "csv" but report different owner values.
	seedClusterSteward(t, server, "node-a", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "node-a"}))
	seedClusterSteward(t, server, "node-b", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "node-b"}))
	seedClusterPoliciesConfig(t, server, "default", "cfg-lab", "csv")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Resources, 1)
	r := resp.Data.Resources[0]
	assert.Equal(t, "csv", r.RoleName)
	assert.Equal(t, clusterregistry.StatusSplitBrain, r.Status)
	assert.ElementsMatch(t, []string{"node-a", "node-b"}, r.AllOwnerClaims,
		"split-brain must surface all distinct owner claims")
	require.Len(t, resp.Data.Alerts, 1, "one critical alert for split-brain")
	assert.Equal(t, health.SeverityCritical, resp.Data.Alerts[0].Severity)
	assert.Equal(t, "cluster_role_split_brain", resp.Data.Alerts[0].MetricName)
}

// TestHandleClusterReconciliation_NotFound verifies 404 for unknown clusters and
// clusters that are out of the caller's tenant scope (404 not 403 — same
// information-hiding pattern as handleGetCluster).
func TestHandleClusterReconciliation_NotFound(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-b", "tenant-b", nil,
		clusterFragment(t, "cfg-prod", nil))

	t.Run("unknown cluster name returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/no-such-cluster/reconciliation", nil)
		req = withVars(req, map[string]string{"name": "no-such-cluster"})
		rec := httptest.NewRecorder()
		server.handleClusterReconciliation(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("cluster outside caller tenant returns 404 not 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-prod/reconciliation", nil)
		req = withVars(req, map[string]string{"name": "cfg-prod"})
		req = withClusterTenant(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleClusterReconciliation(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestHandleClusterReconciliation_MissingName verifies 400 when the {name} path
// variable is empty.
func TestHandleClusterReconciliation_MissingName(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters//reconciliation", nil)
	req = withVars(req, map[string]string{"name": ""})
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleClusterReconciliation_NoDeclaredResources verifies that when no
// cluster-policies config is stored, the response still has 200 with an empty
// resources list (graceful degradation — dead-owner/split-brain can still be
// detected even when the declared set is unknown).
func TestHandleClusterReconciliation_NoDeclaredResources(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-a", "default", nil,
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-02"}))
	// No seedClusterPoliciesConfig call → declared set is empty.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
	req = withVars(req, map[string]string{"name": "cfg-lab"})
	req = withClusterTenant(req, "default")
	rec := httptest.NewRecorder()
	server.handleClusterReconciliation(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data ClusterReconciliationResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.Data.Resources, "no declared resources → nothing to reconcile")
	assert.Empty(t, resp.Data.Alerts)
}

// TestStewardsInTenantScope_FragmentsAndHostnameIndex covers the two views the
// scoping helper returns: fragment-only fleet.StewardData (no DNAAttributes — the
// cluster registry reads fragments alone, Issue #3323) plus the hostname → steward
// ID index the reconciliation liveness check needs.
func TestStewardsInTenantScope_FragmentsAndHostnameIndex(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-a", "tenant-a",
		map[string]string{"hostname": "CFG-70-01", "os": "windows"},
		clusterFragment(t, "cfg-lab", map[string]string{"csv": "CFG-70-01"}))
	seedClusterSteward(t, server, "steward-b", "tenant-b",
		map[string]string{"hostname": "CFG-70-02"},
		clusterFragment(t, "cfg-prod", nil))

	t.Run("root scope sees every steward with fragments and hostnames", func(t *testing.T) {
		stewards, hostnames := server.stewardsInTenantScope("")
		require.Len(t, stewards, 2)
		for _, sd := range stewards {
			assert.Nil(t, sd.DNAAttributes,
				"cluster-registry StewardData must carry fragments only, not flat DNA attributes")
			assert.NotEmpty(t, sd.DNAFragments, "cluster fragments must survive the conversion")
		}
		assert.Equal(t, map[string]string{
			"CFG-70-01": "steward-a",
			"CFG-70-02": "steward-b",
		}, hostnames)
	})

	t.Run("tenant scope filters both views", func(t *testing.T) {
		stewards, hostnames := server.stewardsInTenantScope("tenant-a")
		require.Len(t, stewards, 1)
		assert.Equal(t, "steward-a", stewards[0].ID)
		assert.Equal(t, map[string]string{"CFG-70-01": "steward-a"}, hostnames,
			"a hostname published outside the caller's tenant must not be indexed")
	})
}

// TestStewardsInTenantScope_DuplicateHostnameClaim verifies that when two stewards
// publish the same hostname, the index resolves deterministically to the one with
// the most recent heartbeat rather than by steward iteration order.
func TestStewardsInTenantScope_DuplicateHostnameClaim(t *testing.T) {
	server := setupTestServer(t)

	seedClusterSteward(t, server, "steward-stale", "default",
		map[string]string{"hostname": "CFG-70-02"},
		clusterFragment(t, "cfg-lab", nil))
	seedClusterSteward(t, server, "steward-fresh", "default",
		map[string]string{"hostname": "CFG-70-02"},
		clusterFragment(t, "cfg-lab", nil))

	require.True(t, server.controllerService.RecordHeartbeat("steward-stale", "", time.Now().Add(-10*time.Minute)))
	require.True(t, server.controllerService.RecordHeartbeat("steward-fresh", "", time.Now()))

	for i := 0; i < 5; i++ {
		_, hostnames := server.stewardsInTenantScope("default")
		require.Equal(t, "steward-fresh", hostnames["CFG-70-02"],
			"duplicate hostname claims must resolve to the most recent heartbeat, every call")
	}
}

// TestHandleClusters_RoutedViaAPIKey exercises the full router path with API keys
// to verify the route registration and permission gates are wired correctly.
func TestHandleClusters_RoutedViaAPIKey(t *testing.T) {
	server := setupTestServer(t)

	listKey := NewTestKey(t, server, []string{"cluster:list"})
	readKey := NewTestKey(t, server, []string{"cluster:read"})

	t.Run("GET /api/v1/clusters with cluster:list key returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
		req.Header.Set("X-API-Key", listKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("GET /api/v1/clusters/{name} with cluster:read key returns 404 for unknown", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/no-such-cluster", nil)
		req.Header.Set("X-API-Key", readKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		// 404: cluster does not exist, but the route resolved and permission passed.
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("GET /api/v1/clusters without credentials returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("GET /api/v1/clusters/{name}/reconciliation with cluster:read key returns 404 for unknown", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/no-such-cluster/reconciliation", nil)
		req.Header.Set("X-API-Key", readKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		// 404: cluster not in registry, but route resolved and permission passed.
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("GET /api/v1/clusters/{name}/reconciliation without credentials returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("GET /api/v1/clusters/{name}/reconciliation with insufficient permissions returns 403", func(t *testing.T) {
		stewardKey := NewTestKey(t, server, []string{"steward:list"})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cfg-lab/reconciliation", nil)
		req.Header.Set("X-API-Key", stewardKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
