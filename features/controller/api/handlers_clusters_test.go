// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// seedClusterSteward registers a steward and sets its DNA to carry the given
// cluster DNA attributes. Used by cluster handler tests.
func seedClusterSteward(t *testing.T, server *Server, id, tenantID string, dnaAttrs map[string]string) {
	t.Helper()
	require.NoError(t, server.controllerService.RegisterSteward(id, tenantID, "addr", "active"))
	ok := server.controllerService.SetStewardDNA(id, &commonpb.DNA{Id: id, Attributes: dnaAttrs})
	require.True(t, ok, "SetStewardDNA must return true for a registered steward")
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

	seedClusterSteward(t, server, "steward-a", "default", map[string]string{
		"cluster:cfg-lab.member_nodes":       "CFG-70-02,CFG-AB-02",
		"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
	})
	seedClusterSteward(t, server, "steward-b", "default", map[string]string{
		"cluster:cfg-lab.member_nodes":       "CFG-70-02,CFG-AB-02",
		"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
	})

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
	seedClusterSteward(t, server, "steward-a", "tenant-a", map[string]string{
		"cluster:cfg-lab.member_nodes":       "node-a",
		"cluster:cfg-lab.resource_owner.csv": "node-a",
	})
	// Steward in tenant-b has cluster cfg-prod.
	seedClusterSteward(t, server, "steward-b", "tenant-b", map[string]string{
		"cluster:cfg-prod.member_nodes":       "node-b",
		"cluster:cfg-prod.resource_owner.cno": "node-b",
	})

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

	seedClusterSteward(t, server, "steward-child", "root/msp-a/client-1", map[string]string{
		"cluster:cfg-lab.member_nodes": "node-child",
	})

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

	seedClusterSteward(t, server, "steward-a", "default", map[string]string{
		"cluster:cfg-lab.member_nodes":       "CFG-70-02",
		"cluster:cfg-lab.resource_owner.csv": "CFG-70-02",
		"cluster:cfg-lab.resource_owner.cno": "CFG-AB-02",
	})

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
	seedClusterSteward(t, server, "steward-b", "tenant-b", map[string]string{
		"cluster:cfg-prod.member_nodes": "node-b",
	})

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
}
