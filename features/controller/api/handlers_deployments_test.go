// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	ctrlproto "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupDeploymentServer creates a test server wired with a real push store
// so deployment handler tests can exercise the full handler path.
func setupDeploymentServer(t *testing.T) (*Server, business.PushStore) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false
	logger := logging.NewNoopLogger()

	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	pushStore := storageManager.GetPushStore()
	require.NotNil(t, pushStore, "push store must be available from test storage")

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil,
		auditMgr,
		nil,       // No command publisher needed
		pushStore, // Real push store
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	return server, pushStore
}

// registerStewardForDeploymentTest registers and activates a steward for use
// in deployment handler tests. Stewards registered without tenant context default
// to the "default" tenant (see ControllerService.extractTenantID).
func registerStewardForDeploymentTest(t *testing.T, svc *service.ControllerService, dnaID string) string {
	t.Helper()
	ctx := context.Background()
	resp, err := svc.AcceptRegistration(ctx, &ctrlproto.RegisterRequest{
		Version:    "1.0.0",
		InitialDna: &common.DNA{Id: dnaID},
	})
	require.NoError(t, err)
	_, err = svc.ProcessHeartbeat(ctx, &ctrlproto.HeartbeatRequest{
		StewardId: resp.StewardId,
		Status:    "active",
	})
	require.NoError(t, err)
	return resp.StewardId
}

// deploymentAPIKey creates a key for the "default" tenant — matches push records
// created with TenantID:"default" in test helpers.
func deploymentAPIKey(t *testing.T, server *Server) string {
	t.Helper()
	return NewEphemeralTestKey(t, server, []string{"config:list-deployments"}, "default", 5*time.Minute)
}

func TestHandleGetConfigDeployments_NoPushRecords(t *testing.T) {
	server, _ := setupDeploymentServer(t)

	apiKey := deploymentAPIKey(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/my-config/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "my-config", data["config_id"])

	summary, ok := data["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(0), summary["applied"])
	assert.Equal(t, float64(0), summary["pending"])
	assert.Equal(t, float64(0), summary["failed"])
	assert.Equal(t, float64(0), summary["total"])

	history, ok := data["push_history"].([]interface{})
	require.True(t, ok)
	assert.Empty(t, history)
}

func TestHandleGetConfigDeployments_CompletedPush(t *testing.T) {
	server, pushStore := setupDeploymentServer(t)
	ctx := context.Background()

	// Stewards registered without context default to "default" tenant.
	stewardID := registerStewardForDeploymentTest(t, server.controllerService, "deploy-dna-1")

	now := time.Now().UTC()
	rec := &business.PushRecord{
		ID:        "push-completed-001",
		ConfigID:  "cfg-prod",
		TenantID:  "default",
		Version:   "v2.0.0",
		Status:    business.PushStatusCompleted,
		Data:      []byte(`{}`),
		CreatedAt: now.Add(-10 * time.Minute),
		UpdatedAt: now,
	}
	require.NoError(t, pushStore.CreatePush(ctx, rec))

	apiKey := deploymentAPIKey(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/cfg-prod/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var apiResp APIResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&apiResp))

	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "cfg-prod", data["config_id"])

	summary, ok := data["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), summary["applied"], "one active steward → applied=1")
	assert.Equal(t, float64(0), summary["pending"])
	assert.Equal(t, float64(0), summary["failed"])
	assert.Equal(t, float64(1), summary["total"])

	stewards, ok := data["stewards"].([]interface{})
	require.True(t, ok)
	require.Len(t, stewards, 1, "one active steward should appear in per-steward list")
	st, ok := stewards[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, stewardID, st["steward_id"])
	assert.Equal(t, "applied", st["status"])

	history, ok := data["push_history"].([]interface{})
	require.True(t, ok)
	require.Len(t, history, 1)
	ph, ok := history[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "push-completed-001", ph["push_id"])
	assert.Equal(t, "completed", ph["status"])
	assert.Equal(t, "v2.0.0", ph["version"])
}

func TestHandleGetConfigDeployments_FailedPush(t *testing.T) {
	server, pushStore := setupDeploymentServer(t)
	ctx := context.Background()

	registerStewardForDeploymentTest(t, server.controllerService, "deploy-dna-fail")

	rec := &business.PushRecord{
		ID:       "push-failed-001",
		ConfigID: "cfg-failed",
		TenantID: "default",
		Version:  "v1.0.0",
		Status:   business.PushStatusFailed,
		Data:     []byte(`{}`),
	}
	require.NoError(t, pushStore.CreatePush(ctx, rec))

	apiKey := deploymentAPIKey(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/cfg-failed/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var apiResp APIResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&apiResp))
	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)

	summary, ok := data["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(0), summary["applied"])
	assert.Equal(t, float64(1), summary["failed"])
}

func TestHandleGetConfigDeployments_PendingPush(t *testing.T) {
	server, pushStore := setupDeploymentServer(t)
	ctx := context.Background()

	registerStewardForDeploymentTest(t, server.controllerService, "deploy-dna-pending")

	rec := &business.PushRecord{
		ID:       "push-pending-001",
		ConfigID: "cfg-pending",
		TenantID: "default",
		Version:  "v1.0.0",
		Status:   business.PushStatusInProgress,
		Data:     []byte(`{}`),
	}
	require.NoError(t, pushStore.CreatePush(ctx, rec))

	apiKey := deploymentAPIKey(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/cfg-pending/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var apiResp APIResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&apiResp))
	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)

	summary, ok := data["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), summary["pending"])
	assert.Equal(t, float64(0), summary["applied"])
}

func TestHandleGetConfigDeployments_MultipleHistoryEntries(t *testing.T) {
	server, pushStore := setupDeploymentServer(t)
	ctx := context.Background()

	now := time.Now().UTC()
	statuses := []business.PushStatus{business.PushStatusCompleted, business.PushStatusFailed}
	for i, status := range statuses {
		r := &business.PushRecord{
			ID:        fmt.Sprintf("push-hist-%d", i),
			ConfigID:  "cfg-multi",
			TenantID:  "default",
			Version:   fmt.Sprintf("v%d.0.0", i+1),
			Status:    status,
			Data:      []byte(`{}`),
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
			UpdatedAt: now.Add(time.Duration(i) * time.Minute),
		}
		require.NoError(t, pushStore.CreatePush(ctx, r))
	}

	apiKey := deploymentAPIKey(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/cfg-multi/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var apiResp APIResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&apiResp))
	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)

	history, ok := data["push_history"].([]interface{})
	require.True(t, ok)
	assert.Len(t, history, 2, "both push records should appear in history")

	// Most recent entry (failed, index 1 by creation time) is first because
	// the store returns newest-first.
	ph0, ok := history[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "failed", ph0["status"])
}

func TestHandleGetConfigDeployments_CrossTenantIsolation(t *testing.T) {
	server, pushStore := setupDeploymentServer(t)
	ctx := context.Background()

	// Create a push record for tenant-b with the same config ID.
	tenantBRec := &business.PushRecord{
		ID:       "push-tenant-b-001",
		ConfigID: "cfg-shared",
		TenantID: "tenant-b",
		Version:  "v1.0.0",
		Status:   business.PushStatusCompleted,
		Data:     []byte(`{}`),
	}
	require.NoError(t, pushStore.CreatePush(ctx, tenantBRec))

	// Authenticate as "default" tenant — must NOT see tenant-b's push records.
	apiKey := deploymentAPIKey(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/cfg-shared/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var apiResp APIResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&apiResp))
	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)

	history, ok := data["push_history"].([]interface{})
	require.True(t, ok)
	assert.Empty(t, history, "tenant-b's push records must not be visible to default tenant")

	summary, ok := data["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(0), summary["total"], "summary must reflect zero deployments for default tenant")
}

func TestHandleGetConfigDeployments_RouteRegistered_NoAuth(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/my-cfg/deployments", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// No API key → 401, not 404. Route exists and auth is enforced.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleGetConfigDeployments_MissingPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"config:list"}) // wrong permission

	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/my-cfg/deployments", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
