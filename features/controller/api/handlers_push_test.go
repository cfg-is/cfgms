// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// stubLeaderStatus is a minimal test double for leader-check behavior.
// It is NOT a mock: it has no expectations and carries only a fixed boolean.
type stubLeaderStatus struct{ leader bool }

func (s *stubLeaderStatus) IsLeader() bool { return s.leader }

// validPushPayload returns a minimal valid StewardConfiguration body.
func validPushPayload() push.StewardConfiguration {
	return push.StewardConfiguration{
		ConfigID: "cfg-001",
		Version:  "1.0.0",
		TenantID: "tenant-abc",
	}
}

func marshalPayload(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// setupPushServer creates a test server and returns the audit manager so tests
// can call Flush and then query the audit store for emitted events.
func setupPushServer(t *testing.T) (*Server, *audit.Manager) {
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

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil,
		auditMgr,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	return server, auditMgr
}

// TestHandleConfigPush_Leader verifies that a valid request on the leader node
// returns 202 Accepted with a non-empty push_id and status "accepted".
func TestHandleConfigPush_Leader(t *testing.T) {
	server := setupTestServer(t)
	// nil pushLeaderStatus → treated as leader (OSS single-node default)
	server.pushLeaderStatus = nil

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID, "push_id must be non-empty")
	assert.Equal(t, "accepted", resp.Status)
}

// TestHandleConfigPush_NonLeader verifies that a request forwarded to a
// follower node returns 503 Service Unavailable with {"error":"not the leader"}.
func TestHandleConfigPush_NonLeader(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = &stubLeaderStatus{leader: false}

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "not the leader", resp["error"])
}

// TestHandleConfigPush_MissingFields verifies that omitting any required field
// returns 400 Bad Request with an informative error message.
func TestHandleConfigPush_MissingFields(t *testing.T) {
	tests := []struct {
		name    string
		payload push.StewardConfiguration
	}{
		{
			name: "missing config_id",
			payload: push.StewardConfiguration{
				Version:  "1.0.0",
				TenantID: "tenant-abc",
			},
		},
		{
			name: "missing version",
			payload: push.StewardConfiguration{
				ConfigID: "cfg-001",
				TenantID: "tenant-abc",
			},
		},
		{
			name: "missing tenant_id",
			payload: push.StewardConfiguration{
				ConfigID: "cfg-001",
				Version:  "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupTestServer(t)

			body := marshalPayload(t, tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.handleConfigPush(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code, "expected 400 for %s", tt.name)

			var resp map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.Contains(t, resp["error"], "required", "error message must mention required fields")
		})
	}
}

// TestHandleConfigPush_InvalidJSON verifies that a malformed body returns 400
// with an appropriate error message.
func TestHandleConfigPush_InvalidJSON(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push",
		bytes.NewBufferString("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "invalid request body", resp["error"])
}

// TestHandleConfigPush_RouteRegistered verifies the route is wired into the
// router and that authentication is enforced (no key → 401, not 404).
func TestHandleConfigPush_RouteRegistered(t *testing.T) {
	server := setupTestServer(t)

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// No API key supplied → 401, not 404. Route exists.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleConfigPush_AuditEventEmitted verifies that a successful push on
// the leader records a "config.push.initiated" audit event in the audit store.
func TestHandleConfigPush_AuditEventEmitted(t *testing.T) {
	server, auditMgr := setupPushServer(t)
	server.pushLeaderStatus = nil // leader

	payload := validPushPayload()
	body := marshalPayload(t, payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// Flush the async audit write queue before querying the store.
	require.NoError(t, auditMgr.Flush(context.Background()))

	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"config.push.initiated"},
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one config.push.initiated audit entry")
	assert.Equal(t, payload.TenantID, entries[0].TenantID)
	assert.Equal(t, "config.push.initiated", entries[0].Action)
}
