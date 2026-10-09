// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	stewardRoutePrefix   = "/api/v1/stewards/{id}"
	stewardTerminalRoute = "GET /api/v1/terminal/ws/{steward_id}"
)

// stewardCrossingRoute is one row of the per-steward write/action route table.
type stewardCrossingRoute struct {
	// permission is the RBAC permission ID requirePermission demands, granted to
	// the sibling-MSP tenant-scoped caller so only the tenant gate decides.
	permission string
	// path builds the request path with the steward ID filled in.
	path func(stewardID string) string
	// body builds a request body valid enough to reach the handler's tenant gate.
	body func(stewardID string) interface{}
	// pastGateStatus is the status a caller that cleared the tenant gate gets: the
	// steward is registered but not connected, so most handlers fail downstream.
	pastGateStatus int
	// pastGateBody must appear in the response body of a call past the gate, so a
	// validation error that fires before the gate cannot pass as "past the gate".
	pastGateBody string
}

func stewardPath(suffix string) func(string) string {
	return func(id string) string { return "/api/v1/stewards/" + id + suffix }
}

func noBody(string) interface{} { return nil }

// stewardCrossingTable keys each route by "METHOD route-template" exactly as the
// router reports it. TestStewardRoutes_CrossingBoundaryTable fails when a registered
// non-GET per-steward route has no row here, or a row names an unregistered route.
var stewardCrossingTable = map[string]stewardCrossingRoute{
	"DELETE /api/v1/stewards/{id}": {
		permission: "steward:decommission", path: stewardPath(""), body: noBody,
		pastGateStatus: http.StatusOK, pastGateBody: "deregistered",
	},
	"POST /api/v1/stewards/{id}/auth/refresh": {
		permission: "steward:auth-refresh", path: stewardPath("/auth/refresh"), body: noBody,
		pastGateStatus: http.StatusOK, pastGateBody: "refresh_requested",
	},
	"POST /api/v1/stewards/{id}/move": {
		permission: "steward:move", path: stewardPath("/move"),
		body:           func(string) interface{} { return map[string]string{"new_tenant_id": testRootTenantID} },
		pastGateStatus: http.StatusOK, pastGateBody: `"steward_id"`,
	},
	"PATCH /api/v1/stewards/{id}/visibility": {
		permission: "steward:visibility", path: stewardPath("/visibility"),
		body:           func(string) interface{} { return map[string]bool{"hidden": false} },
		pastGateStatus: http.StatusOK, pastGateBody: `"hidden":false`,
	},
	"PUT /api/v1/stewards/{id}/config": {
		permission: "steward:write-config", path: stewardPath("/config"), body: validStewardConfigBody,
		pastGateStatus: http.StatusOK, pastGateBody: `"data"`,
	},
	"DELETE /api/v1/stewards/{id}/config": {
		permission: "steward:delete-config", path: stewardPath("/config"), body: noBody,
		pastGateStatus: http.StatusNotFound, pastGateBody: "CONFIG_NOT_FOUND",
	},
	"POST /api/v1/stewards/{id}/config/validate": {
		permission: "steward:validate-config", path: stewardPath("/config/validate"), body: validStewardConfigBody,
		pastGateStatus: http.StatusOK, pastGateBody: `"valid"`,
	},
	"POST /api/v1/stewards/{id}/scripts/executions/{execution_id}/retry": {
		permission: "steward:execute-scripts", path: stewardPath("/scripts/executions/exec-1/retry"), body: noBody,
		pastGateStatus: http.StatusNotImplemented, pastGateBody: "NOT_IMPLEMENTED",
	},
	"POST /api/v1/stewards/{id}/tags": {
		permission: "steward:tag:write", path: stewardPath("/tags"),
		body:           func(string) interface{} { return map[string][]string{"tags": {"crossing"}} },
		pastGateStatus: http.StatusServiceUnavailable, pastGateBody: "TAG_STORE_UNAVAILABLE",
	},
	"DELETE /api/v1/stewards/{id}/tags": {
		permission: "steward:tag:write", path: stewardPath("/tags"),
		body:           func(string) interface{} { return map[string][]string{"tags": {"crossing"}} },
		pastGateStatus: http.StatusServiceUnavailable, pastGateBody: "TAG_STORE_UNAVAILABLE",
	},
	"PUT /api/v1/stewards/{id}/reboot-window": {
		permission: "reboot_window:override", path: stewardPath("/reboot-window"),
		body:           func(string) interface{} { return map[string]string{"schedule_yaml": "not: [valid"} },
		pastGateStatus: http.StatusBadRequest, pastGateBody: "INVALID_SCHEDULE",
	},
	"POST /api/v1/stewards/{id}/services/{name}/actions": {
		permission: "steward:service-control", path: stewardPath("/services/svc/actions"),
		body:           func(string) interface{} { return map[string]string{"action": "restart"} },
		pastGateStatus: http.StatusServiceUnavailable, pastGateBody: "Run service not available",
	},
	"POST /api/v1/stewards/{id}/processes/{pid}/actions": {
		permission: "steward:process-control", path: stewardPath("/processes/1/actions"),
		body:           func(string) interface{} { return map[string]string{"action": "kill"} },
		pastGateStatus: http.StatusServiceUnavailable, pastGateBody: "Run service not available",
	},
	"POST /api/v1/stewards/{id}/actions/prepare": {
		permission: "steward:service-control", path: stewardPath("/actions/prepare"),
		body: func(string) interface{} {
			return map[string]string{"target_kind": "service", "target_name": "svc", "action": "restart"}
		},
		pastGateStatus: http.StatusOK, pastGateBody: `"shell":"steward-action"`,
	},
	stewardTerminalRoute: {
		permission: "terminal:create",
		path:       func(id string) string { return "/api/v1/terminal/ws/" + id },
		body:       noBody,

		pastGateStatus: http.StatusServiceUnavailable, pastGateBody: "terminal service not available",
	},
}

func validStewardConfigBody(stewardID string) interface{} {
	return map[string]interface{}{"steward": map[string]interface{}{"id": stewardID, "mode": "controller"}}
}

// collectStewardRoutes walks the router for every non-GET route under
// /api/v1/stewards/{id}, plus the steward-keyed terminal WebSocket route.
func collectStewardRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()
	found := map[string]bool{}
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, pathErr := route.GetPathTemplate()
		if pathErr != nil {
			return nil
		}
		methods, methodErr := route.GetMethods()
		if methodErr != nil {
			return nil
		}
		underSteward := path == stewardRoutePrefix || strings.HasPrefix(path, stewardRoutePrefix+"/")
		for _, method := range methods {
			key := method + " " + path
			if (underSteward && method != http.MethodGet) || key == stewardTerminalRoute {
				found[key] = true
			}
		}
		return nil
	})
	require.NoError(t, err)
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestStewardRoutes_CrossingBoundaryTable guards the ADR-025 tenant-crossing
// boundary on every non-GET per-steward route (Issue #4557). The route list is
// derived from the real router, so a new /stewards/{id}/... write or action route
// that is not added to stewardCrossingTable fails here; each table row is then
// driven through a real bearer session.
func TestStewardRoutes_CrossingBoundaryTable(t *testing.T) {
	server, _, _ := setupProvisionTestServer(t)
	server = wireCrossingStore(t, server)
	ctx := context.Background()

	sessCfg := session.DefaultConfig()
	sessStore := session.NewMemStore(sessCfg, time.Now)
	t.Cleanup(sessStore.Close)
	sessMgr := session.NewManager(sessCfg, sessStore, time.Now)
	server.SetSessionManager(sessMgr)

	registered := collectStewardRoutes(t, server.router)
	require.NotEmpty(t, registered, "the router walk found no per-steward routes")

	t.Run("table matches router", func(t *testing.T) {
		for _, key := range registered {
			_, ok := stewardCrossingTable[key]
			assert.True(t, ok, "registered route %q has no crossing-boundary table entry", key)
		}
		registeredSet := map[string]bool{}
		for _, key := range registered {
			registeredSet[key] = true
		}
		for key := range stewardCrossingTable {
			assert.True(t, registeredSet[key], "table entry %q is not a registered route", key)
		}
	})

	require.NoError(t, ensureTestRootTenant(ctx, server.tenantManager))
	const (
		msp      = "route-msp"
		sibling  = "route-sibling-msp"
		clientTn = "route-msp-client"
	)
	for _, tn := range []struct{ id, parent string }{
		{msp, testRootTenantID}, {sibling, testRootTenantID}, {clientTn, msp},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tn.id, ParentID: tn.parent})
		require.NoError(t, err)
	}

	var seq int
	// newSteward registers a fresh steward for tenantID in both the durable store and
	// the controller service. A fresh one per call keeps destructive routes
	// (decommission, move) from consuming a steward a later call needs.
	newSteward := func(t *testing.T, tenantID string) string {
		t.Helper()
		seq++
		id := fmt.Sprintf("route-steward-%d", seq)
		require.NoError(t, server.stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID: id, TenantID: tenantID, Status: business.StewardStatusActive,
		}))
		require.NoError(t, server.controllerService.RegisterSteward(id, tenantID, "localhost:7100", "online"))
		return id
	}

	// session returns a bearer token for account, elevated to AssuranceStrong so every
	// route clears its assurance floor and only the tenant decision is in play.
	session := func(t *testing.T, acct *account) string {
		t.Helper()
		server.cacheAccount(acct)
		sess, _, err := sessMgr.Issue(ctx, acct.ID, "cfg-cli", acct.TenantID)
		require.NoError(t, err)
		_, token, err := sessMgr.Elevate(ctx, sess.ID, []byte("route-credential"), "192.0.2.1")
		require.NoError(t, err)
		return token
	}
	send := func(t *testing.T, token, method string, row stewardCrossingRoute, stewardID string) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body := row.body(stewardID); body != nil {
			var err error
			raw, err = json.Marshal(body)
			require.NoError(t, err)
		}
		req := httptest.NewRequest(method, row.path(stewardID), bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
	}
	assertPastGate := func(t *testing.T, key string, row stewardCrossingRoute, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := rec.Body.String()
		assert.NotContains(t, body, "tenant_crossing_required", "%s: must not be challenged", key)
		assert.NotContains(t, body, "STEWARD_NOT_FOUND", "%s: the steward must be found", key)
		assert.Equal(t, row.pastGateStatus, rec.Code, "%s: %s", key, body)
		assert.Contains(t, body, row.pastGateBody, "%s: response must come from the handler past the gate", key)
	}

	for _, key := range registered {
		row, ok := stewardCrossingTable[key]
		if !ok {
			continue // reported by "table matches router"
		}
		method := strings.SplitN(key, " ", 2)[0]
		suffix := strings.NewReplacer(" ", "-", "/", "-", "{", "", "}", "").Replace(key)

		t.Run(key, func(t *testing.T) {
			t.Run("root without crossing is challenged", func(t *testing.T) {
				token := session(t, &account{ID: "root-no-" + suffix, Username: "root-no-" + suffix, RootScope: true})
				rec := send(t, token, method, row, newSteward(t, clientTn))
				assertCrossingChallenge(t, rec, clientTn)
			})
			t.Run("root with crossing is past the gate", func(t *testing.T) {
				operator := "root-yes-" + suffix
				token := session(t, &account{ID: operator, Username: operator, RootScope: true})
				grantCrossing(t, server, operator, msp)
				assertPastGate(t, key, row, send(t, token, method, row, newSteward(t, clientTn)))
			})
			t.Run("root on a root-tenant steward is past the gate", func(t *testing.T) {
				token := session(t, &account{ID: "root-own-" + suffix, Username: "root-own-" + suffix, RootScope: true})
				assertPastGate(t, key, row, send(t, token, method, row, newSteward(t, testRootTenantID)))
			})
			t.Run("sibling MSP caller gets not found", func(t *testing.T) {
				id := "sibling-" + suffix
				token := session(t, &account{
					ID: id, Username: id, TenantID: sibling, Permissions: []string{row.permission},
				})
				rec := send(t, token, method, row, newSteward(t, clientTn))
				require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
				assert.Contains(t, rec.Body.String(), "STEWARD_NOT_FOUND")
				assert.NotContains(t, rec.Body.String(), "tenant_crossing_required")
			})
		})
	}
}
