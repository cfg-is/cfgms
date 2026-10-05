// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// rootTenantWorkflowFixture wires a WorkflowHandler to a Server's real tenant
// resolution (root tenant by position, ADR-025 crossing) as SetWorkflowHandler
// does in production, with a client tenant "msp-sel" beneath the root.
func rootTenantWorkflowFixture(t *testing.T) (*Server, *mux.Router, cfgconfig.ConfigStore) {
	t.Helper()
	server := setupTestServer(t)
	prepareSelectedTenantServer(t, server)
	h, configStore := newTestWorkflowHandler(t)
	h.SetTenantResolution(server.rootTenantID, server.authorizeSelectedTenant)
	return server, newWorkflowRouter(h), configStore
}

func serveWorkflowAs(router *mux.Router, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestWorkflow_RootScoped_UsesRootTenant guards Issue #4576: a root-scoped caller's
// create, list, get and execute work, and the workflow is stored under the
// deployment's root tenant — never under an empty tenant, which the config store
// rejects (the 500 the issue reports).
func TestWorkflow_RootScoped_UsesRootTenant(t *testing.T) {
	_, router, configStore := rootTenantWorkflowFixture(t)
	caller := rootScopedPrincipal("root-operator-wf")

	rec := serveWorkflowAs(router, requestAsPrincipal(t, http.MethodPost, "/workflows", "", caller, minimalWorkflowBody("root-wf")))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	stored, err := workflow.NewWorkflowStore(configStore, testRootTenantID).GetLatestWorkflow(context.Background(), "root-wf")
	require.NoError(t, err, "the workflow must be stored under the root tenant")
	assert.Equal(t, "root-wf", stored.Name)

	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows", "", caller, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"root-wf"`, "list must return the root tenant's workflow")

	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows/root-wf", "", caller, nil))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodPost, "/workflows/root-wf/execute", "", caller, []byte("{}")))
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	// ?tenant=<root> selects the same tenant explicitly and needs no crossing.
	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows/root-wf?tenant="+testRootTenantID, "", caller, nil))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestWorkflow_RootScopedClientTenant_RequiresCrossing guards Issue #4576: a
// root-scoped caller selecting a client tenant with ?tenant= is challenged without
// a crossing, nothing is stored there, and the same request succeeds with one.
func TestWorkflow_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server, router, configStore := rootTenantWorkflowFixture(t)
	caller := rootScopedPrincipal("root-operator-wf")

	create := func() *httptest.ResponseRecorder {
		return serveWorkflowAs(router, requestAsPrincipal(t, http.MethodPost, "/workflows?tenant=msp-sel", "", caller, minimalWorkflowBody("client-wf")))
	}

	rec := create()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	_, err := workflow.NewWorkflowStore(configStore, "msp-sel").GetLatestWorkflow(context.Background(), "client-wf")
	assert.Error(t, err, "a challenged create must store nothing")

	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows?tenant=msp-sel", "", caller, nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "listing a client tenant's workflows needs a crossing too")

	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows?tenant=no-such-tenant", "", caller, nil))
	assert.Equal(t, http.StatusNotFound, rec.Code, "an unknown tenant is not found, not challenged")

	grantSelectedTenantCrossing(t, server, caller.ID)
	rec = create()
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	_, err = workflow.NewWorkflowStore(configStore, "msp-sel").GetLatestWorkflow(context.Background(), "client-wf")
	require.NoError(t, err, "with a crossing the workflow is stored under the selected tenant")

	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows", "", caller, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"client-wf"`, "without ?tenant= the root tenant's list is served")
}

// TestWorkflow_RootScoped_NoRootTenant_BadRequest guards Issue #4576: when no root
// tenant can be resolved, a root-scoped request without ?tenant= is a 400 — never a
// store call with an empty tenant.
func TestWorkflow_RootScoped_NoRootTenant_BadRequest(t *testing.T) {
	server := setupTestServer(t)
	h, _ := newTestWorkflowHandler(t)
	// No tenants, or several parentless ones, resolve no root: RootTenantID's "".
	noRoot := func(context.Context) string { return "" }
	h.SetTenantResolution(noRoot, server.authorizeSelectedTenant)
	router := newWorkflowRouter(h)

	rec := serveWorkflowAs(router, requestAsPrincipal(t, http.MethodPost, "/workflows", "", rootScopedPrincipal("root-operator-wf"), minimalWorkflowBody("orphan-wf")))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "tenant is required")
}

// TestWorkflow_RootScoped_TenantResolutionUnwired_Refused guards Issue #4576: a
// handler whose tenant resolution was never wired refuses root-scoped requests
// rather than falling back to an empty tenant.
func TestWorkflow_RootScoped_TenantResolutionUnwired_Refused(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	rec := serveWorkflowAs(router, requestAsPrincipal(t, http.MethodGet, "/workflows", "", rootScopedPrincipal("root-operator-wf"), nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
}
