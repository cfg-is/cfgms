// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
)

func postWorkflowAsTenant(t *testing.T, router *mux.Router, method, path, tenantID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := withTenantContext(httptest.NewRequest(method, path, bytes.NewReader(body)), tenantID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestWorkflow_FilesystemReference_Refused guards Issue #4638: create and update
// refuse a definition that references a workflow by filesystem path at any depth,
// while a workflow_path key inside free-form module config is author data and is
// not mistaken for a reference.
func TestWorkflow_FilesystemReference_Refused(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	const tenant = "tenant-a"

	refused := map[string]CreateWorkflowRequest{
		"nested workflow step inside a parallel block": {
			Name: "nested-path",
			Steps: []workflow.Step{{Name: "fan", Type: workflow.StepTypeParallel, Steps: []workflow.Step{
				{Name: "call", Type: workflow.StepTypeWorkflow, WorkflowCall: &workflow.WorkflowCallConfig{WorkflowPath: "/etc/cfgms/controller.cfg"}},
			}}},
		},
		"step error workflow": {
			Name: "error-path",
			Steps: []workflow.Step{{Name: "s", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: time.Millisecond},
				ErrorWorkflow: &workflow.ErrorWorkflowConfig{WorkflowPath: "/etc/cfgms/controller.cfg"}}},
		},
	}
	for name, req := range refused {
		t.Run(name, func(t *testing.T) {
			rec := postWorkflowAsTenant(t, router, http.MethodPost, "/workflows", tenant, mustMarshal(req))
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "workflow_path is not supported")
		})
	}

	// Update is refused the same way.
	require.Equal(t, http.StatusCreated, postWorkflowAsTenant(t, router, http.MethodPost, "/workflows", tenant, minimalWorkflowBody("upd")).Code)
	rec := postWorkflowAsTenant(t, router, http.MethodPut, "/workflows/upd", tenant, mustMarshal(refused["step error workflow"]))
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// A module config key that happens to be called workflow_path is not a reference.
	allowed := CreateWorkflowRequest{Name: "config-key", Steps: []workflow.Step{
		{Name: "t", Type: workflow.StepTypeTask, Module: "file", Config: map[string]interface{}{"workflow_path": "/srv/app/flow.yaml"}},
	}}
	rec = postWorkflowAsTenant(t, router, http.MethodPost, "/workflows", tenant, mustMarshal(allowed))
	assert.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
}

// TestWorkflow_NestedByName_ResolvesFromExecutionTenantStore guards Issue #4638 end
// to end through the API: with the controller's store-backed resolver wired, a
// nested workflow step that names a child runs the child stored in the executing
// tenant, and a tenant without that child cannot reach another tenant's copy.
func TestWorkflow_NestedByName_ResolvesFromExecutionTenantStore(t *testing.T) {
	h, configStore := newTestWorkflowHandler(t)
	h.engine.SetWorkflowResolver(workflow.NewStoreWorkflowResolver(configStore))
	router := newWorkflowRouter(h)

	child := CreateWorkflowRequest{Name: "child", Steps: []workflow.Step{
		{Name: "pause", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: time.Millisecond}},
	}}
	outer := CreateWorkflowRequest{Name: "outer", Steps: []workflow.Step{
		{Name: "call-child", Type: workflow.StepTypeWorkflow, WorkflowCall: &workflow.WorkflowCallConfig{WorkflowName: "child"}},
	}}

	require.Equal(t, http.StatusCreated, postWorkflowAsTenant(t, router, http.MethodPost, "/workflows", "tenant-a", mustMarshal(child)).Code)
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		require.Equal(t, http.StatusCreated, postWorkflowAsTenant(t, router, http.MethodPost, "/workflows", tenant, mustMarshal(outer)).Code)
	}

	run := func(tenant string) workflow.ExecutionStatus {
		rec := postWorkflowAsTenant(t, router, http.MethodPost, "/workflows/outer/execute", tenant, []byte("{}"))
		require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		execID, _ := resp["execution_id"].(string)
		var status workflow.ExecutionStatus
		require.Eventually(t, func() bool {
			execution, err := h.engine.GetExecution(execID)
			require.NoError(t, err)
			status = execution.Status
			return status == workflow.StatusCompleted || status == workflow.StatusFailed
		}, 10*time.Second, 10*time.Millisecond)
		return status
	}

	assert.Equal(t, workflow.StatusCompleted, run("tenant-a"), "the child stored in tenant-a runs")
	assert.Equal(t, workflow.StatusFailed, run("tenant-b"), "tenant-b cannot reach tenant-a's child by name")
}
