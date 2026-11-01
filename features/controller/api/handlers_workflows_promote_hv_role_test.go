// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestPromoteHVRoleTemplate_CreateAndExecute_AgainstRealController is the
// integration-style regression test for Issue #3106: it drives the
// promote-hv-role.yaml template through the real controller HTTP stack --
// the same api.Server construction (New()) production uses, the real
// validationMiddleware / validateGenericRequest, the real RBAC permission
// gate, the real handleCreateWorkflow -> workflow.ParseSemanticVersion, and
// a real git-backed WorkflowStore -- rather than a hand-rolled httptest mock
// (makePromoteServer in cmd/cfg/cmd/workflow_test.go, which never calls
// validateGenericRequest) or an in-process call directly into
// security.NewValidator() (TestPromoteHVRoleTemplate_PassesProductionValidation).
//
// Before the #3106 fix, POSTing this template's description hit HTTP 400
// from validateGenericRequest's charset:safe_text check; this test proves
// the fixed template clears that check when submitted exactly as
// `cfg workflow promote-hv-role` submits it: create, then execute.
func TestPromoteHVRoleTemplate_CreateAndExecute_AgainstRealController(t *testing.T) {
	server := setupTestServer(t)

	storageManager := pkgtesting.SetupTestStorage(t)
	configStore := storageManager.GetConfigStore()
	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logger, nil, nil, nil, nil, nil)
	handler := NewWorkflowHandler(engine, configStore, nil, logger)
	server.SetWorkflowHandler(handler)

	parser := workflow.NewParser()
	wf, err := parser.ParseFile("../../workflow/templates/promote-hv-role.yaml")
	require.NoError(t, err, "authoritative promote-hv-role.yaml must parse")

	createReq := CreateWorkflowRequest{
		Name:        wf.Name,
		Description: wf.Description,
		Version:     wf.Version,
		Steps:       wf.Steps,
		Variables:   wf.Variables,
		Timeout:     wf.Timeout,
	}
	body, err := json.Marshal(createReq)
	require.NoError(t, err)

	apiKey := NewTestKey(t, server, []string{"workflow:write", "workflow:execute"})

	createHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	createHTTPReq.Header.Set("X-API-Key", apiKey)
	createHTTPReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	server.router.ServeHTTP(createRec, createHTTPReq)

	require.Equal(t, http.StatusCreated, createRec.Code,
		"creating promote-hv-role against the real controller must succeed "+
			"(pre-fix: 400 from validateGenericRequest on description charset): %s", createRec.Body.String())

	variables := map[string]interface{}{
		"vm_name":      "test-vm",
		"steward_id":   "test-steward",
		"cluster_name": "test-cluster",
		"tenant_id":    "test-tenant",
	}
	execBody, err := json.Marshal(map[string]interface{}{"variables": variables})
	require.NoError(t, err)

	execHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wf.Name+"/execute", bytes.NewReader(execBody))
	execHTTPReq.Header.Set("X-API-Key", apiKey)
	execHTTPReq.Header.Set("Content-Type", "application/json")
	execRec := httptest.NewRecorder()
	server.router.ServeHTTP(execRec, execHTTPReq)

	assert.Equal(t, http.StatusAccepted, execRec.Code,
		"executing promote-hv-role against the real controller must succeed: %s", execRec.Body.String())
}
