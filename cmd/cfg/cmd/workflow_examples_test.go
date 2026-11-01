// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/api"
	wfpkg "github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newWorkflowAPIServer serves the controller's real workflow routes with every
// request scoped to one tenant, so a test can submit definitions exactly as the
// controller decodes and stores them.
func newWorkflowAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	logger := logging.NewNoopLogger()
	engine := wfpkg.NewEngine(wfpkg.NewWorkflowModuleFactory(nil, nil), logger, nil, nil, nil, nil, nil)
	h := api.NewWorkflowHandler(engine, pkgtesting.SetupTestStorage(t).GetConfigStore(), nil, logger)
	h.SetRequirePermFn(func(_, _ string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler { return next }
	})
	router := mux.NewRouter()
	require.NoError(t, h.RegisterWorkflowRoutes(router.PathPrefix("/api/v1/workflows").Subrouter()))

	const tenantID = "acme-corp"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxkeys.TenantID, tenantID)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(tenantID))
		router.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestWorkflowExamples_SubmitThroughCLIAndAPI guards Issue #4577: every shipped
// workflow example — flat or nested under "workflow:", with human-readable
// durations — parses with the CLI and is accepted by the controller's create
// endpoint, and what the controller stores is what the file declared: nothing
// is dropped or altered on the way.
func TestWorkflowExamples_SubmitThroughCLIAndAPI(t *testing.T) {
	examples, err := filepath.Glob(filepath.Join("..", "..", "..", "features", "workflow", "examples", "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, examples, "the workflow examples must be found")

	srv := newWorkflowAPIServer(t)

	submit := func(t *testing.T, def workflowDefinition) {
		t.Helper()
		body, err := json.Marshal(def) // what submitWorkflow sends
		require.NoError(t, err)
		resp, err := http.Post(srv.URL+"/api/v1/workflows", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var created map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&created)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "controller rejected %s: %v", def.Name, created)

		got, err := http.Get(srv.URL + "/api/v1/workflows/" + def.Name)
		require.NoError(t, err)
		defer func() { _ = got.Body.Close() }()
		require.Equal(t, http.StatusOK, got.StatusCode)
		var stored wfpkg.Workflow
		require.NoError(t, json.NewDecoder(got.Body).Decode(&stored))

		// The controller fills in what a definition may omit: a default version
		// and the positional step IDs it assigns on create. Everything else must
		// survive unchanged.
		if def.Version == "" {
			def.Version = "1.0.0"
		}
		wfpkg.AssignStepIDs(def.Steps)
		want, err := json.Marshal(def)
		require.NoError(t, err)
		have, err := json.Marshal(stored)
		require.NoError(t, err)
		assert.JSONEq(t, string(want), string(have), "the stored workflow must match the submitted definition")
	}

	for _, path := range examples {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path) // #nosec G304 -- fixed repo example path
			require.NoError(t, err)
			def, err := parseWorkflowFile(data)
			require.NoError(t, err)
			submit(t, def)
		})
	}

	t.Run("embedded promote-hv-role template", func(t *testing.T) {
		def, err := parseWorkflowFile(promoteHVRoleTemplateData)
		require.NoError(t, err)
		submit(t, def)
	})
}

// TestParseWorkflowFile_DurationsAndForms guards Issue #4577: the nested and flat
// forms decode to the same definition, human-readable durations become real
// durations (sent to the controller as nanoseconds), and an invalid semantic
// version or an unknown field is refused before anything is sent.
func TestParseWorkflowFile_DurationsAndForms(t *testing.T) {
	flat := []byte(`name: wait-a-bit
version: "1.0.0"
timeout: 5m
steps:
  - name: pause
    type: delay
    delay:
      duration: 2s
`)
	nested := []byte(`workflow:
  name: wait-a-bit
  version: "1.0.0"
  timeout: 5m
  steps:
    - name: pause
      type: delay
      delay:
        duration: 2s
`)
	a, err := parseWorkflowFile(flat)
	require.NoError(t, err)
	b, err := parseWorkflowFile(nested)
	require.NoError(t, err)
	assert.Equal(t, a, b, "both forms describe the same workflow")
	require.NotNil(t, a.Steps[0].Delay)
	assert.Equal(t, "2s", a.Steps[0].Delay.Duration.String())
	assert.Equal(t, "5m0s", a.Timeout.String())

	body, err := json.Marshal(a)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"duration":2000000000`, "durations reach the controller as nanoseconds")

	_, err = parseWorkflowFile([]byte("name: bad-version\nversion: \"1.0\"\nsteps: []\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MAJOR.MINOR.PATCH")

	_, err = parseWorkflowFile([]byte("name: typo\nsteps:\n  - name: s\n    type: task\n    modul: file\n"))
	require.Error(t, err, "an unknown field must be refused, not dropped")
}
