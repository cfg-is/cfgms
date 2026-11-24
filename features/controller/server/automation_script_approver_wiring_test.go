// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	approverWiringTenant   = "approver-wiring-tenant"
	approverWiringScript   = "inventory"
	approverWiringWorkflow = "tidy-disk"
	approverWiringBody     = "#!/bin/bash\n# cfgms-preapproved: automation\necho hello\n"
	approverRunsPath       = "/api/v1/automation/runs"
)

// approverWiringFixture is the real controller built through New, the construction path
// the binary uses, with one tenant, one steward in it, a grant and a begun run. Nothing
// about the script step executor is built by the test: the approver it asks is the one
// controller startup installed.
type approverWiringFixture struct {
	srv     *Server
	cred    string
	runID   string
	steward string
	repo    *script.TenantScriptRepository
	store   *api.ContentApprovalStore
}

// approverWiringConfig is a controller configuration with a transport, so the
// execution queue a script step queues through is built.
func approverWiringConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig:    &cert.CAConfig{Organization: "Script Approver Wiring Test", Country: "US", ValidityDays: 3650},
	})
	require.NoError(t, err, "failed to create test CA")
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server:               &config.ServerCertificateConfig{CommonName: "script-approver-wiring-controller", Organization: "Script Approver Wiring Test"},
		},
		Transport: &config.TransportConfig{ListenAddr: "127.0.0.1:0", UseCertManager: true, MaxConnections: 10},
		Storage:   createTestStorageConfig(tempDir, "script-approver-wiring"),
	}
}

func newApproverWiringFixture(t *testing.T) *approverWiringFixture {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())
	srv := servernewCharNewServer(t, approverWiringConfig(t), logging.NewNoopLogger())
	require.NotNil(t, srv.httpServer)
	require.NotNil(t, srv.workflowEngine, "the workflow engine must be wired")
	require.NotNil(t, srv.executionQueue, "the execution queue must be wired")
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), approverWiringTenant, approverWiringTenant, "")

	f := &approverWiringFixture{srv: srv, steward: "approver-wiring-steward"}
	require.NoError(t, srv.controllerService.RegisterSteward(f.steward, approverWiringTenant, "127.0.0.1:0", "online"))

	repo, ok := srv.httpServer.ScriptRepository().(*script.TenantScriptRepository)
	require.True(t, ok, "the script library must be tenant-resolved")
	f.repo = repo
	f.store = srv.httpServer.ContentApprovalStore()
	require.NotNil(t, f.store, "the content approval store must be wired")
	ctx := context.Background()
	require.NoError(t, f.store.SetMode(ctx, approverWiringTenant, api.LibraryKindScript, api.ApprovalModeApprove, "admin"))
	require.NoError(t, f.store.SetMode(ctx, approverWiringTenant, api.LibraryKindWorkflow, api.ApprovalModeApprove, "admin"))

	_, f.cred, _ = srv.httpServer.AutomationGrantStore().Create(ctx, approverWiringTenant, "deploy", "operator-1", time.Now().Add(time.Hour))
	require.NotEmpty(t, f.cred)

	rec := f.call(http.MethodPost, approverRunsPath, map[string]any{
		"tenant_id": approverWiringTenant, "event_ref": "ticket-1", "event_source": "psa-a",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var run struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &run))
	require.NotEmpty(t, run.Data.RunID)
	f.runID = run.Data.RunID
	return f
}

func (f *approverWiringFixture) call(method, path string, body any) *httptest.ResponseRecorder {
	raw := ""
	if body != nil {
		b, _ := json.Marshal(body)
		raw = string(b)
	}
	return serveGrantRequest(f.srv, method, path, raw, map[string]string{"Authorization": "Bearer " + f.cred})
}

// publishScript stores a script version in the tenant's library.
func (f *approverWiringFixture) publishScript(t *testing.T, id string, minor int, content string) *script.VersionedScript {
	t.Helper()
	repo, err := f.repo.ForTenant(approverWiringTenant)
	require.NoError(t, err)
	vs := script.VersionedScript{Content: content, Metadata: &script.ScriptMetadata{
		ID: id, Name: id, Description: "d", Version: &script.Version{Major: 1, Minor: minor}, Author: "a",
		Platform: []string{"linux"}, Shell: script.ShellBash, Timeout: time.Minute,
	}}
	if minor == 0 {
		require.NoError(t, repo.Create(&vs))
	} else {
		require.NoError(t, repo.Update(&vs))
	}
	got, err := f.repo.GetForTenant(approverWiringTenant, id, vs.Metadata.Version.String())
	require.NoError(t, err)
	return got
}

func (f *approverWiringFixture) approveScript(t *testing.T, vs *script.VersionedScript) {
	t.Helper()
	require.NoError(t, f.store.PutApproval(context.Background(), api.ContentApproval{
		TenantID: approverWiringTenant, Kind: api.LibraryKindScript, ContentID: vs.Metadata.ID,
		Version: vs.Metadata.Version.String(), ContentHash: script.ScriptApprovalHash(approverWiringTenant, vs),
		ApprovedBy: "admin", Method: api.ApprovalMethodApproveTap,
	}))
}

// storeApprovedWorkflow stores a workflow version in the tenant's library and approves it.
func (f *approverWiringFixture) storeApprovedWorkflow(t *testing.T, name string, steps ...workflow.Step) {
	t.Helper()
	sv, err := workflow.ParseSemanticVersion("1.0.0")
	require.NoError(t, err)
	vw := &workflow.VersionedWorkflow{
		Workflow:                 workflow.Workflow{Name: name, Version: "1.0.0", Steps: steps},
		SemanticVersion:          *sv,
		PreapprovedForAutomation: true,
	}
	ws := workflow.NewWorkflowStore(f.srv.storageManager.GetConfigStore(), approverWiringTenant)
	require.NoError(t, ws.StoreWorkflow(context.Background(), vw))
	stored, err := ws.GetWorkflow(context.Background(), name, *sv)
	require.NoError(t, err)
	hash, err := workflow.CanonicalWorkflowHash(stored)
	require.NoError(t, err)
	require.NoError(t, f.store.PutApproval(context.Background(), api.ContentApproval{
		TenantID: approverWiringTenant, Kind: api.LibraryKindWorkflow, ContentID: name, Version: "1.0.0",
		ContentHash: api.WorkflowApprovalHash(approverWiringTenant, name, "1.0.0", hash),
		ApprovedBy:  "admin", Method: api.ApprovalMethodApproveTap,
	}))
}

func (f *approverWiringFixture) scriptStep(id, version string) workflow.Step {
	return workflow.Step{Name: "collect", Type: workflow.StepTypeScript, Config: map[string]interface{}{
		"script_id": id, "script_version": version, "devices": []interface{}{f.steward},
	}}
}

// startGrantRun starts the pinned workflow through the grant route and returns the
// execution id.
func (f *approverWiringFixture) startGrantRun(t *testing.T, name string) string {
	t.Helper()
	rec := f.call(http.MethodPost, approverRunsPath+"/"+f.runID+"/workflows/"+name, map[string]any{"version": "1.0.0"})
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp struct {
		Data struct {
			ExecutionID string `json:"execution_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.ExecutionID)
	return resp.Data.ExecutionID
}

func executionFinished(s workflow.ExecutionStatus) bool {
	return s == workflow.StatusCompleted || s == workflow.StatusFailed || s == workflow.StatusCancelled
}

// waitFinished waits for the execution to end and returns it.
func (f *approverWiringFixture) waitFinished(t *testing.T, id string) *workflow.WorkflowExecution {
	t.Helper()
	var ex *workflow.WorkflowExecution
	require.Eventually(t, func() bool {
		got, err := f.srv.workflowEngine.GetExecution(context.Background(), approverWiringTenant, id)
		if err != nil {
			return false
		}
		ex = got
		return executionFinished(got.Status)
	}, 20*time.Second, 25*time.Millisecond)
	return ex
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// [REQUIRED TEST] A grant-started run of a pinned, approved workflow queues a script step
// whose exact version is approved for the run tenant, through the approver controller
// startup installed (the test never calls SetApprover).
func TestServer_New_InstallsScriptApprover_ApprovedScriptReachesQueue(t *testing.T) {
	f := newApproverWiringFixture(t)
	vs := f.publishScript(t, approverWiringScript, 0, approverWiringBody)
	f.approveScript(t, vs)
	f.storeApprovedWorkflow(t, approverWiringWorkflow, f.scriptStep(approverWiringScript, "1.0.0"))

	execID := f.startGrantRun(t, approverWiringWorkflow)

	// The step waits for the (absent) steward's result, so the queued command is
	// listed until the test cancels it.
	var queued []*script.QueuedExecution
	require.Eventually(t, func() bool {
		queued = f.srv.executionQueue.PeekForDevice(f.steward)
		return len(queued) == 1
	}, 20*time.Second, 25*time.Millisecond, "the approved script step must reach the execution queue")

	meta := queued[0].Metadata
	assert.Equal(t, approverWiringTenant, meta[script.MetaPinOwnerTenant])
	assert.Equal(t, "1.0.0", meta[script.MetaPinVersion])
	assert.Equal(t, script.ScriptApprovalHash(approverWiringTenant, vs), meta[script.MetaPinApprovalHash])
	assert.Equal(t, f.runID, meta[script.MetaGuardRunID], "the queued command is bound to the run")

	// End the wait: cancelling the queued command fails the step and finishes the run.
	require.NoError(t, f.srv.executionQueue.CancelExecution(f.steward, queued[0].ExecutionID))
	ex := f.waitFinished(t, execID)
	assert.NotContains(t, ex.Error, "no script approver", "the approver must be installed")
}

// [REQUIRED TEST] The same path refuses a script version that was never approved and a
// version that changed after the earlier one was approved: nothing is queued and the
// run records the refusal reason.
func TestServer_New_InstallsScriptApprover_UnapprovedOrChangedScriptIsRefused(t *testing.T) {
	f := newApproverWiringFixture(t)
	approved := f.publishScript(t, approverWiringScript, 0, approverWiringBody)
	f.approveScript(t, approved)
	// A new version of the approved script is a change: its approval is pending.
	f.publishScript(t, approverWiringScript, 1, approverWiringBody+"echo changed\n")
	// A script nobody approved.
	f.publishScript(t, "never-approved", 0, approverWiringBody)

	for _, tc := range []struct{ name, id, version string }{
		{"changed after approval", approverWiringScript, "1.1.0"},
		{"never approved", "never-approved", "1.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wfName := "wf-" + randomHex(t)
			f.storeApprovedWorkflow(t, wfName, f.scriptStep(tc.id, tc.version))

			ex := f.waitFinished(t, f.startGrantRun(t, wfName))

			assert.Equal(t, workflow.StatusFailed, ex.Status)
			assert.Contains(t, ex.Error, "pending approval", "the run records the refusal reason")
			assert.Contains(t, ex.Error, "nothing was queued")
			assert.NotContains(t, ex.Error, "no script approver")
			assert.Empty(t, f.srv.executionQueue.PeekForDevice(f.steward), "nothing was queued")
			assert.Zero(t, f.srv.executionQueue.GetTotalQueueDepth())
		})
	}
}

// [REQUIRED TEST] A run that is not restricted behaves as it did before the approver was
// installed. A workflow without a script step runs; a script step outside a grant and
// without a verified Publication is refused by the engine before any approver is asked,
// and nothing is queued. (Producing a tap Publication needs a WebAuthn ceremony; that
// path is covered by the controller API publish tests and the engine publication tests.)
func TestServer_New_InstallsScriptApprover_UnrestrictedRunUnchanged(t *testing.T) {
	f := newApproverWiringFixture(t)
	vs := f.publishScript(t, approverWiringScript, 0, approverWiringBody)
	f.approveScript(t, vs)
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, approverWiringTenant)
	engine := f.srv.workflowEngine

	t.Run("workflow without a script step runs", func(t *testing.T) {
		wf := workflow.Workflow{Name: "plain", Version: "1.0.0", Steps: []workflow.Step{
			{Name: "wait", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: time.Millisecond}},
		}}
		exec, err := engine.ExecuteWorkflow(ctx, wf, nil)
		require.NoError(t, err)
		ex := f.waitFinished(t, exec.ID)
		assert.Equal(t, workflow.StatusCompleted, ex.Status, ex.Error)
	})

	t.Run("script step is refused although its script is approved", func(t *testing.T) {
		wf := workflow.Workflow{Name: "unpublished", Version: "1.0.0", Steps: []workflow.Step{f.scriptStep(approverWiringScript, "1.0.0")}}
		_, err := engine.ExecuteWorkflow(ctx, wf, nil)
		require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
		assert.Empty(t, f.srv.executionQueue.PeekForDevice(f.steward))
		assert.Zero(t, f.srv.executionQueue.GetTotalQueueDepth())
		assert.True(t, strings.Contains(err.Error(), "restricted"), err.Error())
	})
}
