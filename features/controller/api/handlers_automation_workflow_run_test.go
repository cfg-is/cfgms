// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/workflow"
	workflownodes "github.com/cfgis/cfgms/features/workflow/nodes"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	wfRunName   = "tidy-disk"
	wfRunScript = "inventory"
)

// afterApprovalReadStore is a real config store that runs a hook once, straight after
// the first approval record is read. The evaluator reads that record while it decides, so
// the hook is "an edit lands after evaluation began and before the engine starts".
type afterApprovalReadStore struct {
	cfgconfig.ConfigStore
	mu   sync.Mutex
	hook func()
}

func (s *afterApprovalReadStore) arm(hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hook = hook
}

func (s *afterApprovalReadStore) GetConfig(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	entry, err := s.ConfigStore.GetConfig(ctx, key)
	if key != nil && key.Namespace == contentApprovalNamespace {
		s.mu.Lock()
		hook := s.hook
		s.hook = nil
		s.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	return entry, err
}

// runGuardHookStore is a real config store that runs a one-shot hook around the first
// automation-grant read made under a run binding. The restricted run guard is the only
// reader that does: the auth middleware re-reads the grant before the binding is put in
// the context, so a hook armed ahead of the start request fires on the guard's first
// call, which is the one that admits step 1. The hook is cleared before it runs, so
// whatever it calls does not re-trigger it.
type runGuardHookStore struct {
	cfgconfig.ConfigStore
	mu     sync.Mutex
	before func()
	after  func()
}

// armBefore sets a hook that runs before the guard's first grant read reaches the store.
func (s *runGuardHookStore) armBefore(hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.before = hook
}

// armAfter sets a hook that runs once the guard's first grant read has returned from
// the store, so the guard has already seen a valid grant.
func (s *runGuardHookStore) armAfter(hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.after = hook
}

// take returns and clears the hook for a run-bound grant read, or nil for any other read.
func (s *runGuardHookStore) take(ctx context.Context, key *cfgconfig.ConfigKey, which func(*runGuardHookStore) *func()) func() {
	if key == nil || key.Namespace != automationGrantConfigNamespace || automationRunFromContext(ctx) == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := which(s)
	hook := *slot
	*slot = nil
	return hook
}

func (s *runGuardHookStore) GetConfig(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	if hook := s.take(ctx, key, func(s *runGuardHookStore) *func() { return &s.before }); hook != nil {
		hook()
	}
	entry, err := s.ConfigStore.GetConfig(ctx, key)
	if hook := s.take(ctx, key, func(s *runGuardHookStore) *func() { return &s.after }); hook != nil {
		hook()
	}
	return entry, err
}

// workflowRunFixture is a real server with a real workflow engine and store, approval
// store, script library, run queue and fleet. Workflows and scripts live in the MSP
// tenant (msp-a, the grant tenant); the run tenant is client-1.
type workflowRunFixture struct {
	*scriptRunFixture
	engine *workflow.Engine
	trip   *afterApprovalReadStore
	raw    cfgconfig.ConfigStore
	queue2 *script.ExecutionQueue
}

func newWorkflowRunFixture(t *testing.T) *workflowRunFixture {
	t.Helper()
	f := &workflowRunFixture{scriptRunFixture: newScriptRunFixture(t)}
	f.raw = f.cs
	f.trip = &afterApprovalReadStore{ConfigStore: f.raw}
	var err error
	f.approvals, err = NewContentApprovalStore(f.trip)
	require.NoError(t, err)
	f.srv.SetContentApprovalStore(f.approvals)

	monitor := script.NewExecutionMonitor()
	f.queue2 = script.NewExecutionQueue(monitor, nil, 0, "", nil, f.repo, 0)
	t.Cleanup(f.queue2.Stop)
	f.srv.SetRunManager(controllerrun.NewManager(f.runStore, f.queue2), f.queue2)

	executor := workflownodes.NewScriptStepExecutor(f.repo, monitor, nil)
	executor.SetExecutionQueue(f.queue2)
	executor.SetFleetQuery(f.srv.fleetQuery)
	executor.SetApprover(f.srv.AutomationScriptApprover())
	executor.SetResultWaitTimeout(300 * time.Millisecond)

	f.engine = workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logging.NewNoopLogger(), nil, nil, nil, nil, nil,
		workflow.WithScriptStepExecutor(executor))
	t.Cleanup(f.engine.Shutdown)
	f.srv.SetWorkflowHandler(NewWorkflowHandler(f.engine, f.trip, nil, logging.NewNoopLogger()))
	return f
}

// hookRunGuard rebuilds the grant store over a hooking wrapper of the same config store
// and secret store, so the grant and credential stay valid, and installs it. The run guard
// derives its run and grant reads from the server's grant store, so both go through the
// wrapper.
func (f *workflowRunFixture) hookRunGuard(t *testing.T) *runGuardHookStore {
	t.Helper()
	hooks := &runGuardHookStore{ConfigStore: f.store.configs}
	gs, err := NewAutomationGrantStore(hooks, f.store.secrets)
	require.NoError(t, err)
	f.srv.SetAutomationGrantStore(gs)
	return hooks
}

func delayStep(name string, d time.Duration) workflow.Step {
	return workflow.Step{Name: name, Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: d}}
}

func (f *workflowRunFixture) scriptStep(name, id, version string) workflow.Step {
	return workflow.Step{Name: name, Type: workflow.StepTypeScript, Config: map[string]interface{}{
		"script_id": id, "script_version": version, "devices": []interface{}{f.c1Steward},
	}}
}

func versionedWorkflow(t *testing.T, name, version string, inputs []workflow.InputSpec, steps ...workflow.Step) *workflow.VersionedWorkflow {
	t.Helper()
	sv, err := workflow.ParseSemanticVersion(version)
	require.NoError(t, err)
	return &workflow.VersionedWorkflow{
		Workflow:                 workflow.Workflow{Name: name, Version: version, Steps: steps, Inputs: inputs},
		SemanticVersion:          *sv,
		PreapprovedForAutomation: true,
	}
}

// putWorkflow writes the version into the tenant's workflow library and returns it as read
// back from the store, which is what the resolver loads.
func (f *workflowRunFixture) putWorkflow(t *testing.T, tenantID string, vw *workflow.VersionedWorkflow) *workflow.VersionedWorkflow {
	t.Helper()
	ws := workflow.NewWorkflowStore(f.raw, tenantID)
	require.NoError(t, ws.StoreWorkflow(context.Background(), vw))
	got, err := ws.GetWorkflow(context.Background(), vw.Name, vw.SemanticVersion)
	require.NoError(t, err)
	return got
}

func (f *workflowRunFixture) approveWorkflow(t *testing.T, owner string, vw *workflow.VersionedWorkflow) {
	t.Helper()
	hash, err := workflow.CanonicalWorkflowHash(vw)
	require.NoError(t, err)
	require.NoError(t, f.approvals.PutApproval(context.Background(), ContentApproval{
		TenantID: owner, Kind: LibraryKindWorkflow, ContentID: vw.Name, Version: vw.SemanticVersion.String(),
		ContentHash: WorkflowApprovalHash(owner, vw.Name, vw.SemanticVersion.String(), hash),
		ApprovedBy:  "admin", Method: ApprovalMethodApproveTap,
	}))
}

// stageApproved stores a workflow version in the MSP library, approves it under the MSP
// mode and returns it.
func (f *workflowRunFixture) stageApproved(t *testing.T, vw *workflow.VersionedWorkflow) *workflow.VersionedWorkflow {
	t.Helper()
	require.NoError(t, f.approvals.SetMode(context.Background(), runMSP, LibraryKindWorkflow, ApprovalModeApprove, "admin"))
	stored := f.putWorkflow(t, runMSP, vw)
	f.approveWorkflow(t, runMSP, stored)
	return stored
}

func (f *workflowRunFixture) workflowPath(runID, name string) string {
	return f.runPath(runID, "/workflows/"+name)
}

func (f *workflowRunFixture) start(runID, name string, body any) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, f.workflowPath(runID, name), f.cred, body)
}

func (f *workflowRunFixture) startOK(t *testing.T, runID, name, version string, inputs map[string]any) AutomationWorkflowRunResponse {
	t.Helper()
	body := map[string]any{"version": version}
	if inputs != nil {
		body["inputs"] = inputs
	}
	rec := f.start(runID, name, body)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	return dataOf[AutomationWorkflowRunResponse](t, rec)
}

// executionsOfRunTenant returns every execution the engine holds for client-1.
func (f *workflowRunFixture) executionsOfRunTenant(t *testing.T) []*workflow.WorkflowExecution {
	t.Helper()
	all, err := f.engine.ListExecutions(context.Background(), runClient1)
	require.NoError(t, err)
	return all
}

func (f *workflowRunFixture) waitStatus(t *testing.T, id string, done func(workflow.ExecutionStatus) bool) *workflow.WorkflowExecution {
	t.Helper()
	var got *workflow.WorkflowExecution
	require.Eventually(t, func() bool {
		ex, err := f.engine.GetExecution(context.Background(), runClient1, id)
		if err != nil {
			return false
		}
		got = ex
		return done(ex.Status)
	}, 20*time.Second, 25*time.Millisecond)
	return got
}

// ranSteps lists the names of the steps the execution completed, in order.
func ranSteps(ex *workflow.WorkflowExecution) []string {
	var names []string
	for _, st := range ex.ExecutionTrace {
		if st.Status == workflow.StatusCompleted {
			names = append(names, st.StepName)
		}
	}
	return names
}

func finished(s workflow.ExecutionStatus) bool {
	return s == workflow.StatusCompleted || s == workflow.StatusFailed || s == workflow.StatusCancelled
}

func (f *workflowRunFixture) workflowAudit(t *testing.T) []*business.AuditEntry {
	return f.auditEntries(t, runClient1, automationActionWorkflowRun)
}

// [REQUIRED TEST] An approved pinned version (inherited from the MSP library) runs in
// restricted mode under the run tenant, and its execution is readable by the run, by id
// and in the run's list. The audit event names the grant, run, owner tenant, workflow,
// version and approval hash.
func TestAutomationWorkflowRun_ApprovedPinnedVersionRunsAndIsReadable(t *testing.T) {
	f := newWorkflowRunFixture(t)
	stored := f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("only-step", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	resp := f.startOK(t, runID, wfRunName, "1.0.0", nil)
	hash, err := workflow.CanonicalWorkflowHash(stored)
	require.NoError(t, err)
	assert.Equal(t, runMSP, resp.OwnerTenant)
	assert.Equal(t, runClient1, resp.TenantID)
	assert.Equal(t, "1.0.0", resp.Version)
	assert.Equal(t, WorkflowApprovalHash(runMSP, wfRunName, "1.0.0", hash), resp.ApprovalHash)
	require.NotEmpty(t, resp.ExecutionID)

	ex := f.waitStatus(t, resp.ExecutionID, finished)
	assert.Equal(t, workflow.StatusCompleted, ex.Status)
	assert.Equal(t, runClient1, ex.TenantID, "the execution belongs to the run tenant, not the owner tenant")

	got := f.get(f.runPath(runID, "/executions/"+resp.ExecutionID), f.cred)
	require.Equal(t, http.StatusOK, got.Code, got.Body.String())
	read := dataOf[map[string]any](t, got)
	assert.Equal(t, resp.ExecutionID, read["id"])
	assert.Equal(t, "completed", read["status"])
	assert.NotEmpty(t, read["step_results"], "the output of the execution is readable")
	assert.Contains(t, got.Body.String(), "only-step", "the trace names the step that ran")

	list := f.get(f.runPath(runID, "/executions"), f.cred)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	listed := dataOf[[]map[string]any](t, list)
	require.Len(t, listed, 1)
	assert.Equal(t, resp.ExecutionID, listed[0]["id"])

	events := f.workflowAudit(t)
	require.Len(t, events, 1)
	d := events[0].Details
	assert.Equal(t, business.AuditResultSuccess, events[0].Result)
	assert.Equal(t, f.grant.ID, d["grant_id"])
	assert.Equal(t, runID, d["run_id"])
	assert.Equal(t, "ticket-1", d["event_ref"])
	assert.Equal(t, runMSP, d["owner_tenant_id"], "the grant tenant")
	assert.Equal(t, runMSP, d["workflow_owner_tenant"])
	assert.Equal(t, wfRunName, d["workflow_name"])
	assert.Equal(t, "1.0.0", d["workflow_version"])
	assert.Equal(t, resp.ApprovalHash, d["approval_hash"])
	assert.Equal(t, resp.ExecutionID, d["execution_id"])
}

// [REQUIRED TEST] Omitting the version is a 400 and "latest" is not a version, so a
// grant has no way to run the latest; nothing starts. Each refusal is audited.
func TestAutomationWorkflowRun_VersionIsRequiredAndNeverLatest(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("s", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	for name, body := range map[string]any{
		"omitted":   map[string]any{},
		"empty":     map[string]any{"version": ""},
		"no body":   nil,
		"latest":    map[string]any{"version": "latest"},
		"range":     map[string]any{"version": "^1.0.0"},
		"traversal": map[string]any{"version": "../1.0.0"},
	} {
		rec := f.start(runID, wfRunName, body)
		require.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
		assert.Contains(t, []string{"MISSING_VERSION", "INVALID_VERSION", "INVALID_REQUEST"}, codeOf(t, rec), name)
	}
	assert.Equal(t, "MISSING_VERSION", codeOf(t, f.start(runID, wfRunName, map[string]any{})))
	assert.Equal(t, "INVALID_VERSION", codeOf(t, f.start(runID, wfRunName, map[string]any{"version": "latest"})))
	assert.Empty(t, f.executionsOfRunTenant(t), "nothing may start")
	for _, e := range f.workflowAudit(t) {
		assert.Equal(t, business.AuditResultDenied, e.Result)
	}
	assert.NotEmpty(t, f.workflowAudit(t))
}

// [REQUIRED TEST] An edited, unpublished version is refused: the approval was for the
// earlier content, a new version has none, and an older approved version is never used
// in its place. The pending change is not run and nothing starts.
func TestAutomationWorkflowRun_EditedUnpublishedVersionIsRefused(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("approved-step", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	// The same version is edited in place: its content no longer matches the approval.
	f.putWorkflow(t, runMSP, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("edited-step", time.Millisecond)))
	rec := f.start(runID, wfRunName, map[string]any{"version": "1.0.0"})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "APPROVAL_PENDING", codeOf(t, rec))

	// A new version has no approval, while 1.0.0 remains approved for its old content.
	f.putWorkflow(t, runMSP, versionedWorkflow(t, wfRunName, "1.1.0", nil, delayStep("new-step", time.Millisecond)))
	rec = f.start(runID, wfRunName, map[string]any{"version": "1.1.0"})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "APPROVAL_PENDING", codeOf(t, rec))

	assert.Empty(t, f.executionsOfRunTenant(t), "nothing may start")
	denied := f.workflowAudit(t)
	require.Len(t, denied, 2)
	for _, e := range denied {
		assert.Equal(t, business.AuditResultDenied, e.Result)
		assert.Equal(t, "approval_pending", e.Details["reason"])
		assert.NotEmpty(t, e.Details["approval_hash"])
	}

	// An unopted version is denied, not pending, in every mode.
	noOptIn := versionedWorkflow(t, "no-opt-in", "1.0.0", nil, delayStep("s", time.Millisecond))
	noOptIn.PreapprovedForAutomation = false
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, noOptIn))
	rec = f.start(runID, "no-opt-in", map[string]any{"version": "1.0.0"})
	assert.Contains(t, []int{http.StatusConflict, http.StatusForbidden}, rec.Code, rec.Body.String())
	assert.Empty(t, f.executionsOfRunTenant(t))
}

// [REQUIRED TEST] A workflow held by a tenant outside the run tenant's chain is not
// found, and a grant whose own tenant is the run tenant cannot see an ancestor's
// workflow: the ceiling decides, never the request.
func TestAutomationWorkflowRun_WorkflowOfAnotherTenantIsNotFound(t *testing.T) {
	f := newWorkflowRunFixture(t)
	require.NoError(t, f.approvals.SetMode(context.Background(), runMSP, LibraryKindWorkflow, ApprovalModeApprove, "admin"))
	for _, owner := range []string{runOther, runClient2, runSiteA} {
		require.NoError(t, f.approvals.SetMode(context.Background(), owner, LibraryKindWorkflow, ApprovalModeApprove, "admin"))
		f.approveWorkflow(t, owner, f.putWorkflow(t, owner, versionedWorkflow(t, "theirs", "1.0.0", nil, delayStep("s", time.Millisecond))))
	}
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.start(runID, "theirs", map[string]any{"version": "1.0.0"})
	assert.Equal(t, http.StatusNotFound, rec.Code, "a sibling, a cousin and a descendant tenant: %s", rec.Body.String())
	assert.Equal(t, "WORKFLOW_NOT_FOUND", codeOf(t, rec))

	// A client-level grant has the run tenant as its ceiling: the MSP workflow is out of reach.
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, versionedWorkflow(t, "msp-owned", "1.0.0", nil, delayStep("s", time.Millisecond))))
	_, clientCred := f.newGrant(t, runClient1)
	clientRun := f.beginOK(t, clientCred, runClient1, "ticket-2")
	rec = f.do(http.MethodPost, f.workflowPath(clientRun, "msp-owned"), clientCred, map[string]any{"version": "1.0.0"})
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	rec = f.start(runID, "msp-owned", map[string]any{"version": "1.0.0"})
	assert.Equal(t, http.StatusAccepted, rec.Code, "the MSP-level grant reaches its own library: %s", rec.Body.String())

	for _, name := range []string{"a%2Fb", "a%5Cb", "a..b"} {
		rec = f.start(runID, name, map[string]any{"version": "1.0.0"})
		assert.GreaterOrEqual(t, rec.Code, 400, name)
		assert.Less(t, rec.Code, 500, name)
	}
}

// [REQUIRED TEST] The ceiling is read from the grant record, never from the request, and
// a request cannot raise it: a field, a query parameter and a header naming a higher
// tenant change nothing, and the approver resolves scripts under the ceiling it is handed.
func TestAutomationWorkflowRun_RequestCannotRaiseTheCeiling(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, versionedWorkflow(t, "msp-owned", "1.0.0", nil, delayStep("s", time.Millisecond))))
	require.NoError(t, f.approvals.SetMode(context.Background(), runMSP, LibraryKindWorkflow, ApprovalModeApprove, "admin"))
	_, clientCred := f.newGrant(t, runClient1)
	clientRun := f.beginOK(t, clientCred, runClient1, "ticket-1")
	path := f.workflowPath(clientRun, "msp-owned")

	rec := f.do(http.MethodPost, path, clientCred, map[string]any{"version": "1.0.0", "ceiling": runMSP})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "ceiling is not a request field: %s", rec.Body.String())
	rec = f.do(http.MethodPost, path, clientCred, map[string]any{"version": "1.0.0", "inputs": map[string]any{"ceiling": runMSP}})
	assert.Equal(t, http.StatusNotFound, rec.Code, "an input cannot move the ceiling either: %s", rec.Body.String())

	for _, variant := range []string{"?ceiling=" + runMSP, "?grant_tenant_id=" + runMSP, "?tenant_id=" + runMSP, "?tenant=" + runMSP} {
		rec = f.do(http.MethodPost, path+variant, clientCred, map[string]any{"version": "1.0.0"})
		assert.Contains(t, []int{http.StatusNotFound, http.StatusForbidden}, rec.Code, "%s: %s", variant, rec.Body.String())
	}
	assert.Empty(t, f.executionsOfRunTenant(t))

	// The script approver judges under the ceiling it is handed: the same MSP script is
	// invisible below it and reachable at it.
	f.setMode(t, runMSP, ApprovalModeApprove)
	vs := f.publish(t, runMSP, wfRunScript, requestedBody, nil)
	f.approve(t, runMSP, vs)
	approver := f.srv.AutomationScriptApprover()

	d, err := approver.Approve(context.Background(), runClient1, runClient1, wfRunScript, "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, workflow.ScriptApprovalDenied, d.State, "a client-level ceiling cannot reach the MSP library")
	d, err = approver.Approve(context.Background(), runClient1, runMSP, wfRunScript, "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, workflow.ScriptApprovalApproved, d.State)
	assert.Equal(t, runMSP, d.OwnerTenant)
	assert.Equal(t, script.ScriptApprovalHash(runMSP, vs), d.ApprovalHash)

	// An approver call that does not name a pinned script is denied, never resolved to latest.
	d, err = approver.Approve(context.Background(), runClient1, runMSP, wfRunScript, "")
	require.NoError(t, err)
	assert.Equal(t, workflow.ScriptApprovalDenied, d.State)
}

// [REQUIRED TEST] Executions started by another run are not readable, by id or in the
// list, and an unknown id answers the same 404.
func TestAutomationWorkflowRun_ExecutionsOfAnotherRunAreNotReadable(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("s", time.Millisecond)))
	runA := f.beginOK(t, f.cred, runClient1, "ticket-a")
	runB := f.beginOK(t, f.cred, runClient1, "ticket-b")
	_, otherCred := f.newGrant(t, runMSP)
	runOtherGrant := f.beginOK(t, otherCred, runClient1, "ticket-c")

	a := f.startOK(t, runA, wfRunName, "1.0.0", nil)
	f.waitStatus(t, a.ExecutionID, finished)

	own := f.get(f.runPath(runA, "/executions/"+a.ExecutionID), f.cred)
	require.Equal(t, http.StatusOK, own.Code, own.Body.String())

	for name, c := range map[string]struct{ run, cred string }{
		"another run of the grant": {runB, f.cred},
		"another grant":            {runOtherGrant, otherCred},
	} {
		rec := f.get(f.runPath(c.run, "/executions/"+a.ExecutionID), c.cred)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s: %s", name, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), wfRunName, name)
		list := f.get(f.runPath(c.run, "/executions"), c.cred)
		require.Equal(t, http.StatusOK, list.Code, name)
		assert.Empty(t, dataOf[[]map[string]any](t, list), name)
	}
	rec := f.get(f.runPath(runA, "/executions/no-such-execution"), f.cred)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// An execution of the run tenant that no run started is not readable either.
	human, err := f.engine.ExecuteWorkflow(runTenantCtx(runClient1), versionedWorkflow(t, "human", "1.0.0", nil, delayStep("s", time.Millisecond)).Workflow, nil)
	require.NoError(t, err)
	rec = f.get(f.runPath(runA, "/executions/"+human.ID), f.cred)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	list := f.get(f.runPath(runA, "/executions"), f.cred)
	assert.Len(t, dataOf[[]map[string]any](t, list), 1, "only the execution this run started")
}

func runTenantCtx(tenantID string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
}

// [REQUIRED TEST] Inputs are validated against the declared schema and size-capped, and
// an undeclared input is refused; a refusal names the field and never the value.
func TestAutomationWorkflowRun_InputsAreValidatedAndBounded(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", []workflow.InputSpec{
		{Name: "mode", Type: workflow.InputTypeEnum, Options: []string{"fast", "slow"}, Required: true},
		{Name: "note", Type: workflow.InputTypeString},
		{Name: "force", Type: workflow.InputTypeBool},
	}, delayStep("s", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	secretValue := "value-that-must-not-be-echoed-9d41"

	refused := map[string]struct {
		inputs map[string]any
		code   string
	}{
		"undeclared":    {map[string]any{"mode": "fast", "extra": secretValue}, "INPUT_REFUSED"},
		"bad enum":      {map[string]any{"mode": secretValue}, "INVALID_INPUTS"},
		"missing":       {map[string]any{"note": "x"}, "INVALID_INPUTS"},
		"wrong type":    {map[string]any{"mode": "fast", "force": secretValue}, "INVALID_INPUTS"},
		"oversized":     {map[string]any{"mode": "fast", "note": strings.Repeat("a", automationWorkflowInputMaxLen+1)}, "INPUT_REFUSED"},
		"reserved name": {map[string]any{"mode": "fast", "tenant_id": "msp-a"}, "INPUT_REFUSED"},
	}
	for name, c := range refused {
		rec := f.start(runID, wfRunName, map[string]any{"version": "1.0.0", "inputs": c.inputs})
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
		assert.Equal(t, c.code, codeOf(t, rec), name)
		assert.NotContains(t, rec.Body.String(), secretValue, name)
	}
	tooMany := map[string]any{}
	for i := 0; i <= automationWorkflowMaxInputs; i++ {
		tooMany["k"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)] = "v"
	}
	rec := f.start(runID, wfRunName, map[string]any{"version": "1.0.0", "inputs": tooMany})
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = f.do(http.MethodPost, f.workflowPath(runID, wfRunName), f.cred, map[string]any{
		"version": "1.0.0", "inputs": map[string]any{"mode": "fast", "note": strings.Repeat("a", automationWorkflowBodyMaxBytes)}})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a body over the cap is refused: %s", rec.Body.String())
	assert.Empty(t, f.executionsOfRunTenant(t), "no refused request starts anything")

	f.startOK(t, runID, wfRunName, "1.0.0", map[string]any{"mode": "slow", "note": "ok", "force": true})
	require.Len(t, f.executionsOfRunTenant(t), 1)
}

// automationStops are the two ways a run is stopped from outside the workflow.
var automationStops = map[string]func(t *testing.T, f *workflowRunFixture, runID string){
	"grant revoked": func(t *testing.T, f *workflowRunFixture, _ string) {
		_, err := f.store.Revoke(context.Background(), runMSP, f.grant.ID, "admin")
		require.NoError(t, err)
	},
	"run ended": func(t *testing.T, f *workflowRunFixture, runID string) {
		rec := f.do(http.MethodPost, "/api/v1/automation/runs/"+runID+"/end", f.cred, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	},
}

// [REQUIRED TEST] Revoking the grant, or ending the run, mid-execution stops the
// workflow at the next step. The stop is issued from a hook that runs straight after the
// run guard's step-1 grant read returned a valid grant, so step 1 is admitted and the
// guard call for step 2 is the first to see the stop, with no dependence on timing.
func TestAutomationWorkflowRun_RevocationOrEndStopsAtTheNextStep(t *testing.T) {
	for name, stop := range automationStops {
		t.Run(name, func(t *testing.T) {
			f := newWorkflowRunFixture(t)
			f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil,
				delayStep("slow-step", time.Millisecond), delayStep("after-stop", time.Millisecond)))
			runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
			hooks := f.hookRunGuard(t)

			stopped := false
			hooks.armAfter(func() {
				stopped = true
				stop(t, f, runID)
			})
			resp := f.startOK(t, runID, wfRunName, "1.0.0", nil)

			ex := f.waitStatus(t, resp.ExecutionID, finished)
			assert.True(t, stopped, "the stop was issued after step 1's guard read")
			assert.Equal(t, workflow.StatusCancelled, ex.Status)
			assert.Contains(t, ex.Error, "run guard")
			assert.Equal(t, []string{"slow-step"}, ranSteps(ex), "the step after the stop never ran")
		})
	}
}

// [REQUIRED TEST] The run guard is consulted before the first step too: a revocation that
// lands before step 1's guard grant read runs no step at all. The hook fires before that
// read, after the guard's run read, so it can only reach the guard through the grant; an
// end would be seen by the guard's next call, not this one.
func TestAutomationWorkflowRun_StopBeforeFirstStep(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil,
		delayStep("slow-step", time.Millisecond), delayStep("after-stop", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	hooks := f.hookRunGuard(t)

	stopped := false
	hooks.armBefore(func() {
		stopped = true
		automationStops["grant revoked"](t, f, runID)
	})
	resp := f.startOK(t, runID, wfRunName, "1.0.0", nil)

	ex := f.waitStatus(t, resp.ExecutionID, finished)
	assert.True(t, stopped, "the revocation was issued before step 1's guard grant read")
	assert.Equal(t, workflow.StatusCancelled, ex.Status)
	assert.Contains(t, ex.Error, "run guard")
	assert.Empty(t, ranSteps(ex), "no step ran")
}

// [REQUIRED TEST] An edit that lands between evaluation and engine start cannot run the
// edited version: the object that was evaluated is the object that runs.
func TestAutomationWorkflowRun_EditAfterEvaluationCannotRun(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("original-step", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	var edited bool
	f.trip.arm(func() {
		edited = true
		f.putWorkflow(t, runMSP, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("edited-step", time.Millisecond)))
	})
	resp := f.startOK(t, runID, wfRunName, "1.0.0", nil)
	require.True(t, edited, "the edit landed after the approval was read")

	ex := f.waitStatus(t, resp.ExecutionID, finished)
	assert.Equal(t, workflow.StatusCompleted, ex.Status)
	assert.Equal(t, []string{"original-step"}, ranSteps(ex), "the evaluated content ran and the edited content did not")

	// The edit itself is then judged on its own: it is not approved.
	rec := f.start(runID, wfRunName, map[string]any{"version": "1.0.0"})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
}

// [REQUIRED TEST] A grant-started execution is always restricted: a body that asks
// otherwise is refused, a workflow that needs unrestricted steps does not start, and the
// only engine entry point the route uses is the restricted one.
func TestAutomationWorkflowRun_ExecutionIsAlwaysRestricted(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("s", time.Millisecond)))
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, versionedWorkflow(t, "writes", "1.0.0", nil,
		workflow.Step{Name: "write", Type: workflow.StepTypeTask, Module: "file"})))
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, versionedWorkflow(t, "reaches-out", "1.0.0", nil,
		workflow.Step{Name: "call", Type: workflow.StepTypeHTTP})))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	for _, extra := range []string{"restricted", "unrestricted", "mode", "variables", "grant_id", "run_id", "tenant_id"} {
		rec := f.start(runID, wfRunName, map[string]any{"version": "1.0.0", extra: false})
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, rec.Code, "%s: %s", extra, rec.Body.String())
	}
	assert.Empty(t, f.executionsOfRunTenant(t))

	for _, name := range []string{"writes", "reaches-out"} {
		rec := f.start(runID, name, map[string]any{"version": "1.0.0"})
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "%s: %s", name, rec.Body.String())
		assert.Equal(t, "WORKFLOW_NOT_RESTRICTED_SAFE", codeOf(t, rec), name)
	}
	for _, ex := range f.executionsOfRunTenant(t) {
		assert.Equal(t, workflow.StatusFailed, ex.Status, "a refused workflow only leaves a failed record: %s", ex.WorkflowName)
	}
	refused := f.workflowAudit(t)
	require.NotEmpty(t, refused)

	// A script step is possible only in a restricted execution; the unrestricted engine
	// path refuses it, so reaching one through this route proves the restricted entry.
	f.setMode(t, runMSP, ApprovalModeApprove)
	f.approve(t, runMSP, f.publish(t, runMSP, wfRunScript, requestedBody, nil))
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, versionedWorkflow(t, "with-script", "1.0.0", nil, f.scriptStep("collect", wfRunScript, "1.0.0"))))
	_, err := f.engine.ExecuteWorkflow(runTenantCtx(runClient1), versionedWorkflow(t, "with-script", "1.0.0", nil, f.scriptStep("collect", wfRunScript, "1.0.0")).Workflow, nil)
	require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
	resp := f.startOK(t, runID, "with-script", "1.0.0", nil)
	require.Eventually(t, func() bool { return len(f.queue2.PeekForDevice(f.c1Steward)) == 1 }, 10*time.Second, 20*time.Millisecond)
	assert.NotEmpty(t, resp.ExecutionID)
}

// [REQUIRED TEST] Approving a workflow does not approve its scripts: a script step that
// resolves to an MSP-owned script runs only if that script is itself approved under the
// MSP owner's mode. An unapproved script queues nothing and is recorded as pending for
// the owner; once approved, the step queues the pinned version.
func TestAutomationWorkflowRun_ScriptStepNeedsItsOwnApproval(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	vs := f.publish(t, runMSP, wfRunScript, requestedBody, nil)
	f.approveWorkflow(t, runMSP, f.putWorkflow(t, runMSP, versionedWorkflow(t, wfRunName, "1.0.0", nil, f.scriptStep("collect", wfRunScript, "1.0.0"))))
	require.NoError(t, f.approvals.SetMode(context.Background(), runMSP, LibraryKindWorkflow, ApprovalModeApprove, "admin"))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	first := f.startOK(t, runID, wfRunName, "1.0.0", nil)
	ex := f.waitStatus(t, first.ExecutionID, finished)
	assert.Equal(t, workflow.StatusFailed, ex.Status, "the workflow is approved, the script is not")
	assert.Contains(t, ex.Error, "pending approval")
	assert.Zero(t, f.queue2.GetTotalQueueDepth(), "nothing was queued")

	f.approve(t, runMSP, vs)
	second := f.startOK(t, runID, wfRunName, "1.0.0", nil)
	require.Eventually(t, func() bool { return len(f.queue2.PeekForDevice(f.c1Steward)) == 1 }, 10*time.Second, 20*time.Millisecond)
	queued := f.queue2.PeekForDevice(f.c1Steward)[0]
	assert.Equal(t, runMSP, queued.Metadata[script.MetaPinOwnerTenant])
	assert.Equal(t, "1.0.0", queued.Metadata[script.MetaPinVersion])
	assert.Equal(t, script.ScriptApprovalHash(runMSP, vs), queued.Metadata[script.MetaPinApprovalHash])
	assert.Equal(t, runID, queued.Metadata[script.MetaGuardRunID], "the queued command dies with the run")
	f.waitStatus(t, second.ExecutionID, finished)
}

// The routes are admitted by method and template and nothing else is: the human execute
// and read routes stay closed to a grant principal, and an unwired engine answers 503.
func TestAutomationWorkflowRun_RoutesAreAdmittedAndGuarded(t *testing.T) {
	f := newWorkflowRunFixture(t)
	f.stageApproved(t, versionedWorkflow(t, wfRunName, "1.0.0", nil, delayStep("s", time.Millisecond)))
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	assert.True(t, automationRouteAllowed(http.MethodPost, automationWorkflowRunTemplate))
	assert.True(t, automationRouteAllowed(http.MethodGet, automationExecutionsTemplate))
	assert.True(t, automationRouteAllowed(http.MethodGet, automationExecutionGetTemplate))
	assert.False(t, automationRouteAllowed(http.MethodGet, automationWorkflowRunTemplate))
	assert.False(t, automationRouteAllowed(http.MethodDelete, automationExecutionGetTemplate))

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/workflows/" + wfRunName + "/execute"},
		{http.MethodGet, "/api/v1/workflows/" + wfRunName + "/executions"},
		{http.MethodPost, "/api/v1/workflows/" + wfRunName + "/executions/x/cancel"},
	} {
		rec := f.do(c.method, c.path, f.cred, map[string]any{"version": "1.0.0"})
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
		assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec), "%s %s", c.method, c.path)
	}
	assert.Empty(t, f.executionsOfRunTenant(t))

	f.srv.SetWorkflowHandler(nil)
	rec := f.start(runID, wfRunName, map[string]any{"version": "1.0.0"})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusServiceUnavailable, f.get(f.runPath(runID, "/executions"), f.cred).Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.get(f.runPath(runID, "/executions/x"), f.cred).Code)
}
