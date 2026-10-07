// SPDX-License-Identifier: AGPL-3.0-only
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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const (
	approvalTenant  = "tenant-a"
	approvalStarter = "starter-user"
	approvalDecider = "decider-user"
)

// approvalFixture is a real engine over a real approval store and encrypted secret
// store, behind a real WorkflowHandler.
type approvalFixture struct {
	t       *testing.T
	handler *WorkflowHandler
	engine  *workflow.Engine
	store   business.ApprovalStore
	audit   *audit.Manager
	router  *mux.Router
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	store := sm.GetApprovalStore()
	require.NotNil(t, store)
	secrets, err := (&steward.StewardProvider{}).CreateSecretStore(map[string]interface{}{"secrets_dir": t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = secrets.Close() })

	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logger, secrets, nil, nil, nil, nil,
		workflow.WithApprovalStore(store))
	t.Cleanup(engine.Shutdown)

	auditMgr, err := audit.NewManager(sm.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	h := NewWorkflowHandler(engine, sm.GetConfigStore(), nil, logger)
	h.SetAuditManager(auditMgr)
	h.SetPermissionCheck(func(r *http.Request, perm string) bool {
		p, _ := r.Context().Value(principalContextKey).(*Principal)
		return (&Server{}).hasPermission(p, perm)
	})
	return &approvalFixture{t: t, handler: h, engine: engine, store: store, audit: auditMgr, router: newWorkflowRouter(h)}
}

// status reports the current status of execution id. Resume rebuilds the execution
// under the same ID, so the pointer from the original run goes stale.
func (f *approvalFixture) status(id string) workflow.ExecutionStatus {
	e, err := f.engine.GetExecution(id)
	if err != nil || e == nil {
		return ""
	}
	return e.GetStatus()
}

// startGatedRun starts a run as approvalStarter in approvalTenant and waits for it
// to suspend at its approval gate.
func (f *approvalFixture) startGatedRun(approverPermission string) (*workflow.WorkflowExecution, *business.WorkflowApproval) {
	f.t.Helper()
	wf := workflow.Workflow{
		Name: "gated",
		Steps: []workflow.Step{
			{Name: "gate", Type: workflow.StepTypeApproval, Approval: &workflow.ApprovalConfig{
				Message: "ship it?", ApproverPermission: approverPermission, Timeout: time.Hour,
			}},
			{Name: "after", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: time.Millisecond}},
		},
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, approvalTenant)
	ctx = context.WithValue(ctx, ctxkeys.UserIDKey, approvalStarter)
	exec, err := f.engine.ExecuteWorkflow(ctx, wf, nil)
	require.NoError(f.t, err)
	require.Eventually(f.t, func() bool { return exec.GetStatus() == workflow.StatusAwaitingApproval },
		5*time.Second, 10*time.Millisecond, "run must suspend at the gate; error: %s", exec.GetError())
	pending, err := f.store.ListPending(context.Background(), approvalTenant)
	require.NoError(f.t, err)
	for _, p := range pending {
		if p.ExecutionID == exec.ID {
			return exec, p
		}
	}
	f.t.Fatalf("no pending approval for execution %s", exec.ID)
	return nil, nil
}

func (f *approvalFixture) decide(tenant, userID, approvalID, decision string, perms ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	body, err := json.Marshal(ApprovalDecisionRequest{Decision: decision, Justification: "because"})
	require.NoError(f.t, err)
	req := httptest.NewRequest(http.MethodPost, "/workflows/approvals/"+approvalID+"/decision", bytes.NewReader(body))
	req = withTenantContext(req, tenant)
	ctx := context.WithValue(req.Context(), ctxkeys.UserIDKey, userID)
	ctx = context.WithValue(ctx, principalContextKey, &Principal{ID: userID, Permissions: perms, Assurance: session.AssuranceStrong})
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

func TestWorkflowApproval_ApproveResumesRun(t *testing.T) {
	f := newApprovalFixture(t)
	exec, rec := f.startGatedRun("workflow:approve")

	resp := f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "approve", "workflow:approve")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	require.Eventually(t, func() bool { return f.status(exec.ID) == workflow.StatusCompleted },
		10*time.Second, 10*time.Millisecond, "approved run must complete")

	got, err := f.store.GetApproval(context.Background(), approvalTenant, rec.ApprovalID)
	require.NoError(t, err)
	assert.Equal(t, business.ApprovalStatusApproved, got.Status)
	assert.Equal(t, approvalDecider, got.DecidedBy)
	assert.Equal(t, "because", got.Justification)
}

func TestWorkflowApproval_RejectFailsRun(t *testing.T) {
	f := newApprovalFixture(t)
	exec, rec := f.startGatedRun("workflow:approve")

	resp := f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "reject", "workflow:approve")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	require.Eventually(t, func() bool { return f.status(exec.ID) == workflow.StatusFailed },
		10*time.Second, 10*time.Millisecond, "rejected run must fail")
}

func TestWorkflowApproval_ListPendingScopedToTenant(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("")

	list := func(tenant string) []approvalView {
		req := withTenantContext(httptest.NewRequest(http.MethodGet, "/workflows/approvals", nil), tenant)
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var body struct {
			Approvals []approvalView `json:"approvals"`
		}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		return body.Approvals
	}
	own := list(approvalTenant)
	require.Len(t, own, 1)
	assert.Equal(t, rec.ApprovalID, own[0].ApprovalID)
	assert.Equal(t, approvalStarter, own[0].RequestedBy)
	assert.Empty(t, list("tenant-b"), "another tenant must not see the approval")
}

func TestWorkflowApproval_ForeignTenantGets404AndCannotDecide(t *testing.T) {
	f := newApprovalFixture(t)
	exec, rec := f.startGatedRun("")

	resp := f.decide("tenant-b", approvalDecider, rec.ApprovalID, "approve", "workflow:approve")
	assert.Equal(t, http.StatusNotFound, resp.Code)

	got, err := f.store.GetApproval(context.Background(), approvalTenant, rec.ApprovalID)
	require.NoError(t, err)
	assert.Equal(t, business.ApprovalStatusPending, got.Status, "foreign decision must not land")
	assert.Equal(t, workflow.StatusAwaitingApproval, exec.GetStatus())
}

func TestWorkflowApproval_SecondDecisionIs409(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("")

	require.Equal(t, http.StatusOK, f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "approve").Code)
	resp := f.decide(approvalTenant, "other-decider", rec.ApprovalID, "reject")
	assert.Equal(t, http.StatusConflict, resp.Code)
}

func TestWorkflowApproval_InitiatorCannotApproveOwnRun(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("")

	resp := f.decide(approvalTenant, approvalStarter, rec.ApprovalID, "approve")
	require.Equal(t, http.StatusForbidden, resp.Code)
	assert.Contains(t, resp.Body.String(), "SELF_APPROVAL")

	got, err := f.store.GetApproval(context.Background(), approvalTenant, rec.ApprovalID)
	require.NoError(t, err)
	assert.Equal(t, business.ApprovalStatusPending, got.Status)
}

func TestWorkflowApproval_ApproverPermissionEnforced(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("deploy:approve")

	resp := f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "approve", "workflow:approve")
	assert.Equal(t, http.StatusForbidden, resp.Code, "workflow:approve alone does not satisfy the gate's approver_permission")

	resp = f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "approve", "workflow:approve", "deploy:approve")
	assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
}

func TestWorkflowApproval_InvalidDecisionIs400(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("")
	resp := f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "maybe")
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestWorkflowApproval_DecisionIsAudited(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("")
	require.Equal(t, http.StatusOK, f.decide(approvalTenant, approvalDecider, rec.ApprovalID, "reject").Code)
	require.NoError(t, f.audit.Flush(context.Background()))

	entries, err := f.audit.QueryEntries(context.Background(), &business.AuditFilter{TenantID: approvalTenant})
	require.NoError(t, err)
	var found *business.AuditEntry
	for _, e := range entries {
		if e.Action == "workflow.approval_decided" {
			found = e
		}
	}
	require.NotNil(t, found, "decision must write an audit event")
	assert.Equal(t, approvalDecider, found.UserID)
	assert.Equal(t, rec.ApprovalID, found.ResourceID)
	assert.Equal(t, "reject", found.Details["decision"])
	assert.Equal(t, "because", found.Details["justification"])
	assert.Equal(t, rec.ApprovalID, found.Details["approval_id"])
}

func TestWorkflowApproval_RouteRequiresStrongAssurance(t *testing.T) {
	f := newApprovalFixture(t)
	_, rec := f.startGatedRun("")

	server := setupTestServer(t)
	f.handler.SetRequirePermFn(server.requirePermission)
	router := newWorkflowRouter(f.handler)

	basic := &Principal{ID: approvalDecider, Name: approvalDecider, Assurance: session.AssuranceBasic, ImplicitAdmin: true}
	req := httptest.NewRequest(http.MethodPost, "/workflows/approvals/"+rec.ApprovalID+"/decision",
		bytes.NewReader([]byte(`{"decision":"approve"}`)))
	req = withTenantContext(req, approvalTenant)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basic))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	got, err := f.store.GetApproval(context.Background(), approvalTenant, rec.ApprovalID)
	require.NoError(t, err)
	assert.Equal(t, business.ApprovalStatusPending, got.Status)
}

func TestWorkflowApproval_PermissionRegistered(t *testing.T) {
	req, ok := permissionAssurance["workflow:approve"]
	require.True(t, ok)
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.True(t, knownPermissions["workflow:approve"])
}
