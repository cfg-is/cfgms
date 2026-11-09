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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const workflowApprovalsPath = "/api/v1/automation/approvals/workflows"

type workflowApprovalFixture struct {
	server *Server
	store  *ContentApprovalStore
	cs     cfgconfig.ConfigStore
	owner  string
	vw     *workflow.VersionedWorkflow
}

// newWorkflowApprovalFixture wires a real workflow store and approval store into the
// test server and seeds one workflow version in the root admin's tenant.
func newWorkflowApprovalFixture(t *testing.T) *workflowApprovalFixture {
	t.Helper()
	server := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	cs := sm.GetConfigStore()
	store, err := NewContentApprovalStore(cs)
	require.NoError(t, err)
	server.SetContentApprovalStore(store)
	server.workflowHandler = NewWorkflowHandler(
		workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logging.NewNoopLogger(), nil, nil, nil, nil, nil),
		cs, nil, logging.NewNoopLogger())

	f := &workflowApprovalFixture{server: server, store: store, cs: cs, owner: testRootTenantID}
	f.vw = f.seed(t, testRootTenantID, "cleanup", "1.0.0")
	return f
}

func (f *workflowApprovalFixture) seed(t *testing.T, tenantID, name, version string) *workflow.VersionedWorkflow {
	t.Helper()
	sv, err := workflow.ParseSemanticVersion(version)
	require.NoError(t, err)
	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name: name, Version: version,
			Steps: []workflow.Step{{Name: "step1", Type: workflow.StepTypeTask}},
		},
		SemanticVersion: *sv,
	}
	require.NoError(t, workflow.NewWorkflowStore(f.cs, tenantID).StoreWorkflow(context.Background(), vw))
	return vw
}

func (f *workflowApprovalFixture) approvalHash() string {
	_, h := workflowApprovalHashOf(f.owner, f.vw)
	return h
}

func (f *workflowApprovalFixture) body(approvalHash string) string {
	b, _ := json.Marshal(ApproveWorkflowRequest{WorkflowID: "cleanup", Version: "1.0.0", ApprovalHash: approvalHash})
	return string(b)
}

func (f *workflowApprovalFixture) adminRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := requestWithTLSCert(method, target, makeSelfSignedAdminCert(t))
	if body != "" {
		req.Body = ioNopCloser(body)
		req.ContentLength = int64(len(body))
	}
	return req
}

func (f *workflowApprovalFixture) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	return rec
}

// tappedApprove serves an approve request carrying a presence token bound to
// boundBody and presents it with sentBody.
func (f *workflowApprovalFixture) tappedApprove(t *testing.T, boundBody, sentBody string) *httptest.ResponseRecorder {
	t.Helper()
	bound := f.adminRequest(t, http.MethodPost, workflowApprovalsPath, boundBody)
	req := f.adminRequest(t, http.MethodPost, workflowApprovalsPath, sentBody)
	req.Header.Set(presenceTokenHeader,
		storeBoundTokenWithExpiry(t, f.server, bound, "content-approval:approve", false, time.Now().Add(presenceTokenTTL)))
	return f.serve(req)
}

func (f *workflowApprovalFixture) approvalRecord(t *testing.T, hash string) *ContentApproval {
	t.Helper()
	a, err := f.store.GetApproval(context.Background(), f.owner, LibraryKindWorkflow, "cleanup", "1.0.0", hash)
	require.NoError(t, err)
	return a
}

func (f *workflowApprovalFixture) approve(t *testing.T) {
	t.Helper()
	body := f.body(f.approvalHash())
	require.Equal(t, http.StatusCreated, f.tappedApprove(t, body, body).Code)
}

func (f *workflowApprovalFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	entries, err := f.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: f.owner})
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

func (f *workflowApprovalFixture) revokePath() string {
	return workflowApprovalsPath + "/cleanup/1.0.0/" + f.approvalHash()
}

func (f *workflowApprovalFixture) records(t *testing.T) []*ContentApproval {
	t.Helper()
	list, err := f.store.ListApprovals(context.Background(), f.owner, LibraryKindWorkflow)
	require.NoError(t, err)
	return list
}

func TestApproveWorkflow_WithoutPresenceTokenReturnsStepUp(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	rec := f.serve(f.adminRequest(t, http.MethodPost, workflowApprovalsPath, f.body(f.approvalHash())))
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `permission="content-approval:approve"`)
	assert.Empty(t, f.records(t))
}

func TestApproveWorkflow_WithTokenRecordsApprovalUnderOwnerAndAudits(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	body := f.body(f.approvalHash())
	rec := f.tappedApprove(t, body, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	a := f.approvalRecord(t, f.approvalHash())
	require.NotNil(t, a)
	assert.Equal(t, ApprovalMethodApproveTap, a.Method)
	assert.Equal(t, f.owner, a.TenantID)
	assert.Equal(t, LibraryKindWorkflow, a.Kind)
	assert.NotEmpty(t, a.ApprovedBy)

	require.Eventually(t, func() bool { return f.auditCount(t, auditActionContentApprovalApprove) == 1 },
		5*time.Second, 20*time.Millisecond)
}

// [REQUIRED TEST] A presence token minted for one hash cannot approve another hash.
func TestApproveWorkflow_TokenBoundToOtherHashRefused(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	rec := f.tappedApprove(t, f.body("some-other-hash"), f.body(f.approvalHash()))
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "presence_token_action_mismatch")
	assert.Empty(t, f.records(t))
}

// [REQUIRED TEST] A body carrying a hash that differs from the stored version's hash is
// refused and nothing is written.
func TestApproveWorkflow_HashMismatchRefusedNothingWritten(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	wrong := f.body("deadbeef")
	rec := f.tappedApprove(t, wrong, wrong)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Empty(t, f.records(t))
	assert.Zero(t, f.auditCount(t, auditActionContentApprovalApprove), "a refused approve writes no audit event")

	// A content hash that does not match is refused even with the right approval hash.
	b, _ := json.Marshal(ApproveWorkflowRequest{WorkflowID: "cleanup", Version: "1.0.0", ApprovalHash: f.approvalHash(), ContentHash: "deadbeef"})
	rec = f.tappedApprove(t, string(b), string(b))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Empty(t, f.records(t))

	// The canonical content hash is not the approval hash: it covers no owner tenant.
	contentHash, _ := workflowApprovalHashOf(f.owner, f.vw)
	b2 := f.body(contentHash)
	rec = f.tappedApprove(t, b2, b2)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Empty(t, f.records(t))
}

func TestApproveWorkflow_BodyWithoutApprovalHashRefused(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	contentHash, _ := workflowApprovalHashOf(f.owner, f.vw)
	b, _ := json.Marshal(ApproveWorkflowRequest{WorkflowID: "cleanup", Version: "1.0.0", ContentHash: contentHash})
	rec := f.tappedApprove(t, string(b), string(b))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Empty(t, f.records(t))

	bad := `{"workflow_id":"cleanup","version":"1.0.0","approval_hash":"x","extra":1}`
	rec = f.tappedApprove(t, bad, bad)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "unknown fields are refused")
}

// [REQUIRED TEST] A grant principal and an API-key principal are refused.
func TestApproveWorkflow_APIKeyAndNonHumanPrincipalsRefused(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	key := NewEphemeralTestKey(t, f.server, []string{"content-approval:approve", "content-approval:revoke"}, f.owner, 5*time.Minute)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		target, body := workflowApprovalsPath, f.body(f.approvalHash())
		if method == http.MethodDelete {
			target, body = f.revokePath(), ""
		}
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("X-API-Key", key)
		rec := f.serve(req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", method, rec.Body.String())
	}

	// Defense in depth: even past the assurance gate the handlers refuse a principal
	// that is not a human channel.
	for _, ch := range []AuthChannel{AuthChannelAPIKey, AuthChannelRelay, AuthChannelUnknown} {
		p := &Principal{Channel: ch, ID: "machine-1", TenantID: f.owner, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
		req := withPrincipal(httptest.NewRequest(http.MethodPost, workflowApprovalsPath, bytes.NewReader([]byte(f.body(f.approvalHash())))), p)
		rec := httptest.NewRecorder()
		f.server.handleApproveWorkflow(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "approve, channel %d", ch)

		req = withPrincipal(httptest.NewRequest(http.MethodDelete, f.revokePath(), nil), p)
		rec = httptest.NewRecorder()
		f.server.handleRevokeWorkflowApproval(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "revoke, channel %d", ch)
	}
	assert.Empty(t, f.records(t))
}

func TestApproveWorkflow_UnknownWorkflowOrVersionNotFound(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	for _, req := range []ApproveWorkflowRequest{
		{WorkflowID: "missing", Version: "1.0.0", ApprovalHash: "x"},
		{WorkflowID: "cleanup", Version: "9.9.9", ApprovalHash: "x"},
	} {
		b, _ := json.Marshal(req)
		rec := f.tappedApprove(t, string(b), string(b))
		assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	}
	assert.Empty(t, f.records(t))
}

// A caller cannot approve a workflow held by another tenant, including its parent: the
// caller's own tenant is both run tenant and ceiling, and nothing is written.
func TestApproveWorkflow_OtherTenantsWorkflowNotFound(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	child, err := f.server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ParentID: testRootTenantID, Name: "wf-approval-child"})
	require.NoError(t, err)

	for _, callerTenant := range []string{child.ID, "unknown-tenant"} {
		p := &Principal{Channel: AuthChannelMTLS, ID: "other-admin", TenantID: callerTenant, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
		req := withPrincipal(httptest.NewRequest(http.MethodPost, workflowApprovalsPath, bytes.NewReader([]byte(f.body(f.approvalHash())))), p)
		rec := httptest.NewRecorder()
		f.server.handleApproveWorkflow(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s: %s", callerTenant, rec.Body.String())
	}
	assert.Empty(t, f.records(t))
}

func TestApproveWorkflow_UnwiredReturnsUnavailable(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	f.server.workflowHandler = nil
	body := f.body(f.approvalHash())
	rec := f.tappedApprove(t, body, body)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
}

// [REQUIRED TEST] After a revoke, the evaluator returns pending for that version.
func TestRevokeWorkflowApproval_EvaluatorReturnsPending(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	ctx := context.Background()
	f.approve(t)
	state, _, _, _, err := f.store.evaluateWorkflowApproval(ctx, f.owner, f.vw)
	require.NoError(t, err)
	require.Equal(t, WorkflowApprovalApproved, state)

	rec := f.serve(f.adminRequest(t, http.MethodDelete, f.revokePath(), ""))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	state, a, _, reason, err := f.store.evaluateWorkflowApproval(ctx, f.owner, f.vw)
	require.NoError(t, err)
	assert.Equal(t, WorkflowApprovalPending, state)
	assert.Nil(t, a)
	assert.NotEmpty(t, reason)
	require.Eventually(t, func() bool { return f.auditCount(t, auditActionContentApprovalRevoke) == 1 },
		5*time.Second, 20*time.Millisecond)

	rec = f.serve(f.adminRequest(t, http.MethodDelete, f.revokePath(), ""))
	assert.Equal(t, http.StatusNotFound, rec.Code, "a second revoke finds nothing")
}

// An approval of a version that has since changed is bound to the old hash: the new
// content reads as pending, and the old approval can still be withdrawn by its key.
func TestApproveWorkflow_ChangedVersionIsPendingAndOldApprovalWithdrawable(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	f.approve(t)
	oldHash := f.approvalHash()

	changed := *f.vw
	changed.Steps = append(append([]workflow.Step{}, f.vw.Steps...), workflow.Step{Name: "step2", Type: workflow.StepTypeTask})
	require.NoError(t, workflow.NewWorkflowStore(f.cs, f.owner).StoreWorkflow(context.Background(), &changed))

	state, _, newHash, _, err := f.store.evaluateWorkflowApproval(context.Background(), f.owner, &changed)
	require.NoError(t, err)
	assert.Equal(t, WorkflowApprovalPending, state)
	assert.NotEqual(t, oldHash, newHash)

	rec := f.serve(f.adminRequest(t, http.MethodDelete, workflowApprovalsPath+"/cleanup/1.0.0/"+oldHash, ""))
	assert.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
}

// [REQUIRED TEST] If the audit event cannot be written, approve and revoke change nothing.
func TestApproveAndRevokeWorkflow_AuditFailureChangesNothing(t *testing.T) {
	f := newWorkflowApprovalFixture(t)

	auditMgr := f.server.auditManager
	f.server.auditManager = nil
	body := f.body(f.approvalHash())
	rec := f.tappedApprove(t, body, body)
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Empty(t, f.records(t), "approve must write nothing without an audit event")

	f.server.auditManager = auditMgr
	f.approve(t)
	f.server.auditManager = nil
	rec = f.serve(f.adminRequest(t, http.MethodDelete, f.revokePath(), ""))
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.NotNil(t, f.approvalRecord(t, f.approvalHash()), "revoke must remove nothing without an audit event")
}

func TestListWorkflowApprovals_ShowsStateReasonAndHashes(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	f.seed(t, testRootTenantID, "cleanup", "1.1.0")
	list := func() WorkflowApprovalListResponse {
		rec := f.serve(f.adminRequest(t, http.MethodGet, workflowApprovalsPath, ""))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp struct {
			Data WorkflowApprovalListResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}

	got := list()
	assert.Equal(t, ApprovalModeSigned, got.Mode)
	require.Len(t, got.Workflows, 2, "every version is listed, not only the latest")
	assert.Equal(t, "1.0.0", got.Workflows[0].Version)
	assert.Equal(t, "1.1.0", got.Workflows[1].Version)
	for _, e := range got.Workflows {
		assert.Equal(t, WorkflowApprovalPending, e.State)
		assert.NotEmpty(t, e.Reason)
		assert.NotEmpty(t, e.ApprovalHash)
		assert.NotEmpty(t, e.ContentHash)
		assert.Nil(t, e.Approval)
	}
	contentHash, _ := workflowApprovalHashOf(f.owner, f.vw)
	assert.Equal(t, f.approvalHash(), got.Workflows[0].ApprovalHash)
	assert.Equal(t, contentHash, got.Workflows[0].ContentHash)

	f.approve(t)
	got = list()
	require.Len(t, got.Workflows, 2)
	assert.Equal(t, WorkflowApprovalApproved, got.Workflows[0].State)
	require.NotNil(t, got.Workflows[0].Approval)
	assert.Equal(t, string(ApprovalMethodApproveTap), got.Workflows[0].Approval.Method)
	assert.Equal(t, WorkflowApprovalPending, got.Workflows[1].State, "an approval does not carry to another version")
}

func TestListWorkflowApprovals_OtherTenantsWorkflowsNotListed(t *testing.T) {
	f := newWorkflowApprovalFixture(t)
	child, err := f.server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ParentID: testRootTenantID, Name: "wf-list-child"})
	require.NoError(t, err)

	p := &Principal{Channel: AuthChannelMTLS, ID: "child-admin", TenantID: child.ID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	req := withPrincipal(httptest.NewRequest(http.MethodGet, workflowApprovalsPath, nil), p)
	rec := httptest.NewRecorder()
	f.server.handleListWorkflowApprovals(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data WorkflowApprovalListResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Empty(t, resp.Data.Workflows)
}
