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

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const approvalsPath = "/api/v1/automation/approvals/scripts"

type scriptApprovalFixture struct {
	server *Server
	store  *ContentApprovalStore
	repo   *script.TenantScriptRepository
	owner  string
	vs     *script.VersionedScript
}

// newScriptApprovalFixture wires a real tenant script library and approval store into
// the test server and seeds one script version in the root admin's tenant.
func newScriptApprovalFixture(t *testing.T) *scriptApprovalFixture {
	t.Helper()
	server := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := script.NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)
	store, err := NewContentApprovalStore(sm.GetConfigStore())
	require.NoError(t, err)
	server.SetScriptRepository(repo)
	server.SetContentApprovalStore(store)

	gr, err := repo.ForTenant(testRootTenantID)
	require.NoError(t, err)
	require.NoError(t, gr.Create(&script.VersionedScript{
		Metadata: &script.ScriptMetadata{ID: "cleanup", Name: "cleanup", Version: &script.Version{Major: 1},
			Shell: script.ShellBash, Platform: []string{"linux"}},
		Content: "echo cleanup\n",
	}))
	vs, err := repo.GetForTenant(testRootTenantID, "cleanup", "1.0.0")
	require.NoError(t, err)
	return &scriptApprovalFixture{server: server, store: store, repo: repo, owner: testRootTenantID, vs: vs}
}

func (f *scriptApprovalFixture) approvalHash() string {
	return script.ScriptApprovalHash(f.owner, f.vs)
}

func (f *scriptApprovalFixture) body(approvalHash string) string {
	b, _ := json.Marshal(ApproveScriptRequest{ScriptID: "cleanup", Version: "1.0.0", ApprovalHash: approvalHash})
	return string(b)
}

func (f *scriptApprovalFixture) adminRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := requestWithTLSCert(method, target, makeSelfSignedAdminCert(t))
	if body != "" {
		req.Body = ioNopCloser(body)
		req.ContentLength = int64(len(body))
	}
	return req
}

func (f *scriptApprovalFixture) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	return rec
}

// tappedApprove serves an approve request carrying a presence token bound to
// boundBody and presents it with sentBody.
func (f *scriptApprovalFixture) tappedApprove(t *testing.T, boundBody, sentBody string) *httptest.ResponseRecorder {
	t.Helper()
	bound := f.adminRequest(t, http.MethodPost, approvalsPath, boundBody)
	req := f.adminRequest(t, http.MethodPost, approvalsPath, sentBody)
	req.Header.Set(presenceTokenHeader,
		storeBoundTokenWithExpiry(t, f.server, bound, "content-approval:approve", false, time.Now().Add(presenceTokenTTL)))
	return f.serve(req)
}

func (f *scriptApprovalFixture) approvalRecord(t *testing.T, hash string) *ContentApproval {
	t.Helper()
	a, err := f.store.GetApproval(context.Background(), f.owner, LibraryKindScript, "cleanup", "1.0.0", hash)
	require.NoError(t, err)
	return a
}

func (f *scriptApprovalFixture) auditCount(t *testing.T, action string) int {
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

func TestApproveScript_WithoutPresenceTokenReturnsStepUp(t *testing.T) {
	f := newScriptApprovalFixture(t)
	rec := f.serve(f.adminRequest(t, http.MethodPost, approvalsPath, f.body(f.approvalHash())))
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `permission="content-approval:approve"`)
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()))
}

func TestApproveScript_WithTokenRecordsApprovalAndOneAuditEvent(t *testing.T) {
	f := newScriptApprovalFixture(t)
	body := f.body(f.approvalHash())
	rec := f.tappedApprove(t, body, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	a := f.approvalRecord(t, f.approvalHash())
	require.NotNil(t, a)
	assert.Equal(t, ApprovalMethodApproveTap, a.Method)
	assert.Equal(t, f.owner, a.TenantID)
	assert.NotEmpty(t, a.ApprovedBy)

	require.Eventually(t, func() bool { return f.auditCount(t, auditActionContentApprovalApprove) == 1 },
		5*time.Second, 20*time.Millisecond)
}

func TestApproveScript_HashMismatchRefusedNoRecord(t *testing.T) {
	f := newScriptApprovalFixture(t)
	wrong := f.body("deadbeef")
	rec := f.tappedApprove(t, wrong, wrong)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	list, err := f.store.ListApprovals(context.Background(), f.owner, LibraryKindScript)
	require.NoError(t, err)
	assert.Empty(t, list)
}

// [REQUIRED TEST] The approve body must carry the approval hash; the content
// hash alone is refused.
func TestApproveScript_ContentHashOnlyBodyRefused(t *testing.T) {
	f := newScriptApprovalFixture(t)
	b, _ := json.Marshal(ApproveScriptRequest{ScriptID: "cleanup", Version: "1.0.0", ContentHash: f.vs.Hash})
	rec := f.tappedApprove(t, string(b), string(b))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()))

	// Content hash passed in the approval hash field is a mismatch, not an approval.
	b2 := f.body(f.vs.Hash)
	rec = f.tappedApprove(t, b2, b2)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()))
}

// [REQUIRED TEST] A presence token minted for one hash cannot approve another.
func TestApproveScript_TokenBoundToOtherHashRefused(t *testing.T) {
	f := newScriptApprovalFixture(t)
	rec := f.tappedApprove(t, f.body("some-other-hash"), f.body(f.approvalHash()))
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "presence_token_action_mismatch")
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()))
}

// [REQUIRED TEST] An API-key principal and a grant-style (non-human) principal are refused.
func TestApproveScript_APIKeyAndNonHumanPrincipalsRefused(t *testing.T) {
	f := newScriptApprovalFixture(t)
	key := NewEphemeralTestKey(t, f.server, []string{"content-approval:approve", "content-approval:revoke"}, f.owner, 5*time.Minute)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		target := approvalsPath
		body := f.body(f.approvalHash())
		if method == http.MethodDelete {
			target += "/cleanup/1.0.0/" + f.approvalHash()
			body = ""
		}
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		req.Header.Set("X-API-Key", key)
		rec := f.serve(req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", method, rec.Body.String())
	}

	// Defense in depth: even past the assurance gate the handler refuses a
	// principal that is not a human channel.
	for _, ch := range []AuthChannel{AuthChannelAPIKey, AuthChannelRelay, AuthChannelUnknown} {
		p := &Principal{Channel: ch, ID: "machine-1", Assurance: session.AssuranceStrong, ImplicitAdmin: true}
		req := withPrincipal(httptest.NewRequest(http.MethodPost, approvalsPath, bytes.NewReader([]byte(f.body(f.approvalHash())))), p)
		rec := httptest.NewRecorder()
		f.server.handleApproveScript(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "channel %d", ch)
	}
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()))
}

func TestApproveScript_UnknownScriptNotFound(t *testing.T) {
	f := newScriptApprovalFixture(t)
	b, _ := json.Marshal(ApproveScriptRequest{ScriptID: "missing", Version: "1.0.0", ApprovalHash: "x"})
	rec := f.tappedApprove(t, string(b), string(b))
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

// A caller whose tenant does not own the library holding the script gets 404,
// and nothing is written under the library's owner.
func TestApproveScript_OtherTenantLibraryNotFound(t *testing.T) {
	f := newScriptApprovalFixture(t)
	p := &Principal{Channel: AuthChannelMTLS, ID: "other-admin", TenantID: "other-tenant", Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	req := withPrincipal(httptest.NewRequest(http.MethodPost, approvalsPath, bytes.NewReader([]byte(f.body(f.approvalHash())))), p)
	rec := httptest.NewRecorder()
	f.server.handleApproveScript(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()))
}

func approveScriptFor(t *testing.T, f *scriptApprovalFixture) {
	t.Helper()
	body := f.body(f.approvalHash())
	require.Equal(t, http.StatusCreated, f.tappedApprove(t, body, body).Code)
}

// [REQUIRED TEST] After a revoke, the evaluator returns pending on the next call.
func TestRevokeScriptApproval_EvaluatorReturnsPending(t *testing.T) {
	f := newScriptApprovalFixture(t)
	ctx := context.Background()
	approveScriptFor(t, f)
	state, _, _, err := f.store.evaluateScriptApproval(ctx, f.owner, f.vs)
	require.NoError(t, err)
	require.Equal(t, ScriptApprovalApproved, state)

	rec := f.serve(f.adminRequest(t, http.MethodDelete, approvalsPath+"/cleanup/1.0.0/"+f.approvalHash(), ""))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	state, _, _, err = f.store.evaluateScriptApproval(ctx, f.owner, f.vs)
	require.NoError(t, err)
	assert.Equal(t, ScriptApprovalPending, state)
	require.Eventually(t, func() bool { return f.auditCount(t, auditActionContentApprovalRevoke) == 1 },
		5*time.Second, 20*time.Millisecond)

	rec = f.serve(f.adminRequest(t, http.MethodDelete, approvalsPath+"/cleanup/1.0.0/"+f.approvalHash(), ""))
	assert.Equal(t, http.StatusNotFound, rec.Code, "a second revoke finds nothing")
}

// [REQUIRED TEST] If the audit event cannot be written, approve and revoke change nothing.
func TestApproveAndRevoke_AuditFailureChangesNothing(t *testing.T) {
	f := newScriptApprovalFixture(t)

	auditMgr := f.server.auditManager
	f.server.auditManager = nil
	body := f.body(f.approvalHash())
	rec := f.tappedApprove(t, body, body)
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Nil(t, f.approvalRecord(t, f.approvalHash()), "approve must write nothing without an audit event")

	f.server.auditManager = auditMgr
	approveScriptFor(t, f)
	f.server.auditManager = nil
	rec = f.serve(f.adminRequest(t, http.MethodDelete, approvalsPath+"/cleanup/1.0.0/"+f.approvalHash(), ""))
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.NotNil(t, f.approvalRecord(t, f.approvalHash()), "revoke must remove nothing without an audit event")
}

func TestListScriptApprovals_ShowsBothHashesAndState(t *testing.T) {
	f := newScriptApprovalFixture(t)
	list := func() ScriptApprovalListResponse {
		rec := f.serve(f.adminRequest(t, http.MethodGet, approvalsPath, ""))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp struct {
			Data ScriptApprovalListResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}
	got := list()
	assert.Equal(t, ApprovalModeSigned, got.Mode)
	require.Len(t, got.Scripts, 1)
	assert.Equal(t, ScriptApprovalPending, got.Scripts[0].State)
	assert.Equal(t, f.vs.Hash, got.Scripts[0].ContentHash)
	assert.Equal(t, f.approvalHash(), got.Scripts[0].ApprovalHash)
	assert.Nil(t, got.Scripts[0].Approval)

	approveScriptFor(t, f)
	got = list()
	require.Len(t, got.Scripts, 1)
	assert.Equal(t, ScriptApprovalApproved, got.Scripts[0].State)
	require.NotNil(t, got.Scripts[0].Approval)
	assert.Equal(t, string(ApprovalMethodApproveTap), got.Scripts[0].Approval.Method)
}
