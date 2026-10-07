// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const (
	saSteward = "steward-1"
	saTenant  = "msp-a"
)

// actionNode is one controller node: a Server wired with the real run, queue and cert
// stores, routed through the production action routes.
type actionNode struct {
	t       *testing.T
	server  *Server
	manager *controllerrun.Manager
	queue   *scriptmodule.ExecutionQueue
	router  *mux.Router
}

func newActionNode(t *testing.T) *actionNode {
	t.Helper()
	server, manager, queue := setupRunServer(t, nil)
	seedScopeTenants(t, server)
	require.NoError(t, server.controllerService.RegisterSteward(saSteward, saTenant, "addr", "active"))
	return wrapActionNode(t, server, manager, queue)
}

func wrapActionNode(t *testing.T, server *Server, manager *controllerrun.Manager, queue *scriptmodule.ExecutionQueue) *actionNode {
	t.Helper()
	router := mux.NewRouter()
	registerStewardActionRoutes(server, router)
	registerRunRoutes(server, router)
	return &actionNode{t: t, server: server, manager: manager, queue: queue, router: router}
}

// peer returns a second node over the same run store, queue, steward registry and cert
// roots, standing in for another controller node in the cluster.
func (n *actionNode) peer() *actionNode {
	n.t.Helper()
	other := setupTestServer(n.t)
	other.SetRunManager(n.manager, n.queue)
	other.controllerService = n.server.controllerService
	other.tenantManager = n.server.tenantManager
	other.certManager = n.server.certManager
	return wrapActionNode(n.t, other, n.manager, n.queue)
}

func actionPrincipal(id string) *Principal {
	return &Principal{ID: id, Name: id, TenantID: saTenant, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
}

func (n *actionNode) do(method, path string, p *Principal, body interface{}) *httptest.ResponseRecorder {
	n.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		require.NoError(n.t, err)
	}
	req := withPrincipal(httptest.NewRequest(method, path, bytes.NewReader(raw)), p)
	rec := httptest.NewRecorder()
	n.router.ServeHTTP(rec, req)
	return rec
}

// signedAction is a request body for one action, signed by a real operator certificate
// issued from the node's CA, the way the web assembles it from sign/begin and sign/finish.
type signedAction struct {
	body   map[string]interface{}
	serial string
	proof  *OperatorProof
}

type actionOpts struct {
	steward   string   // steward the envelope is signed for and addressed to (default saSteward)
	targets   []string // overrides the signed and sent targets
	expiresIn time.Duration
	signAs    *operatorpayload.Action // sign this action instead of the one requested
}

func (n *actionNode) serviceAction(word, name string, o actionOpts) signedAction {
	n.t.Helper()
	return n.signAction(operatorpayload.Action{Verb: "service." + word, TargetKind: "service", TargetName: name},
		map[string]interface{}{"action": word}, o)
}

func (n *actionNode) processAction(word, pid, image string, o actionOpts) signedAction {
	n.t.Helper()
	return n.signAction(operatorpayload.Action{Verb: "process." + word, TargetKind: "process", TargetName: pid, Parameters: map[string]string{"image": image}},
		map[string]interface{}{"action": word, "image": image}, o)
}

func (n *actionNode) signAction(a operatorpayload.Action, body map[string]interface{}, o actionOpts) signedAction {
	n.t.Helper()
	if o.steward == "" {
		o.steward = saSteward
	}
	if o.targets == nil {
		o.targets = []string{o.steward}
	}
	if o.expiresIn == 0 {
		o.expiresIn = 3 * time.Minute
	}
	if o.signAs != nil {
		a = *o.signAs
	}
	exp := time.Now().Add(o.expiresIn).UTC().Truncate(time.Second)
	nonce := "nonce-" + time.Now().Format("150405.000000000")
	env := actionEnvelope(n.t, a, o.targets, nonce, exp)
	proof, serial := signActionX509(n.t, n.server, env, cert.SetPayloadSigningMarker)
	body["justification"] = "restore service after incident"
	body["nonce"] = nonce
	body["expires_at"] = exp.Format(time.RFC3339)
	body["targets"] = o.targets
	body["signature"] = proof.X509
	return signedAction{body: body, serial: serial, proof: proof}
}

func (n *actionNode) postService(p *Principal, name string, sa signedAction) *httptest.ResponseRecorder {
	return n.do(http.MethodPost, "/stewards/"+saSteward+"/services/"+name+"/actions", p, sa.body)
}

func (n *actionNode) postProcess(p *Principal, pid string, sa signedAction) *httptest.ResponseRecorder {
	return n.do(http.MethodPost, "/stewards/"+saSteward+"/processes/"+pid+"/actions", p, sa.body)
}

func decodeRunID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.RunID)
	return resp.Data.RunID
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Error.Code
}

func (n *actionNode) queued() int { return len(n.queue.PeekForDevice(saSteward)) }

func (n *actionNode) auditEntries(action string) []*business.AuditEntry {
	n.t.Helper()
	require.NoError(n.t, n.server.auditManager.Flush(context.Background()))
	entries, err := n.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: saTenant})
	require.NoError(n.t, err)
	var out []*business.AuditEntry
	for _, e := range entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (n *actionNode) jobs(runID string, p *Principal) []map[string]interface{} {
	n.t.Helper()
	rec := n.do(http.MethodGet, "/runs/"+runID+"/jobs", p, nil)
	require.Equal(n.t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []map[string]interface{} `json:"data"`
	}
	require.NoError(n.t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func TestStewardAction_ServiceAndProcessReturn202AndRunReachesTerminalStatus(t *testing.T) {
	n := newActionNode(t)
	p := actionPrincipal("op-1")

	svcRun := decodeRunID(t, n.postService(p, "spooler", n.serviceAction("restart", "spooler", actionOpts{})))
	procRun := decodeRunID(t, n.postProcess(p, "4242", n.processAction("end", "4242", "notepad.exe", actionOpts{})))
	assert.NotEqual(t, svcRun, procRun)
	assert.Equal(t, 2, n.queued())

	// The run is visible and carries its kind; the job is not yet terminal.
	rec := n.do(http.MethodGet, "/runs/"+svcRun, p, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var run struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &run))
	assert.Equal(t, "steward_action", run.Data["kind"])
	jobs := n.jobs(svcRun, p)
	require.Len(t, jobs, 1)
	assert.Equal(t, "pending", jobs[0]["status"])

	// The steward reports; the polled job is terminal and carries the result code.
	require.NoError(t, n.manager.RecordActionResult(context.Background(), svcRun, jobs[0]["job_id"].(string), jobs[0]["execution_id"].(string), "ok"))
	jobs = n.jobs(svcRun, p)
	assert.Equal(t, "completed", jobs[0]["status"])
	assert.Equal(t, "ok", jobs[0]["result_code"])
}

func TestStewardAction_ProcessParametersReachQueueEntry(t *testing.T) {
	n := newActionNode(t)
	decodeRunID(t, n.postProcess(actionPrincipal("op-1"), "4242", n.processAction("suspend", "4242", "notepad.exe", actionOpts{})))
	entries := n.queue.PeekForDevice(saSteward)
	require.Len(t, entries, 1)
	require.NotNil(t, entries[0].Action)
	assert.Equal(t, "process.suspend", entries[0].Action.Verb)
	assert.Equal(t, "4242", entries[0].Action.TargetName)
	assert.Equal(t, map[string]string{"image": "notepad.exe"}, entries[0].Action.Parameters)
}

func TestStewardAction_RefusedEnvelopesQueueNothing(t *testing.T) {
	other := operatorpayload.Action{Verb: "service.stop", TargetKind: "service", TargetName: "spooler"}
	otherTarget := operatorpayload.Action{Verb: "service.restart", TargetKind: "service", TargetName: "dnscache"}
	cases := []struct {
		name     string
		opts     actionOpts
		wantCode int
		wantErr  string
	}{
		{"expired", actionOpts{expiresIn: -time.Minute}, http.StatusBadRequest, "ENVELOPE_EXPIRED"},
		{"expiry beyond the 5 minute ceiling", actionOpts{expiresIn: 6 * time.Minute}, http.StatusBadRequest, "ENVELOPE_TTL_EXCEEDED"},
		{"signed for another steward", actionOpts{targets: []string{"steward-2"}}, http.StatusBadRequest, "INVALID_TARGETS"},
		{"multi-target", actionOpts{targets: []string{saSteward, "steward-2"}}, http.StatusBadRequest, "INVALID_TARGETS"},
		{"signature over a different verb", actionOpts{signAs: &other}, http.StatusForbidden, "INVALID_SIGNATURE"},
		{"signature over a different target", actionOpts{signAs: &otherTarget}, http.StatusForbidden, "INVALID_SIGNATURE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newActionNode(t)
			rec := n.postService(actionPrincipal("op-1"), "spooler", n.serviceAction("restart", "spooler", tc.opts))
			assert.Equal(t, tc.wantCode, rec.Code, rec.Body.String())
			assert.Equal(t, tc.wantErr, errorCode(t, rec))
			assert.Zero(t, n.queued(), "a refused request must queue nothing")
		})
	}
}

func TestStewardAction_NoSignatureRefused(t *testing.T) {
	n := newActionNode(t)
	sa := n.serviceAction("restart", "spooler", actionOpts{})
	delete(sa.body, "signature")
	rec := n.postService(actionPrincipal("op-1"), "spooler", sa)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "OPERATOR_SIGNATURE_REQUIRED", errorCode(t, rec))
	assert.Zero(t, n.queued())
}

func TestStewardAction_JustificationAndActionValidated(t *testing.T) {
	n := newActionNode(t)
	p := actionPrincipal("op-1")

	sa := n.serviceAction("restart", "spooler", actionOpts{})
	sa.body["justification"] = "  "
	rec := n.postService(p, "spooler", sa)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_JUSTIFICATION", errorCode(t, rec))

	// A process verb on the service endpoint is not an action of that kind.
	sa = n.serviceAction("restart", "spooler", actionOpts{})
	sa.body["action"] = "end"
	rec = n.postService(p, "spooler", sa)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_ACTION", errorCode(t, rec))

	// A process action requires a plausible image and a numeric PID.
	sa = n.processAction("end", "4242", "a/b.exe", actionOpts{})
	assert.Equal(t, http.StatusBadRequest, n.postProcess(p, "4242", sa).Code)
	sa = n.processAction("end", "abc", "x.exe", actionOpts{})
	assert.Equal(t, http.StatusBadRequest, n.postProcess(p, "abc", sa).Code)
	assert.Zero(t, n.queued())
}

func TestStewardAction_ProofForwardedUnchangedAndCredentialAudited(t *testing.T) {
	n := newActionNode(t)
	sa := n.serviceAction("stop", "spooler", actionOpts{})
	runID := decodeRunID(t, n.postService(actionPrincipal("op-1"), "spooler", sa))

	entries := n.queue.PeekForDevice(saSteward)
	require.Len(t, entries, 1)
	md := entries[0].Metadata
	assert.Equal(t, sa.proof.X509.Value, md["signature_value"], "the operator signature must be forwarded, never re-signed")
	assert.Equal(t, sa.proof.X509.PublicKey, md["signature_public_key"])
	assert.Equal(t, sa.proof.X509.Algorithm, md["signature_algorithm"])
	assert.Equal(t, sa.body["nonce"], md["nonce"])
	assert.Equal(t, sa.body["expires_at"], md["expires_at"])
	assert.Equal(t, []string{saSteward}, md["targets"])
	assert.Equal(t, scriptmodule.QueueKindStewardAction, entries[0].Kind)

	audits := n.auditEntries("steward_action.request")
	require.Len(t, audits, 1)
	assert.Equal(t, "op-1", audits[0].UserID)
	assert.Equal(t, saSteward, audits[0].ResourceID, "audit resource id is the steward id, not a host name")
	assert.Equal(t, sa.serial, audits[0].Details["signer_id"])
	assert.Equal(t, runID, audits[0].Details["run_id"])
	assert.Equal(t, "service.stop", audits[0].Details["verb"])
	assert.Equal(t, "restore service after incident", audits[0].Details["justification"])
	assert.Equal(t, business.AuditResultSuccess, audits[0].Result)
}

func TestStewardAction_RefusalIsAudited(t *testing.T) {
	n := newActionNode(t)
	other := operatorpayload.Action{Verb: "service.stop", TargetKind: "service", TargetName: "spooler"}
	rec := n.postService(actionPrincipal("op-1"), "spooler", n.serviceAction("restart", "spooler", actionOpts{signAs: &other}))
	require.Equal(t, http.StatusForbidden, rec.Code)
	audits := n.auditEntries("steward_action.request")
	require.Len(t, audits, 1)
	assert.Equal(t, business.AuditResultDenied, audits[0].Result)
}

func TestStewardAction_PrepareRoundTripsToVerifierContent(t *testing.T) {
	n := newActionNode(t)
	p := actionPrincipal("op-1")
	rec := n.do(http.MethodPost, "/stewards/"+saSteward+"/actions/prepare", p,
		map[string]string{"target_kind": "process", "target_name": "4242", "action": "end", "image": "notepad.exe"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2, "prepare returns only content and shell")
	assert.NotContains(t, resp.Data, "nonce")
	assert.NotContains(t, resp.Data, "expires_at")
	assert.Equal(t, operatorpayload.ActionShell, resp.Data["shell"])
	got, err := base64.StdEncoding.DecodeString(resp.Data["content"].(string))
	require.NoError(t, err)

	// What the verifier rebuilds from the POST body for the same action.
	action, err := buildStewardAction("process", "4242", "end", "notepad.exe")
	require.NoError(t, err)
	want, err := operatorpayload.ActionContent(action)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// And an envelope signed over the prepared content is accepted by the POST.
	exp := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	env := operatorpayload.Envelope{Content: got, Shell: operatorpayload.ActionShell, Targets: []string{saSteward}, Nonce: "n-prepare", ExpiresAt: exp}
	proof, _ := signActionX509(t, n.server, env, cert.SetPayloadSigningMarker)
	post := n.do(http.MethodPost, "/stewards/"+saSteward+"/processes/4242/actions", p, map[string]interface{}{
		"action": "end", "image": "notepad.exe", "justification": "runaway", "nonce": "n-prepare",
		"expires_at": exp.Format(time.RFC3339), "targets": []string{saSteward}, "signature": proof.X509,
	})
	decodeRunID(t, post)
}

func TestStewardAction_PrepareRejectsUnknownKind(t *testing.T) {
	n := newActionNode(t)
	rec := n.do(http.MethodPost, "/stewards/"+saSteward+"/actions/prepare", actionPrincipal("op-1"),
		map[string]string{"target_kind": "registry", "target_name": "x", "action": "end"})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestStewardAction_RequiresStrongAssurance(t *testing.T) {
	n := newActionNode(t)
	basic := actionPrincipal("op-1")
	basic.Assurance = session.AssuranceBasic

	rec := n.postService(basic, "spooler", n.serviceAction("restart", "spooler", actionOpts{}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	rec = n.postProcess(basic, "4242", n.processAction("end", "4242", "notepad.exe", actionOpts{}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	rec = n.do(http.MethodPost, "/stewards/"+saSteward+"/actions/prepare", basic,
		map[string]string{"target_kind": "service", "target_name": "spooler", "action": "stop"})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Zero(t, n.queued())
}

func TestStewardAction_PermissionRequired(t *testing.T) {
	n := newActionNode(t)
	p := actionPrincipal("op-1")
	p.ImplicitAdmin = false
	p.Permissions = []string{"steward:service-control"}

	// Holding only the service permission: services pass, processes do not.
	decodeRunID(t, n.postService(p, "spooler", n.serviceAction("restart", "spooler", actionOpts{})))
	rec := n.postProcess(p, "4242", n.processAction("end", "4242", "notepad.exe", actionOpts{}))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 1, n.queued())
}

func TestStewardAction_PermissionsRegistered(t *testing.T) {
	for _, perm := range []string{"steward:service-control", "steward:process-control"} {
		req, ok := permissionAssurance[perm]
		require.True(t, ok, perm)
		assert.Equal(t, session.AssuranceStrong, req.Min)
		assert.True(t, knownPermissions[perm], perm)
	}
}

func TestStewardAction_OtherTenantGets404(t *testing.T) {
	n := newActionNode(t)
	foreign := actionPrincipal("op-b")
	foreign.TenantID = "msp-b"
	rec := n.postService(foreign, "spooler", n.serviceAction("restart", "spooler", actionOpts{}))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Zero(t, n.queued())
	assert.Empty(t, n.auditEntries("steward_action.request"))
}

func TestStewardAction_RootCallerWithoutGrantGetsCrossingChallenge(t *testing.T) {
	server, manager, queue := setupRunServer(t, nil)
	wireCrossingStore(t, server)
	seedRootTenant(t, server)
	createTestTenant(t, server, saTenant, "root")
	require.NoError(t, server.controllerService.RegisterSteward(saSteward, saTenant, "addr", "active"))
	n := wrapActionNode(t, server, manager, queue)

	root := rootScopedPrincipal("root-op")
	rec := n.postService(root, "spooler", n.serviceAction("restart", "spooler", actionOpts{}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	assert.Zero(t, n.queued())
}

func TestStewardAction_BudgetSharedAcrossNodesAndRefusalQueuesNothing(t *testing.T) {
	a := newActionNode(t)
	b := a.peer()
	store := pkgtesting.SetupTestRateCounterStore()
	a.server.rateCounterStore = store
	b.server.rateCounterStore = store
	for _, node := range []*actionNode{a, b} {
		blast := newTestBlastRadiusPolicyStore()
		require.NoError(t, blast.SetPolicy(context.Background(), &business.BlastRadiusPolicy{TenantID: saTenant, MaxTargets: ptrInt(2)}))
		node.server.SetBlastRadiusPolicyStore(blast)
		node.server.SetTenantStore(newTestTenantStoreWithPath(map[string][]string{saTenant: {saTenant}}))
	}
	p := actionPrincipal("op-budget")

	decodeRunID(t, a.postService(p, "spooler", a.serviceAction("restart", "spooler", actionOpts{})))
	decodeRunID(t, b.postService(p, "spooler", b.serviceAction("stop", "spooler", actionOpts{})))
	require.Equal(t, 2, a.queued())

	rec := a.postService(p, "spooler", a.serviceAction("start", "spooler", actionOpts{}))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	assert.Equal(t, "ACTION_BUDGET_EXCEEDED", errorCode(t, rec))
	assert.Equal(t, 2, a.queued(), "the over-budget request must queue nothing")

	// Another principal has its own budget.
	decodeRunID(t, a.postService(actionPrincipal("op-other"), "spooler", a.serviceAction("start", "spooler", actionOpts{})))
}

func TestStewardAction_BudgetHoldsWithoutSharedStore(t *testing.T) {
	n := newActionNode(t)
	blast := newTestBlastRadiusPolicyStore()
	require.NoError(t, blast.SetPolicy(context.Background(), &business.BlastRadiusPolicy{TenantID: saTenant, MaxTargets: ptrInt(1)}))
	n.server.SetBlastRadiusPolicyStore(blast)
	n.server.SetTenantStore(newTestTenantStoreWithPath(map[string][]string{saTenant: {saTenant}}))
	p := actionPrincipal("op-local")

	decodeRunID(t, n.postService(p, "spooler", n.serviceAction("restart", "spooler", actionOpts{})))
	rec := n.postService(p, "spooler", n.serviceAction("stop", "spooler", actionOpts{}))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, 1, n.queued())
}

func TestStewardAction_BudgetFailsClosedAtCapacity(t *testing.T) {
	n := newActionNode(t)
	n.server.rateCounterStore = pkgtesting.SetupTestRateCounterStoreWithMaxKeys(1)
	_, _, err := n.server.rateCounterStore.Increment(context.Background(), "occupied", time.Minute)
	require.NoError(t, err)

	rec := n.postService(actionPrincipal("op-1"), "spooler", n.serviceAction("restart", "spooler", actionOpts{}))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Zero(t, n.queued())
}

func TestStewardAction_AcceptedOnOneNodePolledOnAnother(t *testing.T) {
	a := newActionNode(t)
	b := a.peer()
	p := actionPrincipal("op-1")
	runID := decodeRunID(t, a.postService(p, "spooler", a.serviceAction("restart", "spooler", actionOpts{})))

	rec := b.do(http.MethodGet, "/runs/"+runID, p, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), runID)
	assert.Len(t, b.jobs(runID, p), 1)
}

func TestStewardAction_SelfProtectResultVisibleOnRunJobs(t *testing.T) {
	n := newActionNode(t)
	p := actionPrincipal("op-1")
	runID := decodeRunID(t, n.postService(p, "steward-svc", n.serviceAction("stop", "steward-svc", actionOpts{})))
	job := n.jobs(runID, p)[0]
	require.NoError(t, n.manager.RecordActionResult(context.Background(), runID, job["job_id"].(string), job["execution_id"].(string), "self_protect"))

	job = n.jobs(runID, p)[0]
	assert.Equal(t, "self_protect", job["result_code"])
	assert.Equal(t, "failed", job["status"])
}

func TestStewardAction_ExpiredJobReadsBackAsExpiredNotRun(t *testing.T) {
	n := newActionNode(t)
	p := actionPrincipal("op-1")
	runID := decodeRunID(t, n.postService(p, "spooler", n.serviceAction("restart", "spooler", actionOpts{})))

	closed, err := n.manager.ExpireActionJobs(context.Background(), time.Now().Add(scriptmodule.StewardActionTTL+time.Minute))
	require.NoError(t, err)
	require.Len(t, closed, 1)

	job := n.jobs(runID, p)[0]
	assert.Equal(t, "expired", job["status"])
	assert.Equal(t, "expired", job["result_code"])
	assert.Equal(t, "expired, not run", job["result_detail"])
}

func TestStewardAction_WebAuthnProofCarriesManifest(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	server := f.server
	manager := newTestRunManager(t)
	queue := newTestRunQueue(t)
	server.SetRunManager(manager, queue)
	server.certManager = newTLSTestCertManager(t)
	ensureSharedSigningCertificate(t, server.certManager)
	acct, err := server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	acct.RootScope = true // the manifest roster is narrowed to operators whose scope covers the steward
	require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
	server.cacheAccount(acct)
	seedScopeTenants(t, server)
	require.NoError(t, server.controllerService.RegisterSteward(saSteward, saTenant, "addr", "active"))
	n := wrapActionNode(t, server, manager, queue)

	a := operatorpayload.Action{Verb: "service.restart", TargetKind: "service", TargetName: "spooler"}
	exp := time.Now().Add(3 * time.Minute).UTC().Truncate(time.Second)
	env := actionEnvelope(t, a, []string{saSteward}, "n-webauthn", exp)
	proof := f.proofFor(t, env)

	p := &Principal{ID: f.username, Name: f.username, TenantID: saTenant, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := n.do(http.MethodPost, "/stewards/"+saSteward+"/services/spooler/actions", p, map[string]interface{}{
		"action": "restart", "justification": "restart", "nonce": "n-webauthn",
		"expires_at": exp.Format(time.RFC3339), "targets": []string{saSteward}, "webauthn": proof.WebAuthn,
	})
	decodeRunID(t, rec)

	entries := queue.PeekForDevice(saSteward)
	require.Len(t, entries, 1)
	md := entries[0].Metadata
	assert.Equal(t, base64.StdEncoding.EncodeToString(proof.WebAuthn.Signature), md["webauthn_signature"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(proof.WebAuthn.CredentialID), md["webauthn_credential_id"])
	assert.NotEmpty(t, md["webauthn_manifest"])
	assert.NotContains(t, md, "signature_value")
}
