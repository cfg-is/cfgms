// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const (
	scriptRunMetachars = "$(touch /tmp/pwned); rm -rf / && echo \"x\" | cat `id` ; \\n"
	msgParamName       = "msg"
)

// scriptRunFixture is a real server with a real script library, approval store, run
// queue, run store and fleet. The library keeps its scripts in the MSP tenant (msp-a,
// the grant tenant); the run tenant is client-1.
type scriptRunFixture struct {
	*readsFixture
	cs        cfgconfig.ConfigStore
	repo      *script.TenantScriptRepository
	approvals *ContentApprovalStore
	queue     *script.ExecutionQueue
}

func newScriptRunFixture(t *testing.T) *scriptRunFixture {
	t.Helper()
	f := &scriptRunFixture{readsFixture: newReadsFixture(t)}
	f.cs = pkgtesting.SetupTestStorage(t).GetConfigStore()

	var err error
	f.repo, err = script.NewTenantScriptRepository(f.cs)
	require.NoError(t, err)
	f.approvals, err = NewContentApprovalStore(f.cs)
	require.NoError(t, err)
	f.queue = script.NewExecutionQueue(nil, nil, 0, "", nil, f.repo, 0)
	t.Cleanup(f.queue.Stop)

	f.srv.SetScriptRepository(f.repo)
	f.srv.SetContentApprovalStore(f.approvals)
	f.srv.SetPrivilegeStore(f.cs)
	f.srv.SetRunManager(controllerrun.NewManager(f.runStore, f.queue), f.queue)

	// Two stewards share the tag "prod" across client-1 and client-2, so a tag
	// selector spans tenants.
	now := time.Now()
	var data []fleet.StewardData
	for id, tn := range map[string]string{
		f.mspSteward: runMSP, f.c1Steward: runClient1, f.siteSteward: runSiteA, f.c2Steward: runClient2,
	} {
		attrs := map[string]string{"hostname": tn + "-host", "os": "linux"}
		if tn == runClient1 || tn == runClient2 {
			attrs["tags"] = "prod"
		}
		data = append(data, fleet.StewardData{ID: id, TenantID: tn, Status: "online", LastHeartbeat: now, DNAAttributes: attrs})
	}
	f.srv.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: data})
	return f
}

func (f *scriptRunFixture) scriptBody(id string) script.VersionedScript {
	return script.VersionedScript{Metadata: &script.ScriptMetadata{
		ID: id, Name: id, Description: "d", Version: &script.Version{Major: 1}, Author: "a",
		Platform: []string{"linux"}, Shell: script.ShellBash, Timeout: time.Minute,
		Parameters: []script.ScriptParameter{
			{Name: "mode", Type: "string", AllowedValues: []string{"a", "b"}},
			{Name: msgParamName, Type: "string"},
			{Name: "count", Type: "int"},
		},
	}}
}

// publish stores version 1.0.0 of a script in the tenant's library.
func (f *scriptRunFixture) publish(t *testing.T, tenantID, id, content string, sig *script.ScriptSignature) *script.VersionedScript {
	t.Helper()
	repo, err := f.repo.ForTenant(tenantID)
	require.NoError(t, err)
	vs := f.scriptBody(id)
	vs.Content, vs.Signature = content, sig
	require.NoError(t, repo.Create(&vs))
	got, err := f.repo.GetForTenant(tenantID, id, "1.0.0")
	require.NoError(t, err)
	return got
}

// publishNext stores a new version of an existing script and returns it.
func (f *scriptRunFixture) publishNext(t *testing.T, tenantID, id string, minor int, content string) *script.VersionedScript {
	t.Helper()
	repo, err := f.repo.ForTenant(tenantID)
	require.NoError(t, err)
	vs := f.scriptBody(id)
	vs.Metadata.Version = &script.Version{Major: 1, Minor: minor}
	vs.Content = content
	require.NoError(t, repo.Update(&vs))
	got, err := f.repo.GetForTenant(tenantID, id, vs.Metadata.Version.String())
	require.NoError(t, err)
	return got
}

func (f *scriptRunFixture) setMode(t *testing.T, tenantID string, mode ApprovalMode) {
	t.Helper()
	require.NoError(t, f.approvals.SetMode(context.Background(), tenantID, LibraryKindScript, mode, "admin"))
}

func (f *scriptRunFixture) approve(t *testing.T, owner string, vs *script.VersionedScript) {
	t.Helper()
	require.NoError(t, f.approvals.PutApproval(context.Background(), ContentApproval{
		TenantID: owner, Kind: LibraryKindScript, ContentID: vs.Metadata.ID, Version: vs.Metadata.Version.String(),
		ContentHash: script.ScriptApprovalHash(owner, vs), ApprovedBy: "admin", Method: ApprovalMethodApproveTap,
	}))
}

// trustKeys makes the tenant trust the given keys for script signing, by writing the
// tenant-level configuration document the configuration service's inheritance
// cascade reads (the same one that builds the configuration a steward enforces).
func (f *scriptRunFixture) trustKeys(t *testing.T, tenantID string, keys ...evalSigner) {
	t.Helper()
	ctx := ctxkeys.WithSystem(context.Background())
	var refs []stewardtypes.TrustedKeyRef
	for _, k := range keys {
		refs = append(refs, stewardtypes.TrustedKeyRef{Name: "k", Thumbprint: k.thumbprint})
	}
	data, err := yaml.Marshal(&stewardtypes.StewardConfig{Steward: stewardtypes.StewardSettings{
		ID:            tenantID,
		ScriptSigning: stewardtypes.ScriptSigningConfig{TrustMode: stewardtypes.TrustModeTrustedKeys, TrustedKeys: refs},
	}})
	require.NoError(t, err)
	path, err := f.srv.tenantManager.GetTenantPath(ctx, tenantID)
	require.NoError(t, err)
	key, ok := pkgconfig.TenantLevelConfigKey(pkgconfig.TenantLevelForDepth(len(path)-1), tenantID)
	require.True(t, ok)
	require.NoError(t, f.srv.configService.GetConfigStore().StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatYAML, CreatedBy: "test", UpdatedBy: "test",
	}))
}

func (f *scriptRunFixture) post(runID string, body any) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, f.runPath(runID, "/scripts"), f.cred, body)
}

func (f *scriptRunFixture) runBody(id string, extra map[string]any) map[string]any {
	body := map[string]any{"target": "id:" + f.c1Steward, "script_id": id}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func (f *scriptRunFixture) queued(deviceID string) []*script.QueuedExecution {
	return f.queue.PeekForDevice(deviceID)
}

func (f *scriptRunFixture) resultRuns(t *testing.T) []*controllerrun.RunRecord {
	t.Helper()
	runs, err := f.runStore.ListRuns(runClient1, 50, 0)
	require.NoError(t, err)
	return runs
}

func (f *scriptRunFixture) assertNothingStarted(t *testing.T) {
	t.Helper()
	assert.Empty(t, f.resultRuns(t), "no run record may exist")
	for _, id := range []string{f.mspSteward, f.c1Steward, f.siteSteward, f.c2Steward} {
		assert.Empty(t, f.queued(id), "nothing may be queued for %s", id)
	}
}

// scriptAudit returns the audit entries of one action filed under the run tenant.
func (f *scriptRunFixture) scriptAudit(t *testing.T, action string) []*business.AuditEntry {
	return f.auditEntries(t, runClient1, action)
}

// [REQUIRED TEST] An approved version of a script owned by the MSP tenant runs for a
// device in client-1 (inherited), the run is readable through the story #5834 routes,
// and the queue resolves the script from the MSP library.
func TestAutomationScriptRun_InheritedApprovedScriptRuns(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	vs := f.publish(t, runMSP, "s1", requestedBody, nil)
	f.approve(t, runMSP, vs)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.post(runID, f.runBody("s1", map[string]any{"params": map[string]any{"mode": "a"}}))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	resp := dataOf[AutomationScriptRunResponse](t, rec)
	assert.Equal(t, runMSP, resp.OwnerTenant, "the response names the owner tenant")
	assert.Equal(t, runClient1, resp.TenantID)
	assert.Equal(t, "1.0.0", resp.Version)
	assert.Equal(t, script.ScriptApprovalHash(runMSP, vs), resp.ApprovalHash)
	assert.Equal(t, 1, resp.DeviceCount)

	// Readable through the read routes of the run.
	got := f.get(f.runPath(runID, "/results/"+resp.RunID), f.cred)
	require.Equal(t, http.StatusOK, got.Code, got.Body.String())
	jobs := f.get(f.runPath(runID, "/results/"+resp.RunID+"/jobs"), f.cred)
	require.Equal(t, http.StatusOK, jobs.Code, jobs.Body.String())
	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonDataOf(t, jobs)), &rows))
	require.Len(t, rows, 1)
	assert.Equal(t, f.c1Steward, rows[0]["device_id"])

	// Only the in-tenant device holds a command, and the queue resolves the script
	// from the MSP library at the pinned version.
	assert.Empty(t, f.queued(f.c2Steward))
	assert.Empty(t, f.queued(f.siteSteward))
	execs, err := f.queue.DequeueForDevice(f.c1Steward)
	require.NoError(t, err)
	require.Len(t, execs, 1)
	prepared, err := f.queue.PrepareExecutionForDevice(context.Background(), f.c1Steward, runClient1, execs[0])
	require.NoError(t, err)
	assert.Equal(t, requestedBody, prepared.ScriptContent, "the steward receives exactly the approved content")
	assert.Equal(t, "1.0.0", prepared.ScriptVersion)
}

func jsonDataOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	return string(env.Data)
}

// [REQUIRED TEST] Omitting the version resolves latest once and evaluates that exact
// version; a changed script (a new latest) answers 409 APPROVAL_PENDING even though an
// older version is approved, and nothing runs. The version resolved from an omitted
// version is the same in the response, the queue pin and the audit event.
func TestAutomationScriptRun_OmittedVersionResolvesLatestOnce(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	v1 := f.publish(t, runMSP, "s1", requestedBody, nil)
	f.approve(t, runMSP, v1)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.post(runID, f.runBody("s1", nil))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	resp := dataOf[AutomationScriptRunResponse](t, rec)
	assert.Equal(t, "1.0.0", resp.Version)

	queued := f.queued(f.c1Steward)
	require.Len(t, queued, 1)
	assert.Equal(t, resp.Version, queued[0].Metadata[script.MetaPinVersion], "the queue pin carries the resolved version")
	assert.Equal(t, resp.ApprovalHash, queued[0].Metadata[script.MetaPinApprovalHash])
	assert.Equal(t, runMSP, queued[0].Metadata[script.MetaPinOwnerTenant])

	ok := f.scriptAudit(t, automationActionScriptRun)
	require.Len(t, ok, 1)
	assert.Equal(t, resp.Version, ok[0].Details["script_version"], "the audit event carries the resolved version")
	assert.Equal(t, resp.ApprovalHash, ok[0].Details["approval_hash"])

	// The script changes: the new latest is not approved, the old one still is.
	v2 := f.publishNext(t, runMSP, "s1", 1, requestedBody+"echo changed\n")
	require.Equal(t, "1.1.0", v2.Metadata.Version.String())
	before := len(f.resultRuns(t))

	pending := f.post(runID, f.runBody("s1", map[string]any{"params": map[string]any{"mode": "b"}}))
	assert.Equal(t, http.StatusConflict, pending.Code, pending.Body.String())
	assert.Equal(t, "APPROVAL_PENDING", codeOf(t, pending))
	assert.Len(t, f.resultRuns(t), before, "the previous approved version must not run")
	assert.Len(t, f.queued(f.c1Steward), 1, "nothing new is queued")

	refused := f.scriptAudit(t, automationActionScriptRun)
	require.Len(t, refused, 2)
	var denied *business.AuditEntry
	for _, e := range refused {
		if e.Result == business.AuditResultDenied {
			denied = e
		}
	}
	require.NotNil(t, denied)
	assert.Equal(t, "1.1.0", denied.Details["script_version"], "the evaluated version is the resolved latest")
	assert.Equal(t, script.ScriptApprovalHash(runMSP, v2), denied.Details["approval_hash"])
	assert.Equal(t, "approval_pending", denied.Details["reason"])

	// The pending change is recorded for the owner tenant.
	recorded, err := f.approvals.ListPending(context.Background(), runMSP)
	require.NoError(t, err)
	require.Len(t, recorded, 1)
	assert.Equal(t, "1.1.0", recorded[0].Version)
	assert.Equal(t, "1.0.0", recorded[0].PreviousVersion)

	// An older approved version is reached only by asking for it by number.
	older := f.post(runID, f.runBody("s1", map[string]any{"version": "1.0.0", "params": map[string]any{"mode": "b"}}))
	require.Equal(t, http.StatusCreated, older.Code, older.Body.String())
	assert.Equal(t, "1.0.0", dataOf[AutomationScriptRunResponse](t, older).Version)

	// Once the new latest is approved, the omitted version resolves to it everywhere.
	f.approve(t, runMSP, v2)
	latest := f.post(runID, f.runBody("s1", map[string]any{"params": map[string]any{"mode": "a"}}))
	require.Equal(t, http.StatusCreated, latest.Code, latest.Body.String())
	lr := dataOf[AutomationScriptRunResponse](t, latest)
	assert.Equal(t, "1.1.0", lr.Version)
	assert.Equal(t, script.ScriptApprovalHash(runMSP, v2), lr.ApprovalHash)
}

// Pending and denied outcomes use distinct codes and nothing is queued; an unknown
// script is a 404 and an unreadable version is a 400.
func TestAutomationScriptRun_OutcomesAreDistinctAndQueueNothing(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	f.publish(t, runMSP, "pending", requestedBody, nil)
	f.publish(t, runMSP, "silent", silentBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	// A script with a bad signature under trusted keys is denied, never pending.
	f.setMode(t, runClient1, ApprovalModeSigned)
	trusted, other := newEvalSigner(t), newEvalSigner(t)
	f.trustKeys(t, runMSP, trusted)
	f.setMode(t, runMSP, ApprovalModeSigned)
	f.publish(t, runMSP, "badsig", requestedBody, other.sign(t, requestedBody))

	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"pending", f.runBody("pending", nil), http.StatusConflict, "APPROVAL_PENDING"},
		{"header does not request pre-approval", f.runBody("silent", nil), http.StatusConflict, "APPROVAL_PENDING"},
		{"denied", f.runBody("badsig", nil), http.StatusForbidden, "CONTENT_NOT_APPROVED"},
		{"unknown script", f.runBody("nope", nil), http.StatusNotFound, "SCRIPT_NOT_FOUND"},
		{"unknown version", f.runBody("pending", map[string]any{"version": "9.9.9"}), http.StatusNotFound, "SCRIPT_NOT_FOUND"},
		{"bad version", f.runBody("pending", map[string]any{"version": "banana"}), http.StatusBadRequest, "INVALID_VERSION"},
		{"no script", map[string]any{"target": "all"}, http.StatusBadRequest, "MISSING_SCRIPT_ID"},
		{"path in script id", f.runBody("../s1", nil), http.StatusBadRequest, "INVALID_REQUEST"},
		{"unknown field", f.runBody("pending", map[string]any{"shell": "powershell"}), http.StatusBadRequest, "INVALID_REQUEST"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := f.post(runID, c.body)
			assert.Equal(t, c.status, rec.Code, rec.Body.String())
			assert.Equal(t, c.code, codeOf(t, rec))
			f.assertNothingStarted(t)
		})
	}
}

// A signed script and an unsigned script, per approval mode.
func TestAutomationScriptRun_ModeTable(t *testing.T) {
	signer := newEvalSigner(t)
	cases := []struct {
		name     string
		mode     ApprovalMode
		signed   bool
		approved bool
		want     int
	}{
		{"comment unsigned", ApprovalModeComment, false, false, http.StatusCreated},
		{"comment signed", ApprovalModeComment, true, false, http.StatusCreated},
		{"approve unsigned no record", ApprovalModeApprove, false, false, http.StatusConflict},
		{"approve signed no record", ApprovalModeApprove, true, false, http.StatusConflict},
		{"approve unsigned with record", ApprovalModeApprove, false, true, http.StatusCreated},
		{"signed signed script", ApprovalModeSigned, true, false, http.StatusCreated},
		{"signed unsigned script no record", ApprovalModeSigned, false, false, http.StatusConflict},
		{"signed unsigned script with record", ApprovalModeSigned, false, true, http.StatusCreated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newScriptRunFixture(t)
			f.setMode(t, runMSP, c.mode)
			f.trustKeys(t, runMSP, signer)
			var sig *script.ScriptSignature
			if c.signed {
				sig = signer.sign(t, requestedBody)
			}
			vs := f.publish(t, runMSP, "s1", requestedBody, sig)
			if c.approved {
				f.approve(t, runMSP, vs)
			}
			runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
			rec := f.post(runID, f.runBody("s1", nil))
			assert.Equal(t, c.want, rec.Code, rec.Body.String())
			if c.want != http.StatusCreated {
				f.assertNothingStarted(t)
			}
		})
	}
}

// [REQUIRED TEST] A target outside the bound tenant refuses the whole request: a
// client-1 run against a device in client-2, a device in client-1/site-a, a device
// above it, a mix of in-tenant and out-of-tenant devices, and a group or filter that
// would span tenants. An id that matches no device is refused the same way.
func TestAutomationScriptRun_TargetOutsideTenantRefusesWholeRequest(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	for name, target := range map[string]string{
		"device in client-2":          "id:" + f.c2Steward,
		"device in client-1/site-a":   "id:" + f.siteSteward,
		"device in the grant tenant":  "id:" + f.mspSteward,
		"in-tenant and out-of-tenant": "id:" + f.c1Steward + "," + f.c2Steward,
		"tag spanning tenants":        "tag:prod",
		"os filter spanning tenants":  "os:linux",
		"unknown id":                  "id:no-such-device",
		"in-tenant and unknown":       "id:" + f.c1Steward + ",no-such-device",
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.post(runID, map[string]any{"target": target, "script_id": "s1"})
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "TARGET_OUT_OF_TENANT", codeOf(t, rec))
			f.assertNothingStarted(t)
		})
	}

	t.Run("malformed selector", func(t *testing.T) {
		rec := f.post(runID, map[string]any{"target": "bogus:x", "script_id": "s1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "INVALID_TARGET", codeOf(t, rec))
		f.assertNothingStarted(t)
	})

	t.Run("a tenant named in the body is refused by the run binding", func(t *testing.T) {
		rec := f.post(runID, map[string]any{"target": "id:" + f.c2Steward, "script_id": "s1", "tenant_id": runClient2})
		assert.Equal(t, http.StatusForbidden, rec.Code)
		f.assertNothingStarted(t)
	})

	// The whole-tenant selectors run on the run tenant's own devices only.
	for _, target := range []string{"", "all"} {
		rec := f.post(runID, map[string]any{"target": target, "script_id": "s1"})
		require.Equal(t, http.StatusCreated, rec.Code, "target %q: %s", target, rec.Body.String())
		assert.Equal(t, 1, dataOf[AutomationScriptRunResponse](t, rec).DeviceCount)
	}
	assert.Empty(t, f.queued(f.c2Steward))
	assert.Empty(t, f.queued(f.siteSteward))
	assert.Empty(t, f.queued(f.mspSteward))
}

// A target that matches no device in the run tenant is a 404 that queues nothing.
func TestAutomationScriptRun_NoDevicesInRunTenant(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	f.srv.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{})
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.post(runID, map[string]any{"target": "all", "script_id": "s1"})
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Equal(t, "NO_TARGETS", codeOf(t, rec))
	f.assertNothingStarted(t)
}

// [REQUIRED TEST] A grant run refuses a secret-store param binding, an undeclared
// param name and a value outside AllowedValues, and delivers a value holding shell
// metacharacters as data.
func TestAutomationScriptRun_Params(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	refused := []struct {
		name   string
		params map[string]any
		reason string
	}{
		{"secret-store binding", map[string]any{msgParamName: map[string]any{"from": "secret-store", "key": "k"}}, "param_binding_refused"},
		{"secret-store binding with a value", map[string]any{msgParamName: map[string]any{"from": "secret-store", "key": "k", "value": "v"}}, "param_binding_refused"},
		{"binding without a source", map[string]any{msgParamName: map[string]any{"value": "v"}}, "param_binding_refused"},
		{"undeclared name", map[string]any{"nope": "x"}, "param_undeclared"},
		{"undeclared name next to a declared one", map[string]any{"mode": "a", "CFGMS_API_KEY": "x"}, "param_undeclared"},
		{"value outside AllowedValues", map[string]any{"mode": "c"}, "param_value_not_allowed"},
		{"value differs only in case", map[string]any{"mode": "A"}, "param_value_not_allowed"},
		{"value of the wrong type", map[string]any{"count": "many"}, "param_type_mismatch"},
		{"not a string", map[string]any{msgParamName: 5}, "param_value_invalid"},
		{"list value", map[string]any{msgParamName: []string{"a"}}, "param_value_invalid"},
		{"null value", map[string]any{msgParamName: nil}, "param_value_invalid"},
		{"oversized value", map[string]any{msgParamName: strings.Repeat("x", automationParamValueMaxLen+1)}, "param_value_invalid"},
		{"NUL in value", map[string]any{msgParamName: "a\x00b"}, "param_value_invalid"},
	}
	for i, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			// One run per case, so its audit entry is the only one of the run.
			caseRun := f.beginOK(t, f.cred, runClient1, "ticket-param-"+strconv.Itoa(i))
			rec := f.post(caseRun, f.runBody("s1", map[string]any{"params": c.params}))
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, "PARAM_REFUSED", codeOf(t, rec))
			f.assertNothingStarted(t)
			var reasons []any
			for _, e := range f.scriptAudit(t, automationActionScriptRun) {
				if e.ResourceID == caseRun {
					reasons = append(reasons, e.Details["reason"])
				}
			}
			assert.Equal(t, []any{c.reason}, reasons)
			require.Equal(t, http.StatusOK, f.do(http.MethodPost, "/api/v1/automation/runs/"+caseRun+"/end", f.cred, nil).Code)
		})
	}

	t.Run("a literal binding and metacharacters are delivered as data", func(t *testing.T) {
		rec := f.post(runID, f.runBody("s1", map[string]any{"params": map[string]any{
			msgParamName: scriptRunMetachars,
			"mode":       map[string]any{"from": "literal", "value": "b"},
			"count":      "42",
		}}))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		execs, err := f.queue.DequeueForDevice(f.c1Steward)
		require.NoError(t, err)
		require.Len(t, execs, 1)
		assert.Equal(t, scriptRunMetachars, execs[0].Parameters[msgParamName], "the value is stored as is")
		assert.Equal(t, "b", execs[0].Parameters["mode"])
		assert.Equal(t, "42", execs[0].Parameters["count"])

		prepared, err := f.queue.PrepareExecutionForDevice(context.Background(), f.c1Steward, runClient1, execs[0])
		require.NoError(t, err)
		assert.Equal(t, requestedBody, prepared.ScriptContent, "the value is never interpolated into the script text")
		assert.NotContains(t, prepared.ScriptContent, "pwned")
	})
}

func TestValidateGrantParams(t *testing.T) {
	meta := &script.ScriptMetadata{Parameters: []script.ScriptParameter{
		{Name: "need", Type: "string", Required: true},
		{Name: "dflt", Type: "bool", Required: true, Default: true},
		{Name: "dna", Type: "string", Required: true, DNAPath: "os.name"},
		{Name: "n", Type: "int"},
		{Name: "f", Type: "float"},
		{Name: "odd", Type: "weird"},
	}}
	raw := func(m map[string]string) map[string]json.RawMessage {
		out := map[string]json.RawMessage{}
		for k, v := range m {
			b, _ := json.Marshal(v)
			out[k] = b
		}
		return out
	}

	got, refusal := validateGrantParams(meta, raw(map[string]string{"need": "x", "n": "-3", "f": "1.5"}))
	require.Nil(t, refusal)
	assert.Equal(t, map[string]string{"need": "x", "n": "-3", "f": "1.5"}, got)

	_, refusal = validateGrantParams(meta, raw(nil))
	require.NotNil(t, refusal)
	assert.Equal(t, "param_required_missing", refusal.reason)

	for _, bad := range []map[string]string{
		{"need": "x", "n": "1.5"}, {"need": "x", "f": "abc"}, {"need": "x", "odd": "v"},
	} {
		_, refusal = validateGrantParams(meta, raw(bad))
		require.NotNil(t, refusal, "%v", bad)
		assert.Equal(t, "param_type_mismatch", refusal.reason)
	}
	assert.True(t, paramMatchesType("Boolean", "true"))
	assert.False(t, paramMatchesType("bool", "yes please"))
}

// [REQUIRED TEST] A script with a non-empty RequiredAPIScope is refused under a grant,
// both when the run is requested and, if the privilege metadata changes after the
// evaluation, when the queue prepares the command.
func TestAutomationScriptRun_RequiredAPIScopeRefused(t *testing.T) {
	storeScope := func(t *testing.T, f *scriptRunFixture, owner, id string) {
		t.Helper()
		raw, err := json.Marshal(ScriptPrivilegeMetadata{ScriptID: id, RequiredAPIScope: []string{"read:devices"}})
		require.NoError(t, err)
		require.NoError(t, f.cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
			Key:  &cfgconfig.ConfigKey{TenantID: owner, Namespace: privilegeNamespace, Name: id},
			Data: raw, Format: cfgconfig.ConfigFormatJSON,
		}))
	}

	t.Run("at the route", func(t *testing.T) {
		f := newScriptRunFixture(t)
		f.setMode(t, runMSP, ApprovalModeComment)
		f.publish(t, runMSP, "s1", requestedBody, nil)
		storeScope(t, f, runMSP, "s1")
		runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

		rec := f.post(runID, f.runBody("s1", nil))
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, "CONTENT_NOT_APPROVED", codeOf(t, rec))
		f.assertNothingStarted(t)
	})

	t.Run("added after the evaluation, refused at queue prepare", func(t *testing.T) {
		f := newScriptRunFixture(t)
		f.setMode(t, runMSP, ApprovalModeComment)
		f.publish(t, runMSP, "s1", requestedBody, nil)
		runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
		rec := f.post(runID, f.runBody("s1", nil))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		storeScope(t, f, runMSP, "s1")
		execs, err := f.queue.DequeueForDevice(f.c1Steward)
		require.NoError(t, err)
		require.Len(t, execs, 1)
		_, err = f.queue.PrepareExecutionForDevice(context.Background(), f.c1Steward, runClient1, execs[0])
		require.ErrorIs(t, err, script.ErrAPIScopeNotGrantable)
	})
}

// [REQUIRED TEST] Revoking the grant, or ending the run, cancels commands that are
// queued but not yet dispatched.
func TestAutomationScriptRun_RevokeOrEndCancelsQueuedCommands(t *testing.T) {
	start := func(t *testing.T) (*scriptRunFixture, string) {
		f := newScriptRunFixture(t)
		f.setMode(t, runMSP, ApprovalModeComment)
		f.publish(t, runMSP, "s1", requestedBody, nil)
		runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
		rec := f.post(runID, f.runBody("s1", nil))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		require.Len(t, f.queued(f.c1Steward), 1)
		return f, runID
	}

	t.Run("ending the run", func(t *testing.T) {
		f, runID := start(t)
		require.Equal(t, http.StatusOK, f.do(http.MethodPost, "/api/v1/automation/runs/"+runID+"/end", f.cred, nil).Code)
		execs, err := f.queue.DequeueForDevice(f.c1Steward)
		require.NoError(t, err)
		assert.Empty(t, execs, "an ended run's command is not dispatched")
		assert.Empty(t, f.queued(f.c1Steward), "the command is cancelled, not left queued")
	})

	t.Run("revoking the grant", func(t *testing.T) {
		f, _ := start(t)
		_, err := f.store.Revoke(context.Background(), runMSP, f.grant.ID, "admin-1")
		require.NoError(t, err)
		execs, err := f.queue.DequeueForDevice(f.c1Steward)
		require.NoError(t, err)
		assert.Empty(t, execs, "a revoked grant's command is not dispatched")
		assert.Empty(t, f.queued(f.c1Steward))
	})

	t.Run("revoking the grant also stops the last check before the bytes are sent", func(t *testing.T) {
		f, _ := start(t)
		execs, err := f.queue.DequeueForDevice(f.c1Steward)
		require.NoError(t, err)
		require.Len(t, execs, 1)
		_, err = f.store.Revoke(context.Background(), runMSP, f.grant.ID, "admin-1")
		require.NoError(t, err)
		_, err = f.queue.PrepareExecutionForDevice(context.Background(), f.c1Steward, runClient1, execs[0])
		require.ErrorIs(t, err, script.ErrGuardFailed)
	})
}

// Every outcome writes an audit event with grant, run, event ref, owner tenant, script
// id and approval hash.
func TestAutomationScriptRun_AuditNamesGrantRunEventOwnerAndHash(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	v1 := f.publish(t, runMSP, "s1", requestedBody, nil)
	f.publish(t, runMSP, "s2", requestedBody, nil)
	f.approve(t, runMSP, v1)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-audit")

	require.Equal(t, http.StatusCreated, f.post(runID, f.runBody("s1", nil)).Code)
	require.Equal(t, http.StatusConflict, f.post(runID, f.runBody("s2", nil)).Code)
	require.Equal(t, http.StatusForbidden, f.post(runID, map[string]any{"target": "id:" + f.c2Steward, "script_id": "s1"}).Code)

	byReason := map[string]*business.AuditEntry{}
	for _, e := range f.scriptAudit(t, automationActionScriptRun) {
		reason, _ := e.Details["reason"].(string)
		byReason[reason] = e
		assert.Equal(t, f.grant.ID, e.Details["grant_id"], reason)
		assert.Equal(t, runID, e.Details["run_id"], reason)
		assert.Equal(t, "ticket-audit", e.Details["event_ref"], reason)
		assert.Equal(t, runClient1, e.Details["tenant_id"], reason)
		assert.Equal(t, runMSP, e.Details["script_owner_tenant"], reason)
		assert.NotEmpty(t, e.Details["script_id"], reason)
		assert.NotEmpty(t, e.Details["approval_hash"], reason)
	}
	require.Len(t, byReason, 3)
	assert.Equal(t, business.AuditResultSuccess, byReason[""].Result)
	assert.Equal(t, script.ScriptApprovalHash(runMSP, v1), byReason[""].Details["approval_hash"])
	assert.NotEmpty(t, byReason[""].Details["result_run_id"])
	assert.Equal(t, business.AuditResultDenied, byReason["approval_pending"].Result)
	assert.Equal(t, "s2", byReason["approval_pending"].Details["script_id"])
	assert.Equal(t, business.AuditResultDenied, byReason["target_outside_run_tenant"].Result)
}

// [REQUIRED TEST] Grant-started script runs cannot be created through the human run
// route or the unrestricted workflow path: the human routes refuse a grant principal.
func TestAutomationScriptRun_HumanRoutesRefuseGrant(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	f.beginOK(t, f.cred, runClient1, "ticket-1")

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/runs/script"},
		{http.MethodPost, "/api/v1/runs/command"},
		{http.MethodGet, "/api/v1/runs"},
		{http.MethodPost, "/api/v1/jobs"},
		{http.MethodPost, "/api/v1/workflows/wf1/versions/1.0.0/publish/begin"},
	} {
		rec := f.do(c.method, c.path, f.cred, map[string]any{"target": "id:" + f.c1Steward, "script_id": "s1"})
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
		assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec), "%s %s", c.method, c.path)
	}
	f.assertNothingStarted(t)

	// The two script routes are admitted by method and template, and only those.
	var scriptRoutes []string
	for _, rt := range automationRouteTable() {
		if rt.template == automationScriptsTemplate {
			scriptRoutes = append(scriptRoutes, rt.method)
		}
	}
	assert.ElementsMatch(t, []string{http.MethodGet, http.MethodPost}, scriptRoutes)
	assert.False(t, automationRouteAllowed(http.MethodDelete, automationScriptsTemplate))
	assert.False(t, automationRouteAllowed(http.MethodPut, automationScriptsTemplate))
}

// A run that is not open, another grant's run and a request that names another tenant
// never reach the script handler.
func TestAutomationScriptRun_RequiresAnOpenRunOfTheGrant(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	otherGrant, otherCred := f.newGrant(t, runMSP)
	_ = otherGrant

	rec := f.do(http.MethodPost, f.runPath(runID, "/scripts"), otherCred, f.runBody("s1", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "AUTOMATION_RUN_DENIED", codeOf(t, rec))

	rec = f.do(http.MethodPost, f.runPath(runID, "/scripts"), "", f.runBody("s1", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	require.Equal(t, http.StatusOK, f.do(http.MethodPost, "/api/v1/automation/runs/"+runID+"/end", f.cred, nil).Code)
	rec = f.post(runID, f.runBody("s1", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "AUTOMATION_RUN_DENIED", codeOf(t, rec))
	f.assertNothingStarted(t)
}

// A grant tenant above the owner is a ceiling: a script held only above the grant
// tenant is not visible to the run.
func TestAutomationScriptRun_GrantTenantIsTheLibraryCeiling(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, testRootTenantID, ApprovalModeComment)
	f.publish(t, testRootTenantID, "rootonly", requestedBody, nil)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.post(runID, f.runBody("rootonly", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Equal(t, "SCRIPT_NOT_FOUND", codeOf(t, rec))
	f.assertNothingStarted(t)

	list := f.get(f.runPath(runID, "/scripts"), f.cred)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	ids := []string{}
	for _, e := range dataOf[[]AutomationScriptEntry](t, list) {
		ids = append(ids, e.ScriptID)
	}
	assert.Equal(t, []string{"s1"}, ids)
}

// A service that is not wired answers 503 and starts nothing.
func TestAutomationScriptRun_UnwiredServicesAnswer503(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeComment)
	f.publish(t, runMSP, "s1", requestedBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	f.srv.SetScriptRepository(nil)
	rec := f.post(runID, f.runBody("s1", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusServiceUnavailable, f.get(f.runPath(runID, "/scripts"), f.cred).Code)

	f.srv.SetScriptRepository(f.repo)
	f.srv.SetRunManager(nil, nil)
	rec = f.post(runID, f.runBody("s1", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	f.assertNothingStarted(t)
}

// The list route returns the scripts of the library chain with each script's owner and
// evaluator state, nearest copy first, and audits the call.
func TestAutomationScriptRun_ListShowsOwnerAndState(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	f.setMode(t, runClient1, ApprovalModeApprove)
	approved := f.publish(t, runMSP, "approved", requestedBody, nil)
	f.approve(t, runMSP, approved)
	f.publish(t, runMSP, "waiting", requestedBody, nil)
	f.publish(t, runMSP, "shadowed", requestedBody, nil)
	f.publish(t, runClient1, "shadowed", silentBody, nil)
	f.publish(t, runClient2, "elsewhere", requestedBody, nil)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.get(f.runPath(runID, "/scripts"), f.cred)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	got := map[string]AutomationScriptEntry{}
	for _, e := range dataOf[[]AutomationScriptEntry](t, rec) {
		got[e.ScriptID] = e
	}
	require.Len(t, got, 3, "client-2's own library is not visible")
	assert.Equal(t, ContentDecisionApproved, got["approved"].State)
	assert.Equal(t, runMSP, got["approved"].OwnerTenant)
	assert.Equal(t, "1.0.0", got["approved"].Version)
	assert.Equal(t, script.ScriptApprovalHash(runMSP, approved), got["approved"].ApprovalHash)
	assert.Equal(t, ContentDecisionPending, got["waiting"].State)
	assert.Equal(t, runClient1, got["shadowed"].OwnerTenant, "the nearest copy wins")
	assert.Equal(t, ContentDecisionPending, got["shadowed"].State, "its own header does not request pre-approval")
	assert.NotContains(t, rec.Body.String(), requestedBody, "no script text is listed")

	assert.Len(t, f.scriptAudit(t, automationActionScriptList), 1)
}

// The evaluator is the owner's: a script owned by the MSP and approved there runs for
// client-1 even when client-1 itself has a different mode, and an approval recorded
// for the run tenant (not the owner) does not approve the owner's script.
func TestAutomationScriptRun_ApprovalIsTheOwners(t *testing.T) {
	f := newScriptRunFixture(t)
	f.setMode(t, runMSP, ApprovalModeApprove)
	f.setMode(t, runClient1, ApprovalModeComment)
	vs := f.publish(t, runMSP, "s1", requestedBody, nil)
	f.approve(t, runClient1, vs) // an approval in the wrong tenant
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.post(runID, f.runBody("s1", nil))
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "APPROVAL_PENDING", codeOf(t, rec))
	f.assertNothingStarted(t)
}
