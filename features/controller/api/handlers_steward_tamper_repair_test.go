// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// recordingRepairSender stands in for the control-plane provider: it records the
// RepairRequests a connected steward would receive.
type recordingRepairSender struct {
	mu   sync.Mutex
	sent map[string][]controlplaneTypes.RepairRequest
	err  error
}

func (r *recordingRepairSender) SendRepair(_ context.Context, id string, req controlplaneTypes.RepairRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.sent == nil {
		r.sent = map[string][]controlplaneTypes.RepairRequest{}
	}
	r.sent[id] = append(r.sent[id], req)
	return nil
}

func (r *recordingRepairSender) requests(id string) []controlplaneTypes.RepairRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]controlplaneTypes.RepairRequest(nil), r.sent[id]...)
}

func (r *recordingRepairSender) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

// repairEnv is a tamper environment with a real nonce store, pending-refresh
// store, signing certificate and signer chain builder.
type repairEnv struct {
	*tamperEnv
	sender  *recordingRepairSender
	signer  signature.Signer
	certDir string
}

func newRepairEnv(t *testing.T) *repairEnv {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	certDir := filepath.Join(t.TempDir(), "certs")
	certMgr := newSharedTestCertManagerAt(t, certDir)
	ensureSharedSigningCertificate(t, certMgr)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)

	base := &cloneEnv{server: server, steward: stewardSt, certMgr: certMgr, tokenSt: tokenStore}
	ld := fleet.NewLockdown(stewardSt, logging.NewNoopLogger())
	tsender := &recordingTamperSender{}
	ld.SetSender(tsender)
	server.SetTamperStateNotifier(ld)
	server.SetRegistry(registry.NewRegistry())

	storage := pkgtesting.SetupTestStorage(t)
	require.NotNil(t, storage.GetNonceStore())
	server.SetNonceStore(storage.GetNonceStore())
	server.SetPendingRefreshStore(storage.GetPendingRefreshStore())

	signer := signature.NewDynamicSigner(service.NewSigningResolver(certMgr))
	sender := &recordingRepairSender{}
	server.SetRepairDelivery(sender, signer, commands.NewSignerChainBuilder(certMgr))
	return &repairEnv{
		tamperEnv: &tamperEnv{cloneEnv: base, lockdown: ld, sender: tsender},
		sender:    sender, signer: signer, certDir: certDir,
	}
}

func (e *repairEnv) postRepair(id, callerTenant string, approved []string) *httptest.ResponseRecorder {
	return callClone(e.server.handleRepairTamperedSteward, http.MethodPost, "/api/v1/stewards/"+id+"/tamper/repair",
		map[string]string{"id": id}, callerTenant, map[string]interface{}{"reason": "stolen laptop recovered", "approved_loss_codes": approved})
}

func (e *repairEnv) getRepair(id, callerTenant string) *httptest.ResponseRecorder {
	return callClone(e.server.handleGetTamperRepair, http.MethodGet, "/api/v1/stewards/"+id+"/tamper/repair",
		map[string]string{"id": id}, callerTenant, nil)
}

func (e *repairEnv) requestRepair(t *testing.T, id string, approved []string) repairAcceptedResponse {
	t.Helper()
	rec := e.postRepair(id, cloneTenant, approved)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp repairAcceptedResponse
	decodeTamperData(t, rec, &resp)
	return resp
}

func (e *repairEnv) repairStatus(t *testing.T, id string) repairStatusResponse {
	t.Helper()
	rec := e.getRepair(id, cloneTenant)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp repairStatusResponse
	decodeTamperData(t, rec, &resp)
	return resp
}

// progress records a steward-reported repair event the way the heartbeat service
// does.
func (e *repairEnv) progress(t *testing.T, id, action, repairID string, codes ...string) {
	t.Helper()
	rec, err := e.steward.GetSteward(context.Background(), id)
	require.NoError(t, err)
	e.server.recordRepairAudit(context.Background(), rec, action, business.AuditResultSuccess,
		map[string]interface{}{"repair_id": repairID, "codes": codes})
	require.NoError(t, e.server.auditManager.Flush(context.Background()))
}

// addTamperedWithKey registers a tampered steward whose identity key is a real
// file-backed device key.
func (e *repairEnv) addTamperedWithKey(t *testing.T, id string, ks *identity.FileKeyStore, level string, lossCodes ...string) {
	t.Helper()
	pub, alg, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	raw, err := identity.EncodePublicKeyBytes(alg, pub)
	require.NoError(t, err)
	rec := &business.StewardRecord{
		ID: id, TenantID: cloneTenant, Status: business.StewardStatusTampered, DeviceID: ks.DeviceID(),
		IdentityKeyPub: raw, KeyProtectionLevel: level, KeyAlgorithm: string(alg),
		LastHeartbeatAt: time.Now().UTC(),
	}
	for _, c := range lossCodes {
		rec.HealthReasons = append(rec.HealthReasons, business.HealthReasonRecord{Component: "repair", Code: c})
	}
	require.NoError(t, e.steward.RegisterSteward(context.Background(), rec))
}

func newDeviceKey(t *testing.T) *identity.FileKeyStore {
	t.Helper()
	ks, err := identity.NewFileKeyStoreForTesting(t.TempDir())
	require.NoError(t, err)
	return ks
}

func (e *repairEnv) nonceLive(t *testing.T, stewardID, repairID string) bool {
	t.Helper()
	// Reading consumes; put it back so the caller's state is unchanged.
	raw, found, err := e.server.nonceStore.GetAndConsumeNonce(context.Background(), repairRequestKey(stewardID, repairID))
	require.NoError(t, err)
	if found {
		require.NoError(t, e.server.nonceStore.PutNonce(context.Background(), repairRequestKey(stewardID, repairID), raw, time.Hour))
	}
	return found
}

// verifyRepairSignature checks req under the first certificate of its chain and
// that the chain ends in a self-signed root.
func verifyRepairSignature(t *testing.T, stewardID string, req controlplaneTypes.RepairRequest, alg signature.Algorithm) {
	t.Helper()
	require.NotEmpty(t, req.SignerChainPEM)
	certs, err := cert.ParseCertificateChainFromPEM(req.SignerChainPEM)
	require.NoError(t, err)
	require.NotEmpty(t, certs)
	root := certs[len(certs)-1]
	require.NoError(t, root.CheckSignatureFrom(root), "the chain ends in a self-signed root")
	v, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw}),
	})
	require.NoError(t, err)
	payload := controlplaneTypes.RepairSigningPayload(stewardID, req.RepairID, req.LossDigest, req.ExpiresAtUnix)
	require.NoError(t, v.Verify(payload, &signature.ConfigSignature{
		Algorithm: alg, Signature: base64.StdEncoding.EncodeToString(req.Signature),
	}))
	// Another steward's ID, a changed digest or a changed expiry does not verify.
	assert.Error(t, v.Verify(controlplaneTypes.RepairSigningPayload("other", req.RepairID, req.LossDigest, req.ExpiresAtUnix),
		&signature.ConfigSignature{Algorithm: alg, Signature: base64.StdEncoding.EncodeToString(req.Signature)}))
}

func TestLossDigest_SortedAndFixedForEmptySet(t *testing.T) {
	a := controlplaneTypes.LossDigest([]string{"repair.loss.local_logs", "repair.loss.action_history"})
	b := controlplaneTypes.LossDigest([]string{"repair.loss.action_history", "repair.loss.local_logs"})
	assert.Equal(t, a, b, "order does not matter")
	assert.Len(t, a, 64)
	empty := controlplaneTypes.LossDigest(nil)
	assert.Equal(t, empty, controlplaneTypes.LossDigest([]string{}))
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty, "the empty set has the SHA-256 of the empty string")
	assert.NotEqual(t, a, empty)
}

func TestRepair_ConnectedSteward_SendsSignedRequest(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-rep-conn", cloneTenant, cloneDeviceA, time.Second)

	before := time.Now()
	resp := env.requestRepair(t, "s-rep-conn", nil)
	assert.Equal(t, repairStateWaiting, resp.State)
	assert.True(t, resp.Delivered)
	assert.Len(t, resp.RepairID, 32, "128-bit random repair id")
	assert.Contains(t, resp.Note, "contested", "the residual race is stated in the response")

	sent := env.sender.requests("s-rep-conn")
	require.Len(t, sent, 1)
	assert.Equal(t, resp.RepairID, sent[0].RepairID)
	assert.Equal(t, controlplaneTypes.LossDigest(nil), sent[0].LossDigest)
	assert.WithinDuration(t, before.Add(repairRequestTTL), time.Unix(sent[0].ExpiresAtUnix, 0), 5*time.Second)
	verifyRepairSignature(t, "s-rep-conn", sent[0], env.signer.Algorithm())

	entries := env.auditActions(t, auditActionTamperRepairRequested)
	require.Len(t, entries, 1)
	assert.Equal(t, "operator", entries[0].UserID)
	assert.Equal(t, resp.RepairID, entries[0].Details["repair_id"])
	assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-rep-conn"), "requesting a repair does not change the status")
}

func TestRepair_OfflineSteward_WaitsAndIsSentOnConnect(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-rep-off", cloneTenant, cloneDeviceA, time.Second)
	env.sender.setErr(errors.New("steward not connected"))

	resp := env.requestRepair(t, "s-rep-off", nil)
	assert.False(t, resp.Delivered)
	assert.Equal(t, repairStateWaiting, env.repairStatus(t, "s-rep-off").State)
	assert.Empty(t, env.sender.requests("s-rep-off"))

	env.sender.setErr(nil)
	require.NoError(t, env.server.DeliverPendingRepair(context.Background(), "s-rep-off"))
	sent := env.sender.requests("s-rep-off")
	require.Len(t, sent, 1)
	assert.Equal(t, resp.RepairID, sent[0].RepairID, "the same repair id")
	verifyRepairSignature(t, "s-rep-off", sent[0], env.signer.Algorithm())

	// Still unresolved: a later connect is sent it again.
	require.NoError(t, env.server.DeliverPendingRepair(context.Background(), "s-rep-off"))
	assert.Len(t, env.sender.requests("s-rep-off"), 2)

	// A steward that already completed is not sent it again.
	env.progress(t, "s-rep-off", auditActionTamperRepairCompleted, resp.RepairID)
	require.NoError(t, env.server.DeliverPendingRepair(context.Background(), "s-rep-off"))
	assert.Len(t, env.sender.requests("s-rep-off"), 2)
}

func TestRepair_PendingRequestIsNotSentAfterFailureCancelOrRestore(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-rep-end", cloneTenant, cloneDeviceA, time.Second)
	env.sender.setErr(errors.New("offline"))
	resp := env.requestRepair(t, "s-rep-end", nil)
	env.sender.setErr(nil)

	env.progress(t, "s-rep-end", auditActionTamperRepairFailed, resp.RepairID, controlplaneTypes.ReasonCodeRepairFailed)
	require.NoError(t, env.server.DeliverPendingRepair(context.Background(), "s-rep-end"))
	assert.Empty(t, env.sender.requests("s-rep-end"), "a failed repair is not retried on connect")

	// A steward that is no longer tampered is sent nothing either.
	env.addTampered(t, "s-rep-act", cloneTenant, cloneDeviceB, time.Second)
	env.sender.setErr(errors.New("offline"))
	env.requestRepair(t, "s-rep-act", nil)
	env.sender.setErr(nil)
	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", "s-rep-act", cloneTenant, nil).Code)
	require.NoError(t, env.server.DeliverPendingRepair(context.Background(), "s-rep-act"))
	assert.Empty(t, env.sender.requests("s-rep-act"))
}

func TestRepair_LossGate(t *testing.T) {
	const logs, history = controlplaneTypes.ReasonCodeRepairLossLocalLogs, controlplaneTypes.ReasonCodeRepairLossActionHistory

	for name, approval := range map[string][]string{
		"empty":     nil,
		"different": {history},
		"superset":  {logs, history},
	} {
		t.Run("refused/"+name, func(t *testing.T) {
			env := newRepairEnv(t)
			env.addTampered(t, "s-loss", cloneTenant, cloneDeviceA, time.Second, logs)
			rec := env.postRepair("s-loss", cloneTenant, approval)
			require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
			var got repairLossApprovalRequiredResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, "loss_approval_required", got.Error)
			assert.Equal(t, []string{logs}, got.LossCodes)

			// Nothing is stored, sent or audited.
			assert.Empty(t, env.sender.requests("s-loss"))
			assert.Empty(t, env.auditActions(t, auditActionTamperRepairRequested))
			assert.Equal(t, http.StatusNotFound, env.getRepair("s-loss", cloneTenant).Code)
			assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-loss"))
		})
	}

	t.Run("exact set proceeds with the matching digest", func(t *testing.T) {
		env := newRepairEnv(t)
		env.addTampered(t, "s-loss", cloneTenant, cloneDeviceA, time.Second, history, logs, "tamper.data_dir")
		resp := env.requestRepair(t, "s-loss", []string{logs, history})
		assert.Equal(t, []string{history, logs}, resp.LossCodes)
		sent := env.sender.requests("s-loss")
		require.Len(t, sent, 1)
		assert.Equal(t, controlplaneTypes.LossDigest([]string{logs, history}), sent[0].LossDigest)
		assert.Equal(t, []string{history, logs}, sent[0].ApprovedLossCodes)
		assert.Equal(t, []string{history, logs}, env.repairStatus(t, "s-loss").LossCodes)
	})

	t.Run("no loss codes proceeds with an empty approval", func(t *testing.T) {
		env := newRepairEnv(t)
		env.addTampered(t, "s-noloss", cloneTenant, cloneDeviceA, time.Second, "tamper.data_dir")
		env.requestRepair(t, "s-noloss", []string{})
		assert.Len(t, env.sender.requests("s-noloss"), 1)
	})

	t.Run("an unknown approval code is a bad request", func(t *testing.T) {
		env := newRepairEnv(t)
		env.addTampered(t, "s-bad", cloneTenant, cloneDeviceA, time.Second)
		rec := env.postRepair("s-bad", cloneTenant, []string{"repair.loss.everything"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestRepair_RefusedForUnknownScopeAndStatus(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-scope", cloneTenant, cloneDeviceA, time.Second)
	assert.Equal(t, http.StatusNotFound, env.postRepair("s-scope", "tenant-other", nil).Code, "outside the caller's tenant scope")
	assert.Equal(t, http.StatusNotFound, env.postRepair("s-nobody", cloneTenant, nil).Code)

	env.addSteward(t, "s-active", cloneTenant, cloneDeviceB, business.StewardStatusActive)
	rec := env.postRepair("s-active", cloneTenant, nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "STEWARD_NOT_TAMPERED")

	env.addTampered(t, "s-banned", cloneTenant, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", time.Second)
	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", "s-banned", cloneTenant, nil).Code)
	rec = env.postRepair("s-banned", cloneTenant, nil)
	assert.Equal(t, http.StatusConflict, rec.Code, "a banned steward is refused")
	assert.Empty(t, env.sender.requests("s-banned"))
	assert.Empty(t, env.sender.requests("s-scope"))
}

func TestRepair_RoleWithoutPermissionGets403AndRegistryListsIt(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-perm", cloneTenant, cloneDeviceA, time.Second)
	for name, h := range map[string]http.HandlerFunc{"POST": env.server.handleRepairTamperedSteward, "GET": env.server.handleGetTamperRepair} {
		guarded := env.server.requirePermission("steward", "tamper-repair")(h)
		req := httptest.NewRequest(name, "/api/v1/stewards/s-perm/tamper/repair", nil)
		req = withVars(req, map[string]string{"id": "s-perm"})
		req = withPrincipal(req, &Principal{ID: "viewer", Assurance: session.AssuranceStrong, TenantID: cloneTenant})
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code, name+": "+w.Body.String())
	}
	assert.Empty(t, env.sender.requests("s-perm"))

	assert.True(t, knownPermissions["steward:tamper-repair"])
	req, ok := permissionAssurance["steward:tamper-repair"]
	require.True(t, ok)
	assert.Equal(t, session.AssuranceStrong, req.Min)
}

func TestRepair_ParallelWithBan_ExactlyOneWins(t *testing.T) {
	for i := 0; i < 5; i++ {
		env := newRepairEnv(t)
		env.addTampered(t, "s-race", cloneTenant, cloneDeviceA, time.Second)
		env.issueClientCerts(t, "s-race", 1)

		var wg sync.WaitGroup
		var repairCode, banCode int
		wg.Add(2)
		go func() {
			defer wg.Done()
			repairCode = env.postRepair("s-race", cloneTenant, nil).Code
		}()
		go func() {
			defer wg.Done()
			banCode = env.post(env.server.handleBanTamperedSteward, "ban", "s-race", cloneTenant, nil).Code
		}()
		wg.Wait()

		require.Equal(t, http.StatusOK, banCode, "the ban never loses to a repair request")
		assert.Equal(t, business.StewardStatusRevoked, env.status(t, "s-race"))
		// Whatever the order, a repair request that raced the ban cannot complete:
		// the completion path refuses a revoked steward before any proof.
		if repairCode == http.StatusAccepted {
			status := env.repairStatus(t, "s-race")
			assert.Equal(t, repairStateWaiting, status.State)
		} else {
			assert.Equal(t, http.StatusConflict, repairCode)
		}
	}
}

func TestRepair_NewRequestCancelsPreviousUnresolved(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-twice", cloneTenant, cloneDeviceA, time.Second)
	first := env.requestRepair(t, "s-twice", nil)
	require.True(t, env.nonceLive(t, "s-twice", first.RepairID))

	second := env.requestRepair(t, "s-twice", nil)
	assert.NotEqual(t, first.RepairID, second.RepairID)
	assert.False(t, env.nonceLive(t, "s-twice", first.RepairID), "the old nonce can no longer complete")
	assert.True(t, env.nonceLive(t, "s-twice", second.RepairID))

	cancelled := env.auditActions(t, auditActionTamperRepairCancelled)
	require.Len(t, cancelled, 1)
	assert.Equal(t, first.RepairID, cancelled[0].Details["repair_id"])
	assert.Equal(t, second.RepairID, env.repairStatus(t, "s-twice").RepairID)

	// A resolved request is not "cancelled" by the next one.
	env.progress(t, "s-twice", auditActionTamperRepairFailed, second.RepairID, controlplaneTypes.ReasonCodeRepairFailed)
	env.requestRepair(t, "s-twice", nil)
	assert.Len(t, env.auditActions(t, auditActionTamperRepairCancelled), 1)
}

func TestRepair_GetDerivesStateFromAuditEvents(t *testing.T) {
	env := newRepairEnv(t)
	env.addTampered(t, "s-states", cloneTenant, cloneDeviceA, time.Second)
	assert.Equal(t, http.StatusNotFound, env.getRepair("s-states", cloneTenant).Code, "no repair requested yet")

	resp := env.requestRepair(t, "s-states", nil)
	st := env.repairStatus(t, "s-states")
	assert.Equal(t, resp.RepairID, st.RepairID)
	assert.Equal(t, repairStateWaiting, st.State)
	assert.Equal(t, "operator", st.RequestedBy)
	assert.NotEmpty(t, st.RequestedAt)
	assert.Equal(t, []string{}, st.LossCodes)
	assert.Equal(t, []string{}, st.OutcomeCodes)

	// An event of another repair, or another steward, does not count.
	env.progress(t, "s-states", auditActionTamperRepairRunning, "someone-elses-repair", controlplaneTypes.ReasonCodeRepairRunning)
	assert.Equal(t, repairStateWaiting, env.repairStatus(t, "s-states").State)

	env.progress(t, "s-states", auditActionTamperRepairRunning, resp.RepairID, controlplaneTypes.ReasonCodeRepairRunning)
	st = env.repairStatus(t, "s-states")
	assert.Equal(t, repairStateRunning, st.State)
	assert.Equal(t, []string{"repair.running"}, st.OutcomeCodes)

	env.progress(t, "s-states", auditActionTamperRepairFailed, resp.RepairID, controlplaneTypes.ReasonCodeRepairLossSetChanged)
	st = env.repairStatus(t, "s-states")
	assert.Equal(t, repairStateFailed, st.State)
	assert.Contains(t, st.OutcomeCodes, controlplaneTypes.ReasonCodeRepairLossSetChanged)

	cases := map[string]struct {
		events []string // action, then optional code
		want   string
	}{
		"refused_data_loss": {[]string{auditActionTamperRepairFailed, controlplaneTypes.ReasonCodeRepairRefusedDataLoss}, repairStateRefusedDataLoss},
		"completed":         {[]string{auditActionTamperRepairCompleted}, repairStateCompleted},
		"contested":         {[]string{auditActionTamperRepairCompleted, auditActionTamperRepairContested}, repairStateContested},
		"cancelled":         {[]string{auditActionTamperRepairCancelled}, repairStateCancelled},
	}
	for name, tc := range cases {
		id := "s-states-" + name
		env.addTampered(t, id, cloneTenant, cloneDeviceB[:len(cloneDeviceB)-len(name)]+name, time.Second)
		r := env.requestRepair(t, id, nil)
		for i := 0; i < len(tc.events); i++ {
			if tc.events[i] == auditActionTamperRepairFailed {
				env.progress(t, id, tc.events[i], r.RepairID, tc.events[i+1])
				break
			}
			env.progress(t, id, tc.events[i], r.RepairID)
			time.Sleep(2 * time.Millisecond)
		}
		assert.Equal(t, tc.want, env.repairStatus(t, id).State, name)
	}
}

func TestRepair_NonceEntryHoldsExpiryPrincipalAndDigest(t *testing.T) {
	// The nonce entry holds the expiry, the approving principal and the loss digest.
	env := newRepairEnv(t)
	env.addTampered(t, "s-entry", cloneTenant, cloneDeviceA, time.Second)
	resp := env.requestRepair(t, "s-entry", nil)
	raw, found, err := env.server.nonceStore.GetAndConsumeNonce(context.Background(), repairRequestKey("s-entry", resp.RepairID))
	require.NoError(t, err)
	require.True(t, found)
	var entry repairRequestEntry
	require.NoError(t, json.Unmarshal(raw, &entry))
	assert.Equal(t, "operator", entry.ApprovedBy)
	assert.Equal(t, controlplaneTypes.LossDigest(nil), entry.LossDigest)
	assert.WithinDuration(t, time.Now().Add(repairRequestTTL), time.Unix(entry.ExpiresAtUnix, 0), 5*time.Second)
	_, err = hex.DecodeString(resp.RepairID)
	assert.NoError(t, err)
}
