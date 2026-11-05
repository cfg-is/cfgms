// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// recordingTamperSender stands in for the control-plane provider where the test
// only needs to see what the lockdown predicate sends.
type recordingTamperSender struct {
	mu   sync.Mutex
	sent map[string][]bool
	err  error
}

func (r *recordingTamperSender) SendTamperState(_ context.Context, id string, locked bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.sent == nil {
		r.sent = map[string][]bool{}
	}
	r.sent[id] = append(r.sent[id], locked)
	return nil
}

func (r *recordingTamperSender) states(id string) []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.sent[id]...)
}

type tamperEnv struct {
	*cloneEnv
	lockdown *fleet.Lockdown
	sender   *recordingTamperSender
}

func newTamperEnv(t *testing.T) *tamperEnv {
	t.Helper()
	env := newCloneEnv(t)
	ld := fleet.NewLockdown(env.steward, logging.NewNoopLogger())
	sender := &recordingTamperSender{}
	ld.SetSender(sender)
	env.server.SetTamperStateNotifier(ld)
	env.server.SetRegistry(registry.NewRegistry())
	return &tamperEnv{cloneEnv: env, lockdown: ld, sender: sender}
}

// addTampered registers a tampered steward whose last heartbeat was heartbeatAge
// ago (a negative age means it never heartbeated) and who last reported the given
// health reason codes.
func (e *tamperEnv) addTampered(t *testing.T, id, tenantID, deviceID string, heartbeatAge time.Duration, reportCodes ...string) {
	t.Helper()
	rec := &business.StewardRecord{
		ID: id, TenantID: tenantID, Status: business.StewardStatusTampered, DeviceID: deviceID,
		IdentityKeyPub: []byte("old-key-material-of-the-original"), KeyProtectionLevel: "file",
	}
	if heartbeatAge >= 0 {
		rec.LastHeartbeatAt = time.Now().UTC().Add(-heartbeatAge)
	}
	for _, c := range reportCodes {
		rec.HealthReasons = append(rec.HealthReasons, business.HealthReasonRecord{Component: "integrity", Code: c})
	}
	require.NoError(t, e.steward.RegisterSteward(context.Background(), rec))
}

func (e *tamperEnv) post(handler http.HandlerFunc, verb, id, callerTenant string, body interface{}) *httptest.ResponseRecorder {
	return callClone(handler, http.MethodPost, "/api/v1/stewards/"+id+"/tamper/"+verb,
		map[string]string{"id": id}, callerTenant, body)
}

func (e *tamperEnv) status(t *testing.T, id string) business.StewardStatus {
	t.Helper()
	rec, err := e.steward.GetSteward(context.Background(), id)
	require.NoError(t, err)
	return rec.Status
}

func decodeTamperData(t *testing.T, rec *httptest.ResponseRecorder, out interface{}) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	require.NoError(t, json.Unmarshal(env.Data, out))
}

func TestTamperRestore_ReturnsToActiveAndReleasesLatch(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-tamper", cloneTenant, cloneDeviceA, 0)

	locked, err := env.lockdown.IsLockedDown(context.Background(), "s-tamper")
	require.NoError(t, err)
	require.True(t, locked)

	rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-tamper", cloneTenant, map[string]string{"reason": "reimaged and checked"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp tamperVerbResponse
	decodeTamperData(t, rec, &resp)
	assert.Equal(t, "active", resp.Status)
	assert.Equal(t, business.StewardStatusActive, env.status(t, "s-tamper"))

	locked, err = env.lockdown.IsLockedDown(context.Background(), "s-tamper")
	require.NoError(t, err)
	assert.False(t, locked, "automated commands and config pulls are allowed again")
	assert.Equal(t, []bool{false}, env.sender.states("s-tamper"), "a connected steward is sent TamperState{locked:false}")

	entries := env.auditActions(t, auditActionTamperRestored)
	require.Len(t, entries, 1)
	assert.Equal(t, "operator", entries[0].UserID, "the audit event names the acting principal")
	assert.Equal(t, "reimaged and checked", entries[0].Details["reason"])
}

func TestTamperRestore_NeverHeartbeatedReturnsToRegistered(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-new", cloneTenant, cloneDeviceA, -1)

	rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-new", cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, business.StewardStatusRegistered, env.status(t, "s-new"))
}

func TestTamperRestore_RefusedWhileFaultStillReported(t *testing.T) {
	const code = types.ReasonCodeTamperDataDir
	require.True(t, isTamperCodeForTest(code), "the fixture must use a real tamper code")
	env := newTamperEnv(t)
	env.addTampered(t, "s-fault", cloneTenant, cloneDeviceA, time.Minute, code)

	for _, body := range []interface{}{nil, map[string]interface{}{"force": true, "reason": "override"}} {
		rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-fault", cloneTenant, body)
		require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
		var got faultStillReportedResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, "fault_still_reported", got.Error)
		assert.Equal(t, []string{code}, got.Codes)
		assert.Contains(t, got.Message, "repaired and restored")
		assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-fault"))
	}

	refused := env.auditActions(t, auditActionTamperRestoreRefused)
	require.Len(t, refused, 2)
	assert.Equal(t, []string{code}, auditStringSlice(refused[0].Details["codes"]))
	assert.Empty(t, env.sender.states("s-fault"), "a refused restore sends nothing to the steward")
}

func isTamperCodeForTest(code string) bool {
	return len(tamperCodesIn([]types.HealthReason{{Code: code}})) == 1
}

func TestTamperRestore_FaultWindow(t *testing.T) {
	const code = types.ReasonCodeTamperDataDir
	t.Run("stale heartbeat does not block", func(t *testing.T) {
		env := newTamperEnv(t)
		env.addTampered(t, "s-stale", cloneTenant, cloneDeviceA, 2*tamperRestoreFaultWindow, code)
		rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-stale", cloneTenant, nil)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
	t.Run("recent heartbeat without a tamper code does not block", func(t *testing.T) {
		env := newTamperEnv(t)
		env.addTampered(t, "s-clean", cloneTenant, cloneDeviceA, time.Minute, "service.degraded")
		rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-clean", cloneTenant, nil)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

func TestTamperRestore_ThenHeartbeatWithCodeReturnsToTampered(t *testing.T) {
	const code = types.ReasonCodeTamperDataDir
	env := newTamperEnv(t)
	env.addTampered(t, "s-again", cloneTenant, cloneDeviceA, 2*tamperRestoreFaultWindow, code)
	require.Equal(t, http.StatusOK, env.post(env.server.handleRestoreTamperedSteward, "restore", "s-again", cloneTenant, nil).Code)
	require.Equal(t, business.StewardStatusActive, env.status(t, "s-again"))

	env.server.HandleStewardTamperAlarm(context.Background(), "s-again", []types.HealthReason{{Component: "integrity", Code: code}})
	assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-again"))
}

func TestTamperRestore_OfflineSteward_ReleasedOnNextConnect(t *testing.T) {
	env := newTamperEnv(t)
	env.sender.err = errors.New("steward not connected")
	env.addTampered(t, "s-off", cloneTenant, cloneDeviceA, 0)

	rec := env.post(env.server.handleRestoreTamperedSteward, "restore", "s-off", cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, "an offline steward does not fail the restore")
	assert.Equal(t, business.StewardStatusActive, env.status(t, "s-off"))

	env.sender.mu.Lock()
	env.sender.err = nil
	env.sender.mu.Unlock()
	require.NoError(t, env.lockdown.OnConnect(context.Background(), "s-off"))
	assert.Equal(t, []bool{false}, env.sender.states("s-off"), "the connect-time send releases the latch")
}

func TestTamperBan_RevokesSerialsAndStatus(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-ban", cloneTenant, cloneDeviceA, 0, "tamper.binary_modified")
	serials := env.issueClientCerts(t, "s-ban", 2)

	rec := env.post(env.server.handleBanTamperedSteward, "ban", "s-ban", cloneTenant, map[string]string{"reason": "stolen laptop"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp tamperVerbResponse
	decodeTamperData(t, rec, &resp)
	assert.Equal(t, "revoked", resp.Status)
	assert.ElementsMatch(t, serials, resp.RevokedSerials)
	assert.Contains(t, resp.Note, "only this identity")
	assert.Equal(t, business.StewardStatusRevoked, env.status(t, "s-ban"))
	for _, s := range serials {
		revoked, err := env.certMgr.IsRevoked(s)
		require.NoError(t, err)
		assert.True(t, revoked, "serial %s", s)
	}

	entries := env.auditActions(t, auditActionTamperBanned)
	require.Len(t, entries, 1)
	assert.Equal(t, "operator", entries[0].UserID)
	assert.Equal(t, "stolen laptop", entries[0].Details["reason"])
}

func TestTamperBan_EvictsLiveStream(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-live", cloneTenant, cloneDeviceA, 0)
	reg := registry.NewRegistry()
	env.server.SetRegistry(reg)
	evicted := make(chan error, 1)
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID: "s-live", Sender: nopSender{}, Evict: func(err error) { evicted <- err },
	}))

	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", "s-live", cloneTenant, nil).Code)
	select {
	case err := <-evicted:
		assert.Contains(t, err.Error(), "banned")
	case <-time.After(time.Second):
		t.Fatal("the live control stream was not evicted")
	}
}

type nopSender struct{}

func (nopSender) SendMsg(interface{}) error { return nil }

func TestTamperBan_DoesNotBanLockedCopy(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-old", cloneTenant, cloneDeviceA, 0)
	env.addTampered(t, "s-copy", cloneTenant, cloneDeviceB, 0)
	env.addPending(t, "pending-copy", cloneTenant, "s-old", cloneDeviceB)
	env.issueClientCerts(t, "s-old", 1)
	copySerials := env.issueClientCerts(t, "s-copy", 1)

	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", "s-old", cloneTenant, nil).Code)

	assert.Equal(t, business.StewardStatusRevoked, env.status(t, "s-old"))
	assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-copy"), "the copy is a different identity")
	revoked, err := env.certMgr.IsRevoked(copySerials[0])
	require.NoError(t, err)
	assert.False(t, revoked, "the copy's certificates are untouched")
	pending, err := env.server.pendingStore.GetPendingByID(context.Background(), "pending-copy")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusPending, pending.Status)
}

func TestTamperBan_StickyForRegistrationAndRefresh(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-sticky", cloneTenant, cloneDeviceA, 0)
	require.Equal(t, http.StatusOK, env.post(env.server.handleBanTamperedSteward, "ban", "s-sticky", cloneTenant, nil).Code)

	// A registration naming the banned ID as clone_of is refused outright.
	rec := postRegisterWithBody(env.server, RegistrationRequest{
		Token: env.regToken, DeviceID: testValidDeviceID, IdentityKeyPub: testValidIdentityKeyPub,
		CSRPEM: testValidCSRPEM, CloneOf: "s-sticky",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	pending, err := env.server.pendingStore.ListPending(context.Background(), cloneTenant)
	require.NoError(t, err)
	assert.Empty(t, pending, "nothing is queued")

	// Refresh challenge and complete are refused, and nothing reaches the refresh queue.
	for name, h := range map[string]http.HandlerFunc{
		"challenge": env.server.handleRefreshChallenge,
		"complete":  env.server.handleRefreshComplete,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+cloneDeviceA+"/refresh/"+name, strings.NewReader(`{}`))
		req = withVars(req, map[string]string{"device_id": cloneDeviceA})
		w := httptest.NewRecorder()
		h(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code, name+": "+w.Body.String())
	}
	if env.server.pendingRefreshStore != nil {
		queued, err := env.server.pendingRefreshStore.ListPendingRefresh(context.Background(), "")
		require.NoError(t, err)
		assert.Empty(t, queued)
	}
}

func TestTamperVerbs_RefuseNonTamperedAndOtherTenant(t *testing.T) {
	verbs := map[string]func(*Server) http.HandlerFunc{
		"restore": func(s *Server) http.HandlerFunc { return s.handleRestoreTamperedSteward },
		"ban":     func(s *Server) http.HandlerFunc { return s.handleBanTamperedSteward },
	}
	for verb, pick := range verbs {
		t.Run(verb, func(t *testing.T) {
			env := newTamperEnv(t)
			h := pick(env.server)
			env.addSteward(t, "s-active", cloneTenant, cloneDeviceA, business.StewardStatusActive)
			env.addTampered(t, "s-other", cloneOtherTenant, cloneDeviceB, 0)

			assert.Equal(t, http.StatusConflict, env.post(h, verb, "s-active", cloneTenant, nil).Code)
			assert.Equal(t, business.StewardStatusActive, env.status(t, "s-active"))
			assert.Equal(t, http.StatusNotFound, env.post(h, verb, "s-other", cloneTenant, nil).Code, "outside the caller's tenant")
			assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-other"))
			assert.Equal(t, http.StatusNotFound, env.post(h, verb, "s-missing", cloneTenant, nil).Code)
		})
	}
}

func TestTamperVerbs_ParallelCallsExactlyOneWins(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-race", cloneTenant, cloneDeviceA, 0)
	env.issueClientCerts(t, "s-race", 1)

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				codes[i] = env.post(env.server.handleRestoreTamperedSteward, "restore", "s-race", cloneTenant, nil).Code
			} else {
				codes[i] = env.post(env.server.handleBanTamperedSteward, "ban", "s-race", cloneTenant, nil).Code
			}
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		default:
			assert.Equal(t, http.StatusConflict, c)
		}
	}
	assert.Equal(t, 1, wins, "exactly one of the parallel calls succeeds: %v", codes)
	restored := len(env.auditActions(t, auditActionTamperRestored))
	banned := len(env.auditActions(t, auditActionTamperBanned))
	assert.Equal(t, 1, restored+banned, "one outcome is audited")
}

func TestTamperVerbs_RoleWithoutPermissionGets403(t *testing.T) {
	env := newTamperEnv(t)
	env.addTampered(t, "s-perm", cloneTenant, cloneDeviceA, 0)
	for verb, perm := range map[string]string{"restore": "tamper-restore", "ban": "tamper-ban"} {
		var h http.HandlerFunc
		if verb == "restore" {
			h = env.server.handleRestoreTamperedSteward
		} else {
			h = env.server.handleBanTamperedSteward
		}
		guarded := env.server.requirePermission("steward", perm)(h)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/s-perm/tamper/"+verb, nil)
		req = withVars(req, map[string]string{"id": "s-perm"})
		req = withPrincipal(req, &Principal{ID: "viewer", Assurance: session.AssuranceStrong, TenantID: cloneTenant})
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code, verb+": "+w.Body.String())
	}
	assert.Equal(t, business.StewardStatusTampered, env.status(t, "s-perm"))
}

func TestTamperPermissions_RegisteredStrongAndKnown(t *testing.T) {
	for _, id := range []string{"steward:tamper-restore", "steward:tamper-ban"} {
		assert.True(t, knownPermissions[id], id)
		req, ok := permissionAssurance[id]
		require.True(t, ok, id)
		assert.Equal(t, session.AssuranceStrong, req.Min, id)
	}
}

// --- real control plane: restore and ban against a connected steward ---

type livePKI struct {
	certMgr   *cert.Manager
	serverTLS *tls.Config
	caPEM     []byte
}

func newLivePKI(t *testing.T, mgr *cert.Manager) *livePKI {
	t.Helper()
	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)
	sc, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{CommonName: "localhost", DNSNames: []string{"localhost"}, ValidityDays: 1})
	require.NoError(t, err)
	serverTLS, err := cert.CreateServerTLSConfig(sc.CertificatePEM, sc.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	return &livePKI{certMgr: mgr, serverTLS: serverTLS, caPEM: caPEM}
}

func (p *livePKI) clientTLS(t *testing.T, id string) *tls.Config {
	t.Helper()
	cc, err := p.certMgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: id, ValidityDays: 1})
	require.NoError(t, err)
	cfg, err := cert.CreateClientTLSConfig(cc.CertificatePEM, cc.PrivateKeyPEM, p.caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// auditingObserver records the command gate's operator-command events through
// the real audit manager, as the controller's observer does.
type auditingObserver struct {
	env *tamperEnv
}

func (o auditingObserver) CommandRefused(context.Context, string, types.CommandType, string) {}

func (o auditingObserver) OperatorCommandAllowed(ctx context.Context, operator, stewardID string, cmdType types.CommandType) {
	b := audit.NewEventBuilder().
		Tenant(cloneTenant).
		Type(business.AuditEventSecurityEvent).
		Action("operator_command_to_locked_steward").
		User(operator, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Detail("command_type", string(cmdType))
	_ = o.env.server.auditManager.RecordEvent(ctx, b)
}

type liveSteward struct {
	client   *grpcCP.Provider
	mu       sync.Mutex
	tamper   []bool
	commands chan *types.SignedCommand
}

func (l *liveSteward) tamperStates() []bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]bool(nil), l.tamper...)
}

type liveEnv struct {
	*tamperEnv
	pki    *livePKI
	server *grpcCP.Provider
	reg    registry.Registry
}

func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	env := newTamperEnv(t)
	pki := newLivePKI(t, env.certMgr)
	reg := registry.NewRegistry()
	env.server.SetRegistry(reg)
	srv := grpcCP.New(grpcCP.ModeServer,
		grpcCP.WithOnConnectHook(env.lockdown),
		grpcCP.WithLockdown(env.lockdown, auditingObserver{env: env}),
		grpcCP.WithApprovalChecker(grpcCP.NewStewardStoreApprovalChecker(env.steward)),
		grpcCP.WithRevocationChecker(env.certMgr),
		grpcCP.WithRevocationRecheckInterval(100*time.Millisecond),
	)
	env.lockdown.SetSender(srv)
	require.NoError(t, srv.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": pki.serverTLS, "registry": reg,
	}))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(srv.ForceStop)
	return &liveEnv{tamperEnv: env, pki: pki, server: srv, reg: reg}
}

func (e *liveEnv) connect(t *testing.T, id string) *liveSteward {
	t.Helper()
	ls := &liveSteward{commands: make(chan *types.SignedCommand, 8)}
	ls.client = grpcCP.New(grpcCP.ModeClient)
	ls.client.SetInboundHooks(interfaces.InboundHooks{OnTamperState: func(locked bool) {
		ls.mu.Lock()
		ls.tamper = append(ls.tamper, locked)
		ls.mu.Unlock()
	}})
	require.NoError(t, ls.client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": e.server.ListenAddr(), "tls_config": e.pki.clientTLS(t, id), "steward_id": id,
	}))
	require.NoError(t, ls.client.Start(context.Background()))
	t.Cleanup(func() { _ = ls.client.Stop(context.Background()) })
	require.NoError(t, ls.client.SubscribeCommands(context.Background(), id, func(_ context.Context, sc *types.SignedCommand) error {
		ls.commands <- sc
		return nil
	}))
	require.Eventually(t, func() bool { _, ok := e.reg.Get(id); return ok }, 5*time.Second, 10*time.Millisecond)
	return ls
}

func liveCmd(id, steward string, typ types.CommandType) *types.SignedCommand {
	return &types.SignedCommand{Command: types.Command{ID: id, Type: typ, StewardID: steward, Timestamp: time.Now()}}
}

func expectCommand(t *testing.T, ch chan *types.SignedCommand, id string) {
	t.Helper()
	select {
	case got := <-ch:
		assert.Equal(t, id, got.Command.ID)
	case <-time.After(5 * time.Second):
		t.Fatalf("command %s was not delivered", id)
	}
}

func TestTamperLive_OperatorCommandThenRestoreResumesAutomatedTraffic(t *testing.T) {
	env := newLiveEnv(t)
	env.addTampered(t, "s-e2e", cloneTenant, cloneDeviceA, 2*tamperRestoreFaultWindow)
	steward := env.connect(t, "s-e2e")
	require.Eventually(t, func() bool { return len(steward.tamperStates()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []bool{true}, steward.tamperStates(), "the tamper state is sent on connect")

	ctx := context.Background()
	// Automated traffic is refused; an operator's signed command is delivered and audited.
	require.ErrorIs(t, env.server.SendCommand(ctx, liveCmd("auto-1", "s-e2e", types.CommandSyncConfig)), interfaces.ErrStewardLockedDown)
	opCtx := commands.NewOperatorOrigin(ctx, "alice")
	require.NoError(t, env.server.SendCommand(opCtx, liveCmd("op-1", "s-e2e", types.CommandExecuteScript)))
	expectCommand(t, steward.commands, "op-1")
	allowed := env.auditActions(t, "operator_command_to_locked_steward")
	require.Len(t, allowed, 1)
	assert.Equal(t, "alice", allowed[0].UserID)

	// Restore: the steward is released and automated commands flow again.
	rec := env.post(env.cloneEnv.server.handleRestoreTamperedSteward, "restore", "s-e2e", cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Eventually(t, func() bool { return len(steward.tamperStates()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []bool{true, false}, steward.tamperStates(), "restore delivers TamperState{locked:false}")
	require.NoError(t, env.server.SendCommand(ctx, liveCmd("auto-2", "s-e2e", types.CommandSyncConfig)))
	expectCommand(t, steward.commands, "auto-2")
	assert.Len(t, env.auditActions(t, auditActionTamperRestored), 1)
}

func TestTamperLive_BanClosesStreamAndRefusesNewConnection(t *testing.T) {
	env := newLiveEnv(t)
	env.addTampered(t, "s-banlive", cloneTenant, cloneDeviceA, 0)
	steward := env.connect(t, "s-banlive")
	require.Eventually(t, func() bool { return len(steward.tamperStates()) == 1 }, 5*time.Second, 10*time.Millisecond)

	rec := env.post(env.cloneEnv.server.handleBanTamperedSteward, "ban", "s-banlive", cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.Eventually(t, func() bool { _, ok := env.reg.Get("s-banlive"); return !ok }, 5*time.Second, 20*time.Millisecond,
		"the live control stream is closed")
	// Nothing reaches the steward any more.
	require.Error(t, env.server.SendCommand(commands.NewOperatorOrigin(context.Background(), "alice"),
		liveCmd("after-ban", "s-banlive", types.CommandExecuteScript)))

	// A new connection with a freshly issued certificate for the banned ID is
	// refused at admission (status revoked), even though the certificate is valid.
	fresh := grpcCP.New(grpcCP.ModeClient)
	require.NoError(t, fresh.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": env.server.ListenAddr(), "tls_config": env.pki.clientTLS(t, "s-banlive"), "steward_id": "s-banlive",
	}))
	_ = fresh.Start(context.Background())
	t.Cleanup(func() { _ = fresh.Stop(context.Background()) })
	require.Never(t, func() bool { _, ok := env.reg.Get("s-banlive"); return ok }, time.Second, 25*time.Millisecond,
		"a banned identity is never admitted again")
}
