// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// repairSigner is a controller signing identity: a root and a code-signing leaf.
type repairSigner struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
	chainPEM []byte
}

func newRepairSigner(t *testing.T, cn string) *repairSigner {
	t.Helper()
	mk := func(name string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: isCA,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.KeyUsage = x509.KeyUsageDigitalSignature
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}
		signer, signerKey := tmpl, key
		if parent != nil {
			signer, signerKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
		require.NoError(t, err)
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return c, key
	}
	s := &repairSigner{}
	s.root, s.rootKey = mk(cn+"-root", true, nil, nil)
	s.leaf, s.leafKey = mk(cn+"-signer", false, s.root, s.rootKey)
	s.chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.root.Raw})...)
	return s
}

func (s *repairSigner) sign(t *testing.T, payload []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.leafKey, sum[:])
	require.NoError(t, err)
	return sig
}

// repairController is the controller's HTTPS side of a repair: the refresh-complete
// endpoint with the repair fields, backed by the real CA the link server trusts.
// It verifies both identity-key proofs, uses each repair ID once, rotates the
// recorded identity key, revokes the retired certificate at admission and keeps
// the completion result so a lost response can be retried.
type repairController struct {
	t      *testing.T
	srv    *roServer
	server *httptest.Server

	mu          sync.Mutex
	stewardID   string
	deviceID    string
	identityKey []byte // raw ed25519 public key currently recorded
	status      string
	oldSerials  []string
	allowed     map[string]bool // repair IDs that may complete
	used        map[string]bool
	results     map[string]*repairResult
	calls       []repairCall
	refuse      int // answer this status instead of completing
	dropFirst   bool
	onComplete  func()
}

type repairResult struct {
	oldDeviceID string
	newKey      string
	csr         string
	response    []byte
}

type repairCall struct {
	DeviceID string
	Body     map[string]string
}

func newRepairController(t *testing.T, srv *roServer, stewardID, deviceID string, identityKey []byte, oldSerials ...string) *repairController {
	t.Helper()
	c := &repairController{
		t: t, srv: srv, stewardID: stewardID, deviceID: deviceID, identityKey: identityKey, status: "tampered",
		oldSerials: oldSerials, allowed: map[string]bool{}, used: map[string]bool{}, results: map[string]*repairResult{},
	}
	c.server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.server.Close)
	return c
}

func (c *repairController) allow(repairID string) {
	c.mu.Lock()
	c.allowed[repairID] = true
	c.mu.Unlock()
}

func (c *repairController) callList() []repairCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]repairCall(nil), c.calls...)
}

func (c *repairController) record() (deviceID string, identityKey []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deviceID, append([]byte(nil), c.identityKey...)
}

func (c *repairController) serve(w http.ResponseWriter, r *http.Request) {
	const prefix, suffix = "/api/v1/stewards/", "/refresh/complete"
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
		http.Error(w, "unexpected path", http.StatusNotFound)
		return
	}
	deviceID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
	raw, err := io.ReadAll(r.Body)
	require.NoError(c.t, err)
	body := map[string]string{}
	require.NoError(c.t, json.Unmarshal(raw, &body))

	c.mu.Lock()
	c.calls = append(c.calls, repairCall{DeviceID: deviceID, Body: body})
	hook := c.onComplete
	refuse := c.refuse
	drop := c.dropFirst && len(c.calls) == 1
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	if refuse != 0 {
		http.Error(w, "refused by test", refuse)
		return
	}
	resp, status := c.complete(deviceID, body)
	if status != http.StatusOK {
		http.Error(w, string(resp), status)
		return
	}
	if drop {
		// The response is lost: the work is done, the steward never hears.
		hj, ok := w.(http.Hijacker)
		require.True(c.t, ok)
		conn, _, err := hj.Hijack()
		require.NoError(c.t, err)
		_ = conn.Close()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func (c *repairController) complete(deviceID string, body map[string]string) ([]byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	repairID := body["repair_id"]
	if res := c.results[repairID]; res != nil && deviceID == res.oldDeviceID {
		// A lost response being retried: the same new key and CSR get the stored answer.
		if body["new_identity_key_pub"] != res.newKey || body["csr_pem"] != res.csr {
			return []byte("different key"), http.StatusConflict
		}
		return res.response, http.StatusOK
	}
	if deviceID != c.deviceID {
		return []byte("device not found"), http.StatusNotFound
	}
	if c.status != "tampered" {
		return []byte("steward is not tampered"), http.StatusConflict
	}
	if !c.allowed[repairID] || c.used[repairID] {
		return []byte("repair request expired or not found"), http.StatusUnauthorized
	}
	newPub, err := base64.RawURLEncoding.DecodeString(body["new_identity_key_pub"])
	if err != nil || len(newPub) != ed25519.PublicKeySize {
		return []byte("invalid new key"), http.StatusBadRequest
	}
	oldProof, _ := base64.RawURLEncoding.DecodeString(body["old_key_proof"])
	newProof, _ := base64.RawURLEncoding.DecodeString(body["new_key_proof"])
	digest := cpTypes.RepairRotationProofDigest(c.stewardID, repairID, newPub, body["csr_pem"])
	if !ed25519.Verify(ed25519.PublicKey(c.identityKey), digest, oldProof) ||
		!ed25519.Verify(ed25519.PublicKey(newPub), digest, newProof) {
		return []byte("proof-of-possession verification failed"), http.StatusUnauthorized
	}
	block, _ := pem.Decode([]byte(body["csr_pem"]))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(c.t, err)

	c.used[repairID] = true
	oldDevice := c.deviceID
	sum := sha256.Sum256(newPub)
	c.deviceID, c.identityKey = hex.EncodeToString(sum[:]), newPub
	for _, serial := range c.oldSerials {
		c.srv.revoked.Store(serial, true)
	}
	issued, err := c.srv.mgr.SignClientCertificateRequest(csr.PublicKey, &cert.ClientCertConfig{
		CommonName: c.stewardID, ClientID: c.stewardID, ValidityDays: 30,
	})
	require.NoError(c.t, err)
	c.oldSerials = append(c.oldSerials, issued.SerialNumber)
	resp, err := json.Marshal(map[string]string{"status": "approved", "client_cert": string(issued.CertificatePEM)})
	require.NoError(c.t, err)
	c.results[repairID] = &repairResult{oldDeviceID: oldDevice, newKey: body["new_identity_key_pub"], csr: body["csr_pem"], response: resp}
	return resp, http.StatusOK
}

// repairFixture is a latched steward with real local data, a real link server and a
// controller that can complete a repair.
type repairFixture struct {
	t         *testing.T
	env       *alarmEnv
	ctrl      *repairController
	paths     repairPaths
	latch     *tamperLatch
	alarm     *tamperAlarm
	ks        *identity.FileKeyStore
	oldPub    ed25519.PublicKey
	oldSerial string

	// lifeMu guards cancel and done: stop can run on a controller handler
	// goroutine while the test goroutine restarts the fixture.
	lifeMu sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	removedMu sync.Mutex
	removed   []string
}

type repairFixtureOpts struct {
	code   string
	signer *repairSigner // when set, the binary has this root baked in
}

func clientSerials(t *testing.T, dir string) []string {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{StoragePath: dir, LoadExistingCA: true})
	require.NoError(t, err)
	certs, err := mgr.ListCertificates()
	require.NoError(t, err)
	var out []string
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient {
			out = append(out, c.SerialNumber)
		}
	}
	return out
}

func newRepairFixture(t *testing.T, opts repairFixtureOpts) *repairFixture {
	t.Helper()
	if opts.code == "" {
		opts.code = cpTypes.ReasonCodeTamperDataDir
	}
	e := newAlarmEnv(t, trustSourceTOFU)
	f := &repairFixture{t: t, env: e, done: make(chan struct{})}

	ks, err := identity.NewFileKeyStoreForTesting(e.f.dir)
	require.NoError(t, err)
	pub, alg, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	f.ks, f.oldPub = ks, pub.(ed25519.PublicKey)
	id, err := withRotatedIdentityKey(e.f.id, alg, ks.ProtectionLevel(), pub)
	require.NoError(t, err)
	require.NoError(t, saveIdentity(e.f.dir, id))
	serials := clientSerials(t, e.f.dir)
	require.Len(t, serials, 1)
	f.oldSerial = serials[0]

	f.paths = repairPaths{dataDir: t.TempDir(), certStoreDir: e.f.dir, logDir: t.TempDir()}
	require.NoError(t, os.WriteFile(filepath.Join(f.paths.logDir, "steward.log"), []byte("log line one\nlog line two\n"), 0o600))
	require.NoError(t, os.WriteFile(f.paths.actionHistory(), []byte(`{"action":"first"}`+"\n"+`{"action":"second"}`+"\n"), 0o600))

	f.ctrl = newRepairController(t, e.f.srv, roStewardID, ks.DeviceID(), f.oldPub, f.oldSerial)

	prevPaths, prevOpen, prevTake, prevRemove, prevRights := repairPathsResolver, repairOpenKeyStore, repairTakeOver, repairRemoveItem, repairRightsCheck
	prevRetry, prevMax := repairRetryBase, repairRetryMax
	repairPathsResolver = func() repairPaths { return f.paths }
	repairOpenKeyStore = func(ctx context.Context, dir string, _ logging.Logger) (identity.KeyStore, error) {
		s, err := identity.NewFileKeyStoreForTesting(dir)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.GenerateOrLoad(ctx); err != nil {
			return nil, err
		}
		return s, nil
	}
	repairTakeOver = testTakeOver
	repairRemoveItem = func(path string) error {
		f.removedMu.Lock()
		f.removed = append(f.removed, path)
		f.removedMu.Unlock()
		return removeRepairItem(path)
	}
	repairRetryBase, repairRetryMax = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		repairPathsResolver, repairOpenKeyStore, repairTakeOver, repairRemoveItem, repairRightsCheck = prevPaths, prevOpen, prevTake, prevRemove, prevRights
		repairRetryBase, repairRetryMax = prevRetry, prevMax
		for _, c := range []string{cpTypes.HealthComponentRepair, cpTypes.ReasonCodeRepairLossLocalLogs, cpTypes.ReasonCodeRepairLossActionHistory} {
			startupReasons.Clear(c)
		}
	})
	if opts.signer != nil {
		setBaked(t, fpOf(opts.signer.root))
	}

	f.latch = openTamperLatch(e.f.dir, logging.NewLogger("error"))
	f.latch.raise(opts.code)
	return f
}

// start runs the tamper alarm until stop.
func (f *repairFixture) start() {
	f.t.Helper()
	f.alarm = newTamperAlarm(f.latch, logging.NewLogger("error"), f.ctrl.server.URL)
	f.alarm.sinkFn = func() systemLogWriter { return f.env.sink }
	alarm := f.alarm
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	f.lifeMu.Lock()
	f.cancel = cancel
	f.done = done
	f.lifeMu.Unlock()
	go func() {
		defer close(done)
		_, _ = alarm.run(ctx)
	}()
	f.t.Cleanup(f.stop)
	waitConnected(f.t, f.env.f.srv)
}

func (f *repairFixture) stop() {
	f.lifeMu.Lock()
	cancel, done := f.cancel, f.done
	f.lifeMu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			f.t.Error("the alarm did not stop")
		}
	}
}

func (f *repairFixture) removedPaths() []string {
	f.removedMu.Lock()
	defer f.removedMu.Unlock()
	return append([]string(nil), f.removed...)
}

// request builds a RepairRequest. A signer signs it; sig tampering is left to the test.
type requestOpts struct {
	approved []string
	expires  time.Duration
	digest   string
	signer   *repairSigner
	badSig   bool
}

func (f *repairFixture) request(repairID string, o requestOpts) cpTypes.RepairRequest {
	f.t.Helper()
	if o.expires == 0 {
		o.expires = 5 * time.Minute
	}
	if o.digest == "" {
		o.digest = cpTypes.LossDigest(o.approved)
	}
	exp := time.Now().Add(o.expires).Unix()
	req := cpTypes.RepairRequest{RepairID: repairID, ApprovedLossCodes: o.approved, LossDigest: o.digest, ExpiresAtUnix: exp}
	if o.signer != nil {
		req.SignerChainPEM = o.signer.chainPEM
		req.Signature = o.signer.sign(f.t, cpTypes.RepairSigningPayload(roStewardID, repairID, o.digest, exp))
		if o.badSig {
			req.Signature[len(req.Signature)-1] ^= 0xff
		}
	}
	return req
}

func (f *repairFixture) send(req cpTypes.RepairRequest) {
	f.t.Helper()
	require.NoError(f.t, f.env.f.srv.cp.SendRepair(context.Background(), roStewardID, req))
}

// repairReason waits for a heartbeat carrying the repair outcome code.
func repairReason(t *testing.T, srv *roServer, component, code string) cpTypes.HealthReason {
	t.Helper()
	return repairReasonAfterLoss(t, srv, component, code, 0, 30*time.Second)
}

// repairReasonAfterLoss is repairReason for a controller that loses the first
// `lost` heartbeats carrying the reason, and that waits `within` for one more.
func repairReasonAfterLoss(t *testing.T, srv *roServer, component, code string, lost int, within time.Duration) cpTypes.HealthReason {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case hb := <-srv.heartbeats:
			for _, r := range hb.Reasons {
				if r.Component != component || r.Code != code {
					continue
				}
				if lost > 0 {
					lost--
					break
				}
				return r
			}
		case <-deadline:
			t.Fatalf("no heartbeat carried %s/%s", component, code)
			return cpTypes.HealthReason{}
		}
	}
}

func awaitOutcome(t *testing.T, f *repairFixture, code string) cpTypes.HealthReason {
	return repairReason(t, f.env.f.srv, cpTypes.HealthComponentRepair, code)
}

// shallowSnapshot records path, mode and size of every entry under the roots without
// opening any file (some are unreadable on purpose).
func shallowSnapshot(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		require.NoError(t, filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			out[p] = info.Mode().String() + "|" + hex.EncodeToString([]byte{byte(info.Size()), byte(info.Size() >> 8)})
			return nil
		}))
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test-owned temp tree
	require.NoError(t, err)
	return string(b)
}

func TestRepair_CompletesEndToEnd_KeepsStewardIDLogsAndHistory(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	logBefore := readFile(t, filepath.Join(f.paths.logDir, "steward.log"))
	historyBefore := readFile(t, f.paths.actionHistory())
	idBefore, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	f.start()

	// Rights verify only once the takeover has fixed the directory.
	f.env.dirBad.Store(false)
	f.ctrl.allow("repair-1")
	f.send(f.request("repair-1", requestOpts{}))
	reason := awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)
	assert.Equal(t, "repair-1", reason.Message, "the outcome carries the repair ID")

	idAfter, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	assert.Equal(t, idBefore.StewardID, idAfter.StewardID, "the steward ID is kept")
	assert.Equal(t, idBefore.TenantID, idAfter.TenantID)
	assert.Equal(t, idBefore.TransportAddress, idAfter.TransportAddress)
	assert.NotEqual(t, idBefore.IdentityKeyPub, idAfter.IdentityKeyPub, "the identity key changed")
	assert.NotEqual(t, idBefore.DeviceID, idAfter.DeviceID)

	// The controller's record carries the new key, and it is the one on disk.
	recDevice, recKey := f.ctrl.record()
	assert.Equal(t, idAfter.DeviceID, recDevice)
	assert.Equal(t, idAfter.IdentityKeyPub, base64.StdEncoding.EncodeToString(recKey))
	assert.NotEqual(t, []byte(f.oldPub), recKey)

	// The mTLS key changed: one client certificate, a different serial.
	serials := clientSerials(t, f.env.f.dir)
	require.Len(t, serials, 1)
	assert.NotEqual(t, f.oldSerial, serials[0])

	// Local logs and action history are untouched and nothing was deleted.
	assert.Equal(t, logBefore, readFile(t, filepath.Join(f.paths.logDir, "steward.log")))
	assert.Equal(t, historyBefore, readFile(t, f.paths.actionHistory()))
	assert.Empty(t, f.removedPaths())

	// The old certificate is refused at admission; the heartbeat that carried
	// repair.completed arrived on the new one.
	_, revoked := f.env.f.srv.revoked.Load(f.oldSerial)
	assert.True(t, revoked)
	seen := f.env.f.srv.handshakeSerials()
	assert.Equal(t, serials[0], seen[len(seen)-1])

	// The state needed to resume is gone, and no staged key remains.
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, repairStateFileName))
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, "device_identity.enc.next"))
	assert.True(t, f.latch.isLatched(), "the steward stays latched until the controller unlocks it")
}

// The repair outcome reaches the controller on the link opened after the repair.
// A link's own first heartbeat is a single fire-and-forget send (the next
// periodic one is 20 to 30 s later), so when the controller does not receive it
// the steward must still report the outcome within seconds.
func TestRepair_OutcomeHeartbeatLost_ReportedAgainWithoutWaitingForThePeriodicOne(t *testing.T) {
	prevInterval := repairOutcomeResendInterval
	repairOutcomeResendInterval = 200 * time.Millisecond
	t.Cleanup(func() { repairOutcomeResendInterval = prevInterval })

	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	f.env.dirBad.Store(false)
	f.ctrl.allow("repair-lost")
	f.send(f.request("repair-lost", requestOpts{}))

	// The periodic heartbeat is at least 20 s apart, so a 10 s wait cannot be
	// satisfied by it.
	reason := repairReasonAfterLoss(t, f.env.f.srv, cpTypes.HealthComponentRepair, cpTypes.ReasonCodeRepairCompleted, 1, 10*time.Second)
	assert.Equal(t, "repair-lost", reason.Message, "the outcome carries the repair ID")
}

// A steward with no repair outcome to report sends nothing extra.
func TestRepairer_ConfirmOutcome_NothingToReportStartsNothing(t *testing.T) {
	var r *repairer
	r.confirmOutcome(context.Background(), nil) // no repairer, no link: must not panic

	r = &repairer{reasons: client.NewHealthReasonRegistry()}
	r.confirmOutcome(context.Background(), nil)
}

func TestRepair_ReconnectHold_NoDialPresentsTheOldCertificate(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	srv := f.env.f.srv
	f.env.dirBad.Store(false)

	var during struct {
		sync.Mutex
		before, after int
		openErr       error
		connected     bool
	}
	f.ctrl.mu.Lock()
	f.ctrl.onComplete = func() {
		during.Lock()
		defer during.Unlock()
		during.before = len(srv.handshakeSerials())
		time.Sleep(700 * time.Millisecond) // long enough for any reconnect to dial
		during.after = len(srv.handshakeSerials())
		_, during.openErr = f.alarm.openLink(context.Background())
		_, during.connected = srv.reg.Get(roStewardID)
	}
	f.ctrl.mu.Unlock()

	handshakesBefore := len(srv.handshakeSerials())
	f.ctrl.allow("repair-hold")
	f.send(f.request("repair-hold", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	during.Lock()
	defer during.Unlock()
	assert.Equal(t, during.before, during.after, "no dial while the completion is in flight")
	assert.ErrorIs(t, during.openErr, errRepairHoldsDials)
	assert.False(t, during.connected, "the old link is closed before the completion")

	newSerial := clientSerials(t, f.env.f.dir)[0]
	for _, serial := range srv.handshakeSerials()[handshakesBefore:] {
		assert.Equal(t, newSerial, serial, "every dial after the repair presents the new certificate")
	}
}

func TestRepair_RightsVerificationFailureStopsBeforeAnyKeyIsMade(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	verified := 0
	repairRightsCheck = func(logging.Logger) error {
		verified++
		return os.ErrPermission
	}
	f.ctrl.allow("repair-order")
	f.send(f.request("repair-order", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairFailed)

	assert.Equal(t, 1, verified)
	assert.Empty(t, f.ctrl.callList(), "the controller is never asked")
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, "device_identity.enc.next"), "no new identity key was generated")
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, repairStateFileName), "no new mTLS key was generated")
	assert.Equal(t, []string{f.oldSerial}, clientSerials(t, f.env.f.dir))
	assert.True(t, f.latch.isLatched())
}

func TestRepair_ControllerRefusal_KeepsOldKeysAndDoesNotRetry(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	f.env.dirBad.Store(false)
	idBefore, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	// The nonce was used (or the steward is in the wrong state): never allowed.
	f.send(f.request("repair-used", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairFailed)

	time.Sleep(600 * time.Millisecond) // many retry periods
	assert.Len(t, f.ctrl.callList(), 1, "a refusal is not retried")
	idAfter, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	assert.Equal(t, idBefore.IdentityKeyPub, idAfter.IdentityKeyPub)
	assert.Equal(t, []string{f.oldSerial}, clientSerials(t, f.env.f.dir))
	currentPub, _, err := f.ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, f.oldPub, currentPub, "the old identity key is still the current one")
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, "device_identity.enc.next"))
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, repairStateFileName))
	assert.True(t, f.latch.isLatched())
}

func TestRepair_LostResponse_RetriedWithTheSameNewKey(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	f.env.dirBad.Store(false)
	f.ctrl.mu.Lock()
	f.ctrl.dropFirst = true
	f.ctrl.mu.Unlock()

	f.ctrl.allow("repair-lost")
	f.send(f.request("repair-lost", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	calls := f.ctrl.callList()
	require.Len(t, calls, 2, "the lost response is retried once, not in a tight loop")
	assert.Equal(t, calls[0].Body["new_identity_key_pub"], calls[1].Body["new_identity_key_pub"], "the same new identity key")
	assert.Equal(t, calls[0].Body["csr_pem"], calls[1].Body["csr_pem"], "the same new mTLS key")
	assert.Equal(t, calls[0].DeviceID, calls[1].DeviceID, "the retry is addressed to the same, still-current device ID")
	assert.NotEqual(t, f.oldSerial, clientSerials(t, f.env.f.dir)[0])
}

func TestRepair_RestartMidRepair_ResumesWithTheSameRepairID(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	f.env.dirBad.Store(false)
	srv := f.env.f.srv
	f.ctrl.mu.Lock()
	f.ctrl.dropFirst = true
	// The process is killed while the first completion is in flight.
	f.ctrl.onComplete = func() {
		f.ctrl.mu.Lock()
		first := len(f.ctrl.calls) == 1
		f.ctrl.mu.Unlock()
		if first {
			go f.stop()
		}
	}
	f.ctrl.mu.Unlock()
	f.ctrl.allow("repair-restart")
	f.send(f.request("repair-restart", requestOpts{}))
	select {
	case <-f.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the first alarm did not stop")
	}
	require.FileExists(t, filepath.Join(f.env.f.dir, repairStateFileName), "the repair is recorded for the restart")
	f.ctrl.mu.Lock()
	f.ctrl.onComplete = nil
	f.ctrl.mu.Unlock()

	// A new process: nothing dials before the repair resumes.
	handshakesBefore := len(srv.handshakeSerials())
	f.latch = openTamperLatch(f.env.f.dir, logging.NewLogger("error"))
	require.True(t, f.latch.isLatched())
	f.start()
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	calls := f.ctrl.callList()
	require.GreaterOrEqual(t, len(calls), 2)
	assert.Equal(t, "repair-restart", calls[len(calls)-1].Body["repair_id"])
	assert.Equal(t, calls[0].Body["new_identity_key_pub"], calls[len(calls)-1].Body["new_identity_key_pub"])
	newSerial := clientSerials(t, f.env.f.dir)[0]
	for _, serial := range srv.handshakeSerials()[handshakesBefore:] {
		assert.Equal(t, newSerial, serial, "the resumed steward never presents the retired certificate")
	}
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, repairStateFileName))
}

func TestRepair_UnlockLeavesTheLatchAfterARepair(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	f.start()
	srv := f.env.f.srv
	ctx := context.Background()
	require.NoError(t, srv.cp.SendTamperState(ctx, roStewardID, true))

	f.env.dirBad.Store(false)
	f.ctrl.allow("repair-unlock")
	f.send(f.request("repair-unlock", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)
	assert.True(t, f.latch.isLatched(), "still latched until the controller sends the unlock")

	// The controller locks the repaired host on its new link, then unlocks it.
	require.Eventually(t, func() bool { return srv.cp.SendTamperState(ctx, roStewardID, true) == nil }, 20*time.Second, 50*time.Millisecond)
	require.NoError(t, srv.cp.SendTamperState(ctx, roStewardID, false))
	select {
	case <-f.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the alarm did not release the latch")
	}
	assert.False(t, f.latch.isLatched())
	assert.NoFileExists(t, filepath.Join(f.env.f.dir, tamperLatchFileName))
}

func TestRepair_FaultPersists_StaysLatchedAndReports(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{code: cpTypes.ReasonCodeTamperSecurityProfile})
	prev := SecurityProfile
	SecurityProfile = securityProfilePublicBeta
	t.Setenv("CFGMS_SECURITY_PROFILE", securityProfileDevelopment) // the fault the repair cannot clear
	t.Cleanup(func() { SecurityProfile = prev })
	f.start()

	f.ctrl.allow("repair-fault")
	f.send(f.request("repair-fault", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairFaultPersists)
	assert.True(t, f.latch.isLatched())
	assert.NotEqual(t, f.oldSerial, clientSerials(t, f.env.f.dir)[0], "the keys were rotated; the fault is not about keys")
}

func TestRepair_MalformedRepairIDIsIgnored(t *testing.T) {
	f := newRepairFixture(t, repairFixtureOpts{})
	r := newRepairer(f.latch, func() *tamperFault { return nil }, f.ctrl.server.URL, logging.NewLogger("error"))
	for _, id := range []string{"", "has space", "semi;colon", strings.Repeat("a", maxRepairIDLen+1), "new\nline"} {
		assert.Nil(t, r.handle(context.Background(), nil, cpTypes.RepairRequest{RepairID: id}), id)
	}
	assert.Empty(t, r.reasons.List(), "a malformed or missing repair ID reports nothing and changes nothing")
	assert.Empty(t, f.ctrl.callList())
}

func TestRepair_NotLatched_ReportsNotLocked(t *testing.T) {
	f := newROFixture(t, trustSourceCompileBaked)
	tc := connectRO(t, f, trustSourceCompileBaked)
	latch := openTamperLatch(f.dir, logging.NewLogger("error")) // never raised
	watchRepairWhileNotLocked(tc, latch)

	require.NoError(t, f.srv.cp.SendRepair(context.Background(), roStewardID, cpTypes.RepairRequest{
		RepairID: "repair-nl", LossDigest: cpTypes.LossDigest(nil), ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
	}))
	reason := repairReason(t, f.srv, cpTypes.HealthComponentRepair, cpTypes.ReasonCodeRepairNotLocked)
	assert.Equal(t, "repair-nl", reason.Message)
	assert.False(t, latch.isLatched())
}

func TestRepair_NoBakedList_ExpiredRequestIsNotLocked_CAClassIsAnchorUntrusted(t *testing.T) {
	setBaked(t, "")
	now := time.Now()
	req := cpTypes.RepairRequest{RepairID: "r", LossDigest: cpTypes.LossDigest(nil), ExpiresAtUnix: now.Add(time.Minute).Unix()}
	assert.Equal(t, "", verifyRepairRequest(roStewardID, req, []string{cpTypes.ReasonCodeTamperDataDir}, now),
		"no baked list: honored on any session that passed the anchor check")

	expired := req
	expired.ExpiresAtUnix = now.Add(-time.Second).Unix()
	assert.Equal(t, cpTypes.ReasonCodeRepairNotLocked, verifyRepairRequest(roStewardID, expired, []string{cpTypes.ReasonCodeTamperDataDir}, now))

	for _, code := range []string{cpTypes.ReasonCodeTamperCAMismatch, cpTypes.ReasonCodeTamperTrustDowngrade} {
		assert.Equal(t, cpTypes.ReasonCodeRepairAnchorUntrusted, verifyRepairRequest(roStewardID, req, []string{code}, now),
			"%s: the anchor is under suspicion and nothing verifies to a baked fingerprint", code)
	}
}

func TestRepair_CAClassCode_UnsignedRequest_ReportsAnchorUntrusted(t *testing.T) {
	setBaked(t, "")
	f := newRepairFixture(t, repairFixtureOpts{code: cpTypes.ReasonCodeTamperCAMismatch})
	f.start()
	before := shallowSnapshot(t, f.paths.dataDir, f.paths.logDir)
	f.ctrl.allow("repair-ca")
	f.send(f.request("repair-ca", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairAnchorUntrusted)
	assert.Empty(t, f.ctrl.callList())
	assert.Equal(t, before, shallowSnapshot(t, f.paths.dataDir, f.paths.logDir))
	assert.Empty(t, f.removedPaths())
}

func TestRepair_BakedHost_BadSignatureExpiredAndPlantedCA_AreSignatureInvalid(t *testing.T) {
	good := newRepairSigner(t, "controller")
	planted := newRepairSigner(t, "planted")
	cases := map[string]requestOpts{
		"bad signature": {signer: good, badSig: true},
		"expired":       {signer: good, expires: -time.Minute},
		"planted CA":    {signer: planted},
		"unsigned":      {},
		"approved list differs from the signed digest": {signer: good, approved: []string{cpTypes.ReasonCodeRepairLossLocalLogs}, digest: cpTypes.LossDigest(nil)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRepairFixture(t, repairFixtureOpts{signer: good})
			f.start()
			certsBefore := shallowSnapshot(t, f.env.f.dir)
			dataBefore := shallowSnapshot(t, f.paths.dataDir, f.paths.logDir)
			f.ctrl.allow("repair-sig")
			f.send(f.request("repair-sig", opts))
			awaitOutcome(t, f, cpTypes.ReasonCodeRepairSignatureInvalid)

			assert.Empty(t, f.ctrl.callList())
			assert.Empty(t, f.removedPaths())
			assert.Equal(t, dataBefore, shallowSnapshot(t, f.paths.dataDir, f.paths.logDir))
			// The latch file is the only thing the alarm itself rewrites in the cert store.
			assert.Equal(t, certsBefore, shallowSnapshot(t, f.env.f.dir))
			assert.True(t, f.latch.isLatched())
		})
	}
}

func TestRepair_BakedHost_ValidSignatureCompletes(t *testing.T) {
	good := newRepairSigner(t, "controller")
	f := newRepairFixture(t, repairFixtureOpts{signer: good})
	f.start()
	f.env.dirBad.Store(false)
	f.ctrl.allow("repair-signed")
	f.send(f.request("repair-signed", requestOpts{signer: good}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)
}

func TestRepair_DiscardsExposedTrustMaterial(t *testing.T) {
	good := newRepairSigner(t, "controller")
	f := newRepairFixture(t, repairFixtureOpts{signer: good, code: cpTypes.ReasonCodeTamperCAMismatch})
	f.stop()

	// The installer CA is the anchor; the CA persisted in the data folder was
	// replaced, and a signing certificate was pushed while the folder was exposed.
	installerCA := filepath.Join(t.TempDir(), "controller-ca.crt")
	require.NoError(t, os.WriteFile(installerCA, []byte(f.env.f.srv.caPEM), 0o600))
	t.Setenv("CFGMS_HTTP_CA_CERT_PATH", installerCA)

	plantedCA := newROServer(t).caPEM
	id, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	id.TrustMode = trustModeString(trustSourceInstallPinned)
	id.CACertPEM = plantedCA
	id.ServerCertPEM = "planted-server-cert"
	id.SigningCertPEMs = []string{"planted-signing-cert"}
	require.NoError(t, saveIdentity(f.env.f.dir, *id))

	f.start()
	f.env.dirBad.Store(false)
	f.ctrl.allow("repair-exposed")
	f.send(f.request("repair-exposed", requestOpts{signer: good}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	after, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	assert.NotContains(t, after.CACertPEM, "planted")
	canonical, err := verifyPersistedCA(after.CACertPEM, after.CAPinFingerprint)
	require.NoError(t, err, "the CA is re-anchored to the one the pin vouches for")
	assert.Equal(t, strings.TrimSpace(f.env.f.srv.caPEM), strings.TrimSpace(canonical))
	assert.Empty(t, after.ServerCertPEM)
	assert.Empty(t, after.SigningCertPEMs)
	assert.Empty(t, after.SigningCertPEM)
}

func TestAssessRepairLoss_NothingLostWhenEverythingIsReadable(t *testing.T) {
	p := repairPaths{dataDir: t.TempDir(), certStoreDir: t.TempDir(), logDir: t.TempDir()}
	require.NoError(t, os.WriteFile(filepath.Join(p.logDir, "a.log"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(p.actionHistory(), []byte(`{"a":1}`+"\n"), 0o600))
	a := assessRepairLoss(p, nil)
	assert.Empty(t, a.Codes)
	assert.Equal(t, cpTypes.LossDigest(nil), a.digest())
}

func TestAssessRepairLoss_CorruptActionHistory(t *testing.T) {
	p := repairPaths{dataDir: t.TempDir(), certStoreDir: t.TempDir(), logDir: t.TempDir()}
	require.NoError(t, os.WriteFile(p.actionHistory(), []byte(`{"a":1}`+"\n"+"not json\n"), 0o600))
	a := assessRepairLoss(p, nil)
	assert.Equal(t, []string{cpTypes.ReasonCodeRepairLossActionHistory}, a.Codes)
}

func TestAssessRepairLoss_NamesEntriesAnEarlierResetRefused(t *testing.T) {
	p := repairPaths{dataDir: t.TempDir(), certStoreDir: t.TempDir(), logDir: t.TempDir()}
	log := filepath.Join(p.logDir, "locked.log")
	require.NoError(t, os.WriteFile(log, []byte("x"), 0o600))
	a := assessRepairLoss(p, []string{log, filepath.Join(t.TempDir(), "elsewhere")})
	assert.Equal(t, []string{cpTypes.ReasonCodeRepairLossLocalLogs}, a.Codes)
	assert.Equal(t, []string{log}, a.items[cpTypes.ReasonCodeRepairLossLocalLogs], "a path outside the declared directories is not claimed")
}

func TestDecideRepairLoss(t *testing.T) {
	logs := repairAssessment{Codes: []string{cpTypes.ReasonCodeRepairLossLocalLogs}}
	none := repairAssessment{}
	approve := func(codes ...string) cpTypes.RepairRequest {
		return cpTypes.RepairRequest{ApprovedLossCodes: codes, LossDigest: cpTypes.LossDigest(codes)}
	}
	assert.Equal(t, repairProceed, decideRepairLoss(approve(), none))
	assert.Equal(t, repairProceed, decideRepairLoss(approve(cpTypes.ReasonCodeRepairLossLocalLogs), logs))
	assert.Equal(t, repairRefusedDataLoss, decideRepairLoss(approve(), logs), "no approval: refused")
	assert.Equal(t, repairLossSetChanged, decideRepairLoss(approve(cpTypes.ReasonCodeRepairLossLocalLogs), none), "the loss went away: changed")
	assert.Equal(t, repairLossSetChanged,
		decideRepairLoss(approve(cpTypes.ReasonCodeRepairLossLocalLogs, cpTypes.ReasonCodeRepairLossActionHistory), logs),
		"an approval wider than the assessment deletes nothing extra")
	assert.Equal(t, repairLossSetChanged,
		decideRepairLoss(approve(cpTypes.ReasonCodeRepairLossActionHistory), logs), "a different set is refused")
}

func TestRepairPaths_RootsDedupeAndDropShallowDirectories(t *testing.T) {
	base := t.TempDir()
	p := repairPaths{dataDir: base, certStoreDir: filepath.Join(base, "steward", "certs"), logDir: filepath.Join(t.TempDir(), "logs")}
	roots := p.roots()
	assert.Contains(t, roots, base)
	assert.NotContains(t, roots, p.certStoreDir, "covered by the data directory")
	assert.Contains(t, roots, p.logDir)
	// Built from the volume root, not from the temp directory: macOS and Windows
	// temp directories are deeper than a direct child of the volume.
	volRoot := filepath.VolumeName(base) + string(filepath.Separator)
	assert.Empty(t, repairPaths{dataDir: volRoot, logDir: filepath.Join(volRoot, "steward-shallow")}.roots(), "never the top of a volume or a direct child of it")
}
