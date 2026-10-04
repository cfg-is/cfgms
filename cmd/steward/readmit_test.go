// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// readmitTestController is the controller's HTTPS side of re-admission backed by
// a real pkg/cert CA: /refresh/challenge, /refresh/complete (issue now, queue, or
// reject), /refresh/claim, and /register (counted; answers 409 or 503).
type readmitTestController struct {
	server  *httptest.Server
	certMgr *cert.Manager
	caPEM   string

	completeMode string // "issue" | "queue" | "reject"
	unknown      bool   // challenge answers 404
	registerCode int    // status /register answers with

	mu         sync.Mutex
	pendingCSR *x509.CertificateRequest
	approved   bool
	issuedCert string
	completes  int
	claims     []string // pending IDs claimed
	registers  atomic.Int32
}

func newReadmitTestController(t *testing.T, completeMode string) *readmitTestController {
	t.Helper()
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "CFGMS Readmit Test CA", Country: "US", ValidityDays: 30},
	})
	require.NoError(t, err)
	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	c := &readmitTestController{certMgr: certMgr, caPEM: string(caPEM), completeMode: completeMode, registerCode: http.StatusServiceUnavailable}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/refresh/challenge"):
			if c.unknown {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"nonce":"dGVzdA","server_ts":1,"expires_in":60}`))
		case strings.HasSuffix(r.URL.Path, "/refresh/complete"):
			c.handleComplete(t, w, r)
		case strings.HasSuffix(r.URL.Path, "/refresh/claim"):
			c.handleClaim(t, w, r)
		case strings.HasSuffix(r.URL.Path, "/api/v1/register"):
			c.registers.Add(1)
			http.Error(w, "registration answered by test", c.registerCode)
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *readmitTestController) handleComplete(t *testing.T, w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSRPEM string `json:"csr_pem"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
	block, _ := pem.Decode([]byte(body.CSRPEM))
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	c.mu.Lock()
	c.completes++
	c.mu.Unlock()
	switch c.completeMode {
	case "reject":
		http.Error(w, "refresh rejected by tenant policy", http.StatusForbidden)
	case "queue":
		c.mu.Lock()
		c.pendingCSR = csr
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"queued","pending_id":"refresh-pending-1"}`))
	default:
		c.writeBundle(t, w, csr)
	}
}

func (c *readmitTestController) handleClaim(t *testing.T, w http.ResponseWriter, r *http.Request) {
	var body struct {
		PendingID string `json:"pending_id"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
	c.mu.Lock()
	c.claims = append(c.claims, body.PendingID)
	approved, csr := c.approved, c.pendingCSR
	c.mu.Unlock()
	switch {
	case body.PendingID != "refresh-pending-1" || csr == nil:
		http.Error(w, "pending refresh not found", http.StatusNotFound)
	case !approved:
		w.WriteHeader(http.StatusAccepted)
	default:
		c.writeBundle(t, w, csr)
	}
}

func (c *readmitTestController) writeBundle(t *testing.T, w http.ResponseWriter, csr *x509.CertificateRequest) {
	issued, err := c.certMgr.SignClientCertificateRequest(csr.PublicKey, &cert.ClientCertConfig{
		CommonName: csr.Subject.CommonName, ClientID: csr.Subject.CommonName, ValidityDays: 30,
	})
	require.NoError(t, err)
	c.mu.Lock()
	c.issuedCert = string(issued.CertificatePEM)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":            "approved",
		"client_cert":       string(issued.CertificatePEM),
		"ca_cert":           c.caPEM,
		"steward_id":        "steward-readmitted",
		"tenant_id":         "tenant-readmit",
		"transport_address": "127.0.0.1:1",
	})
}

func (c *readmitTestController) approve() {
	c.mu.Lock()
	c.approved = true
	c.mu.Unlock()
}

func newReadmitKeyStore(t *testing.T) *identity.FileKeyStore {
	t.Helper()
	ks, err := identity.NewFileKeyStoreForTesting(t.TempDir())
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	return ks
}

func readmit(t *testing.T, controller *readmitTestController, dir string, id *StewardIdentity, ks *identity.FileKeyStore) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := readmitWithDeviceKey(ctx, id, ks, dir, "tok", controller.server.URL, trustSourceCompileBaked, "",
		stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	return err
}

// TestReadmit_QueuedRequestIsClaimedAfterApproval guards Issue #4532: a re-admission
// queued for approval keeps its CSR key and pending ID, and a later cycle collects
// the approved certificate with that key instead of filing a new request — before
// this, an approval was never delivered and the steward queued forever.
func TestReadmit_QueuedRequestIsClaimedAfterApproval(t *testing.T) {
	dir := t.TempDir()
	controller := newReadmitTestController(t, "queue")
	ks := newReadmitKeyStore(t)
	storedID := &StewardIdentity{StewardID: "steward-q", TenantID: "tenant-q", TransportAddress: "127.0.0.1:1", ServerCertPEM: "server"}

	err := readmit(t, controller, dir, storedID, ks)
	var queued *registration.RefreshPendingError
	require.ErrorAs(t, err, &queued)
	assert.Equal(t, "refresh-pending-1", queued.PendingID)
	pending, err := loadRefreshPendingState(dir)
	require.NoError(t, err)
	require.NotNil(t, pending, "the queued request and its CSR key are persisted")

	err = readmit(t, controller, dir, storedID, ks)
	require.ErrorIs(t, err, registration.ErrRefreshPending, "still queued until an operator approves")
	assert.Equal(t, 1, controller.completes, "the steward claims rather than filing a second request")

	controller.approve()
	blockTLSCredentialSources(t, dir)
	err = readmit(t, controller, dir, storedID, ks)
	require.Error(t, err, "no real transport is listening")
	assert.Contains(t, err.Error(), errNoTLSMaterial, "the approved certificate reached the connect step")
	assert.Equal(t, []string{"refresh-pending-1", "refresh-pending-1"}, controller.claims)

	_, pairErr := tls.X509KeyPair([]byte(controller.issuedCert), []byte(pending.ClientKeyPEM))
	require.NoError(t, pairErr, "the claimed certificate pairs with the key kept for the queued CSR")
	cleared, err := loadRefreshPendingState(dir)
	require.NoError(t, err)
	assert.Nil(t, cleared, "the pending state is cleared once the certificate is collected")
}

// TestReadmit_RejectedReturnsRejected guards Issue #4532: an explicit refusal is
// reported as ErrRefreshRejected (the connect loop keeps asking slowly) and never
// falls through to registration.
func TestReadmit_RejectedReturnsRejected(t *testing.T) {
	controller := newReadmitTestController(t, "reject")
	err := readmit(t, controller, t.TempDir(), &StewardIdentity{StewardID: "steward-r", TenantID: "tenant-r", TransportAddress: "127.0.0.1:1", ServerCertPEM: "server"}, newReadmitKeyStore(t))
	require.ErrorIs(t, err, registration.ErrRefreshRejected)
	assert.Zero(t, controller.registers.Load())
}

// TestReadmit_WithoutStoredIdentityRebuildsFromResponse guards Issue #4532: after a
// 409 the steward has no stored identity record; re-admission rebuilds it from the
// identity the controller returns with the certificate.
func TestReadmit_WithoutStoredIdentityRebuildsFromResponse(t *testing.T) {
	dir := t.TempDir()
	controller := newReadmitTestController(t, "issue")
	blockTLSCredentialSources(t, dir)

	err := readmit(t, controller, dir, nil, newReadmitKeyStore(t))
	require.Error(t, err, "no real transport is listening")
	assert.Contains(t, err.Error(), errNoTLSMaterial, "the bundle built from the response reached the connect step")
}

// TestRegisterAndConnect_RejectedStoredIdentityReadmitsWithDeviceKey guards Issue
// #4532: a controller that refuses the stored identity sends the steward to
// re-admission with its device key, not to token registration.
func TestRegisterAndConnect_RejectedStoredIdentityReadmitsWithDeviceKey(t *testing.T) {
	controller := newReadmitTestController(t, "queue")
	f := newStoredIdentityFixture(t, "placeholder")
	f.pointAtRefusingController(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "tok", controller.server.URL, trustSourceCompileBaked, "", newReadmitKeyStore(t), false, logging.NewLogger("error"))

	require.ErrorIs(t, err, registration.ErrRefreshPending)
	assert.Equal(t, 1, controller.completes, "re-admission was requested")
	assert.Zero(t, controller.registers.Load(), "a known device never re-registers with its token")
	id, loadErr := loadIdentity(f.certStoreDir)
	require.NoError(t, loadErr)
	assert.NotNil(t, id, "the stored identity is kept until a replacement is issued")
}

// TestRegisterAndConnect_UnknownDeviceRegistersWithToken guards Issue #4532: when
// the controller has no record of the device, the steward falls back to
// registering with its configured token.
func TestRegisterAndConnect_UnknownDeviceRegistersWithToken(t *testing.T) {
	controller := newReadmitTestController(t, "issue")
	controller.unknown = true
	f := newStoredIdentityFixture(t, "placeholder")
	f.pointAtRefusingController(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "tok", controller.server.URL, trustSourceCompileBaked, "", newReadmitKeyStore(t), false, logging.NewLogger("error"))

	require.Error(t, err, "the test controller answers registration with 503")
	assert.Positive(t, controller.registers.Load(), "an unknown device registers with its token")
}

// TestRegisterAndConnect_ConflictReadmitsWithDeviceKey guards Issue #4532: a 409
// from registration (the controller already holds this device's record) routes to
// re-admission instead of being refused forever.
func TestRegisterAndConnect_ConflictReadmitsWithDeviceKey(t *testing.T) {
	controller := newReadmitTestController(t, "queue")
	controller.registerCode = http.StatusConflict
	dir := t.TempDir()
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return dir }
	t.Cleanup(func() { certStoreDirResolver = prev })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "tok", controller.server.URL, trustSourceCompileBaked, "", newReadmitKeyStore(t), false, logging.NewLogger("error"))

	require.ErrorIs(t, err, registration.ErrRefreshPending)
	assert.Equal(t, int32(1), controller.registers.Load())
	assert.Equal(t, 1, controller.completes, "the 409 led to a re-admission request")
}

// TestRunSteward_RejectedReadmissionKeepsAsking guards Issue #4532: a refused
// re-admission no longer stops the connect loop; it asks again later.
func TestRunSteward_RejectedReadmissionKeepsAsking(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	saved := ControllerURL
	ControllerURL = "https://ctrl.test:4433"
	defer func() { ControllerURL = saved }()
	prevRetry := rejectedReadmissionRetry
	rejectedReadmissionRetry = 20 * time.Millisecond
	defer func() { rejectedReadmissionRetry = prevRetry }()

	var attempts atomic.Int32
	rejected := connectFuncT(func(context.Context, string, string, TrustSource, string, *identity.FileKeyStore, bool, logging.Logger) (*client.TransportClient, error) {
		attempts.Add(1)
		return nil, fmt.Errorf("re-admission: %w", registration.ErrRefreshRejected)
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, runStewardInternal(ctx, "tok_test_rejected", "", "", rejected))
	assert.GreaterOrEqual(t, attempts.Load(), int32(2), "a rejected steward keeps asking")
}

// TestRegisterAndConnect_UnreachableForBudgetReadmits guards Issue #4532: a stored
// identity whose controller stays unreachable for the whole connect budget, while
// the controller's HTTPS side answers, leads to re-admission with the device key
// rather than an endless retry — and the stored identity is kept.
func TestRegisterAndConnect_UnreachableForBudgetReadmits(t *testing.T) {
	prevBudget := storedIdentityConnectBudget
	storedIdentityConnectBudget = 2 * time.Second
	defer func() { storedIdentityConnectBudget = prevBudget }()
	prevJitter := unreachableReadmitJitter
	unreachableReadmitJitter = 0
	defer func() { unreachableReadmitJitter = prevJitter }()

	controller := newReadmitTestController(t, "queue")
	f := newStoredIdentityFixture(t, unusedUDPAddr(t))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "tok", controller.server.URL, trustSourceCompileBaked, "", newReadmitKeyStore(t), false, logging.NewLogger("error"))

	require.ErrorIs(t, err, registration.ErrRefreshPending)
	assert.Equal(t, 1, controller.completes)
	assert.Zero(t, controller.registers.Load())
	id, loadErr := loadIdentity(f.certStoreDir)
	require.NoError(t, loadErr)
	assert.NotNil(t, id, "the stored identity is kept while re-admission is pending")
}

// TestReadmissionPacer_PacesUnreachableReadmission guards the #4533 review: an
// unreachable control plane re-admits after a random initial delay and then at
// most once per interval — and the pace survives a restart (a new pacer reading
// the same directory), so a flapping host does not re-admit on every start.
func TestReadmissionPacer_PacesUnreachableReadmission(t *testing.T) {
	prevInterval, prevJitter := unreachableReadmitInterval, unreachableReadmitJitter
	unreachableReadmitInterval, unreachableReadmitJitter = time.Hour, 30*time.Minute
	defer func() { unreachableReadmitInterval, unreachableReadmitJitter = prevInterval, prevJitter }()

	dir := t.TempDir()
	start := time.Now()
	assert.False(t, (&readmissionPacer{}).due(dir, start), "the first call only schedules")
	assert.True(t, (&readmissionPacer{}).due(dir, start.Add(30*time.Minute)), "due once the initial jitter (< 30m) has passed, across a restart")
	assert.False(t, (&readmissionPacer{}).due(dir, start.Add(31*time.Minute)), "a restart does not reset the interval")
	assert.False(t, (&readmissionPacer{}).due(dir, start.Add(89*time.Minute)), "the interval is at least an hour after the last attempt")
	assert.True(t, (&readmissionPacer{}).due(dir, start.Add(2*time.Hour+time.Minute)), "due again after interval plus jitter")
}

// TestRegisterAndConnect_OpenRequestIsCollectedUnpaced guards the #4533 review:
// pacing limits new requests, not collection — with a request already filed the
// steward claims it on the normal cadence even while the pacer says not yet.
func TestRegisterAndConnect_OpenRequestIsCollectedUnpaced(t *testing.T) {
	prevBudget := storedIdentityConnectBudget
	storedIdentityConnectBudget = 2 * time.Second
	defer func() { storedIdentityConnectBudget = prevBudget }()

	controller := newReadmitTestController(t, "queue")
	f := newStoredIdentityFixture(t, unusedUDPAddr(t))
	saveReadmitPace(f.certStoreDir, time.Now().Add(time.Hour))
	require.NoError(t, saveRefreshPendingState(f.certStoreDir, PendingState{PendingID: "refresh-pending-1", ClientKeyPEM: "unused"}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "tok", controller.server.URL, trustSourceCompileBaked, "", newReadmitKeyStore(t), false, logging.NewLogger("error"))

	require.Error(t, err)
	assert.Equal(t, []string{"refresh-pending-1"}, controller.claims, "the open request is collected despite the pacer")
	assert.Zero(t, controller.completes, "no new request is filed")
}

// TestRegisterAndConnect_UnreachablePacedReturnsWithoutReadmitting verifies that
// while the pacer says not yet, an unreachable stored identity is retried without
// contacting the re-admission endpoint.
func TestRegisterAndConnect_UnreachablePacedReturnsWithoutReadmitting(t *testing.T) {
	prevBudget := storedIdentityConnectBudget
	storedIdentityConnectBudget = 2 * time.Second
	defer func() { storedIdentityConnectBudget = prevBudget }()
	controller := newReadmitTestController(t, "queue")
	f := newStoredIdentityFixture(t, unusedUDPAddr(t))
	saveReadmitPace(f.certStoreDir, time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "tok", controller.server.URL, trustSourceCompileBaked, "", newReadmitKeyStore(t), false, logging.NewLogger("error"))

	require.ErrorIs(t, err, errStoredIdentityUnreachable)
	assert.Zero(t, controller.completes, "no re-admission before the pacer allows it")
}

// TestReadmissionPacer_DistrustsImplausiblePaceFile guards the #4533 review: the
// pace file is unauthenticated local state, so a far-future or corrupt value must
// not stall re-admission — it is treated as absent and a fresh delay is drawn.
func TestReadmissionPacer_DistrustsImplausiblePaceFile(t *testing.T) {
	prevInterval, prevJitter := unreachableReadmitInterval, unreachableReadmitJitter
	unreachableReadmitInterval, unreachableReadmitJitter = time.Hour, 0
	defer func() { unreachableReadmitInterval, unreachableReadmitJitter = prevInterval, prevJitter }()

	now := time.Now()
	t.Run("far future", func(t *testing.T) {
		dir := t.TempDir()
		saveReadmitPace(dir, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))
		assert.True(t, (&readmissionPacer{}).due(dir, now), "an implausible schedule is redrawn (no jitter: due at once)")
	})
	t.Run("corrupt", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, readmitPaceFileName), []byte("{not json"), 0600))
		assert.True(t, (&readmissionPacer{}).due(dir, now), "a corrupt file is treated as absent")
	})
	t.Run("plausible future is honoured", func(t *testing.T) {
		dir := t.TempDir()
		saveReadmitPace(dir, now.Add(30*time.Minute))
		assert.False(t, (&readmissionPacer{}).due(dir, now))
	})
	t.Run("cleared on connect", func(t *testing.T) {
		dir := t.TempDir()
		saveReadmitPace(dir, now.Add(30*time.Minute))
		clearReadmitPace(dir)
		_, ok := loadReadmitPace(dir)
		assert.False(t, ok)
	})
}
