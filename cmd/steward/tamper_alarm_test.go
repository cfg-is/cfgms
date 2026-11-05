// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/subscribers/systemlog"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// alarmSink is the local system log, observed.
type alarmSink struct {
	mu   sync.Mutex
	keys []string
}

func (r *alarmSink) WriteOnce(_ systemlog.Level, key, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
	return nil
}

func (r *alarmSink) written() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

// alarmEnv isolates the process-wide seams a tamper test touches.
type alarmEnv struct {
	f       *roFixture
	dirBad  atomic.Bool
	connect atomic.Int32
	sink    *alarmSink
}

func newAlarmEnv(t *testing.T, mode TrustSource) *alarmEnv {
	t.Helper()
	f := newROFixture(t, mode)
	e := &alarmEnv{f: f, sink: &alarmSink{}}

	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	t.Setenv("CFGMS_HTTP_CA_CERT_PATH", filepath.Join(t.TempDir(), "absent-installer-ca.crt"))
	t.Setenv("CFGMS_MODULE_BUNDLE_DIR", t.TempDir())
	restore := func(set func()) { set() }
	prevStore, prevCheck, prevURL, prevSink := certStoreDirResolver, dataDirCheck, ControllerURL, newSystemLogSink
	prevRecheck, prevRetry, prevBudget := tamperRecheckInterval, tamperConnectRetry, reportOnlyConnectBudget
	prevProfile := SecurityProfile
	certStoreDirResolver = func() string { return f.dir }
	dataDirCheck = func(logging.Logger) error {
		if e.dirBad.Load() {
			return errors.New("data directory is not secure")
		}
		return nil
	}
	ControllerURL = ""
	newSystemLogSink = func() systemLogWriter { return e.sink }
	tamperRecheckInterval, tamperConnectRetry, reportOnlyConnectBudget = 100*time.Millisecond, 100*time.Millisecond, 10*time.Second
	t.Cleanup(func() {
		restore(func() {
			certStoreDirResolver, dataDirCheck, ControllerURL, newSystemLogSink = prevStore, prevCheck, prevURL, prevSink
			tamperRecheckInterval, tamperConnectRetry, reportOnlyConnectBudget = prevRecheck, prevRetry, prevBudget
			SecurityProfile = prevProfile
			startupReasons.Clear(tamperReasonComponent)
		})
	})
	startupReasons.Clear(tamperReasonComponent)
	return e
}

// cf is a connect function that records every call and never connects.
func (e *alarmEnv) cf() connectFuncT {
	return func(context.Context, string, string, TrustSource, string, identity.KeyStore, bool, logging.Logger) (*client.TransportClient, error) {
		e.connect.Add(1)
		return nil, errors.New("normal connect must not run")
	}
}

// runSteward starts runStewardInternal and returns a function that stops it and
// returns its result.
func (e *alarmEnv) runSteward(t *testing.T, controllerURL string, cf connectFuncT) (stop func() error, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- runStewardInternal(ctx, "planted-token", controllerURL, "", cf) }()
	var once sync.Once
	var result error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-ch:
			case <-time.After(30 * time.Second):
				result = errors.New("runStewardInternal did not return after cancel")
			}
		})
		return result
	}
	t.Cleanup(func() { _ = stop() })
	return stop, ch
}

// tamperHeartbeat waits for a heartbeat carrying a tamper reason with code.
func tamperHeartbeat(t *testing.T, srv *roServer, code string) *cpTypes.Heartbeat {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case hb := <-srv.heartbeats:
			for _, r := range hb.Reasons {
				if r.Code == code {
					return hb
				}
			}
		case <-deadline:
			t.Fatalf("no heartbeat carried tamper code %q", code)
			return nil
		}
	}
}

func assertAlive(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("the steward must not exit on a tamper refusal, but returned %v", err)
	default:
	}
}

func TestTamperAlarm_DataDir_ReportsAndStaysAlive(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	e.dirBad.Store(true)
	logDir := filepath.Join(t.TempDir(), "logs")
	t.Setenv("CFGMS_LOG_DIR", logDir)

	stop, done := e.runSteward(t, "", e.cf())
	hb := tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperDataDir)

	assert.Equal(t, cpTypes.StatusError, hb.Status)
	assertAlive(t, done)
	assert.Zero(t, e.connect.Load(), "the normal connect is never attempted")
	assert.Zero(t, e.f.srv.pulls.Load(), "nothing is pulled from the controller")
	_, statErr := os.Stat(logDir)
	assert.True(t, os.IsNotExist(statErr), "no log file is created inside a refused data directory")
	assert.FileExists(t, filepath.Join(e.f.dir, tamperLatchFileName))
	require.NoError(t, stop())
}

// Report-only is entered before the planted config, token and module cache are
// read: the steward reaches the controller with them in place.
func TestTamperAlarm_DataDir_NothingPlantedIsOpened(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	e.dirBad.Store(true)
	planted := plantUnreadable(t)
	moduleRoot := t.TempDir()
	t.Setenv("CFGMS_MODULE_BUNDLE_DIR", moduleRoot)
	plantUnreadableAt(t, filepath.Join(moduleRoot, "vendor-a"))

	ctx, cancel := context.WithCancel(withRegTokenFile(context.Background(), planted))
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runStewardInternal(ctx, "planted-token", "", planted, e.cf()) }()

	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperDataDir)
	assertAlive(t, done)
	assert.Zero(t, e.connect.Load())
	cancel()
	require.NoError(t, <-done)
}

func TestTamperAlarm_TrustDowngrade_NormalConnectNeverAttempted(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)

	// A controller URL with no installer CA resolves to TOFU, weaker than the
	// compile-baked enrollment.
	stop, done := e.runSteward(t, "https://ctrl.test:4433", e.cf())
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperTrustDowngrade)

	assertAlive(t, done)
	assert.Zero(t, e.connect.Load(), "the normal connect is never attempted")
	require.NoError(t, stop())
}

// A downgrade found by a connect attempt (not the start scan) raises the alarm
// and does not retry.
func TestTamperAlarm_TrustDowngradeFromConnectAttempt_Latches(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	var attempts atomic.Int32
	cf := connectFuncT(func(context.Context, string, string, TrustSource, string, identity.KeyStore, bool, logging.Logger) (*client.TransportClient, error) {
		attempts.Add(1)
		return nil, checkTrustDowngrade(trustSourceTOFU, "", &StewardIdentity{TrustMode: "install-pinned"})
	})
	stop, done := e.runSteward(t, "", cf)
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperTrustDowngrade)
	assertAlive(t, done)
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(1), attempts.Load(), "the refusal is not retried")
	require.NoError(t, stop())
}

func TestTamperAlarm_CAMismatch_IdentityCAReplaced_AlarmOnPinVerifiedCA(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	// The pin-verified CA survives in the install source.
	installCA := filepath.Join(t.TempDir(), "controller-ca.crt")
	require.NoError(t, os.WriteFile(installCA, []byte(e.f.srv.caPEM), 0o600))
	t.Setenv("CFGMS_HTTP_CA_CERT_PATH", installCA)

	other := newROServer(t)
	bad := e.f.id
	bad.CACertPEM = other.caPEM // a different valid CA; the pin is untouched
	require.NoError(t, saveIdentity(e.f.dir, bad))

	stop, done := e.runSteward(t, "", e.cf())
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperCAMismatch)

	assertAlive(t, done)
	assert.Zero(t, e.connect.Load())
	assert.Zero(t, e.f.srv.pulls.Load(), "no config or module is pulled")
	assert.Zero(t, other.reg.Count(), "the replacement CA's controller is never dialed")
	require.NoError(t, stop())
}

// Decision rule against S20: when no pin-verified CA can be rebuilt the typed
// anchor error goes to S20 and the reason is kept locally.
func TestTamperAlarm_CAMismatch_CannotReconstruct_FallsToS20(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	other := newROServer(t)
	bad := e.f.id
	bad.CACertPEM = other.caPEM
	require.NoError(t, saveIdentity(e.f.dir, bad))

	latch := openTamperLatch(e.f.dir, logging.NewNoopLogger())
	latch.raise(cpTypes.ReasonCodeTamperCAMismatch)
	alarm := &tamperAlarm{latch: latch, logger: logging.NewNoopLogger(), sink: e.sink}

	_, err := alarm.openLink(context.Background())
	require.ErrorIs(t, err, errTamperBrokenTrust)
	require.ErrorIs(t, err, errReportOnlyAnchor, "the S11 typed error is preserved for S20")
	assert.Zero(t, e.f.srv.reg.Count())
	assert.Zero(t, other.reg.Count())

	stop, done := e.runSteward(t, "", e.cf())
	require.Eventually(t, func() bool { return len(e.sink.written()) > 0 }, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, cpTypes.ReasonCodeTamperCAMismatch, e.sink.written()[0], "the reason is kept locally")
	assertAlive(t, done)
	assert.Zero(t, e.f.srv.reg.Count(), "nothing is dialed")
	require.NoError(t, stop())
}

func TestTamperAlarm_InstallerCAReplaced_LinkUsesIdentityCA(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	other := newROServer(t)
	installCA := filepath.Join(t.TempDir(), "controller-ca.crt")
	require.NoError(t, os.WriteFile(installCA, []byte(other.caPEM), 0o600)) // wrong CA at the pin's path
	t.Setenv("CFGMS_HTTP_CA_CERT_PATH", installCA)

	stop, done := e.runSteward(t, "", e.cf())
	// The install source cannot be rebuilt, but the identity's own CA still
	// verifies against its pin and the link's default anchor works.
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperCAMismatch)
	assertAlive(t, done)
	assert.Zero(t, e.connect.Load())
	require.NoError(t, stop())
}

func TestTamperAlarm_SecurityProfile_DowngradeKeepsStewardAlive(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	SecurityProfile = securityProfilePublicBeta
	t.Setenv("CFGMS_SECURITY_PROFILE", securityProfileDevelopment)

	stop, done := e.runSteward(t, "", e.cf())
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperSecurityProfile)
	assertAlive(t, done)
	assert.Zero(t, e.connect.Load())
	require.NoError(t, stop())
}

// S8 ordering: a bad token file and a tampered directory give the tamper path.
func TestTamperAlarm_BadTokenFileAndTamperedDir_TamperPath(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	e.dirBad.Store(true)
	resetStartupReasons(t)
	bad := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(bad, []byte(""), 0o600)) // empty: refused
	startupTokenFromFile(bad)

	stop, done := e.runSteward(t, "", e.cf())
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperDataDir)
	assertAlive(t, done)
	assert.Zero(t, e.connect.Load(), "no normal connect on the stored identity")
	require.NoError(t, stop())
}

// waitConnected waits until the steward's alarm link is registered at the controller.
func waitConnected(t *testing.T, srv *roServer) {
	t.Helper()
	require.Eventually(t, func() bool { _, ok := srv.reg.Get(roStewardID); return ok }, 20*time.Second, 20*time.Millisecond)
}

func TestTamperAlarm_Latch_ReleasesOnlyWithBothConditions(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	e.dirBad.Store(true)
	stop, done := e.runSteward(t, "", e.cf())
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperDataDir)
	waitConnected(t, e.f.srv)
	ctx := context.Background()
	latchPath := filepath.Join(e.f.dir, tamperLatchFileName)
	stillLatched := func(why string) {
		t.Helper()
		time.Sleep(600 * time.Millisecond) // several recheck intervals
		assert.FileExists(t, latchPath, why)
		assert.Zero(t, e.connect.Load(), why)
		assertAlive(t, done)
	}

	// The controller acknowledges the lock; the local fault is fixed but no
	// restore has been sent.
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, true))
	e.dirBad.Store(false)
	stillLatched("fault fixed locally, no restore signal")

	// Restore with the fault present again.
	e.dirBad.Store(true)
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, false))
	stillLatched("restore signal with the fault still present")

	// Both: the fault clears and the restore stands.
	e.dirBad.Store(false)
	require.Eventually(t, func() bool { return e.connect.Load() > 0 }, 20*time.Second, 20*time.Millisecond,
		"the steward leaves report-only and takes the normal connect, which refetches config")
	assert.NoFileExists(t, latchPath)
	require.NoError(t, stop())
}

func TestTamperAlarm_TrustDowngradeLatch_ReleasesOnlyWithBothConditions(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	// A controller URL with no installer CA resolves to TOFU, weaker than the
	// compile-baked enrollment.
	_, done := e.runSteward(t, "https://ctrl.test:4433", e.cf())
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperTrustDowngrade)
	waitConnected(t, e.f.srv)
	ctx := context.Background()
	latchPath := filepath.Join(e.f.dir, tamperLatchFileName)

	// Restore while the downgrade stands: stays report-only.
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, true))
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, false))
	time.Sleep(600 * time.Millisecond)
	assert.Zero(t, e.connect.Load(), "restore signal with the downgrade still present")
	assert.FileExists(t, latchPath)

	// The downgrade condition is removed (the identity is re-enrolled at the
	// weaker level, which is the only way to change the anchor) and the restore
	// is withdrawn by a new lock: stays report-only.
	weaker := e.f.id
	weaker.TrustMode = trustModeString(trustSourceTOFU)
	require.NoError(t, saveIdentity(e.f.dir, weaker))
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, true))
	time.Sleep(600 * time.Millisecond)
	assert.Zero(t, e.connect.Load(), "downgrade removed but no restore signal")
	assert.FileExists(t, latchPath)
	assertAlive(t, done)

	// Both: leaves.
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, false))
	require.Eventually(t, func() bool { return e.connect.Load() > 0 }, 20*time.Second, 20*time.Millisecond)
	assert.NoFileExists(t, latchPath)
}

func TestTamperLatch_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"corrupt":         "{not json",
		"unknown version": `{"version":99,"codes":["tamper.data_dir"]}`,
		"no codes":        `{"version":1,"codes":[]}`,
		"unknown code":    `{"version":1,"codes":["tamper.invented"]}`,
		"empty file":      "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, tamperLatchFileName), []byte(content), 0o600))
			l := openTamperLatch(dir, logging.NewNoopLogger())
			assert.True(t, l.isLatched(), "a present latch file that cannot be understood is a latch")
			assert.False(t, l.restoreReady())
			assert.NotEmpty(t, l.primaryCode())
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		dir := t.TempDir()
		// A directory where the file should be cannot be read as a file.
		require.NoError(t, os.Mkdir(filepath.Join(dir, tamperLatchFileName), 0o700))
		assert.True(t, openTamperLatch(dir, logging.NewNoopLogger()).isLatched())
	})
	t.Run("a pipe is never opened", func(t *testing.T) {
		dir := t.TempDir()
		plantUnreadableAt(t, filepath.Join(dir, tamperLatchFileName))
		assert.True(t, openTamperLatch(dir, logging.NewNoopLogger()).isLatched())
	})
	t.Run("absent is not latched", func(t *testing.T) {
		assert.False(t, openTamperLatch(t.TempDir(), logging.NewNoopLogger()).isLatched())
	})
}

func TestTamperLatch_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	l := openTamperLatch(dir, logging.NewNoopLogger())
	l.raise(cpTypes.ReasonCodeTamperCAMismatch)
	again := openTamperLatch(dir, logging.NewNoopLogger())
	assert.True(t, again.isLatched())
	assert.Equal(t, cpTypes.ReasonCodeTamperCAMismatch, again.primaryCode())
}

// A restore the controller sends before it acknowledged the lock (for example
// its state on connect) never releases.
func TestTamperLatch_RestoreNeedsLockAcknowledged(t *testing.T) {
	l := openTamperLatch(t.TempDir(), logging.NewNoopLogger())
	l.raise(cpTypes.ReasonCodeTamperDataDir)
	l.onController(false)
	assert.False(t, l.restoreReady())
	l.onController(true)
	l.onController(false)
	assert.True(t, l.restoreReady())
	l.onController(true)
	assert.False(t, l.restoreReady(), "a new lock withdraws the restore")
}

// Lost latch file plus TamperState{locked: true} on connect -> re-latched.
func TestTamperLatch_LostFileRelatchedByControllerLock(t *testing.T) {
	f := newROFixture(t, trustSourceCompileBaked)
	tc := connectRO(t, f, trustSourceCompileBaked)
	latchDir := t.TempDir()
	latch := openTamperLatch(latchDir, logging.NewNoopLogger())
	require.False(t, latch.isLatched(), "the latch file is lost")

	locked := watchControllerLock(tc, latch)
	require.NoError(t, f.srv.cp.SendTamperState(context.Background(), roStewardID, true))
	select {
	case <-locked:
	case <-time.After(15 * time.Second):
		t.Fatal("the lock was not seen")
	}
	assert.True(t, latch.isLatched())
	assert.FileExists(t, filepath.Join(latchDir, tamperLatchFileName))
	assert.True(t, openTamperLatch(latchDir, logging.NewNoopLogger()).isLatched(), "and it survives a restart")
}

// A lock that reached the client before the handler existed is not lost.
func TestWatchControllerLock_LockBeforeHandler(t *testing.T) {
	f := newROFixture(t, trustSourceCompileBaked)
	tc := connectRO(t, f, trustSourceCompileBaked)
	// The link is already report-only; this is the reason EnterReportOnly records.
	tc.SetHealthReason(client.ReportOnlyReasonComponent, client.ReasonTamperLocked, "controller reports this host locked")
	latch := openTamperLatch(t.TempDir(), logging.NewNoopLogger())
	locked := watchControllerLock(tc, latch)
	select {
	case <-locked:
	default:
		t.Fatal("the earlier lock must be picked up")
	}
	assert.True(t, latch.isLatched())
}

// After release the steward takes the normal connect on the stored identity
// and pulls its config from the controller again.
func TestTamperAlarm_Release_RefetchesConfigFromController(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	serverCert, err := e.f.srv.mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidityDays: 30,
	})
	require.NoError(t, err)
	withServerCert := e.f.id
	withServerCert.ServerCertPEM = string(serverCert.CertificatePEM)
	require.NoError(t, saveIdentity(e.f.dir, withServerCert))

	e.dirBad.Store(true)
	e.runSteward(t, "", nil)
	tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperDataDir)
	waitConnected(t, e.f.srv)
	assert.Zero(t, e.f.srv.pulls.Load(), "nothing is pulled while latched")

	ctx := context.Background()
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, true))
	e.dirBad.Store(false)
	require.NoError(t, e.f.srv.cp.SendTamperState(ctx, roStewardID, false))
	require.Eventually(t, func() bool { return e.f.srv.pulls.Load() > 0 }, 60*time.Second, 50*time.Millisecond,
		"the released steward refetches config from the controller")
}
