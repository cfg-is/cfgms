// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

const brokenTrustToken = "cfgms_reg_clone_test"

func clearBrokenTrustReasonOnCleanup(t *testing.T) {
	t.Helper()
	startupReasons.Clear(brokenTrustReasonComponent)
	t.Cleanup(func() { startupReasons.Clear(brokenTrustReasonComponent) })
}

func hasBrokenTrustReason() bool {
	for _, r := range startupReasons.List() {
		if r.Component == brokenTrustReasonComponent && r.Code == brokenTrustReasonCode {
			return true
		}
	}
	return false
}

func corruptIdentityFile(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, identityFileName), []byte("{not json"), 0o600))
}

func registerBodyField(t *testing.T, body, field string) (string, bool) {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(body), &m))
	v, ok := m[field].(string)
	return v, ok
}

func connectOnce(t *testing.T, c *cloneTestController, token string, src TrustSource, ks identity.KeyStore, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := registerAndConnect(ctx, token, c.server.URL, src, "", ks, false, logging.NewLogger("error"))
	return err
}

func TestDecideBrokenTrust(t *testing.T) {
	ok := brokenTrustInput{cause: causeIdentityCorrupt, tokenAvailable: true, trustSrc: trustSourceCompileBaked, hasKeyStore: true}
	allowed, _ := decideBrokenTrust(ok)
	assert.True(t, allowed)

	pinned := ok
	pinned.trustSrc = trustSourceInstallPinned
	allowed, _ = decideBrokenTrust(pinned)
	assert.True(t, allowed)

	for name, mutate := range map[string]func(*brokenTrustInput){
		"no cause":     func(i *brokenTrustInput) { i.cause = "" },
		"no token":     func(i *brokenTrustInput) { i.tokenAvailable = false },
		"no key store": func(i *brokenTrustInput) { i.hasKeyStore = false },
		"tofu":         func(i *brokenTrustInput) { i.trustSrc = trustSourceTOFU },
		"no source":    func(i *brokenTrustInput) { i.trustSrc = 0 },
		"data dir":     func(i *brokenTrustInput) { i.dataDirTampered = true },
	} {
		t.Run(name, func(t *testing.T) {
			in := ok
			mutate(&in)
			allowed, why := decideBrokenTrust(in)
			assert.False(t, allowed)
			assert.NotEmpty(t, why)
		})
	}
}

// A corrupt stored identity with a token: re-key, register as a new device
// naming the old steward ID, declare clone_reason=broken_trust.
func TestRegisterAndConnect_CorruptIdentity_ReKeysAndRegistersBrokenTrust(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()
	corruptIdentityFile(t, f.certStoreDir)

	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 8*time.Second), "approval never comes")

	assert.NotEqual(t, deviceBefore, ks.DeviceID(), "the device key changed")
	assert.Equal(t, int32(1), controller.registerHits.Load())
	assert.Zero(t, controller.refreshHits.Load(), "the old identity is never presented")
	body := controller.lastRegisterBody()
	reason, _ := registerBodyField(t, body, "clone_reason")
	cloneOf, _ := registerBodyField(t, body, "clone_of")
	assert.Equal(t, cloneReasonBrokenTrust, reason)
	assert.Equal(t, f.stewardID, cloneOf, "the old ID is recovered from the certificate subject")
	assert.Equal(t, ks.DeviceID(), registerDevice(t, body))

	entries, err := controller.pending.ListPending(context.Background(), "default")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, f.stewardID, entries[0].CloneOf)

	m, err := loadCloneMarker(f.certStoreDir)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, cloneReasonBrokenTrust, m.Reason)
	assert.False(t, m.Rekey)
	assert.True(t, hasBrokenTrustReason(), "the first heartbeat names the broken-trust reason")
}

func registerDevice(t *testing.T, body string) string {
	t.Helper()
	v, _ := registerBodyField(t, body, "device_id")
	return v
}

// The old ID is taken from the identity file's steward_id when that still parses
// partially, before the clone marker and the certificate.
func TestRecoverOldStewardID_Sources(t *testing.T) {
	dir := t.TempDir()
	assert.Empty(t, recoverOldStewardID(dir))

	require.NoError(t, os.WriteFile(filepath.Join(dir, cloneMarkerFileName), []byte(`{"clone_of":"from-marker"}`), 0o600))
	assert.Equal(t, "from-marker", recoverOldStewardID(dir))

	require.NoError(t, os.WriteFile(filepath.Join(dir, identityFileName), []byte(`{"steward_id":"from-identity","transport_address":`), 0o600))
	assert.Empty(t, tolerantStewardID(filepath.Join(dir, identityFileName), "steward_id"), "truncated JSON yields nothing")
	assert.Equal(t, "from-marker", recoverOldStewardID(dir))

	require.NoError(t, os.WriteFile(filepath.Join(dir, identityFileName), []byte(`{"steward_id":"from-identity","extra":`+"1"+`}`), 0o600))
	assert.Equal(t, "from-identity", recoverOldStewardID(dir))
}

// A corrupt clone marker with a token is handled by the same path and does not
// retry silently forever.
func TestRegisterAndConnect_CorruptCloneMarker_BrokenTrust(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	require.NoError(t, os.WriteFile(filepath.Join(f.certStoreDir, cloneMarkerFileName), []byte("{corrupt"), 0o600))

	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 8*time.Second))

	m, err := loadCloneMarker(f.certStoreDir)
	require.NoError(t, err, "the corrupt marker was replaced")
	require.NotNil(t, m)
	assert.Equal(t, cloneReasonBrokenTrust, m.Reason)
	assert.Equal(t, f.stewardID, m.CloneOf)
	reason, _ := registerBodyField(t, controller.lastRegisterBody(), "clone_reason")
	assert.Equal(t, cloneReasonBrokenTrust, reason)
}

func TestRegisterAndConnect_CorruptCloneMarker_NoToken_NothingSent(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()
	marker := []byte("{corrupt")
	require.NoError(t, os.WriteFile(filepath.Join(f.certStoreDir, cloneMarkerFileName), marker, 0o600))

	err := connectOnce(t, controller, "", trustSourceCompileBaked, ks, 3*time.Second)
	require.ErrorIs(t, err, errBrokenTrustNotAllowed)
	assert.Zero(t, controller.registerHits.Load())
	assert.Equal(t, deviceBefore, ks.DeviceID())
}

// A pinned CA that does not verify (not the data directory case) with a token.
func TestRegisterAndConnect_PinnedCAUnverifiable_BrokenTrust(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()
	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.CAPinFingerprint = strings.Repeat("0", 64)
	require.NoError(t, saveIdentity(f.certStoreDir, *id))

	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceInstallPinned, ks, 8*time.Second))

	assert.NotEqual(t, deviceBefore, ks.DeviceID())
	body := controller.lastRegisterBody()
	reason, _ := registerBodyField(t, body, "clone_reason")
	cloneOf, _ := registerBodyField(t, body, "clone_of")
	assert.Equal(t, cloneReasonBrokenTrust, reason)
	assert.Equal(t, f.stewardID, cloneOf, "recovered from the unusable identity file")
}

// Corrupt identity and only a network-fetched CA (TOFU): the token is never sent.
func TestRegisterAndConnect_CorruptIdentity_TOFU_NoRegistrationNoToken(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()
	corruptIdentityFile(t, f.certStoreDir)

	err := connectOnce(t, controller, brokenTrustToken, trustSourceTOFU, ks, 3*time.Second)
	require.ErrorIs(t, err, errBrokenTrustNotAllowed)
	assert.Zero(t, controller.registerHits.Load(), "no request, so no token, reached the controller")
	assert.Zero(t, controller.refreshHits.Load())
	assert.Equal(t, deviceBefore, ks.DeviceID(), "nothing was re-keyed")
	m, mErr := loadCloneMarker(f.certStoreDir)
	require.NoError(t, mErr)
	assert.Nil(t, m)
}

// No token: the fallback does not run and the steward never mints an identity.
func TestRegisterAndConnect_CorruptIdentity_NoToken_NoFallback(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()
	corruptIdentityFile(t, f.certStoreDir)

	err := connectOnce(t, controller, "", trustSourceCompileBaked, ks, 3*time.Second)
	require.ErrorIs(t, err, errBrokenTrustNotAllowed)
	assert.Zero(t, controller.registerHits.Load())
	assert.Equal(t, deviceBefore, ks.DeviceID())
	_, statErr := os.Stat(filepath.Join(f.certStoreDir, cloneMarkerFileName))
	assert.True(t, errors.Is(statErr, os.ErrNotExist))
}

// Boundary with the no-token loop, both ways.
func TestBrokenTrust_BoundaryWithNoTokenLoop(t *testing.T) {
	dir := t.TempDir()
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return dir }
	t.Cleanup(func() { certStoreDirResolver = prev })
	corruptIdentityFile(t, dir)

	// No token: the no-token loop keeps waiting, with the reason kept locally.
	token, reason := checkEnrollment("")
	assert.Empty(t, token)
	assert.Equal(t, reasonIdentityUnusable, reason)

	// A usable token: the loop returns it and the steward proceeds to connect,
	// where the corrupt identity takes the broken-trust path.
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeSafeTokenFile(t, tokenFile, brokenTrustToken)
	token, reason = checkEnrollment(tokenFile)
	assert.Equal(t, brokenTrustToken, token)
	assert.Empty(t, reason)
}

// Bad-permission token file plus a corrupt identity: the no-token loop, and no
// token is read.
func TestBrokenTrust_BadPermissionTokenFile_StaysInNoTokenLoop(t *testing.T) {
	dir := t.TempDir()
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return dir }
	t.Cleanup(func() { certStoreDirResolver = prev })
	corruptIdentityFile(t, dir)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeSafeTokenFile(t, tokenFile, brokenTrustToken)
	makeReadableByOthers(t, tokenFile)

	token, reason := checkEnrollment(tokenFile)
	assert.Empty(t, token, "the unsafe file is never used")
	assert.Contains(t, reason, reasonTokenFilePrefix)
	assert.Empty(t, startupTokenFromFile(tokenFile))
}

// Marker-first: when the key step fails the marker remains and the old identity
// is untouched.
type failingRegenerateKeyStore struct{ identity.KeyStore }

func (failingRegenerateKeyStore) Regenerate(context.Context) (crypto.PublicKey, identity.Algorithm, error) {
	return nil, "", errors.New("key step failed")
}

func TestBrokenTrust_MarkerPersistedBeforeKeyRegeneration(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	ks := failingRegenerateKeyStore{newReadmitKeyStore(t)}

	err := beginBrokenTrust(context.Background(), f.certStoreDir, f.stewardID, ks)
	require.Error(t, err)

	m, mErr := loadCloneMarker(f.certStoreDir)
	require.NoError(t, mErr)
	require.NotNil(t, m, "the marker remains after the key step failed")
	assert.Equal(t, f.stewardID, m.CloneOf)
	assert.True(t, m.Rekey, "the re-key is still owed")
	stored, idErr := loadIdentity(f.certStoreDir)
	require.NoError(t, idErr)
	assert.NotNil(t, stored, "the old identity is not deleted before the key is regenerated")
}

// A restart mid-pending resumes the same pending registration.
func TestRegisterAndConnect_BrokenTrust_RestartResumesSamePendingRegistration(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	corruptIdentityFile(t, f.certStoreDir)

	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 6*time.Second))
	deviceAfterFirst := ks.DeviceID()
	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 6*time.Second))

	assert.Equal(t, deviceAfterFirst, ks.DeviceID(), "the restart does not re-key again")
	assert.Equal(t, int32(1), controller.registerHits.Load(), "no second registration is filed")
	entries, err := controller.pending.ListPending(context.Background(), "default")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no second clone is minted")
}

// A crash between marker and re-key resumes the re-key once, then registers.
func TestRegisterAndConnect_BrokenTrust_ResumesInterruptedRekey(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()
	require.NoError(t, saveCloneMarkerDetail(f.certStoreDir, cloneMarker{CloneOf: f.stewardID, Reason: cloneReasonBrokenTrust, Rekey: true}))

	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 6*time.Second))

	assert.NotEqual(t, deviceBefore, ks.DeviceID())
	reason, _ := registerBodyField(t, controller.lastRegisterBody(), "clone_reason")
	assert.Equal(t, cloneReasonBrokenTrust, reason)
	stored, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	assert.Nil(t, stored, "the old identity was discarded by the resumed re-key")
}

// clone_reason is on the wire only for the broken-trust fallback.
func TestRegisterAndConnect_OrdinaryClone_SendsNoCloneReason(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	require.NoError(t, saveCloneMarker(f.certStoreDir, f.stewardID))
	_, _, err := ks.Regenerate(context.Background())
	require.NoError(t, err)

	require.Error(t, connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 6*time.Second))

	body := controller.lastRegisterBody()
	require.NotEmpty(t, body)
	_, has := registerBodyField(t, body, "clone_reason")
	assert.False(t, has)
	cloneOf, _ := registerBodyField(t, body, "clone_of")
	assert.Equal(t, f.stewardID, cloneOf)
	assert.Empty(t, cloneReasonForMarker(f.certStoreDir, f.stewardID))
}

func TestBuildRegistrationRequest_CloneReasonOnlyWhenSet(t *testing.T) {
	ks := newReadmitKeyStore(t)
	plain, err := json.Marshal(buildRegistrationRequest("tok", "old", "", ks))
	require.NoError(t, err)
	assert.NotContains(t, string(plain), "clone_reason")
	withReason, err := json.Marshal(buildRegistrationRequest("tok", "old", cloneReasonBrokenTrust, ks))
	require.NoError(t, err)
	assert.Contains(t, string(withReason), `"clone_reason":"broken_trust"`)
}

// The device-key trigger: the lifecycle hook, wired by the connected path's own
// constructor, persists the marker and ends the connected run; the registration
// token (not the old certificate) authenticates the registration that follows.
func TestIdentityLifecycle_DeviceKeyUnusable_StartsBrokenTrust(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	h := newLifecycleHarness(t, 4*time.Second, time.Hour)
	time.Sleep(2500 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restart := &brokenTrustRestart{dir: h.dir, token: brokenTrustToken, trustSrc: trustSourceCompileBaked, ks: h.ks, cancel: cancel, logger: logging.NewLogger("error")}
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return h.dir }
	t.Cleanup(func() { certStoreDirResolver = prev })
	lc := newConnectedIdentityLifecycle(h.tc, nil, h.controller.server.URL, trustSourceCompileBaked, "", logging.NewLogger("error"), nil, 0, 0, restart)
	lc.mu = h.lifecycle(t).mu

	require.False(t, lc.checkOnce(ctx), "no device key store: renewal cannot proceed")

	assert.True(t, restart.Requested())
	assert.Error(t, ctx.Err(), "the connected run is ended")
	m, err := loadCloneMarker(h.dir)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "steward-lifecycle", m.CloneOf)
	assert.Equal(t, cloneReasonBrokenTrust, m.Reason)
	assert.True(t, m.Rekey)
	assert.True(t, hasBrokenTrustReason())
	h.tc.ClearHealthReason(clientCertReasonComponent)
}

// Without a token, the key-unusable hook does nothing: no marker, no restart.
func TestIdentityLifecycle_DeviceKeyUnusable_NoToken_NoFallback(t *testing.T) {
	dir := t.TempDir()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	restart := &brokenTrustRestart{dir: dir, token: "", trustSrc: trustSourceCompileBaked, ks: newReadmitKeyStore(t), cancel: cancel, logger: logging.NewLogger("error")}
	restart.onDeviceKeyUnusable()
	assert.False(t, restart.Requested())
	m, err := loadCloneMarker(dir)
	require.NoError(t, err)
	assert.Nil(t, m)
}

// An expired certificate with a working device key renews; it is not broken trust.
func TestIdentityLifecycle_ExpiredCertificateWithWorkingKey_NoFallback(t *testing.T) {
	h := newLifecycleHarness(t, 2*time.Second, time.Hour)
	time.Sleep(2500 * time.Millisecond)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	restart := &brokenTrustRestart{dir: h.dir, token: brokenTrustToken, trustSrc: trustSourceCompileBaked, ks: h.ks, cancel: cancel, logger: logging.NewLogger("error")}
	lc := h.lifecycle(t)
	lc.onDeviceKeyUnusable = restart.onDeviceKeyUnusable

	assert.True(t, lc.checkOnce(context.Background()), "the expired certificate renews by proof")
	assert.False(t, restart.Requested())
	m, err := loadCloneMarker(h.dir)
	require.NoError(t, err)
	assert.Nil(t, m)
}

// rekeyFromAlarm refuses every case the fallback does not own.
func TestRekeyFromAlarm_Guards(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	ControllerURL = "https://ctrl.test:4433"
	other := newROServer(t)
	bad := e.f.id
	bad.CACertPEM = other.caPEM
	require.NoError(t, saveIdentity(e.f.dir, bad))
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeSafeTokenFile(t, tokenFile, brokenTrustToken)
	ctx := withRegTokenFile(context.Background(), tokenFile)
	logger := logging.NewNoopLogger()

	newLatch := func(codes ...string) *tamperLatch {
		l := openTamperLatch(t.TempDir(), logger)
		for _, c := range codes {
			l.raise(c)
		}
		return l
	}
	unchanged := func(t *testing.T) {
		t.Helper()
		m, err := loadCloneMarker(e.f.dir)
		require.NoError(t, err)
		assert.Nil(t, m)
		id, err := loadIdentity(e.f.dir)
		require.NoError(t, err)
		assert.NotNil(t, id)
	}

	t.Run("data directory tamper owns its case", func(t *testing.T) {
		assert.False(t, rekeyFromAlarm(ctx, newLatch(cpTypes.ReasonCodeTamperDataDir), "", logger))
		unchanged(t)
	})
	t.Run("data directory tamper alongside the CA", func(t *testing.T) {
		assert.False(t, rekeyFromAlarm(ctx, newLatch(cpTypes.ReasonCodeTamperCAMismatch, cpTypes.ReasonCodeTamperDataDir), "", logger))
		unchanged(t)
	})
	t.Run("bad-permission token file", func(t *testing.T) {
		unsafe := filepath.Join(t.TempDir(), "token")
		writeSafeTokenFile(t, unsafe, brokenTrustToken)
		makeReadableByOthers(t, unsafe)
		assert.False(t, rekeyFromAlarm(withRegTokenFile(context.Background(), unsafe), newLatch(cpTypes.ReasonCodeTamperCAMismatch), "", logger))
		unchanged(t)
	})
	t.Run("no token file", func(t *testing.T) {
		assert.False(t, rekeyFromAlarm(context.Background(), newLatch(cpTypes.ReasonCodeTamperCAMismatch), "", logger))
		unchanged(t)
	})
	t.Run("only a network-fetched CA", func(t *testing.T) {
		assert.False(t, rekeyFromAlarm(ctx, newLatch(cpTypes.ReasonCodeTamperCAMismatch), "https://ctrl.example", logger))
		unchanged(t)
	})
}

// The full alarm path: an unverifiable pinned CA with a token re-keys, discards
// the identity, releases the latch and connects to register as a new device.
func TestTamperAlarm_CAUnverifiable_WithToken_RunsBrokenTrust(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	e := newAlarmEnv(t, trustSourceCompileBaked)
	ControllerURL = "https://ctrl.test:4433" // the compile-time trust source; restored by newAlarmEnv
	other := newROServer(t)
	bad := e.f.id
	bad.CACertPEM = other.caPEM
	require.NoError(t, saveIdentity(e.f.dir, bad))
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeSafeTokenFile(t, tokenFile, brokenTrustToken)

	ksBefore, err := identity.Open(context.Background(), e.f.dir, logging.NewNoopLogger())
	require.NoError(t, err)
	deviceBefore := ksBefore.DeviceID()

	type call struct {
		token  string
		device string
	}
	calls := make(chan call, 4)
	cf := func(_ context.Context, token, _ string, _ TrustSource, _ string, ks identity.KeyStore, _ bool, _ logging.Logger) (*client.TransportClient, error) {
		calls <- call{token: token, device: ks.DeviceID()}
		return nil, errors.New("test connect stops here")
	}
	ctx, cancel := context.WithCancel(withRegTokenFile(context.Background(), tokenFile))
	done := make(chan error, 1)
	go func() { done <- runStewardInternal(ctx, "", "", "", cf) }()
	t.Cleanup(func() {
		cancel()
		if runErr := <-done; runErr != nil {
			assert.ErrorIs(t, runErr, context.Canceled, "the steward stops only because the test cancelled it")
		}
	})

	select {
	case c := <-calls:
		assert.Equal(t, brokenTrustToken, c.token, "the registration token authenticates the new registration")
		assert.NotEqual(t, deviceBefore, c.device, "the device key was regenerated")
	case <-time.After(30 * time.Second):
		t.Fatal("the steward never reached the registration connect")
	}
	m, mErr := loadCloneMarker(e.f.dir)
	require.NoError(t, mErr)
	require.NotNil(t, m)
	assert.Equal(t, roStewardID, m.CloneOf)
	assert.Equal(t, cloneReasonBrokenTrust, m.Reason)
	stored, idErr := loadIdentity(e.f.dir)
	require.NoError(t, idErr)
	assert.Nil(t, stored)
	assert.Zero(t, e.f.srv.reg.Count(), "the unverifiable CA's link was never dialed")
}

// Data directory tamper with a token present runs the data directory alarm, not
// this fallback.
func TestTamperAlarm_DataDirTamper_WithToken_NotBrokenTrust(t *testing.T) {
	e := newAlarmEnv(t, trustSourceCompileBaked)
	e.dirBad.Store(true)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeSafeTokenFile(t, tokenFile, brokenTrustToken)
	corruptIdentityFile(t, e.f.dir)

	ctx, cancel := context.WithCancel(withRegTokenFile(context.Background(), tokenFile))
	done := make(chan error, 1)
	go func() { done <- runStewardInternal(ctx, brokenTrustToken, "", "", e.cf()) }()
	time.Sleep(1500 * time.Millisecond)
	cancel()
	require.NoError(t, <-done)

	assert.Zero(t, e.connect.Load())
	m, err := loadCloneMarker(e.f.dir)
	require.NoError(t, err)
	assert.Nil(t, m, "no fallback state was written")
}

// Link completion on the steward.
func linkFixture(t *testing.T, oldID string) (*readmitTestController, string, *StewardIdentity, identity.KeyStore) {
	t.Helper()
	controller := newReadmitTestController(t, "issue")
	dir := t.TempDir()
	blockTLSCredentialSources(t, dir)
	ks := newReadmitKeyStore(t)
	id := &StewardIdentity{StewardID: "steward-new-copy", TenantID: "tenant-q", TransportAddress: "127.0.0.1:1", ServerCertPEM: "server", DeviceID: ks.DeviceID()}
	require.NoError(t, saveIdentity(dir, *id))
	require.NoError(t, saveCloneMarkerDetail(dir, cloneMarker{CloneOf: oldID, Reason: cloneReasonBrokenTrust}))
	return controller, dir, id, ks
}

// "steward-readmitted" is the ID the test controller's re-admission response carries.
func TestReadmit_LinkAdoptsMarkedOldStewardID(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	setBrokenTrustReason()
	controller, dir, id, ks := linkFixture(t, "steward-readmitted")

	err := readmit(t, controller, dir, id, ks)
	require.Error(t, err, "no real transport is listening")
	assert.Contains(t, err.Error(), errNoTLSMaterial, "the credential reached the connect step")

	stored, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	require.NotNil(t, stored)
	assert.Equal(t, "steward-readmitted", stored.StewardID, "runs as the old steward")
	m, mErr := loadCloneMarker(dir)
	require.NoError(t, mErr)
	assert.Nil(t, m, "the marker is cleared")
	assert.False(t, hasBrokenTrustReason())
}

func TestReadmit_LinkRefusesUnrecordedStewardID(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	controller, dir, id, ks := linkFixture(t, "steward-someone-else")

	err := readmit(t, controller, dir, id, ks)
	require.ErrorIs(t, err, errLinkIDMismatch)

	stored, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	assert.Equal(t, "steward-new-copy", stored.StewardID, "no adoption")
	m, mErr := loadCloneMarker(dir)
	require.NoError(t, mErr)
	require.NotNil(t, m, "the marker is kept")
	assert.Equal(t, "steward-someone-else", m.CloneOf)
	reported := false
	for _, r := range startupReasons.List() {
		reported = reported || r.Code == linkMismatchReasonCode
	}
	assert.True(t, reported, "the refusal is reported")
	startupReasons.Clear(brokenTrustReasonComponent)
}

func TestReadmit_NoMarker_StoredStewardIDKept(t *testing.T) {
	controller, dir, id, ks := linkFixture(t, "steward-readmitted")
	require.NoError(t, clearCloneMarker(dir))

	err := readmit(t, controller, dir, id, ks)
	require.Error(t, err)
	stored, loadErr := loadIdentity(dir)
	require.NoError(t, loadErr)
	assert.Equal(t, "steward-new-copy", stored.StewardID, "without a marker the stored ID still wins")
}

// After an adoption whose connect failed, the next start drops the marker.
func TestRegisterAndConnect_LinkedIdentityDropsBrokenTrustMarker(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	ks := newReadmitKeyStore(t)
	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.DeviceID = ks.DeviceID()
	require.NoError(t, saveIdentity(f.certStoreDir, *id))
	require.NoError(t, saveCloneMarkerDetail(f.certStoreDir, cloneMarker{CloneOf: f.stewardID, Reason: cloneReasonBrokenTrust}))
	controller := newCloneTestController(t, f.stewardID)

	_ = connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 3*time.Second)

	m, mErr := loadCloneMarker(f.certStoreDir)
	require.NoError(t, mErr)
	assert.Nil(t, m)
	assert.Zero(t, controller.registerHits.Load(), "no new registration")
}

// While registered but not yet linked, the broken-trust marker is kept.
func TestRegisterAndConnect_RegisteredBrokenTrustMarkerSurvivesUntilLink(t *testing.T) {
	clearBrokenTrustReasonOnCleanup(t)
	f := newStoredIdentityFixture(t, "placeholder")
	ks := newReadmitKeyStore(t)
	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.StewardID, id.DeviceID = "steward-new-copy", ks.DeviceID()
	require.NoError(t, saveIdentity(f.certStoreDir, *id))
	require.NoError(t, saveCloneMarkerDetail(f.certStoreDir, cloneMarker{CloneOf: "steward-old", Reason: cloneReasonBrokenTrust}))
	controller := newCloneTestController(t, f.stewardID)

	_ = connectOnce(t, controller, brokenTrustToken, trustSourceCompileBaked, ks, 3*time.Second)

	m, mErr := loadCloneMarker(f.certStoreDir)
	require.NoError(t, mErr)
	require.NotNil(t, m, "the marker waits for the link")
	assert.Equal(t, "steward-old", m.CloneOf)
	assert.Zero(t, controller.registerHits.Load(), "no second clone is minted")
	assert.True(t, hasBrokenTrustReason())
}

// The fallback has local triggers only: nothing in the client, which receives
// every ControlMessage kind, reaches it.
func TestBrokenTrust_NotReachableFromControllerMessages(t *testing.T) {
	entry := []string{"registerBrokenTrust", "beginBrokenTrust", "rekeyFromAlarm", "brokenTrustRestart", "completeBrokenTrustRekey", "resumeBrokenTrust", "saveCloneMarkerDetail"}
	roots := []string{"../../features/steward/client", "../../pkg/controlplane"}
	for _, root := range roots {
		require.NoError(t, filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			require.NoError(t, err)
			if d.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			src, readErr := os.ReadFile(p) // #nosec G304 -- repository source under test
			require.NoError(t, readErr)
			for _, name := range entry {
				assert.NotContains(t, string(src), name, "%s must not reach the broken-trust fallback", p)
			}
			return nil
		}))
	}
}
