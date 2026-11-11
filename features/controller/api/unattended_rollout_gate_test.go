// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	gateTestVersion  = "v1.2.3"
	gateRollbackVer  = "v1.2.2"
	gateTestSteward  = "gate-steward-1"
	gateStartPath    = "/api/v1/rollout"
	gateDispatchPath = "/api/v1/stewards/upgrade"
)

// gateFixture is a real server (durable secret, config and audit stores, real router
// with real authentication and requirePermission) with the rollout, upgrade and binary
// routes behind it. Keys are minted by the real routes and presented as X-API-Key.
type gateFixture struct {
	*rolloutCredFixture
	setting      *UnattendedRolloutStore
	rolloutStore *testRolloutStore
	upgradeStore *testUpgradeStore
	trust        stewardBinaryTestFixture
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	f := &gateFixture{rolloutCredFixture: newRolloutCredFixture(t)}
	srv := f.srv

	f.setting, _ = newUnattendedRolloutStore(t)
	srv.SetUnattendedRolloutStore(f.setting)

	// A long soak keeps a started rollout in progress, so halt has something to halt.
	srv.cfg.DeploymentRings = &controllerconfig.DeploymentRingConfig{
		Rings: []controllerconfig.RingSpec{
			{Name: "pre-release", Soak: controllerconfig.Duration(time.Hour), HaltThreshold: 0.05},
			{Name: "stable", Soak: controllerconfig.Duration(time.Hour), HaltThreshold: 0.05},
		},
		FallbackRing: "pre-release",
	}
	f.rolloutStore = newTestRolloutStore()
	f.upgradeStore = newTestUpgradeStore()
	srv.rolloutStore = f.rolloutStore
	srv.upgradeStore = f.upgradeStore
	srv.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: []fleet.StewardData{
		{ID: gateTestSteward, TenantID: rolloutCredTestTenant, Status: "online"},
	}})

	srv.blobStore = newFSBlobStore(t)
	f.trust = newStewardBinaryFixture(t)
	srv.stewardBinaryTrustStore = f.trust.store
	return f
}

func (f *gateFixture) setEnabled(t *testing.T, enabled bool) {
	t.Helper()
	_, err := f.setting.Set(t.Context(), enabled, "gate-test-admin")
	require.NoError(t, err)
}

// rolloutKey mints a scoped rollout credential; genericKey mints an ordinary key.
func (f *gateFixture) rolloutKey() string { return f.mint().Data.Key }
func (f *gateFixture) genericKey(perms []string) string {
	return f.mintGeneric(perms, nil).Data.Key
}

func (f *gateFixture) startRollout(key string) *httptest.ResponseRecorder {
	body := `{"target_version":"` + gateTestVersion + `"}`
	return f.callWithKey(f.srv.router, http.MethodPost, gateStartPath, key, body)
}

func (f *gateFixture) dispatch(key, version string) *httptest.ResponseRecorder {
	body := `{"selector":"id:` + gateTestSteward + `","version":"` + version + `","platform":"linux","arch":"amd64"}`
	return f.callWithKey(f.srv.router, http.MethodPost, gateDispatchPath, key, body)
}

func (f *gateFixture) rollback(key, upgradeID, version string) *httptest.ResponseRecorder {
	return f.callWithKey(f.srv.router, http.MethodPost, gateDispatchPath+"/"+upgradeID+"/rollback", key,
		`{"version":"`+version+`"}`)
}

func (f *gateFixture) halt(key, rolloutID string) *httptest.ResponseRecorder {
	return f.callWithKey(f.srv.router, http.MethodPost, gateStartPath+"/"+rolloutID+"/halt", key, "")
}

// publish posts a signed steward binary through the real route.
func (f *gateFixture) publish(key, version string) *httptest.ResponseRecorder {
	content := []byte("gate-test steward binary " + version)
	q := url.Values{}
	q.Set("signature", f.trust.signContent(content, version, "linux", "amd64"))
	path := "/api/v1/installer/steward-binaries/" + version + "/linux/amd64?" + q.Encode()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(content)))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func (f *gateFixture) binaryExists(t *testing.T, version string) bool {
	t.Helper()
	ok, err := f.srv.blobStore.BlobExists(t.Context(), stewardBinaryBlobKey(rolloutCredTestTenant, version, "linux", "amd64"))
	require.NoError(t, err)
	return ok
}

func (f *gateFixture) approveBinary(t *testing.T, version string) {
	t.Helper()
	publishApprovedBinary(t, f.srv, rolloutCredTestTenant, version, "linux", "amd64")
}

func (f *gateFixture) rolloutCount() int {
	f.rolloutStore.mu.RLock()
	defer f.rolloutStore.mu.RUnlock()
	return len(f.rolloutStore.records)
}

func (f *gateFixture) upgradeCount() int {
	f.upgradeStore.mu.RLock()
	defer f.upgradeStore.mu.RUnlock()
	return len(f.upgradeStore.records)
}

// stopRollout halts a started rollout and waits for its goroutine, so no goroutine
// outlives the test.
func (f *gateFixture) stopRollout(t *testing.T, rolloutID string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, gateStartPath+"/"+rolloutID+"/halt", nil)
	req = withPrincipal(req, &Principal{
		ID: "gate-cleanup", Assurance: session.AssuranceStrong, TenantID: rolloutCredTestTenant,
		Permissions: []string{"installer:dispatch:steward"},
	})
	req = mux.SetURLVars(req, map[string]string{"rollout_id": rolloutID})
	rec := httptest.NewRecorder()
	f.srv.handleHaltRollout(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	f.waitRolloutGoroutineExit(t, rolloutID)
}

// waitRolloutGoroutineExit blocks until runRollout has returned: an operator halt
// fires no terminal hook, but the goroutine's last act is to drop its halt channel.
func (f *gateFixture) waitRolloutGoroutineExit(t *testing.T, rolloutID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, running := f.srv.rolloutHaltChans.Load(rolloutID)
		return !running
	}, 5*time.Second, 5*time.Millisecond, "rollout goroutine did not exit after halt")
}

func gateResponseData(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	data, _ := resp.Data.(map[string]interface{})
	return data
}

func assertGateRefusal(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	assert.Equal(t, status, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), code)
}

func TestRolloutCredentialStartRefusedWhenOff(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()

	rec := f.startRollout(key)
	assertGateRefusal(t, rec, http.StatusForbidden, "UNATTENDED_ROLLOUTS_DISABLED")
	assert.Zero(t, f.rolloutCount(), "no rollout record is created")

	// An explicit OFF is the same as no record.
	f.setEnabled(t, false)
	assertGateRefusal(t, f.startRollout(key), http.StatusForbidden, "UNATTENDED_ROLLOUTS_DISABLED")
	assert.Zero(t, f.rolloutCount())
}

func TestRolloutCredentialStartAllowedWhenOn(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()
	f.setEnabled(t, true)

	rec := f.startRollout(key)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	id, _ := gateResponseData(t, rec)["rollout_id"].(string)
	require.NotEmpty(t, id)
	assert.Equal(t, 1, f.rolloutCount())
	f.stopRollout(t, id)
}

func TestRolloutCredentialUpgradeDispatchRefusedWhenOff(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()
	f.approveBinary(t, gateTestVersion)

	rec := f.dispatch(key, gateTestVersion)
	assertGateRefusal(t, rec, http.StatusForbidden, "UNATTENDED_ROLLOUTS_DISABLED")
	assert.Zero(t, f.upgradeCount(), "no upgrade record is created")

	// With the setting on the same call succeeds as today.
	f.setEnabled(t, true)
	rec = f.dispatch(key, gateTestVersion)
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, 1, f.upgradeCount())
}

func TestRolloutCredentialPublishRefusedWhenOff(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()

	rec := f.publish(key, gateTestVersion)
	assertGateRefusal(t, rec, http.StatusForbidden, "UNATTENDED_ROLLOUTS_DISABLED")
	assert.False(t, f.binaryExists(t, gateTestVersion), "no blob is written")

	// With the setting on the same call succeeds as today.
	f.setEnabled(t, true)
	rec = f.publish(key, gateTestVersion)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, f.binaryExists(t, gateTestVersion))
}

// TestExistingAPIKeyStillStartsRolloutWhenOff pins #5298: an ordinary key with the
// dispatch permission, such as the env-seeded e2e key, is not a rollout credential.
func TestExistingAPIKeyStillStartsRolloutWhenOff(t *testing.T) {
	f := newGateFixture(t)
	key := f.genericKey([]string{"installer:dispatch:steward"})

	rec := f.startRollout(key)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))
	assert.Equal(t, 1, f.rolloutCount())
}

// TestSupersetAndPartialKeysNotGated: only the explicit kind is gated. A key with the
// same four permissions minted through the generic route, a superset, and each
// three-of-four subset (on the routes it can reach) pass the gate with the setting off.
func TestSupersetAndPartialKeysNotGated(t *testing.T) {
	f := newGateFixture(t)

	same := f.genericKey(rolloutCredentialPermissions)
	superset := f.genericKey(append([]string{"steward:read"}, rolloutCredentialPermissions...))
	for name, key := range map[string]string{"same permissions, generic route": same, "superset": superset} {
		rec := f.startRollout(key)
		require.Equal(t, http.StatusAccepted, rec.Code, "%s: %s", name, rec.Body.String())
		f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))
		assert.Equal(t, http.StatusOK, f.publish(key, gateTestVersion+"-"+strconv.Itoa(len(name))).Code, name)
	}

	// Without installer:publish:steward the key passes the gate on start and is refused
	// by requirePermission on publish, not by the gate.
	partial := f.genericKey([]string{"installer:dispatch:steward", "installer:read", "monitoring:write-markers"})
	rec := f.startRollout(partial)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))
	rec = f.publish(partial, gateTestVersion)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), "UNATTENDED_ROLLOUTS_DISABLED")

	assert.Empty(t, auditEntriesByAction(t, f.srv, unattendedRolloutRefusedAction), "no non-credential refusal is audited")
}

func TestHumanRolloutUnaffectedBySetting(t *testing.T) {
	f := newGateFixture(t)
	human := &Principal{
		ID: "human-operator", Assurance: session.AssuranceStrong, TenantID: rolloutCredTestTenant,
		Permissions: []string{"installer:dispatch:steward"},
	}
	for _, enabled := range []bool{false, true} {
		f.setEnabled(t, enabled)
		req := httptest.NewRequest(http.MethodPost, gateStartPath, strings.NewReader(`{"target_version":"`+gateTestVersion+`"}`))
		req = withPrincipal(req, human)
		rec := httptest.NewRecorder()
		f.srv.handleStartRollout(rec, req)
		require.Equal(t, http.StatusAccepted, rec.Code, "enabled=%v: %s", enabled, rec.Body.String())
		f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))
	}
}

func TestHaltAndRollbackNotGated(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()
	f.approveBinary(t, gateTestVersion)
	f.approveBinary(t, gateRollbackVer)

	// Start a rollout and an upgrade while the setting is on, then turn it off.
	f.setEnabled(t, true)
	rec := f.startRollout(key)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	rolloutID := gateResponseData(t, rec)["rollout_id"].(string)
	rec = f.dispatch(key, gateTestVersion)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	upgradeID := gateResponseData(t, rec)["upgrade_id"].(string)
	require.NoError(t, f.upgradeStore.UpdateUpgradeStatus(t.Context(), upgradeID, business.UpgradeStatusCommitted, ""))
	f.setEnabled(t, false)

	// Halt and rollback still work with the setting off.
	rec = f.halt(key, rolloutID)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	f.waitRolloutGoroutineExit(t, rolloutID)
	rec = f.rollback(key, upgradeID, gateRollbackVer)
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	assert.Empty(t, auditEntriesByAction(t, f.srv, unattendedRolloutRefusedAction), "neither route is gated")
}

// TestGateFailsClosedOnStoreError reads the setting from a real durable config store whose
// stored record has been damaged so the read fails. The credential is refused with 503
// on every gated route and
// nothing is created; an ordinary key is not gated and so is not affected.
func TestGateFailsClosedOnStoreError(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()
	generic := f.genericKey([]string{"installer:dispatch:steward"})
	f.approveBinary(t, gateTestVersion)

	f.srv.SetUnattendedRolloutStore(f.unreadableSettingStore(t))

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"start":    f.startRollout(key),
		"dispatch": f.dispatch(key, gateTestVersion),
		"publish":  f.publish(key, gateTestVersion+"-new"),
	} {
		t.Run(name, func(t *testing.T) {
			assertGateRefusal(t, rec, http.StatusServiceUnavailable, "UNATTENDED_ROLLOUTS_UNAVAILABLE")
		})
	}
	assert.Zero(t, f.rolloutCount())
	assert.Zero(t, f.upgradeCount())
	assert.False(t, f.binaryExists(t, gateTestVersion+"-new"))

	entries := auditEntriesByAction(t, f.srv, unattendedRolloutRefusedAction)
	require.Len(t, entries, 3, "each refusal is audited")
	for _, e := range entries {
		assert.Equal(t, "setting_unreadable", e.Details["reason"])
	}

	rec := f.startRollout(generic)
	require.Equal(t, http.StatusAccepted, rec.Code, "an ordinary key is not gated: %s", rec.Body.String())
	f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))

	// An unwired store is also fail closed.
	f.srv.mu.Lock()
	f.srv.unattendedRolloutStore = nil
	f.srv.mu.Unlock()
	assertGateRefusal(t, f.startRollout(key), http.StatusServiceUnavailable, "UNATTENDED_ROLLOUTS_UNAVAILABLE")
}

// TestGateSeesDisableImmediately: the setting is read on every call, so an OFF refuses
// the very next request.
func TestGateSeesDisableImmediately(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()

	f.setEnabled(t, true)
	rec := f.startRollout(key)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))

	f.setEnabled(t, false)
	assertGateRefusal(t, f.startRollout(key), http.StatusForbidden, "UNATTENDED_ROLLOUTS_DISABLED")
	assert.Equal(t, 1, f.rolloutCount(), "only the rollout started while on exists")

	f.setEnabled(t, true)
	rec = f.startRollout(key)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	f.stopRollout(t, gateResponseData(t, rec)["rollout_id"].(string))
}

// TestRolloutCredentialRefusedOnUnlistedRoute: outside its four permissions the
// credential is refused by requirePermission (403), whatever the setting, and the gate
// is not what refuses it.
func TestRolloutCredentialRefusedOnUnlistedRoute(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()
	routes := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/api-keys", `{"name":"x","permissions":["steward:read"]}`},
		{http.MethodPost, "/api/v1/config/push", "{}"},
		{http.MethodGet, "/api/v1/stewards", ""},
		{http.MethodPut, "/api/v1/rollout-settings/unattended", `{"enabled":true}`},
		{http.MethodPost, "/api/v1/rollout-credentials", rolloutBody(time.Now().Add(time.Hour))},
	}
	for _, enabled := range []bool{false, true} {
		f.setEnabled(t, enabled)
		for _, c := range routes {
			rec := f.callWithKey(f.srv.router, c.method, c.path, key, c.body)
			assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s enabled=%v: %s", c.method, c.path, enabled, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "UNATTENDED_ROLLOUTS_DISABLED")
		}
	}
	got, err := f.setting.Get(t.Context())
	require.NoError(t, err)
	assert.True(t, got.Enabled, "the credential could not change the setting")
	assert.Empty(t, auditEntriesByAction(t, f.srv, unattendedRolloutRefusedAction))
}

func TestRefusalAudited(t *testing.T) {
	f := newGateFixture(t)
	key := f.rolloutKey()
	principalID := f.principalFor(key).ID
	require.NotEmpty(t, principalID)
	f.approveBinary(t, gateTestVersion)

	require.Equal(t, http.StatusForbidden, f.startRollout(key).Code)
	require.Equal(t, http.StatusForbidden, f.dispatch(key, gateTestVersion).Code)
	require.Equal(t, http.StatusForbidden, f.publish(key, gateTestVersion+"-new").Code)

	entries := auditEntriesByAction(t, f.srv, unattendedRolloutRefusedAction)
	require.Len(t, entries, 3)
	routes := map[string]bool{}
	for _, e := range entries {
		assert.Equal(t, principalID, e.UserID)
		assert.Equal(t, business.AuditResultDenied, e.Result)
		assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
		assert.Equal(t, rolloutCredTestTenant, e.TenantID)
		assert.Equal(t, principalID, e.Details["principal"])
		assert.Equal(t, "unattended_rollouts_disabled", e.Details["reason"])
		route, _ := e.Details["route"].(string)
		routes[route] = true
	}
	assert.Equal(t, map[string]bool{
		gateRouteStartRollout:    true,
		gateRouteDispatchUpgrade: true,
		gateRoutePublishBinary:   true,
	}, routes)
}

// unreadableSettingStore returns an UnattendedRolloutStore over a real durable config
// store that holds a setting record, then damages the record on disk so that every read
// returns an error (never the default and never not-found).
func (f *gateFixture) unreadableSettingStore(t *testing.T) *UnattendedRolloutStore {
	t.Helper()
	root := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(root, "file:gate-unreadable-"+strconv.FormatInt(time.Now().UnixNano(), 10)+"?mode=memory")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	st, err := NewUnattendedRolloutStore(sm.GetConfigStore())
	require.NoError(t, err)
	_, err = st.Set(t.Context(), true, "gate-test-admin")
	require.NoError(t, err)

	var damaged int
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(d.Name(), unattendedRolloutName+".") {
			return err
		}
		damaged++
		return os.WriteFile(path, []byte("{not a config entry"), 0o600)
	}))
	require.Equal(t, 1, damaged, "exactly one stored record is damaged")
	_, err = st.Get(t.Context())
	require.Error(t, err, "a damaged record must fail the read, not read as a value")
	return st
}
