// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for desired_version auto-convergence in TriggerConvergence. (Issue #2260, #2833)
//
// Tests:
//   - TestTriggerConvergence_VersionConvergence_InvokesSwapWhenVersionDiffers
//   - TestTriggerConvergence_VersionConvergence_NoOpWhenVersionMatches
//   - TestTriggerConvergence_VersionConvergence_NoOpWhenDesiredVersionAbsent
//   - TestTriggerConvergence_VersionConvergence_DowngradeGuardBlocksOlderVersion
//   - TestTriggerConvergence_VersionConvergence_AllowDowngradeInCfgPermitsOlderVersion
//   - TestTriggerConvergence_SelfFetch_HappyPath
//   - TestTriggerConvergence_SelfFetch_OwnTenant404FallsBackToDefault
//   - TestTriggerConvergence_SelfFetch_NoHTTPSBase_DoesNotFetch
package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/version"
)

// makeVersionCfgYAML marshals a StewardConfig with the given upgrade settings
// to YAML bytes for use as lastConfigYAML in convergence tests.
func makeVersionCfgYAML(t *testing.T, desiredVersion string, allowDowngrade bool) []byte {
	t.Helper()
	cfg := stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			Upgrade: stewardconfig.UpgradeConfig{
				DesiredVersion: desiredVersion,
				AllowDowngrade: allowDowngrade,
			},
		},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return data
}

// newClientForVersionConvergenceTest returns a TransportClient wired for version
// convergence unit tests. The injected launcherSwapFunc and executor avoid any
// real binary I/O; launcherManaged=false prevents a shutdown trigger.
func newClientForVersionConvergenceTest(
	t *testing.T,
	stagedVersion, stagedPath string,
	swapFn func(ctx context.Context, lPath, ver, bin string) error,
) *TransportClient {
	t.Helper()
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	c := &TransportClient{
		stewardID:            "test-steward",
		tenantID:             "test-tenant",
		heartbeatStop:        make(chan struct{}),
		convergenceStop:      make(chan struct{}),
		logger:               newTestLogger(t),
		configExecutor:       exec,
		launcherSwapFunc:     swapFn,
		lastStagedVersion:    stagedVersion,
		lastStagedBinaryPath: stagedPath,
		// launcherManaged=false: successful swap must not trigger a real shutdown.
		launcherManaged: false,
	}
	return c
}

// TestTriggerConvergence_VersionConvergence_InvokesSwapWhenVersionDiffers proves
// that when desired_version differs from the running version and a matching staged
// binary exists, TriggerConvergence invokes the launcher swap with the correct
// version. (AC: required unit test with injectable launcherSwapFunc)
func TestTriggerConvergence_VersionConvergence_InvokesSwapWhenVersionDiffers(t *testing.T) {
	const desiredVersion = "v99.0.0" // clearly newer than any dev build

	var swapCalled bool
	var swappedVersion string
	swapFn := func(_ context.Context, _, ver, _ string) error {
		swapCalled = true
		swappedVersion = ver
		return nil
	}

	c := newClientForVersionConvergenceTest(t, desiredVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, desiredVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.True(t, swapCalled, "expected launcher swap to be invoked for desired_version mismatch")
	assert.Equal(t, desiredVersion, swappedVersion, "swap must target the desired version")
}

// TestTriggerConvergence_VersionConvergence_NoOpWhenVersionMatches proves that
// TriggerConvergence does NOT invoke the swap when the running version already
// equals desired_version. (AC: matching versions → no-op)
func TestTriggerConvergence_VersionConvergence_NoOpWhenVersionMatches(t *testing.T) {
	runningVersion := version.Short()

	swapCalled := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForVersionConvergenceTest(t, runningVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, runningVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, swapCalled, "swap must NOT be called when running version equals desired_version")
}

// TestTriggerConvergence_VersionConvergence_NoOpWhenDesiredVersionAbsent proves
// back-compat: when desired_version is absent from the config, TriggerConvergence
// proceeds normally without invoking the swap path. (AC: absent desired_version → no-op)
func TestTriggerConvergence_VersionConvergence_NoOpWhenDesiredVersionAbsent(t *testing.T) {
	swapCalled := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForVersionConvergenceTest(t, "", "", swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, "", false) // no desired_version
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, swapCalled, "swap must NOT be called when desired_version is absent")
}

// TestTriggerConvergence_VersionConvergence_DowngradeGuardBlocksOlderVersion
// proves that when desired_version is older than the running version and
// AllowDowngrade is false, the swap is not invoked. (AC: downgrade guard)
func TestTriggerConvergence_VersionConvergence_DowngradeGuardBlocksOlderVersion(t *testing.T) {
	const olderVersion = "v0.0.1"

	swapCalled := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForVersionConvergenceTest(t, olderVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.upgradeAllowDowngrade = false
	c.lastConfigYAML = makeVersionCfgYAML(t, olderVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, swapCalled, "swap must NOT be called when downgrade is blocked and desired_version is older")
}

// TestTriggerConvergence_VersionConvergence_AllowDowngradeInCfgPermitsOlderVersion
// proves that when allow_downgrade is set in the controller-delivered config, the
// swap IS invoked even when desired_version is older than the running version.
func TestTriggerConvergence_VersionConvergence_AllowDowngradeInCfgPermitsOlderVersion(t *testing.T) {
	const olderVersion = "v0.0.1"

	var swapCalled bool
	var swappedVersion string
	swapFn := func(_ context.Context, _, ver, _ string) error {
		swapCalled = true
		swappedVersion = ver
		return nil
	}

	c := newClientForVersionConvergenceTest(t, olderVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.upgradeAllowDowngrade = false
	c.lastConfigYAML = makeVersionCfgYAML(t, olderVersion, true) // allow_downgrade set in cfg
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.True(t, swapCalled, "swap MUST be called when AllowDowngrade is enabled in cfg")
	assert.Equal(t, olderVersion, swappedVersion)
}

// ---- Self-fetch tests (Issue #2833) ----------------------------------------

// newSelfFetchTestServer returns a TLS test server that serves a steward binary
// with the correct version-bound signature headers. tenantFilter, when non-empty,
// makes the server return 404 for that tenant and 200 for all others — used to
// test the own-tenant-404 → default fallback.
func newSelfFetchTestServer(
	t *testing.T,
	content []byte,
	hexSHA256 string,
	publisherName string,
	sigB64 string,
	tenantFilter string, // return 404 for this tenant; empty = always 200
) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tenantFilter != "" && r.URL.Query().Get("tenant") == tenantFilter {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-CFGMS-SHA256", hexSHA256)
		w.Header().Set("X-CFGMS-Publisher", publisherName)
		w.Header().Set("X-CFGMS-Signature", sigB64)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
}

// newClientForSelfFetchTest returns a TransportClient wired for self-fetch tests.
// The configExecutor is real so TriggerConvergence does not short-circuit.
func newClientForSelfFetchTest(
	t *testing.T,
	httpsBaseURL string,
	httpClient *http.Client,
	ts trust.TrustStore,
	swapFn func(ctx context.Context, lPath, ver, bin string) error,
) *TransportClient {
	t.Helper()
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	c := &TransportClient{
		stewardID:                  "test-steward",
		tenantID:                   "test-tenant",
		transportAddress:           "127.0.0.1:4433",
		controllerHTTPSBaseURL:     httpsBaseURL,
		certStoreDir:               t.TempDir(),
		upgradePublisherTrustStore: ts,
		upgradeHTTPClient:          httpClient,
		launcherSwapFunc:           swapFn,
		heartbeatStop:              make(chan struct{}),
		convergenceStop:            make(chan struct{}),
		logger:                     newTestLogger(t),
		configExecutor:             exec,
		launcherManaged:            false,
	}
	return c
}

// TestTriggerConvergence_SelfFetch_HappyPath proves AC 1 and AC 5: when
// desired_version is set and the binary is NOT pre-staged, TriggerConvergence
// self-fetches from the controller (own tenant), verifies the version-bound
// publisher signature, stages the binary, and invokes the launcher swap — with
// zero controller-initiated push. (Issue #2833)
func TestTriggerConvergence_SelfFetch_HappyPath(t *testing.T) {
	const desiredVersion = "v99.10.0"
	content := []byte("self-fetch steward binary for happy-path test")
	hexSHA256 := computeSHA256(content)

	// Build the version-bound composite for signing. Version/Platform/Arch are the
	// steward's own values (same as mapRuntimePlatformArch() will produce at runtime).
	platform, arch := runtime.GOOS, runtime.GOARCH
	if platform != "windows" && platform != "darwin" {
		platform = "linux"
	}
	if arch != "arm64" {
		arch = "amd64"
	}
	composite := hexSHA256 + "|" + desiredVersion + "|" + platform + "|" + arch

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(composite)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	srv := newSelfFetchTestServer(t, content, hexSHA256, "cfgms", sigB64, "")
	defer srv.Close()

	var swapCalled bool
	var swappedVersion string
	swapFn := func(_ context.Context, _, ver, _ string) error {
		swapCalled = true
		swappedVersion = ver
		return nil
	}

	c := newClientForSelfFetchTest(t, srv.URL, srv.Client(), ts, swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, desiredVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.True(t, swapCalled, "launcher swap must be called after self-fetch succeeds")
	assert.Equal(t, desiredVersion, swappedVersion, "swap must target the desired version")

	c.mu.RLock()
	staged := c.lastStagedVersion
	c.mu.RUnlock()
	assert.Equal(t, desiredVersion, staged, "lastStagedVersion must be recorded after self-fetch")
}

// TestTriggerConvergence_SelfFetch_OwnTenant404FallsBackToDefault proves that
// when the steward's own tenant returns 404, TriggerConvergence retries under
// the "default" tenant and successfully stages and swaps. (AC 1, AC 5)
func TestTriggerConvergence_SelfFetch_OwnTenant404FallsBackToDefault(t *testing.T) {
	const desiredVersion = "v99.11.0"
	content := []byte("self-fetch binary for tenant fallback test")
	hexSHA256 := computeSHA256(content)

	platform, arch := runtime.GOOS, runtime.GOARCH
	if platform != "windows" && platform != "darwin" {
		platform = "linux"
	}
	if arch != "arm64" {
		arch = "amd64"
	}
	composite := hexSHA256 + "|" + desiredVersion + "|" + platform + "|" + arch

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(composite)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Server returns 404 for the steward's own tenant ("test-tenant") and 200 for "default".
	srv := newSelfFetchTestServer(t, content, hexSHA256, "cfgms", sigB64, "test-tenant")
	defer srv.Close()

	var swapCalled bool
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForSelfFetchTest(t, srv.URL, srv.Client(), ts, swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, desiredVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.True(t, swapCalled, "launcher swap must succeed via the default-tenant fallback")

	c.mu.RLock()
	staged := c.lastStagedVersion
	c.mu.RUnlock()
	assert.Equal(t, desiredVersion, staged, "binary must be staged after fallback to default tenant")
}

// TestTriggerConvergence_SelfFetch_NoHTTPSBase_DoesNotFetch proves that when
// ControllerHTTPSBaseURL is not configured, TriggerConvergence does NOT attempt
// a self-fetch and instead returns without error — preserving backward compat
// with controller-push-only deployments. (Issue #2833)
func TestTriggerConvergence_SelfFetch_NoHTTPSBase_DoesNotFetch(t *testing.T) {
	const desiredVersion = "v99.12.0"

	fetchAttempted := false
	swapCalled := false

	// Sentinel transport: if selfFetchForUpgrade ever calls the HTTP client it records the attempt.
	sentinelClient := &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			fetchAttempted = true
			return nil, fmt.Errorf("sentinel: unexpected fetch attempt")
		}),
	}

	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	// controllerHTTPSBaseURL is "" — self-fetch must not be attempted.
	c := newClientForSelfFetchTest(t, "", sentinelClient, nil, swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, desiredVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, fetchAttempted, "HTTP client must NOT be called when no HTTPS base URL is configured")
	assert.False(t, swapCalled, "swap must NOT be called when no HTTPS base URL is configured")
}
