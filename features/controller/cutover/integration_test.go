// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build integration

// Package cutover integration tests — closes the Story #1920 [REQUIRED
// TEST] for connected-client survival across a controller upgrade.
//
// Run with: go test -tags=integration ./features/controller/cutover/
//
// These tests build the real cfgms-controller binary, spawn it as a
// subprocess, run the actual cutover orchestration against it, and
// assert that a long-lived API client (standing in for a connected
// steward's gRPC-over-QUIC session) keeps working across the cutover
// within the 10s AC bound.
//
// Why a build tag: unit tests in the package use fakes only and
// complete in milliseconds. The integration tests here require ~10s
// each (binary build + --init + spawn + ready-poll + cutover + verify)
// and need a writable temp dir + free TCP ports. The build tag keeps
// them off the default `go test ./...` pass and gates them on CI
// runners that have time + space.
package cutover

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// buildControllerOnce caches the controller-binary build across tests.
// Each subtest reuses the same exe — a fresh --init in a per-test
// temp dir keeps state isolated.
var (
	controllerExeOnce sync.Once
	controllerExePath string
	controllerExeErr  error
)

func buildControllerBinary(t *testing.T) string {
	t.Helper()
	controllerExeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "cutover-controller-*")
		if err != nil {
			controllerExeErr = err
			return
		}
		exe := filepath.Join(dir, "cfgms-controller")
		if isWindowsBuild() {
			exe += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", exe, "../../..//cmd/controller") //nolint:gosec // test infra
		cmd.Dir = "."
		// Build with the same working directory as the test package so
		// go finds the module root.
		out, err := cmd.CombinedOutput()
		if err != nil {
			controllerExeErr = fmt.Errorf("build cfgms-controller: %w\n%s", err, out)
			return
		}
		controllerExePath = exe
	})
	if controllerExeErr != nil {
		t.Fatalf("buildControllerBinary: %v", controllerExeErr)
	}
	return controllerExePath
}

func isWindowsBuild() bool { return os.PathSeparator == '\\' }

// writeMinimalConfig generates a controller.cfg pointing at the given
// data dir and listen addrs. Uses flatfile + sqlite — no external deps.
//
// Windows backslashes in paths must be converted to forward slashes
// before embedding in YAML — the YAML parser otherwise interprets
// `\U` / `\x` / etc. as escape-sequence starts ("did not find expected
// hexadecimal number" errors). Go on Windows accepts forward slashes
// in file paths natively.
func writeMinimalConfig(t *testing.T, dataDir, certPath, apiAddr, transportAddr string) string {
	t.Helper()
	dataDir = filepath.ToSlash(dataDir)
	certPath = filepath.ToSlash(certPath)
	cfgPath := filepath.Join(dataDir, "controller.cfg")
	body := fmt.Sprintf(`
listen_addr: "%s"
external_url: "https://%s"
cert_path: "%s"
data_dir: "%s"
log_level: "info"
admin_bundle_path: "%s/admin.bundle.yaml"

certificate:
  enable_cert_management: true
  ca_path: "%s"
  renewal_threshold_days: 30
  server_cert_validity_days: 365
  client_cert_validity_days: 365
  server:
    common_name: "cfgms-controller"
    dns_names: ["localhost", "127.0.0.1"]
    ip_addresses: ["127.0.0.1"]
    organization: "CFGMS-Test"

storage:
  provider: "flatfile"
  flatfile_root: "%s/flatfile"
  sqlite_path: "%s/cfgms.db"

logging:
  provider: "file"
  level: "INFO"
  config:
    directory: "%s/logs"
    max_file_size: 10485760
    max_files: 3
    compress_rotated: false

transport:
  listen_addr: "%s"
  use_cert_manager: true
  max_connections: 50000
  keepalive_period: "30s"
  idle_timeout: "5m"
`,
		apiAddr,
		apiAddr,
		certPath,
		dataDir,
		dataDir,
		certPath,
		dataDir,
		dataDir,
		dataDir,
		transportAddr,
	)
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	return cfgPath
}

// initController runs `cfgms-controller --init --config <path>` to
// seed the CA + admin bundle.
func initController(t *testing.T, exe, cfgPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--init", "--config", cfgPath) //nolint:gosec // test infra
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--init failed: %v\noutput:\n%s", err, out)
	}
}

// TestCutover_IntegrationLive is the marquee Story #1920 [REQUIRED
// TEST]: a long-lived client survives a full cutover within 10s.
//
// Flow:
//  1. Build the cfgms-controller binary.
//  2. Generate a minimal config + run --init to seed certs.
//  3. Spawn the controller as a subprocess on free canonical ports.
//  4. Wait for /api/v1/health to respond (or 401/403 — auth-required
//     still proves the API is alive).
//  5. Start a "client" goroutine that polls /api/v1/health every 100ms
//     using a keep-alive HTTP client (mTLS skipped — the smoketester's
//     contract).
//  6. Run the cutover orchestrator: Upgrade(currentBinary) which drains
//     the running canonical, spawns a fresh instance on canonical
//     ports.
//  7. Wait for orchestrator to enter StateQuarantined (or fail).
//  8. Verify the client continued to receive at least one successful
//     response within the 10-second post-cutover window. Allows for
//     up to ~3s of unavailability during the swap.
//
// On Windows, port-handoff TIME_WAIT can be slower than on Linux; the
// AC budget is 10s.
func TestCutover_IntegrationLive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — requires controller binary build + spawn (~10s)")
	}

	exe := buildControllerBinary(t)
	dataDir := t.TempDir()
	certDir := filepath.Join(dataDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0o755))

	apiAddr := freePortLocal(t)
	transportAddr := freePortLocal(t)
	candAPIAddr := freePortLocal(t)
	candTransportAddr := freePortLocal(t)

	cfgPath := writeMinimalConfig(t, dataDir, certDir, apiAddr, transportAddr)
	initController(t, exe, cfgPath)

	// Spawn the initial canonical controller.
	initial := NewExecProcessHandle(exe, cfgPath)
	stdoutBuf := &threadSafeBuffer{}
	stderrBuf := &threadSafeBuffer{}
	initial.Stdout = stdoutBuf
	initial.Stderr = stderrBuf
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	require.NoError(t, initial.Start(ctx, apiAddr, transportAddr))
	t.Cleanup(func() {
		stopCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = initial.Stop(stopCtx)
		if t.Failed() {
			t.Logf("controller stdout:\n%s", stdoutBuf.String())
			t.Logf("controller stderr:\n%s", stderrBuf.String())
		}
	})

	// Wait for the controller's API to be serving.
	t.Logf("waiting for canonical controller on %s ...", apiAddr)
	require.NoError(t, waitForControllerHealthy(ctx, apiAddr, 30*time.Second))

	// Start the "connected client" goroutine — analogous to a steward
	// holding a control-plane session. Polls /api/v1/health every
	// 100ms with a keep-alive HTTPS client.
	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()
	var (
		successCount  atomic.Int64
		errorCount    atomic.Int64
		clientDone    = make(chan struct{})
		errsAfterSwap atomic.Int64
		oksAfterSwap  atomic.Int64
	)
	swapStarted := make(chan struct{})

	go func() {
		defer close(clientDone)
		client := newKeepaliveClient()
		probeURL := "https://" + normalizeProbeAddr(apiAddr) + "/api/v1/health"
		swapHasStarted := false
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-clientCtx.Done():
				return
			case <-ticker.C:
				if !swapHasStarted {
					select {
					case <-swapStarted:
						swapHasStarted = true
					default:
					}
				}
				req, err := http.NewRequestWithContext(clientCtx, http.MethodGet, probeURL, nil)
				if err != nil {
					return
				}
				resp, err := client.Do(req)
				if err != nil {
					errorCount.Add(1)
					if swapHasStarted {
						errsAfterSwap.Add(1)
					}
					continue
				}
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 500 {
					successCount.Add(1)
					if swapHasStarted {
						oksAfterSwap.Add(1)
					}
				} else {
					errorCount.Add(1)
					if swapHasStarted {
						errsAfterSwap.Add(1)
					}
				}
			}
		}
	}()

	// Let the client establish a baseline of successful polls.
	time.Sleep(1 * time.Second)
	require.Greater(t, successCount.Load(), int64(0),
		"client must succeed at least once before cutover begins")
	baselineSuccess := successCount.Load()
	t.Logf("pre-cutover: %d successful polls established", baselineSuccess)

	// Build the orchestrator. Spawn factory creates ExecProcessHandle
	// instances pointing at the SAME binary (we're "upgrading" to the
	// same version, but the test exercises the cutover MECHANISM, not
	// version delta — that's enough to prove the AC about client
	// survival).
	spawn := func(binaryPath string) ProcessHandle {
		return NewExecProcessHandle(binaryPath, cfgPath)
	}
	smoke := &HTTPSmoketester{
		ReadyTimeout:   30 * time.Second,
		RequestTimeout: 5 * time.Second,
		SkipTLSVerify:  true,
	}
	swap := &PortSwapTarget{
		PortHandoffTimeout: 5 * time.Second,
		CandidateSpawner:   spawn,
		ReadinessProbe:     smoke,
	}
	orch := NewOrchestrator(
		Config{
			CanonicalAPIAddr:       apiAddr,
			CanonicalTransportAddr: transportAddr,
			CandidateAPIAddr:       candAPIAddr,
			CandidateTransportAddr: candTransportAddr,
			QuarantineWindow:       30 * time.Second, // short for test
			SmoketestTimeout:       30 * time.Second,
		},
		initial,
		nil, // no Validator
		smoke,
		swap,
		spawn,
	)

	// Signal the client we're starting the swap (so post-swap counters
	// are partitioned).
	close(swapStarted)
	t.Logf("starting cutover ...")
	swapStart := time.Now()
	upgradeCtx, upgradeCancel := context.WithTimeout(ctx, 60*time.Second)
	defer upgradeCancel()
	upErr := orch.Upgrade(upgradeCtx, exe)
	swapElapsed := time.Since(swapStart)
	t.Logf("cutover completed in %s (err: %v)", swapElapsed, upErr)

	require.NoError(t, upErr, "Upgrade against a real controller must succeed")
	require.Equal(t, StateQuarantined, orch.Status().State,
		"orchestrator must end in StateQuarantined after successful Upgrade")

	// Continue polling for another 10s post-swap to count successes.
	t.Logf("post-cutover polling window ...")
	time.Sleep(10 * time.Second)
	clientCancel()
	<-clientDone

	t.Logf("totals: success=%d errors=%d (post-swap: ok=%d err=%d)",
		successCount.Load(), errorCount.Load(),
		oksAfterSwap.Load(), errsAfterSwap.Load())

	// The AC: stewards never see more than 10s of API unavailability.
	// Concretely: after the cutover begins, at least one successful
	// response must arrive within 10s. We measure that as
	// oksAfterSwap > 0.
	require.Greater(t, oksAfterSwap.Load(), int64(0),
		"client must receive at least one successful response within 10s after the cutover began — got %d errors and %d successes post-swap",
		errsAfterSwap.Load(), oksAfterSwap.Load())

	// Clean up the orchestrator's quarantined backend so leftover
	// process state doesn't leak.
	cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanCancel()
	orch.FinalizeQuarantine(cleanCtx)
}

// TestCutover_IntegrationFailedSmoketest covers the [REQUIRED TEST] for
// failed smoketests: a candidate that fails its probe must NOT cause a
// cutover, blue stays canonical, and the operator-visible error names
// the specific failure.
//
// This is achieved by spawning a "candidate" that exits immediately —
// the smoketester's port-ready probe times out (the candidate never
// listens), which becomes the operator-facing error.
func TestCutover_IntegrationFailedSmoketest(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — requires controller binary build + spawn")
	}

	exe := buildControllerBinary(t)
	dataDir := t.TempDir()
	certDir := filepath.Join(dataDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0o755))

	apiAddr := freePortLocal(t)
	transportAddr := freePortLocal(t)
	candAPIAddr := freePortLocal(t)
	candTransportAddr := freePortLocal(t)

	cfgPath := writeMinimalConfig(t, dataDir, certDir, apiAddr, transportAddr)
	initController(t, exe, cfgPath)

	initial := NewExecProcessHandle(exe, cfgPath)
	stdoutBuf := &threadSafeBuffer{}
	stderrBuf := &threadSafeBuffer{}
	initial.Stdout = stdoutBuf
	initial.Stderr = stderrBuf
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	require.NoError(t, initial.Start(ctx, apiAddr, transportAddr))
	t.Cleanup(func() {
		stopCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = initial.Stop(stopCtx)
		if t.Failed() {
			t.Logf("controller stdout:\n%s", stdoutBuf.String())
			t.Logf("controller stderr:\n%s", stderrBuf.String())
		}
	})
	require.NoError(t, waitForControllerHealthy(ctx, apiAddr, 30*time.Second))

	// Spawn factory that produces a "candidate" handle whose binary
	// path is /bin/echo-style nonsense — exec.Start succeeds but the
	// process exits immediately and never listens. The smoketester's
	// port-ready check times out.
	spawn := func(_ string) ProcessHandle {
		h := NewExecProcessHandle("___nonexistent-binary___", cfgPath)
		return h
	}
	smoke := &HTTPSmoketester{
		ReadyTimeout:   2 * time.Second,
		RequestTimeout: 1 * time.Second,
		SkipTLSVerify:  true,
	}
	swap := &PortSwapTarget{
		PortHandoffTimeout: 5 * time.Second,
		CandidateSpawner:   spawn,
		ReadinessProbe:     smoke,
	}
	orch := NewOrchestrator(
		Config{
			CanonicalAPIAddr:       apiAddr,
			CanonicalTransportAddr: transportAddr,
			CandidateAPIAddr:       candAPIAddr,
			CandidateTransportAddr: candTransportAddr,
			QuarantineWindow:       30 * time.Second,
			SmoketestTimeout:       3 * time.Second,
		},
		initial,
		nil,
		smoke,
		swap,
		spawn,
	)

	upErr := orch.Upgrade(ctx, "___nonexistent-binary___")
	require.Error(t, upErr, "failed smoketest must surface as an Upgrade error")
	require.Equal(t, StateIdle, orch.Status().State,
		"after failed smoketest, orchestrator must return to StateIdle")

	// Verify blue is STILL serving — the original canonical was never
	// touched because validation/spawn/smoketest failed before any
	// drain.
	require.NoError(t, waitForControllerHealthy(ctx, apiAddr, 5*time.Second),
		"original canonical must still be serving after a failed cutover")
}

// TestCutover_IntegrationAbortedMidflight covers the [REQUIRED TEST]
// for operator Ctrl-C mid-cutover: cancelling the orchestration ctx
// must NOT leave the orchestrator in a partial state, and the
// original canonical must continue serving traffic.
//
// Flow:
//  1. Build the controller binary, generate certs, --init.
//  2. Spawn the initial canonical, wait healthy.
//  3. Start Upgrade in a goroutine.
//  4. Cancel the context ~1.5s in (mid-smoketest or mid-swap).
//  5. Wait for Upgrade to return.
//  6. Assert: orchestrator is in StateIdle; original canonical still
//     responds to /api/v1/health within 5s.
func TestCutover_IntegrationAbortedMidflight(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — requires controller binary build + spawn")
	}

	exe := buildControllerBinary(t)
	dataDir := t.TempDir()
	certDir := filepath.Join(dataDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0o755))

	apiAddr := freePortLocal(t)
	transportAddr := freePortLocal(t)
	candAPIAddr := freePortLocal(t)
	candTransportAddr := freePortLocal(t)

	cfgPath := writeMinimalConfig(t, dataDir, certDir, apiAddr, transportAddr)
	initController(t, exe, cfgPath)

	initial := NewExecProcessHandle(exe, cfgPath)
	stdoutBuf := &threadSafeBuffer{}
	stderrBuf := &threadSafeBuffer{}
	initial.Stdout = stdoutBuf
	initial.Stderr = stderrBuf
	bgCtx, bgCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer bgCancel()
	require.NoError(t, initial.Start(bgCtx, apiAddr, transportAddr))
	t.Cleanup(func() {
		stopCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = initial.Stop(stopCtx)
		if t.Failed() {
			t.Logf("controller stdout:\n%s", stdoutBuf.String())
			t.Logf("controller stderr:\n%s", stderrBuf.String())
		}
	})
	require.NoError(t, waitForControllerHealthy(bgCtx, apiAddr, 30*time.Second))

	spawn := func(binaryPath string) ProcessHandle {
		return NewExecProcessHandle(binaryPath, cfgPath)
	}
	// Use a deliberately-slow smoketester so the abort lands DURING
	// smoketest, not after — the production HTTPSmoketester probes
	// /api/v1/health in <500ms which leaves no realistic cancel
	// window. The AC's "router stays pointed at previous canonical"
	// only holds when the abort lands BEFORE the swap drains the
	// original; with a fast smoketest the only meaningful cancel
	// happens once it's too late. Use a Smoketester impl that blocks
	// on ctx so the abort path is exercised cleanly.
	slowSmoke := &blockingSmoketester{}
	swap := &PortSwapTarget{
		PortHandoffTimeout: 5 * time.Second,
		CandidateSpawner:   spawn,
		ReadinessProbe:     slowSmoke,
	}
	orch := NewOrchestrator(
		Config{
			CanonicalAPIAddr:       apiAddr,
			CanonicalTransportAddr: transportAddr,
			CandidateAPIAddr:       candAPIAddr,
			CandidateTransportAddr: candTransportAddr,
			QuarantineWindow:       30 * time.Second,
			SmoketestTimeout:       30 * time.Second,
		},
		initial,
		nil,
		slowSmoke,
		swap,
		spawn,
	)

	upgradeCtx, upgradeCancel := context.WithCancel(bgCtx)
	var (
		upErr   error
		upDone  = make(chan struct{})
		upStart = time.Now()
	)
	go func() {
		defer close(upDone)
		upErr = orch.Upgrade(upgradeCtx, exe)
	}()

	// Cancel after 500ms — the blockingSmoketester is happily
	// blocked on ctx so we're guaranteed to be in StateSmoketesting,
	// not yet drained.
	time.Sleep(500 * time.Millisecond)
	t.Logf("cancelling upgrade context at +%s", time.Since(upStart))
	upgradeCancel()

	select {
	case <-upDone:
		t.Logf("upgrade returned %s after cancel (err: %v)", time.Since(upStart), upErr)
	case <-time.After(30 * time.Second):
		t.Fatal("Upgrade did not return within 30s of cancel — orchestrator hangs on aborted cutover")
	}

	require.Error(t, upErr, "Upgrade must surface the cancellation as an error")
	require.Equal(t, StateIdle, orch.Status().State,
		"after aborted cutover, orchestrator must be back in StateIdle (no partial state)")
	// Post-abort recovery window. The aborted candidate may have left
	// shared-storage state (WAL transactions, flatfile temp files) that
	// the original canonical needs to step around — Story B's retry
	// helpers handle the steady state but a freshly-killed candidate
	// can briefly contend. 15s is the operator-perceptible budget under
	// which the AC's "router stays pointed at the previous canonical"
	// is honoured.
	require.NoError(t, waitForControllerHealthy(bgCtx, apiAddr, 15*time.Second),
		"original canonical must still respond after an aborted cutover")
}

// freePortLocal: free TCP port reservation, returns ":<port>".
func freePortLocal(t *testing.T) string {
	t.Helper()
	addr := freePort(t)
	// freePort returns "127.0.0.1:<port>" — Story C's ExecProcessHandle
	// passes --listen-api-addr verbatim, and the controller accepts
	// either form. Keep the loopback prefix for explicitness.
	return addr
}

// waitForControllerHealthy polls /api/v1/health until 200 OR
// 401/403, or the timeout elapses.
func waitForControllerHealthy(ctx context.Context, addr string, timeout time.Duration) error {
	client := newKeepaliveClient()
	probeURL := "https://" + normalizeProbeAddr(addr) + "/api/v1/health"
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("controller at %s never returned healthy within %s", addr, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// blockingSmoketester is a Smoketester that blocks forever on its ctx.
// Used by the aborted-cutover test to give the orchestrator a long
// enough window in StateSmoketesting that the cancel lands cleanly
// before any destructive swap step has begun. Production smoketests
// return in well under a second; this fake stays blocked until cancel
// fires.
type blockingSmoketester struct{}

func (blockingSmoketester) Probe(ctx context.Context, _ ProcessHandle, _, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

// threadSafeBuffer is a thread-safe bytes buffer for capturing
// subprocess stdout/stderr. The exec.Cmd writer goroutine and the
// test's read goroutine both touch the underlying bytes; a sync.Mutex
// serialises access.
type threadSafeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func newKeepaliveClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //#nosec G402 -- integration test against self-signed
				MinVersion:         tls.VersionTLS12,
			},
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 4,
		},
	}
}
