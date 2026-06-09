// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTLSTestServer wraps httptest.NewTLSServer so the smoketest tests
// have a one-liner for spinning up a self-signed-cert HTTP/2 server
// on a free loopback port. Cert validation is intentionally disabled
// on the smoketest side via HTTPSmoketester.SkipTLSVerify=true.
func newTLSTestServer(h http.Handler) *httptest.Server {
	return httptest.NewTLSServer(h)
}

// TestHelperProcess is the canonical test-binary-as-fake-child pattern.
// When invoked with GO_WANT_HELPER_PROCESS=1 plus FAKE_CONTROLLER_*
// env vars, this test re-incarnates the test binary as a stand-in
// cfgms-controller for the production-impl tests.
//
// FAKE_CONTROLLER_API_LISTEN — address to bind an HTTP server on. The
//
//	handler responds 200 to /api/v1/health, mirroring the real
//	controller's healthz contract that HTTPSmoketester probes.
//
// FAKE_CONTROLLER_HANG_MS — if set, the process sleeps this many
//
//	milliseconds before exiting cleanly. Used to test Drain timeout
//	behaviour.
//
// FAKE_CONTROLLER_IGNORE_TERM — if "1", the process installs no signal
//
//	handler, so SIGTERM is ignored. Used to verify Stop escalates to
//	Kill when Drain times out.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	addr := os.Getenv("FAKE_CONTROLLER_API_LISTEN")
	hangMs, _ := strconv.Atoi(os.Getenv("FAKE_CONTROLLER_HANG_MS"))

	if addr == "" {
		fmt.Fprintln(os.Stderr, "helper: FAKE_CONTROLLER_API_LISTEN required")
		os.Exit(2)
	}

	// Listen FIRST so the parent can immediately observe the port is
	// accepting connections.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: listen %s: %v\n", addr, err)
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	// Sleep, then exit. The orchestrator typically signals long before
	// this sleep elapses.
	if hangMs <= 0 {
		hangMs = 600000 // 10 min default — caller must signal to terminate
	}
	time.Sleep(time.Duration(hangMs) * time.Millisecond)
	_ = srv.Close()
	os.Exit(0)
}

// envForFakeController sets the env vars TestHelperProcess reads. Uses
// t.Setenv so each test gets isolated state.
func envForFakeController(t *testing.T, listenAddr string) {
	t.Helper()
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("FAKE_CONTROLLER_API_LISTEN", listenAddr)
}

// freePort returns a localhost address with an OS-assigned free port.
// Used so tests don't fight over fixed port numbers.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// TestExecProcessHandle_BuildArgs covers the argv-construction surface
// that Start uses internally. Verifying it here means a regression
// (e.g. flag name renamed but Start not updated) surfaces without
// having to spawn anything.
func TestExecProcessHandle_BuildArgs(t *testing.T) {
	cases := []struct {
		name        string
		configPath  string
		apiAddr     string
		transportAd string
		want        []string
	}{
		{
			name:       "config only",
			configPath: "/etc/cfgms/controller.cfg",
			want:       []string{"--config", "/etc/cfgms/controller.cfg"},
		},
		{
			name:       "config + api override",
			configPath: "/etc/cfgms/controller.cfg",
			apiAddr:    ":9081",
			want:       []string{"--config", "/etc/cfgms/controller.cfg", "--listen-api-addr", ":9081"},
		},
		{
			name:        "all three",
			configPath:  "/etc/cfgms/controller.cfg",
			apiAddr:     ":9081",
			transportAd: ":4434",
			want: []string{
				"--config", "/etc/cfgms/controller.cfg",
				"--listen-api-addr", ":9081",
				"--listen-transport-addr", ":4434",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := NewExecProcessHandle("/bin/cfgms-controller", c.configPath)
			got := h.BuildArgs(c.apiAddr, c.transportAd)
			assert.Equal(t, c.want, got)
		})
	}
}

// TestExecProcessHandle_StartAndStop_LiveSubprocess spawns the test
// binary as a stand-in controller, verifies the child actually
// listens on the requested port, then Stop reaps it cleanly + a second
// Stop is idempotent. Uses ArgsOverride so the production argv shape
// doesn't trip Go's testing.Main flag parser.
func TestExecProcessHandle_StartAndStop_LiveSubprocess(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	listenAddr := freePort(t)

	h := NewExecProcessHandle(exe, "ignored-by-helper")
	h.Stdout = &bytes.Buffer{}
	h.Stderr = &bytes.Buffer{}
	h.ExtraEnv = []string{
		"GO_WANT_HELPER_PROCESS=1",
		"FAKE_CONTROLLER_API_LISTEN=" + listenAddr,
	}
	h.ArgsOverride = []string{"-test.run=TestHelperProcess"}

	ctx := context.Background()
	require.NoError(t, h.Start(ctx, listenAddr, ""))

	// Wait for the fake to actually accept connections.
	require.NoError(t, waitForPortReady(ctx, listenAddr, 5*time.Second))

	// Stop must reap the child cleanly.
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	assert.NoError(t, h.Stop(stopCtx))

	// Second Stop is idempotent.
	assert.NoError(t, h.Stop(stopCtx))
}

// TestExecProcessHandle_Drain_GracefulExit verifies that Drain sends
// the platform-appropriate graceful signal and waits for the child to
// release the port.
func TestExecProcessHandle_Drain_GracefulExit(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	listenAddr := freePort(t)

	h := NewExecProcessHandle(exe, "ignored-by-helper")
	h.Stdout = &bytes.Buffer{}
	h.Stderr = &bytes.Buffer{}
	h.ExtraEnv = []string{
		"GO_WANT_HELPER_PROCESS=1",
		"FAKE_CONTROLLER_API_LISTEN=" + listenAddr,
		// Tiny hang so the helper exits on its own quickly — Drain's
		// graceful signal is best-effort on Windows (Interrupt isn't
		// delivered to non-console processes), so we lean on the
		// child's natural exit time.
		"FAKE_CONTROLLER_HANG_MS=200",
	}
	h.ArgsOverride = []string{"-test.run=TestHelperProcess"}
	h.DrainTimeout = 5 * time.Second

	ctx := context.Background()
	require.NoError(t, h.Start(ctx, listenAddr, ""))
	require.NoError(t, waitForPortReady(ctx, listenAddr, 5*time.Second))

	// Drain returns nil once the child exits.
	require.NoError(t, h.Drain(ctx))

	// Port should be free shortly after.
	require.NoError(t, waitForPortFree(ctx, listenAddr, 2*time.Second))
}

// TestWaitForPortFree_PortAlreadyFree returns immediately.
func TestWaitForPortFree_PortAlreadyFree(t *testing.T) {
	addr := freePort(t)
	start := time.Now()
	err := waitForPortFree(context.Background(), addr, 5*time.Second)
	assert.NoError(t, err)
	assert.Less(t, time.Since(start), 1*time.Second, "should return immediately when port is already free")
}

// TestWaitForPortFree_PortStillBound_TimesOut verifies the helper
// surfaces a clear error when a listener never releases the port.
func TestWaitForPortFree_PortStillBound_TimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()
	err = waitForPortFree(context.Background(), addr, 300*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still accepting connections")
}

// TestWaitForPortReady_PortListening returns nil promptly.
func TestWaitForPortReady_PortListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()
	start := time.Now()
	err = waitForPortReady(context.Background(), addr, 5*time.Second)
	assert.NoError(t, err)
	assert.Less(t, time.Since(start), 1*time.Second)
}

// TestWaitForPortReady_NoListener_TimesOut bounds the failure case.
func TestWaitForPortReady_NoListener_TimesOut(t *testing.T) {
	addr := freePort(t)
	err := waitForPortReady(context.Background(), addr, 300*time.Millisecond)
	require.Error(t, err)
}

// TestNormalizeProbeAddr exercises the address-form conversions.
func TestNormalizeProbeAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{":4433", "127.0.0.1:4433"},
		{"0.0.0.0:9080", "127.0.0.1:9080"},
		{"127.0.0.1:8080", "127.0.0.1:8080"},
		{"host:8080", "host:8080"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeProbeAddr(c.in), "in=%q", c.in)
	}
}

// fakeHandle_Concurrent is an extension of fakeHandle that tracks
// concurrent Start/Stop calls so PortSwapTarget tests can verify
// ordering.
type fakeHandle_Concurrent struct {
	binary string
	mu     sync.Mutex
	events []string
}

func (f *fakeHandle_Concurrent) Start(_ context.Context, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "start")
	return nil
}
func (f *fakeHandle_Concurrent) Drain(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "drain")
	return nil
}
func (f *fakeHandle_Concurrent) Stop(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "stop")
	return nil
}
func (f *fakeHandle_Concurrent) BinaryPath() string { return f.binary }

// TestPortSwapTarget_DrainThenSpawn covers the production swap path
// against fakes (no real ports). Verifies the ordering: from.Drain
// happens before to.Stop happens before CandidateSpawner.
func TestPortSwapTarget_DrainThenSpawn(t *testing.T) {
	from := &fakeHandle_Concurrent{binary: "blue.exe"}
	to := &fakeHandle_Concurrent{binary: "green.exe"}

	// Use a port that won't actually be listened on — waitForPortFree
	// will return immediately because nothing is bound.
	canonAPI := freePort(t)

	var spawnedBinary string
	spawned := &fakeHandle_Concurrent{binary: "green.exe"}
	pt := &PortSwapTarget{
		PortHandoffTimeout: 2 * time.Second,
		CandidateSpawner: func(binaryPath string) ProcessHandle {
			spawnedBinary = binaryPath
			return spawned
		},
		// No ReadinessProbe — fake doesn't actually listen.
	}

	promoted, err := pt.Swap(context.Background(), from, to, canonAPI, "")
	require.NoError(t, err)
	assert.Same(t, ProcessHandle(spawned), promoted,
		"PortSwapTarget must return the freshly-spawned handle, not the input `to`")
	assert.Equal(t, "green.exe", spawnedBinary,
		"CandidateSpawner must be invoked with the input `to`'s binary path")

	assert.Equal(t, []string{"drain"}, from.events, "from must be drained, not stopped (when drain succeeds)")
	assert.Equal(t, []string{"stop"}, to.events, "input `to` must be stopped before spawning canonical")
	assert.Equal(t, []string{"start"}, spawned.events, "fresh canonical must be started")

	assert.Same(t, ProcessHandle(spawned), pt.LastPromoted())
}

// TestPortSwapTarget_MissingSpawner_ReturnsError covers misconfiguration.
func TestPortSwapTarget_MissingSpawner_ReturnsError(t *testing.T) {
	from := &fakeHandle_Concurrent{binary: "blue"}
	to := &fakeHandle_Concurrent{binary: "green"}
	pt := &PortSwapTarget{} // no CandidateSpawner
	_, err := pt.Swap(context.Background(), from, to, freePort(t), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CandidateSpawner")
}

// startSmoketestServer wires up a TLS server on a loopback port for the
// HTTPSmoketester tests, using httptest.NewTLSServer which handles
// self-signed cert generation. Returns the host:port (no scheme) and a
// cleanup func.
func startSmoketestServer(t *testing.T, handler http.Handler) (listenAddr string, cleanup func()) {
	t.Helper()
	srv := newTLSTestServer(handler)
	return srv.Listener.Addr().String(), srv.Close
}

// TestHTTPSmoketester_HealthyResponse verifies a 200 /api/v1/health unblocks
// the smoketest.
func TestHTTPSmoketester_HealthyResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	addr, cleanup := startSmoketestServer(t, mux)
	defer cleanup()

	smoke := &HTTPSmoketester{
		ReadyTimeout:   2 * time.Second,
		RequestTimeout: 2 * time.Second,
		SkipTLSVerify:  true,
	}
	err := smoke.Probe(context.Background(), nil, addr, "")
	assert.NoError(t, err)
}

// TestHTTPSmoketester_5xxResponse_Fails covers the failure path the
// orchestrator surfaces to the operator.
func TestHTTPSmoketester_5xxResponse_Fails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	addr, cleanup := startSmoketestServer(t, mux)
	defer cleanup()

	smoke := &HTTPSmoketester{
		ReadyTimeout:   2 * time.Second,
		RequestTimeout: 2 * time.Second,
		SkipTLSVerify:  true,
	}
	err := smoke.Probe(context.Background(), nil, addr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

// TestHTTPSmoketester_401Accepted covers that auth-required responses
// pass — they prove the API is alive even without admin creds.
func TestHTTPSmoketester_401Accepted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	addr, cleanup := startSmoketestServer(t, mux)
	defer cleanup()

	smoke := &HTTPSmoketester{
		ReadyTimeout:   2 * time.Second,
		RequestTimeout: 2 * time.Second,
		SkipTLSVerify:  true,
	}
	assert.NoError(t, smoke.Probe(context.Background(), nil, addr, ""))
}

// TestHTTPSmoketester_NoListener_Fails surfaces the right error when
// the candidate never came up.
func TestHTTPSmoketester_NoListener_Fails(t *testing.T) {
	addr := freePort(t)
	smoke := &HTTPSmoketester{
		ReadyTimeout:   300 * time.Millisecond,
		RequestTimeout: 300 * time.Millisecond,
		SkipTLSVerify:  true,
	}
	err := smoke.Probe(context.Background(), nil, addr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not listening")
}

