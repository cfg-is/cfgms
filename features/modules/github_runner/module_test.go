// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// errEnsureBoom is a sentinel the test service executor returns to verify Set
// propagates a service-convergence failure.
var errEnsureBoom = errors.New("ensure failed (test)")

// Compile-time assertions: the module satisfies the core interfaces.
var (
	_ modules.Module       = (*runnerModule)(nil)
	_ modules.Configurable = (*runnerModule)(nil)
	_ modules.ConfigState  = (*RunnerConfig)(nil)
)

// testServiceExecutor is a test implementation of runnerServiceExecutor (a small
// internal interface), not a mock of a CFGMS component. The OS init system is
// unavailable in CI, so convergence logic is validated against a controllable
// in-memory service. It records ensure calls so idempotency can be asserted.
type testServiceExecutor struct {
	installed    bool
	running      bool
	enabled      bool
	ensureCalls  int
	failEnsure   error
	makeRunOnSet bool // when true, ensure() flips running/enabled true (models a real start)
}

func (e *testServiceExecutor) status(_ context.Context, _ string) (svcStatus, error) {
	return svcStatus{Installed: e.installed, Running: e.running, Enabled: e.enabled}, nil
}

func (e *testServiceExecutor) ensure(_ context.Context, _ string, running, enabled bool) error {
	e.ensureCalls++
	if e.failEnsure != nil {
		return e.failEnsure
	}
	if e.makeRunOnSet {
		e.running = running
		e.enabled = enabled
	}
	return nil
}

// countingInstaller wraps the real httpInstaller and counts install calls, so a
// test can assert that a converged Set does not re-download the agent.
type countingInstaller struct {
	inner agentInstaller
	calls int
}

func (c *countingInstaller) install(ctx context.Context, src installSource) error {
	c.calls++
	return c.inner.install(ctx, src)
}

func validConfig(workDir, serviceName string) *RunnerConfig {
	return &RunnerConfig{
		Version:     "2.319.1",
		AgentURL:    "https://example.invalid/runner.tar.gz",
		AgentSHA256: strings.Repeat("a", 64),
		Labels:      []string{"linux", "ci", "self-hosted"},
		WorkDir:     workDir,
		ServiceName: serviceName,
	}
}

func TestRunnerConfig_Validate(t *testing.T) {
	base := validConfig("/opt/runner", "actions.runner.acme-repo.host1.service")
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]func(*RunnerConfig){
		"missing version":  func(c *RunnerConfig) { c.Version = "" },
		"non-http url":     func(c *RunnerConfig) { c.AgentURL = "ftp://x/y" },
		"short sha":        func(c *RunnerConfig) { c.AgentSHA256 = "abc" },
		"missing work_dir": func(c *RunnerConfig) { c.WorkDir = "" },
		"bad service_name": func(c *RunnerConfig) { c.ServiceName = "-bad name" },
		"bad label":        func(c *RunnerConfig) { c.Labels = []string{"ok", "has space"} },
	}
	for name, mutate := range cases {
		c := validConfig("/opt/runner", "actions.runner.acme-repo.host1.service")
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestRunnerConfig_AsMap_HasNoTokenField(t *testing.T) {
	m := validConfig("/opt/runner", "svc").AsMap()
	for k := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "registration") {
			t.Errorf("RunnerConfig.AsMap exposes a token/secret field %q — the module must be token-free", k)
		}
	}
}

// TestSchema_NoRegistrationTokenField asserts the resource schema declares no
// registration-token (or any secret) field — the module never registers.
func TestSchema_NoRegistrationTokenField(t *testing.T) {
	data, err := os.ReadFile("schema.yaml")
	if err != nil {
		t.Fatalf("read schema.yaml: %v", err)
	}
	var schema struct {
		Resources map[string]struct {
			Required   []string                          `yaml:"required"`
			Properties map[string]map[string]interface{} `yaml:"properties"`
		} `yaml:"resources"`
	}
	if err := yaml.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse schema.yaml: %v", err)
	}
	runner, ok := schema.Resources["runner"]
	if !ok {
		t.Fatal("schema.yaml has no 'runner' resource")
	}
	for prop := range runner.Properties {
		lp := strings.ToLower(prop)
		if strings.Contains(lp, "token") || strings.Contains(lp, "registration") || strings.Contains(lp, "secret") {
			t.Errorf("schema.yaml declares a forbidden property %q — module must not consume registration tokens", prop)
		}
	}
	for _, req := range runner.Required {
		if strings.Contains(strings.ToLower(req), "token") {
			t.Errorf("schema.yaml requires a token field %q", req)
		}
	}
}

func TestConfigure_RejectsInvalid(t *testing.T) {
	m := newModule(&testServiceExecutor{}, newHTTPInstaller())
	if err := m.Configure(validConfig("/opt/runner", "svc")); err != nil {
		t.Fatalf("Configure rejected a valid config: %v", err)
	}
	bad := validConfig("/opt/runner", "svc")
	bad.AgentSHA256 = "nope"
	if err := m.Configure(bad); err == nil {
		t.Fatal("Configure accepted an invalid config")
	}
}

// agentServer serves an agent archive in the current OS's format (so the module's
// Set path, which selects format via archiveFormatForOS, can unpack it) over
// HTTPS — exercising the module's https-only agent_url validation — and returns
// (server, url, sha256hex). Use srv.Client() to build the installer so the
// self-signed test cert is trusted.
func agentServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	return agentServerContent(t, "listener")
}

// agentServerContent is agentServer with caller-chosen file content, so an
// upgrade test can serve a distinct archive (distinct sha) for a new version.
func agentServerContent(t *testing.T, content string) (*httptest.Server, string, string) {
	t.Helper()
	var archive []byte
	if archiveFormatForOS() == "zip" {
		archive = makeZip(t, map[string]string{"bin/Runner.Listener.exe": content})
	} else {
		archive = makeTarGz(t, map[string]string{"bin/Runner.Listener": content})
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	return srv, srv.URL, sha256Hex(archive)
}

// moduleFor builds a module wired with the given service executor and an
// install path that trusts srv's self-signed TLS cert, plus the counting
// installer so re-download can be asserted.
func moduleFor(exec runnerServiceExecutor, srv *httptest.Server) (*runnerModule, *countingInstaller) {
	inst := &countingInstaller{inner: newHTTPInstallerWithClient(srv.Client())}
	return newModule(exec, inst), inst
}

func TestModule_Set_InstallsAndIsIdempotent(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()

	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, makeRunOnSet: true}
	m, inst := moduleFor(exec, srv)

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.AgentURL = url
	cfg.AgentSHA256 = sha

	ctx := context.Background()

	// First Set: installs the agent and converges the service.
	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("first Set failed: %v", err)
	}
	if inst.calls != 1 {
		t.Fatalf("first Set: installer called %d times, want 1", inst.calls)
	}

	// After convergence, Test reports no drift.
	ok, err := m.Test(ctx, workDir, cfg)
	if err != nil {
		t.Fatalf("Test after Set: %v", err)
	}
	if !ok {
		t.Fatal("Test reported drift immediately after a successful Set")
	}

	// Second Set: a no-op — the pinned version is already installed, so the
	// agent is NOT re-downloaded and the converged service state is unchanged.
	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("second Set failed: %v", err)
	}
	if inst.calls != 1 {
		t.Fatalf("second Set re-installed the agent (installer calls=%d, want 1) — not idempotent", inst.calls)
	}
	if !exec.running || !exec.enabled {
		t.Fatalf("second Set changed converged service state: running=%v enabled=%v, want both true", exec.running, exec.enabled)
	}
	// Idempotency end-state: Test still reports no drift after the second Set.
	ok, err = m.Test(ctx, workDir, cfg)
	if err != nil {
		t.Fatalf("Test after second Set: %v", err)
	}
	if !ok {
		t.Fatal("Test reported drift after an idempotent second Set")
	}
}

func TestModule_Set_VersionUpgradeReinstalls(t *testing.T) {
	srv1, url1, sha1 := agentServerContent(t, "listener-v1")
	defer srv1.Close()
	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, makeRunOnSet: true}
	m, inst := moduleFor(exec, srv1)

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.Version, cfg.AgentURL, cfg.AgentSHA256 = "2.319.1", url1, sha1
	ctx := context.Background()
	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("initial Set: %v", err)
	}
	if inst.calls != 1 {
		t.Fatalf("initial install calls=%d, want 1", inst.calls)
	}

	// Pin a newer version served by a second server (distinct archive + sha).
	srv2, url2, sha2 := agentServerContent(t, "listener-v2")
	defer srv2.Close()
	m2, inst2 := moduleFor(exec, srv2)
	upgrade := *cfg
	upgrade.Version, upgrade.AgentURL, upgrade.AgentSHA256 = "2.320.0", url2, sha2

	// Before upgrade, Test sees version drift.
	if ok, err := m2.Test(ctx, workDir, &upgrade); err != nil || ok {
		t.Fatalf("Test before upgrade: ok=%v err=%v, want drift (ok=false)", ok, err)
	}
	// Upgrade Set re-downloads the new version.
	if err := m2.Set(ctx, workDir, &upgrade); err != nil {
		t.Fatalf("upgrade Set: %v", err)
	}
	if inst2.calls != 1 {
		t.Fatalf("upgrade did not re-download (installer calls=%d, want 1)", inst2.calls)
	}
	if ok, err := m2.Test(ctx, workDir, &upgrade); err != nil || !ok {
		t.Fatalf("Test after upgrade: ok=%v err=%v, want converged (ok=true)", ok, err)
	}
}

func TestModule_Set_EnsureFailurePropagates(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, failEnsure: errEnsureBoom}
	m, _ := moduleFor(exec, srv)

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.AgentURL, cfg.AgentSHA256 = url, sha

	err := m.Set(context.Background(), workDir, cfg)
	if err == nil {
		t.Fatal("Set did not propagate the service ensure failure")
	}
	if !errors.Is(err, errEnsureBoom) {
		t.Fatalf("Set error = %v, want it to wrap errEnsureBoom", err)
	}
}

func TestModule_Test_DetectsDrift(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, makeRunOnSet: true}
	m, _ := moduleFor(exec, srv)

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.AgentURL, cfg.AgentSHA256 = url, sha
	ctx := context.Background()

	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Version drift.
	verDrift := *cfg
	verDrift.Version = "2.320.0"
	if ok, err := m.Test(ctx, workDir, &verDrift); err != nil {
		t.Fatalf("Test (version drift): %v", err)
	} else if ok {
		t.Error("Test did not detect version drift")
	}

	// Label drift.
	labelDrift := *cfg
	labelDrift.Labels = []string{"linux", "ci"} // dropped "self-hosted"
	if ok, err := m.Test(ctx, workDir, &labelDrift); err != nil {
		t.Fatalf("Test (label drift): %v", err)
	} else if ok {
		t.Error("Test did not detect label drift")
	}

	// Service-not-running drift.
	exec.running = false
	if ok, err := m.Test(ctx, workDir, cfg); err != nil {
		t.Fatalf("Test (service drift): %v", err)
	} else if ok {
		t.Error("Test did not detect that the service is not running")
	}
}

func TestModule_Set_ServiceNotRegistered_StagesAgent(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	// Service not registered yet (provisioning has not run the register step).
	exec := &testServiceExecutor{installed: false}
	m, _ := moduleFor(exec, srv)

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.AgentURL, cfg.AgentSHA256 = url, sha
	ctx := context.Background()

	// Set must succeed (agent staged) even though the service is not registered;
	// ensure() must NOT be called against a non-registered service.
	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("Set with unregistered service failed: %v", err)
	}
	if exec.ensureCalls != 0 {
		t.Fatalf("ensure() called %d times against an unregistered service, want 0", exec.ensureCalls)
	}
	// Test reports drift (not running) until registration completes.
	if ok, err := m.Test(ctx, workDir, cfg); err != nil {
		t.Fatalf("Test (unregistered): %v", err)
	} else if ok {
		t.Fatal("Test reported converged while the runner service is not yet registered")
	}
}

func TestModule_Get_ReportsState(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, running: true, enabled: true}
	m, _ := moduleFor(exec, srv)

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.AgentURL, cfg.AgentSHA256 = url, sha
	ctx := context.Background()
	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	state, err := m.Get(ctx, workDir)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	rc := state.(*RunnerConfig)
	if rc.Version != "2.319.1" {
		t.Errorf("Get version = %q, want 2.319.1", rc.Version)
	}
	if !rc.Installed || !rc.ServiceRunning || !rc.ServiceEnabled {
		t.Errorf("Get state = installed:%v running:%v enabled:%v, want all true", rc.Installed, rc.ServiceRunning, rc.ServiceEnabled)
	}
}

func TestModule_Get_InvalidResourceID(t *testing.T) {
	m := newModule(&testServiceExecutor{}, newHTTPInstaller())
	if _, err := m.Get(context.Background(), ""); err == nil {
		t.Fatal("Get accepted an empty resource ID")
	}
}
