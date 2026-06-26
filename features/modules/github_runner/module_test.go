// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

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
	statusCalls  int
	failEnsure   error
	makeRunOnSet bool // when true, ensure() flips running/enabled true (models a real start)
}

func (e *testServiceExecutor) status(_ context.Context, _ string) (svcStatus, error) {
	e.statusCalls++
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
// Set path, which selects format via archiveFormatForOS, can unpack it) and
// returns (server, url, sha256hex).
func agentServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	var archive []byte
	if archiveFormatForOS() == "zip" {
		archive = makeZip(t, map[string]string{"bin/Runner.Listener.exe": "listener"})
	} else {
		archive = makeTarGz(t, map[string]string{"bin/Runner.Listener": "listener"})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	return srv, srv.URL, sha256Hex(archive)
}

func TestModule_Set_InstallsAndIsIdempotent(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()

	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, makeRunOnSet: true}
	inst := &countingInstaller{inner: newHTTPInstaller()}
	m := newModule(exec, inst)

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
	ensureAfterFirst := exec.ensureCalls

	// After convergence, Test reports no drift.
	ok, err := m.Test(ctx, workDir, cfg)
	if err != nil {
		t.Fatalf("Test after Set: %v", err)
	}
	if !ok {
		t.Fatal("Test reported drift immediately after a successful Set")
	}

	// Second Set: a no-op — the pinned version is already installed, so the
	// agent is NOT re-downloaded.
	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("second Set failed: %v", err)
	}
	if inst.calls != 1 {
		t.Fatalf("second Set re-installed the agent (installer calls=%d, want 1) — not idempotent", inst.calls)
	}
	_ = ensureAfterFirst // ensure may be called again, but it is itself idempotent (no state change)
}

func TestModule_Test_DetectsDrift(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, makeRunOnSet: true}
	m := newModule(exec, &countingInstaller{inner: newHTTPInstaller()})

	cfg := validConfig(workDir, "actions.runner.acme-repo.host1.service")
	cfg.AgentURL, cfg.AgentSHA256 = url, sha
	ctx := context.Background()

	if err := m.Set(ctx, workDir, cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Version drift.
	verDrift := *cfg
	verDrift.Version = "2.320.0"
	if ok, _ := m.Test(ctx, workDir, &verDrift); ok {
		t.Error("Test did not detect version drift")
	}

	// Label drift.
	labelDrift := *cfg
	labelDrift.Labels = []string{"linux", "ci"} // dropped "self-hosted"
	if ok, _ := m.Test(ctx, workDir, &labelDrift); ok {
		t.Error("Test did not detect label drift")
	}

	// Service-not-running drift.
	exec.running = false
	if ok, _ := m.Test(ctx, workDir, cfg); ok {
		t.Error("Test did not detect that the service is not running")
	}
}

func TestModule_Set_ServiceNotRegistered_StagesAgent(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	// Service not registered yet (provisioning has not run the register step).
	exec := &testServiceExecutor{installed: false}
	m := newModule(exec, &countingInstaller{inner: newHTTPInstaller()})

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
	if ok, _ := m.Test(ctx, workDir, cfg); ok {
		t.Fatal("Test reported converged while the runner service is not yet registered")
	}
}

func TestModule_Get_ReportsState(t *testing.T) {
	srv, url, sha := agentServer(t)
	defer srv.Close()
	workDir := t.TempDir()
	exec := &testServiceExecutor{installed: true, running: true, enabled: true}
	m := newModule(exec, &countingInstaller{inner: newHTTPInstaller()})

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
