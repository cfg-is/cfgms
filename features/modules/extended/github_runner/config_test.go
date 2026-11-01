// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

func TestSanitizeComponent(t *testing.T) {
	cases := []struct{ input, want string }{
		{"hello", "hello"},
		{"my.host", "my.host"},
		{"my_host", "my_host"},
		{"my-host", "my-host"},
		{"my@host", "my@host"},
		{"my host", "my-host"},
		{"org/repo", "org-repo"},
		{"host#1", "host-1"},
		{"org!@#$", "org-@--"},
	}
	for _, tc := range cases {
		if got := sanitizeComponent(tc.input); got != tc.want {
			t.Errorf("sanitizeComponent(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestResolveServiceName_Derived(t *testing.T) {
	cfg := &RunnerConfig{Owner: "myorg", Repo: "myrepo"}
	want := "actions.runner.myorg-myrepo.myhost"
	if got := cfg.ResolveServiceName("myhost"); got != want {
		t.Errorf("ResolveServiceName = %q, want %q", got, want)
	}
}

func TestResolveServiceName_ExplicitHonored(t *testing.T) {
	const explicit = "actions.runner.my-org.my-repo.explicit.service"
	cfg := &RunnerConfig{
		Owner:       "myorg",
		Repo:        "myrepo",
		ServiceName: explicit,
	}
	if got := cfg.ResolveServiceName("somehostname"); got != explicit {
		t.Errorf("ResolveServiceName = %q, want explicit %q", got, explicit)
	}
}

func TestResolveServiceName_SanitizesComponents(t *testing.T) {
	cases := []struct {
		owner, repo, hostname, want string
	}{
		{"my org", "my repo", "my host", "actions.runner.my-org-my-repo.my-host"},
		{"org/sub", "my/repo", "host.local", "actions.runner.org-sub-my-repo.host.local"},
	}
	for _, tc := range cases {
		cfg := &RunnerConfig{Owner: tc.owner, Repo: tc.repo}
		got := cfg.ResolveServiceName(tc.hostname)
		if got != tc.want {
			t.Errorf("owner=%q repo=%q hostname=%q: got %q, want %q",
				tc.owner, tc.repo, tc.hostname, got, tc.want)
		}
	}
}

func TestValidate_ServiceName_OptionalWithOwnerRepo(t *testing.T) {
	workDir := t.TempDir()
	cfg := &RunnerConfig{
		Version:     "2.319.1",
		AgentURL:    "https://example.invalid/runner.tar.gz",
		AgentSHA256: strings.Repeat("a", 64),
		WorkDir:     workDir,
		Owner:       "myorg",
		Repo:        "myrepo",
		// ServiceName intentionally empty
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config with owner+repo but no service_name rejected: %v", err)
	}
}

func TestValidate_ServiceName_MissingOwner(t *testing.T) {
	workDir := t.TempDir()
	cfg := &RunnerConfig{
		Version:     "2.319.1",
		AgentURL:    "https://example.invalid/runner.tar.gz",
		AgentSHA256: strings.Repeat("a", 64),
		WorkDir:     workDir,
		Repo:        "myrepo",
		// Owner and ServiceName both empty
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted empty service_name with no owner")
	}
}

func TestValidate_ServiceName_MissingRepo(t *testing.T) {
	workDir := t.TempDir()
	cfg := &RunnerConfig{
		Version:     "2.319.1",
		AgentURL:    "https://example.invalid/runner.tar.gz",
		AgentSHA256: strings.Repeat("a", 64),
		WorkDir:     workDir,
		Owner:       "myorg",
		// Repo and ServiceName both empty
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted empty service_name with no repo")
	}
}

func TestValidate_ServiceName_BothEmptyAndMissingOwnerRepo(t *testing.T) {
	workDir := t.TempDir()
	cfg := &RunnerConfig{
		Version:     "2.319.1",
		AgentURL:    "https://example.invalid/runner.tar.gz",
		AgentSHA256: strings.Repeat("a", 64),
		WorkDir:     workDir,
		// Owner, Repo, and ServiceName all empty
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted empty service_name with no owner or repo")
	}
}

// TestValidate_ErrorBranches exercises each distinct rejection path in
// Validate() individually, starting from an otherwise-valid config and mutating
// exactly one field per case. Every rejection must wrap modules.ErrInvalidInput
// so callers can classify it as a bad-input error.
func TestValidate_ErrorBranches(t *testing.T) {
	workDir := t.TempDir()

	// valid returns a fresh, fully-valid config each call so cases mutate in
	// isolation without sharing slice/state.
	valid := func() *RunnerConfig {
		return &RunnerConfig{
			Version:     "2.319.1",
			AgentURL:    "https://example.invalid/runner.tar.gz",
			AgentSHA256: strings.Repeat("a", 64),
			WorkDir:     workDir,
			Owner:       "myorg",
			Repo:        "myrepo",
		}
	}

	// Sanity: the baseline itself must validate, otherwise the mutations below
	// would not be isolating the intended branch.
	if err := valid().Validate(); err != nil {
		t.Fatalf("baseline valid config rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*RunnerConfig)
		wantSub string
	}{
		{
			name:    "empty version",
			mutate:  func(c *RunnerConfig) { c.Version = "   " },
			wantSub: "version is required",
		},
		{
			name:    "empty agent_url",
			mutate:  func(c *RunnerConfig) { c.AgentURL = "" },
			wantSub: "agent_url is required",
		},
		{
			name:    "non-https agent_url",
			mutate:  func(c *RunnerConfig) { c.AgentURL = "http://example.invalid/runner.tar.gz" },
			wantSub: "must be an https:// URL",
		},
		{
			name:    "malformed agent_sha256",
			mutate:  func(c *RunnerConfig) { c.AgentSHA256 = "deadbeef" },
			wantSub: "agent_sha256 must be a 64-character hex",
		},
		{
			name:    "empty work_dir",
			mutate:  func(c *RunnerConfig) { c.WorkDir = "   " },
			wantSub: "work_dir is required",
		},
		{
			name:    "relative work_dir",
			mutate:  func(c *RunnerConfig) { c.WorkDir = "relative/runner" },
			wantSub: "must be an absolute path",
		},
		{
			name:    "invalid service_name characters",
			mutate:  func(c *RunnerConfig) { c.ServiceName = "bad name;rm -rf" },
			wantSub: "contains invalid characters",
		},
		{
			name:    "invalid label characters",
			mutate:  func(c *RunnerConfig) { c.Labels = []string{"good", "bad label!"} },
			wantSub: "contains invalid characters",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted invalid config (%s)", tc.name)
			}
			if !errors.Is(err, modules.ErrInvalidInput) {
				t.Errorf("error %v does not wrap ErrInvalidInput", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestReadState_MissingMarkerIsZeroValue confirms the documented contract that a
// never-converged runner (no marker on disk) yields zero-value state, not an error.
func TestReadState_MissingMarkerIsZeroValue(t *testing.T) {
	st, err := readState(t.TempDir())
	if err != nil {
		t.Fatalf("readState on missing marker returned error: %v", err)
	}
	if st.Version != "" || st.ServiceName != "" || len(st.Labels) != 0 {
		t.Errorf("readState on missing marker = %+v, want zero value", st)
	}
}

// TestReadState_RoundTrip exercises the happy path: a marker written by writeState
// is read back byte-for-byte by readState.
func TestReadState_RoundTrip(t *testing.T) {
	workDir := t.TempDir()
	want := runnerState{
		Version:     "2.319.1",
		Labels:      []string{"linux", "self-hosted"},
		ServiceName: "actions.runner.org-repo.host",
	}
	if err := writeState(workDir, want); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	got, err := readState(workDir)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if got.Version != want.Version || got.ServiceName != want.ServiceName ||
		len(got.Labels) != len(want.Labels) {
		t.Errorf("readState round-trip = %+v, want %+v", got, want)
	}
}

// TestReadState_NonNotExistReadError exercises the branch where os.ReadFile fails
// with an error other than os.IsNotExist. Placing a directory at the marker path
// makes ReadFile fail with EISDIR, which must surface to the caller unwrapped.
func TestReadState_NonNotExistReadError(t *testing.T) {
	workDir := t.TempDir()
	// Create a directory where the marker file is expected so os.ReadFile fails
	// with "is a directory" rather than "not found".
	if err := os.Mkdir(statePath(workDir), 0o750); err != nil {
		t.Fatalf("setup mkdir marker-as-dir: %v", err)
	}
	_, err := readState(workDir)
	if err == nil {
		t.Fatal("readState accepted a marker path that is a directory")
	}
	if os.IsNotExist(err) {
		t.Errorf("readState returned a not-exist error, want a distinct read error: %v", err)
	}
}

// TestReadState_UnmarshalError exercises the branch where the marker exists but
// contains invalid JSON; readState must wrap the parse failure.
func TestReadState_UnmarshalError(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(statePath(workDir), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("setup write corrupt marker: %v", err)
	}
	_, err := readState(workDir)
	if err == nil {
		t.Fatal("readState accepted a corrupt (non-JSON) marker")
	}
	if !strings.Contains(err.Error(), "parse runner state marker") {
		t.Errorf("error %q does not identify the parse failure", err.Error())
	}
}

// TestWriteState_MkdirAllError exercises the branch where os.MkdirAll cannot create
// the work directory because a component of the path is an existing regular file.
func TestWriteState_MkdirAllError(t *testing.T) {
	base := t.TempDir()
	// A regular file stands in for what should be a directory component, so
	// MkdirAll on a path *below* it fails with ENOTDIR.
	blocker := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup write blocker file: %v", err)
	}
	workDir := filepath.Join(blocker, "runner")
	err := writeState(workDir, runnerState{Version: "2.319.1"})
	if err == nil {
		t.Fatal("writeState accepted a work_dir whose parent is a regular file")
	}
}

// TestWriteState_WriteFileError exercises the branch where the work directory
// exists but os.WriteFile fails because the marker path is itself a directory.
func TestWriteState_WriteFileError(t *testing.T) {
	workDir := t.TempDir()
	// A directory at the marker path makes os.WriteFile fail while MkdirAll on the
	// already-existing workDir succeeds, isolating the WriteFile error branch.
	if err := os.Mkdir(statePath(workDir), 0o750); err != nil {
		t.Fatalf("setup mkdir marker-as-dir: %v", err)
	}
	err := writeState(workDir, runnerState{Version: "2.319.1"})
	if err == nil {
		t.Fatal("writeState accepted a marker path that is a directory")
	}
}

func TestAsMap_StateRollup(t *testing.T) {
	cases := []struct {
		name           string
		installed      bool
		serviceRunning bool
		wantState      string
	}{
		{"not-installed", false, false, "not-installed"},
		{"installed-stopped", true, false, "installed-stopped"},
		{"enrolled-running", true, true, "enrolled-running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &RunnerConfig{
				Installed:      tc.installed,
				ServiceRunning: tc.serviceRunning,
			}
			m := cfg.AsMap()
			got, ok := m["state"].(string)
			if !ok {
				t.Fatalf("AsMap()[\"state\"] missing or not a string, got %T", m["state"])
			}
			if got != tc.wantState {
				t.Errorf("installed=%v serviceRunning=%v: state = %q, want %q",
					tc.installed, tc.serviceRunning, got, tc.wantState)
			}
		})
	}
}
