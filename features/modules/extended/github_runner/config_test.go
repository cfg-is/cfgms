// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"strings"
	"testing"
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
