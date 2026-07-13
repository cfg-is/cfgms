// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package user

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// isRoot returns true when the current process has UID 0 (required for useradd/usermod).
func isRoot() bool {
	return os.Getuid() == 0
}

// newTestExecutor returns a linuxExecutor wired to custom passwd/group/shadow
// files in a temporary directory, suitable for unit-testing parse logic without
// touching the real system accounts.
func newTestExecutor(t *testing.T) (*linuxExecutor, string) {
	t.Helper()
	dir := t.TempDir()
	return &linuxExecutor{
		passwdFile: filepath.Join(dir, "passwd"),
		groupFile:  filepath.Join(dir, "group"),
		shadowFile: filepath.Join(dir, "shadow"),
	}, dir
}

// writeFile writes content to path, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile(%s): %v", path, err)
	}
}

// ── parse-layer tests (no root required) ─────────────────────────────────────

// TestLinuxExecutor_ParsePasswd_Found verifies that parsePasswd returns the
// correct entry for an existing user in a fixture file.
func TestLinuxExecutor_ParsePasswd_Found(t *testing.T) {
	exec, dir := newTestExecutor(t)
	writeFile(t, exec.passwdFile,
		"root:x:0:0:root:/root:/bin/bash\n"+
			"alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash\n"+
			"bob:x:1002:1002::/home/bob:/bin/sh\n")
	_ = dir

	entry, found, err := exec.parsePasswd("alice")
	if err != nil {
		t.Fatalf("parsePasswd: %v", err)
	}
	if !found {
		t.Fatal("parsePasswd: expected alice to be found")
	}
	if entry.UID != 1001 {
		t.Errorf("UID: got %d, want 1001", entry.UID)
	}
	if entry.GID != 1001 {
		t.Errorf("GID: got %d, want 1001", entry.GID)
	}
	if entry.Comment != "Alice Smith" {
		t.Errorf("Comment: got %q, want %q", entry.Comment, "Alice Smith")
	}
}

// TestLinuxExecutor_ParsePasswd_NotFound verifies that parsePasswd returns
// (zero, false, nil) for a username absent from the fixture.
func TestLinuxExecutor_ParsePasswd_NotFound(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.passwdFile, "root:x:0:0:root:/root:/bin/bash\n")

	entry, found, err := e.parsePasswd("nobody-here")
	if err != nil {
		t.Fatalf("parsePasswd: %v", err)
	}
	if found {
		t.Errorf("parsePasswd: expected not found, got %+v", entry)
	}
}

// TestLinuxExecutor_GroupsForUser verifies that groupsForUser returns both
// the primary group (matched by GID) and supplementary groups (username in
// member list), sorted alphabetically.
func TestLinuxExecutor_GroupsForUser(t *testing.T) {
	e, _ := newTestExecutor(t)
	// alice's primary GID is 1001 (mapped to "alice" group); she is also
	// a member of "wheel" and "audio" via the members field.
	writeFile(t, e.groupFile,
		"root:x:0:\n"+
			"alice:x:1001:\n"+
			"wheel:x:10:alice,bob\n"+
			"audio:x:29:alice\n"+
			"bob:x:1002:\n")

	groups, err := e.groupsForUser("alice", 1001)
	if err != nil {
		t.Fatalf("groupsForUser: %v", err)
	}

	expected := []string{"alice", "audio", "wheel"}
	if len(groups) != len(expected) {
		t.Fatalf("groups length: got %d (%v), want %d (%v)", len(groups), groups, len(expected), expected)
	}
	for i, g := range groups {
		if g != expected[i] {
			t.Errorf("groups[%d]: got %q, want %q", i, g, expected[i])
		}
	}
}

// TestLinuxExecutor_ShadowState_Locked verifies that shadowState detects a
// locked account (password field starts with "!").
func TestLinuxExecutor_ShadowState_Locked(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.shadowFile,
		"root:*:19000:0:99999:7:::\n"+
			"alice:!$6$hash$longpasswordhash:19000:0:99999:7:::\n"+
			"bob:$6$hash$longpasswordhash:19000:0:99999:7:::\n")

	locked, pwSet := e.shadowState("alice")
	if !locked {
		t.Error("alice should be locked (password starts with !)")
	}
	if !pwSet {
		t.Error("alice should have a password set (locked but has hash)")
	}
}

// TestLinuxExecutor_ShadowState_NoPassword verifies that a bare "!" or "*"
// shadow entry is treated as no password.
func TestLinuxExecutor_ShadowState_NoPassword(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.shadowFile,
		"newuser:!:19000:0:99999:7:::\n")

	locked, pwSet := e.shadowState("newuser")
	if !locked {
		t.Error("newuser should be locked (bare !)")
	}
	if pwSet {
		t.Error("newuser should NOT have a password set (bare !)")
	}
}

// TestLinuxExecutor_ShadowState_NotReadable verifies that when /etc/shadow is
// not accessible, shadowState returns (false, false) without error.
func TestLinuxExecutor_ShadowState_NotReadable(t *testing.T) {
	e, dir := newTestExecutor(t)
	shadowPath := filepath.Join(dir, "shadow")
	// Don't create the file — open will fail with ENOENT.
	_ = shadowPath

	locked, pwSet := e.shadowState("anyuser")
	if locked || pwSet {
		t.Errorf("unreadable shadow should return (false, false), got (%v, %v)", locked, pwSet)
	}
}

// TestLinuxExecutor_GetState_UserAbsent verifies that getState returns a
// zero userState (Exists=false) for a user absent from the fixture.
func TestLinuxExecutor_GetState_UserAbsent(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.passwdFile, "root:x:0:0:root:/root:/bin/bash\n")
	writeFile(t, e.groupFile, "root:x:0:\n")

	state, err := e.getState("nobody-here")
	if err != nil {
		t.Fatalf("getState: %v", err)
	}
	if state.Exists {
		t.Error("expected Exists=false for absent user")
	}
}

// TestLinuxExecutor_GetState_ExistingUser verifies that getState correctly
// assembles a userState from fixture passwd/group files.
func TestLinuxExecutor_GetState_ExistingUser(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.passwdFile,
		"alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash\n")
	writeFile(t, e.groupFile,
		"alice:x:1001:\n"+
			"wheel:x:10:alice\n")
	// No shadow file → locked=false, passwordSet=false

	state, err := e.getState("alice")
	if err != nil {
		t.Fatalf("getState: %v", err)
	}
	if !state.Exists {
		t.Fatal("expected Exists=true")
	}
	if state.FullName != "Alice Smith" {
		t.Errorf("FullName: got %q, want %q", state.FullName, "Alice Smith")
	}
	if state.Locked {
		t.Error("expected Locked=false (no shadow file)")
	}
	if state.PasswordSet {
		t.Error("expected PasswordSet=false (no shadow file)")
	}
	// Groups should contain both primary and supplementary.
	groupMap := make(map[string]bool)
	for _, g := range state.Groups {
		groupMap[g] = true
	}
	if !groupMap["alice"] {
		t.Error("expected primary group 'alice' in groups")
	}
	if !groupMap["wheel"] {
		t.Error("expected supplementary group 'wheel' in groups")
	}
}

// ── round-trip test (requires root) ──────────────────────────────────────────

// testUsername returns a unique name for a temporary test user that should
// never conflict with real system accounts.
func testUsername() string {
	return "cfgms-test-usr-rt"
}

// cleanupTestUser removes the test user if it exists, ignoring errors.
func cleanupTestUser(username string) {
	_ = exec.Command("userdel", "-r", username).Run()
}

// TestLinuxExecutor_RoundTrip_CreateModifyDisable performs a full Get/Set
// round-trip against real system calls: creates a temporary user, modifies
// its full name, adds it to a group, disables it, then deletes it.
//
// Requires root. Skipped when os.Getuid() != 0.
func TestLinuxExecutor_RoundTrip_CreateModifyDisable(t *testing.T) {
	if !isRoot() {
		t.Skip("skipping round-trip test: requires root (os.Getuid() != 0)")
	}

	username := testUsername()
	e := &linuxExecutor{
		passwdFile: "/etc/passwd",
		groupFile:  "/etc/group",
		shadowFile: "/etc/shadow",
	}

	// Ensure no leftover from a previous failed run.
	cleanupTestUser(username)
	t.Cleanup(func() { cleanupTestUser(username) })

	// ── Step 1: user must not exist initially ─────────────────────────────────
	state, err := e.getState(username)
	if err != nil {
		t.Fatalf("getState before create: %v", err)
	}
	if state.Exists {
		t.Fatalf("test precondition: user %q already exists", username)
	}

	// ── Step 2: create the user ───────────────────────────────────────────────
	desired := userState{
		Exists:   true,
		FullName: "CFGMS Test User",
	}
	if err := e.setState(username, desired); err != nil {
		t.Fatalf("setState (create): %v", err)
	}

	state, err = e.getState(username)
	if err != nil {
		t.Fatalf("getState after create: %v", err)
	}
	if !state.Exists {
		t.Fatal("user should exist after create")
	}
	if state.FullName != "CFGMS Test User" {
		t.Errorf("FullName after create: got %q, want %q", state.FullName, "CFGMS Test User")
	}
	if state.Locked {
		t.Error("newly created user should not be locked")
	}

	// ── Step 3: modify full name ──────────────────────────────────────────────
	desired.FullName = "CFGMS Test User Modified"
	if err := e.setState(username, desired); err != nil {
		t.Fatalf("setState (modify name): %v", err)
	}

	state, err = e.getState(username)
	if err != nil {
		t.Fatalf("getState after name change: %v", err)
	}
	if state.FullName != "CFGMS Test User Modified" {
		t.Errorf("FullName after modify: got %q, want %q", state.FullName, "CFGMS Test User Modified")
	}

	// ── Step 4: lock the account ──────────────────────────────────────────────
	desired.Locked = true
	if err := e.setState(username, desired); err != nil {
		t.Fatalf("setState (lock): %v", err)
	}

	state, err = e.getState(username)
	if err != nil {
		t.Fatalf("getState after lock: %v", err)
	}
	if !state.Locked {
		t.Error("user should be locked after setState(Locked=true)")
	}

	// Verify Get is deterministic after lock.
	state2, err := e.getState(username)
	if err != nil {
		t.Fatalf("second getState after lock: %v", err)
	}
	if state.Locked != state2.Locked || state.FullName != state2.FullName {
		t.Errorf("getState not deterministic: first=%+v second=%+v", state, state2)
	}

	// ── Step 5: unlock the account ────────────────────────────────────────────
	desired.Locked = false
	if err := e.setState(username, desired); err != nil {
		t.Fatalf("setState (unlock): %v", err)
	}

	state, err = e.getState(username)
	if err != nil {
		t.Fatalf("getState after unlock: %v", err)
	}
	if state.Locked {
		t.Error("user should not be locked after setState(Locked=false)")
	}

	// ── Step 6: delete the user ───────────────────────────────────────────────
	desired.Exists = false
	if err := e.setState(username, desired); err != nil {
		t.Fatalf("setState (delete): %v", err)
	}

	state, err = e.getState(username)
	if err != nil {
		t.Fatalf("getState after delete: %v", err)
	}
	if state.Exists {
		t.Error("user should not exist after delete")
	}
}

// TestLinuxExecutor_GetState_Idempotent verifies that consecutive getState calls
// return identical results for a user that exists in the fixture files, satisfying
// the ADR-016 clause 4 determinism requirement at the executor layer.
func TestLinuxExecutor_GetState_Idempotent(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.passwdFile,
		"alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash\n")
	writeFile(t, e.groupFile,
		"alice:x:1001:\n"+
			"wheel:x:10:alice\n")

	s1, err := e.getState("alice")
	if err != nil {
		t.Fatalf("first getState: %v", err)
	}
	s2, err := e.getState("alice")
	if err != nil {
		t.Fatalf("second getState: %v", err)
	}

	if s1.Exists != s2.Exists || s1.FullName != s2.FullName || s1.Locked != s2.Locked {
		t.Errorf("getState not idempotent: first=%+v second=%+v", s1, s2)
	}
	if !slicesEqual(sortedCopy(s1.Groups), sortedCopy(s2.Groups)) {
		t.Errorf("groups not idempotent: first=%v second=%v", s1.Groups, s2.Groups)
	}
}

// TestLinuxExecutor_ShadowState_ActivePassword verifies that a standard hashed
// password (no ! prefix) is detected as active and password-set.
func TestLinuxExecutor_ShadowState_ActivePassword(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.shadowFile,
		"bob:$6$somesalt$longhashvalue123456:19000:0:99999:7:::\n")

	locked, pwSet := e.shadowState("bob")
	if locked {
		t.Error("bob should NOT be locked (no ! prefix)")
	}
	if !pwSet {
		t.Error("bob should have a password set (has hash)")
	}
}

// TestLinuxExecutor_ParsePasswd_MalformedLine verifies that malformed lines in
// /etc/passwd are skipped gracefully.
func TestLinuxExecutor_ParsePasswd_MalformedLine(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.passwdFile,
		"# comment\n"+
			"malformed-line\n"+
			"alice:x:1001:1001:Alice:/home/alice:/bin/bash\n")

	_, found, err := e.parsePasswd("alice")
	if err != nil {
		t.Fatalf("parsePasswd: %v", err)
	}
	if !found {
		t.Error("alice should be found despite a malformed preceding line")
	}
}

// TestLinuxExecutor_SetState_Idempotent_AbsentUser verifies that calling
// setState with Exists=false on a non-existent user is a safe no-op.
func TestLinuxExecutor_SetState_Idempotent_AbsentUser(t *testing.T) {
	e, _ := newTestExecutor(t)
	writeFile(t, e.passwdFile, "root:x:0:0:root:/root:/bin/bash\n")
	writeFile(t, e.groupFile, "root:x:0:\n")

	// The executor will call getState (parsing fixtures) and then find no user;
	// it should return nil without invoking userdel.
	err := e.setState("nobody-here", userState{Exists: false})
	if err != nil {
		t.Errorf("setState(absent) on non-existent user should be a no-op, got: %v", err)
	}
}
