// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeVersionDir creates a version subdirectory under versionsDir with a
// dummy binary file of the given size, and sets the directory mod time.
func makeVersionDir(t *testing.T, versionsDir, name string, size int64, modTime time.Time) {
	t.Helper()
	dir := filepath.Join(versionsDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("makeVersionDir mkdir: %v", err)
	}
	f := filepath.Join(dir, "cfgms-steward")
	if err := os.WriteFile(f, make([]byte, size), 0o755); err != nil {
		t.Fatalf("makeVersionDir write binary: %v", err)
	}
	if err := os.Chtimes(dir, modTime, modTime); err != nil {
		t.Fatalf("makeVersionDir chtimes: %v", err)
	}
}

func TestPruneVersions_InvalidPolicy_ReturnsError(t *testing.T) {
	cases := []struct {
		name   string
		policy RetentionPolicy
	}{
		{"negative QuarantineWindow", RetentionPolicy{QuarantineWindow: -time.Second}},
		{"negative MaxVersions", RetentionPolicy{MaxVersions: -1}},
		{"negative MaxBytes", RetentionPolicy{MaxBytes: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pruneVersions(t.TempDir(), "v1", tc.policy, time.Now())
			if err == nil {
				t.Errorf("pruneVersions with %s: want error, got nil", tc.name)
			}
		})
	}
}

func TestPruneVersions_EmptyDir_NoOp(t *testing.T) {
	versionsDir := t.TempDir()
	decisions, err := pruneVersions(versionsDir, "v1", defaultRetentionPolicy(), time.Now())
	if err != nil {
		t.Fatalf("pruneVersions on empty dir: %v", err)
	}
	if len(decisions) != 0 {
		t.Errorf("got %d decisions for empty dir, want 0", len(decisions))
	}
}

func TestPruneVersions_MissingDir_NoOp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nonexistent")
	decisions, err := pruneVersions(dir, "v1", defaultRetentionPolicy(), time.Now())
	if err != nil {
		t.Fatalf("pruneVersions on missing dir: %v", err)
	}
	if len(decisions) != 0 {
		t.Errorf("got %d decisions for missing dir, want 0", len(decisions))
	}
}

func TestPruneVersions_ActiveVersion_NeverPruned(t *testing.T) {
	versionsDir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour) // well past quarantine window
	makeVersionDir(t, versionsDir, "v-active", 300*1024*1024, old)

	// Policy that would normally prune v-active (small MaxBytes, MaxVersions=0)
	policy := RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      0,
		MaxBytes:         1, // 1 byte — would prune everything except active
	}

	decisions, err := pruneVersions(versionsDir, "v-active", policy, now)
	if err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0].Action != "kept" {
		t.Errorf("active version action = %q, want kept", decisions[0].Action)
	}
	if _, err := os.Stat(filepath.Join(versionsDir, "v-active")); err != nil {
		t.Errorf("active version dir should still exist after pruning: %v", err)
	}
}

func TestPruneVersions_QuarantineWindow_ProtectsRecentVersions(t *testing.T) {
	versionsDir := t.TempDir()
	now := time.Now()
	recent := now.Add(-30 * time.Minute) // within 1h quarantine window
	old := now.Add(-2 * time.Hour)       // past quarantine window

	makeVersionDir(t, versionsDir, "v-old", 1, old)
	makeVersionDir(t, versionsDir, "v-recent", 1, recent)

	// MaxVersions=1 would prune v-old if it were a candidate, but v-recent
	// is in quarantine so only v-old is a candidate; with MaxVersions=1, v-old
	// is not over the limit (only 1 candidate).
	policy := RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      1,
		MaxBytes:         0,
	}

	decisions, err := pruneVersions(versionsDir, "v-does-not-exist", policy, now)
	if err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}

	dm := make(map[string]string)
	for _, d := range decisions {
		dm[d.Version.Name] = d.Action
	}
	if dm["v-recent"] != "kept" {
		t.Errorf("v-recent (in quarantine) action = %q, want kept", dm["v-recent"])
	}
	if dm["v-old"] != "kept" {
		t.Errorf("v-old action = %q, want kept (only 1 candidate, MaxVersions=1)", dm["v-old"])
	}
	// Both dirs must still exist
	for _, name := range []string{"v-old", "v-recent"} {
		if _, err := os.Stat(filepath.Join(versionsDir, name)); err != nil {
			t.Errorf("%s should still exist: %v", name, err)
		}
	}
}

func TestPruneVersions_MaxVersions_PrunesOldest(t *testing.T) {
	versionsDir := t.TempDir()
	now := time.Now()
	base := now.Add(-24 * time.Hour) // all past quarantine window

	// 5 versions, spread so sort order is deterministic
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("v%d", i+1)
		makeVersionDir(t, versionsDir, name, 1, base.Add(time.Duration(i)*time.Hour))
	}

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      2,
		MaxBytes:         0,
	}

	decisions, err := pruneVersions(versionsDir, "v-does-not-exist", policy, now)
	if err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}

	dm := make(map[string]string)
	for _, d := range decisions {
		dm[d.Version.Name] = d.Action
	}

	// Oldest 3 (v1, v2, v3) pruned; newest 2 (v4, v5) kept.
	for _, pruned := range []string{"v1", "v2", "v3"} {
		if dm[pruned] != "deleted" {
			t.Errorf("%s action = %q, want deleted (exceeds MaxVersions=2)", pruned, dm[pruned])
		}
		if _, err := os.Stat(filepath.Join(versionsDir, pruned)); err == nil {
			t.Errorf("%s dir should be deleted but still exists", pruned)
		}
	}
	for _, kept := range []string{"v4", "v5"} {
		if dm[kept] != "kept" {
			t.Errorf("%s action = %q, want kept", kept, dm[kept])
		}
		if _, err := os.Stat(filepath.Join(versionsDir, kept)); err != nil {
			t.Errorf("%s dir should still exist: %v", kept, err)
		}
	}
}

func TestPruneVersions_MaxBytes_PrunesOldestFirst(t *testing.T) {
	versionsDir := t.TempDir()
	now := time.Now()
	base := now.Add(-24 * time.Hour) // all past quarantine

	// 3 versions at 200 MB each = 600 MB total. MaxBytes=300 MB.
	// Delete v1 (200 MB removed → 400 MB, still > 300 MB).
	// Delete v2 (200 MB removed → 200 MB, ≤ 300 MB) → stop.
	// Result: v1 and v2 deleted, v3 kept.
	makeVersionDir(t, versionsDir, "v1", 200*1024*1024, base)
	makeVersionDir(t, versionsDir, "v2", 200*1024*1024, base.Add(time.Hour))
	makeVersionDir(t, versionsDir, "v3", 200*1024*1024, base.Add(2*time.Hour))

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      0,
		MaxBytes:         300 * 1024 * 1024,
	}

	decisions, err := pruneVersions(versionsDir, "v-does-not-exist", policy, now)
	if err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}

	dm := make(map[string]string)
	for _, d := range decisions {
		dm[d.Version.Name] = d.Action
	}

	if dm["v1"] != "deleted" {
		t.Errorf("v1 action = %q, want deleted (oldest, exceeds MaxBytes)", dm["v1"])
	}
	if dm["v2"] != "deleted" {
		t.Errorf("v2 action = %q, want deleted (total still over MaxBytes after v1)", dm["v2"])
	}
	if dm["v3"] != "kept" {
		t.Errorf("v3 action = %q, want kept (removing v3 not needed to reach MaxBytes)", dm["v3"])
	}
}

func TestPruneVersions_SubdirectoryEnumeration_FilesIgnored(t *testing.T) {
	versionsDir := t.TempDir()
	now := time.Now()
	old := now.Add(-2 * time.Hour)

	makeVersionDir(t, versionsDir, "v1", 1, old)
	// A plain file at the versions/ level must be ignored — it is not a version unit.
	if err := os.WriteFile(filepath.Join(versionsDir, "not-a-version.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write flat file: %v", err)
	}

	policy := RetentionPolicy{QuarantineWindow: time.Hour, MaxVersions: 0, MaxBytes: 0}
	decisions, err := pruneVersions(versionsDir, "v-does-not-exist", policy, now)
	if err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}

	for _, d := range decisions {
		if d.Version.Name == "not-a-version.txt" {
			t.Errorf("flat file appeared in pruneVersions decisions — must be ignored")
		}
	}
	// The flat file must still be present (not deleted by pruner).
	if _, err := os.Stat(filepath.Join(versionsDir, "not-a-version.txt")); err != nil {
		t.Errorf("flat file should still exist after prune: %v", err)
	}
}

func TestPruneVersions_ActiveVersionExemptedEvenWhenOldAndLarge(t *testing.T) {
	versionsDir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour)

	// All 4 versions are old; v2 is active.
	for i, name := range []string{"v1", "v2", "v3", "v4"} {
		makeVersionDir(t, versionsDir, name, 200*1024*1024, old.Add(time.Duration(i)*time.Hour))
	}

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      1,
		MaxBytes:         0,
	}

	decisions, err := pruneVersions(versionsDir, "v2", policy, now)
	if err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}

	dm := make(map[string]string)
	for _, d := range decisions {
		dm[d.Version.Name] = d.Action
	}

	// v2 (active) must never be pruned.
	if dm["v2"] != "kept" {
		t.Errorf("v2 (active) action = %q, want kept", dm["v2"])
	}
	// Candidates: v1, v3, v4 (v2 is active). MaxVersions=1 → keep 1, delete 2.
	// Sorted oldest-first: v1 (oldest non-active) → delete; v3 → delete; v4 → kept.
	// Note: v2 is skipped as active so the sort position for non-active is v1, v3, v4.
	deleted := 0
	for _, d := range decisions {
		if d.Action == "deleted" {
			deleted++
		}
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2 (3 non-active candidates, MaxVersions=1)", deleted)
	}
	if _, err := os.Stat(filepath.Join(versionsDir, "v2")); err != nil {
		t.Errorf("active version v2 dir must still exist: %v", err)
	}
}
