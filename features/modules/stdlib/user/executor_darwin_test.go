// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package user

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// TestParseDsclRealName covers both dscl output shapes: the inline
// "RealName: value" form and the multi-line "RealName:\n value" form.
func TestParseDsclRealName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "inline form",
			in:   "RecordName: alice\nRealName: Alice Smith\nUniqueID: 501\n",
			want: "Alice Smith",
		},
		{
			name: "multi-line form",
			in:   "RecordName: alice\nRealName:\n Alice Smith\nUniqueID: 501\n",
			want: "Alice Smith",
		},
		{
			name: "multi-line form with extra indentation",
			in:   "RealName:\n    Bob O'Brien\n",
			want: "Bob O'Brien",
		},
		{
			name: "missing RealName yields empty",
			in:   "RecordName: carol\nUniqueID: 502\n",
			want: "",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
		{
			name: "inline empty value",
			in:   "RealName: \n",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDsclRealName(tt.in)
			if got != tt.want {
				t.Fatalf("parseDsclRealName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseUsedUIDs verifies extraction of allocated UIDs from
// "dscl . -list /Users UniqueID" output, skipping malformed lines.
func TestParseUsedUIDs(t *testing.T) {
	const fixture = `_mbsetupuser                                     248
daemon                                           1
nobody                                           -2
root                                             0
alice                                            501
bob                                              502
malformed-line-no-uid
extra    fields    here    503
`

	got := parseUsedUIDs(fixture)

	for _, uid := range []int{248, 1, 0, 501, 502} {
		if !got[uid] {
			t.Errorf("parseUsedUIDs: expected UID %d to be marked used", uid)
		}
	}
	// "extra fields here 503": Sscanf on the second field ("fields") fails, so
	// 503 must NOT be recorded.
	if got[503] {
		t.Error("parseUsedUIDs: UID 503 should not be recorded (second field is non-numeric)")
	}
	if got[999] {
		t.Error("parseUsedUIDs: UID 999 was never present")
	}
}

// TestFirstFreeUID verifies selection of the lowest free UID in the macOS
// regular-user range starting at 501.
func TestFirstFreeUID(t *testing.T) {
	t.Run("501 free when unused", func(t *testing.T) {
		uid, err := firstFreeUID(map[int]bool{0: true, 1: true, 248: true})
		if err != nil {
			t.Fatalf("firstFreeUID: unexpected error: %v", err)
		}
		if uid != 501 {
			t.Fatalf("firstFreeUID = %d, want 501", uid)
		}
	})

	t.Run("skips contiguous used UIDs", func(t *testing.T) {
		uid, err := firstFreeUID(map[int]bool{501: true, 502: true, 503: true})
		if err != nil {
			t.Fatalf("firstFreeUID: unexpected error: %v", err)
		}
		if uid != 504 {
			t.Fatalf("firstFreeUID = %d, want 504", uid)
		}
	})

	t.Run("exhausted range returns error", func(t *testing.T) {
		used := make(map[int]bool, 60000)
		for i := 501; i < 60000; i++ {
			used[i] = true
		}
		if _, err := firstFreeUID(used); err == nil {
			t.Fatal("firstFreeUID: expected error when range exhausted, got nil")
		}
	})
}

func TestGroupsToRemove(t *testing.T) {
	protected := map[string]bool{"staff": true, "everyone": true, "localaccounts": true}
	got := groupsToRemove([]string{"everyone", "localaccounts", "staff", "a", "b"}, []string{"a"}, protected)
	if !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("groupsToRemove = %v, want [b]", got)
	}
	if m := missingGroups([]string{"staff"}, []string{"a", "staff"}); !reflect.DeepEqual(m, []string{"a"}) {
		t.Fatalf("missingGroups = %v, want [a]", m)
	}
}

// TestSetStateRemovesUndeclaredGroups creates a user in two extra groups, then
// declares one and expects the other to be removed with protected groups kept.
// Requires root; runs on native macOS only.
func TestSetStateRemovesUndeclaredGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to manage local accounts")
	}
	e := &darwinExecutor{}
	suffix := fmt.Sprintf("%d", os.Getpid())
	user, keep, drop := "cfgmstu"+suffix, "cfgmsga"+suffix, "cfgmsgb"+suffix
	for _, g := range []string{keep, drop} {
		if out, err := exec.Command("dseditgroup", "-o", "create", g).CombinedOutput(); err != nil {
			t.Fatalf("create group %s: %v (%s)", g, err, out)
		}
		g := g
		t.Cleanup(func() { _ = exec.Command("dseditgroup", "-o", "delete", g).Run() })
	}
	t.Cleanup(func() { _ = e.setState(user, userState{}) })

	if err := e.setState(user, userState{Exists: true, Groups: []string{keep, drop}}); err != nil {
		t.Fatalf("initial setState: %v", err)
	}
	if err := e.setState(user, userState{Exists: true, Groups: []string{keep}}); err != nil {
		t.Fatalf("setState: %v", err)
	}
	st, err := e.getState(user)
	if err != nil {
		t.Fatal(err)
	}
	have := strings.Join(st.Groups, " ")
	if strings.Contains(have, drop) {
		t.Errorf("user still in %s: %s", drop, have)
	}
	for _, g := range []string{keep, "staff", "everyone", "localaccounts"} {
		if !strings.Contains(" "+have+" ", " "+g+" ") {
			t.Errorf("user missing %s: %s", g, have)
		}
	}
}
