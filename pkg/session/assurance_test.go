// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

import (
	"testing"
)

// TestAssuranceLevel_Constants verifies the numeric values match ADR-021 Decision 1.
// These values are load-bearing (used in < comparisons) so a regression here would
// silently flip the enforcement direction.
func TestAssuranceLevel_Constants(t *testing.T) {
	if AssuranceMachine != 0 {
		t.Errorf("AssuranceMachine = %d, want 0 (ADR-021 Decision 1)", AssuranceMachine)
	}
	if AssuranceBasic != 1 {
		t.Errorf("AssuranceBasic = %d, want 1 (ADR-021 Decision 1)", AssuranceBasic)
	}
	if AssuranceStrong != 2 {
		t.Errorf("AssuranceStrong = %d, want 2 (ADR-021 Decision 1)", AssuranceStrong)
	}
}

// TestAssuranceLevel_Ordering verifies the natural ordering required by enforcement
// (Machine < Basic < Strong).
func TestAssuranceLevel_Ordering(t *testing.T) {
	if AssuranceMachine >= AssuranceBasic {
		t.Error("AssuranceMachine must be less than AssuranceBasic")
	}
	if AssuranceBasic >= AssuranceStrong {
		t.Error("AssuranceBasic must be less than AssuranceStrong")
	}
	if AssuranceMachine >= AssuranceStrong {
		t.Error("AssuranceMachine must be less than AssuranceStrong")
	}
}

// TestAssuranceLevel_String verifies the level-name strings used in WWW-Authenticate
// responses (ADR-021 Decision 6).
func TestAssuranceLevel_String(t *testing.T) {
	cases := []struct {
		level AssuranceLevel
		want  string
	}{
		{AssuranceMachine, "machine"},
		{AssuranceBasic, "basic"},
		{AssuranceStrong, "strong"},
		{AssuranceLevel(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.level.String(); got != tc.want {
			t.Errorf("AssuranceLevel(%d).String() = %q, want %q", tc.level, got, tc.want)
		}
	}
}
