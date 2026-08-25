// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import "testing"

// TestStewardIDPattern_MatchesLegacyAndCurrentFormats guards the regex used by
// DockerComposeHelper.StewardID against the ID-format change from Issue #3526:
// generateStewardID (features/controller/api/handlers_registration.go) now
// appends "-<hex>" (8 crypto/rand bytes) to the timestamp. The pattern must
// still accept the pre-#3526 steward-<nanos> shape recorded by any steward
// that registered against an older controller build, and must not match
// unrelated JSON fields.
func TestStewardIDPattern_MatchesLegacyAndCurrentFormats(t *testing.T) {
	tests := []struct {
		name    string
		logLine string
		want    string
		matches bool
	}{
		{
			name:    "current format: nanos-hex",
			logLine: `{"level":"info","steward_id":"steward-1735689600123456789-a1b2c3d4e5f6a7b8","msg":"registered"}`,
			want:    "steward-1735689600123456789-a1b2c3d4e5f6a7b8",
			matches: true,
		},
		{
			name:    "legacy format: nanos only",
			logLine: `{"level":"info","steward_id":"steward-1735689600123456789","msg":"registered"}`,
			want:    "steward-1735689600123456789",
			matches: true,
		},
		{
			name:    "unrelated field does not match",
			logLine: `{"level":"info","device_id":"steward-east-1","msg":"connecting"}`,
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := stewardIDPattern.FindStringSubmatch(tt.logLine)
			if !tt.matches {
				if match != nil {
					t.Fatalf("expected no match, got %q", match[1])
				}
				return
			}
			if match == nil {
				t.Fatalf("expected match %q, got none", tt.want)
			}
			if match[1] != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, match[1])
			}
		})
	}
}
