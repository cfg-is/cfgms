// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cert_trust

import (
	"strings"
	"testing"
)

// TestParseCertutilDate verifies parseCertutilDate produces RFC3339 output for
// common certutil date formats and returns empty string for unrecognized input.
func TestParseCertutilDate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// wantPrefix is checked when wantRFC3339 is empty (non-empty result expected).
		wantRFC3339 string
		wantEmpty   bool
	}{
		{
			name:        "en-US 12h AM midnight",
			input:       "1/15/2035 12:00 AM",
			wantRFC3339: "2035-01-15T00:00:00Z",
		},
		{
			name:        "en-US 12h PM",
			input:       "5/9/2021 11:28 PM",
			wantRFC3339: "2021-05-09T23:28:00Z",
		},
		{
			name:        "en-US 12h with leading spaces",
			input:       "  1/1/2035 12:00 AM  ",
			wantRFC3339: "2035-01-01T00:00:00Z",
		},
		{
			name:        "en-US 24h format",
			input:       "1/15/2035 23:59",
			wantRFC3339: "2035-01-15T23:59:00Z",
		},
		{
			name:        "European day-first 24h",
			input:       "15/1/2035 23:59",
			wantRFC3339: "2035-01-15T23:59:00Z",
		},
		{
			name:      "unknown locale format returns empty",
			input:     "January 15, 2035",
			wantEmpty: true,
		},
		{
			name:      "empty string returns empty",
			input:     "",
			wantEmpty: true,
		},
		{
			name:      "garbage returns empty",
			input:     "not a date",
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCertutilDate(tt.input)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("parseCertutilDate(%q) = %q, want empty string", tt.input, got)
				}
				return
			}
			if got != tt.wantRFC3339 {
				t.Errorf("parseCertutilDate(%q) = %q, want %q", tt.input, got, tt.wantRFC3339)
			}
			// Verify output is valid RFC3339.
			if !strings.HasSuffix(got, "Z") && !strings.Contains(got, "+") && !strings.Contains(got, "-0") {
				t.Errorf("parseCertutilDate(%q) = %q: does not look like RFC3339", tt.input, got)
			}
		})
	}
}

// TestParseCertutilDate_RFC3339Output verifies the output format of
// parseCertutilDate always ends in Z (UTC) so callers can rely on it.
func TestParseCertutilDate_RFC3339Output(t *testing.T) {
	validInputs := []string{
		"1/15/2035 12:00 AM",
		"5/9/2021 11:28 PM",
		"12/31/2035 11:59 PM",
	}
	for _, input := range validInputs {
		got := parseCertutilDate(input)
		if got == "" {
			t.Errorf("parseCertutilDate(%q) returned empty for a known-good input", input)
			continue
		}
		if !strings.HasSuffix(got, "Z") {
			t.Errorf("parseCertutilDate(%q) = %q: want UTC suffix 'Z' (RFC3339)", input, got)
		}
	}
}
