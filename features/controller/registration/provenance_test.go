// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProvenanceMatcher_FuzzyMatch(t *testing.T) {
	tests := []struct {
		name        string
		storedJSON  string
		incoming    map[string]string
		wantScore   float64
		wantMatched int
		wantTotal   int
	}{
		{
			name:       "empty stored JSON returns zero result",
			storedJSON: "",
			incoming:   map[string]string{"hostname": "host1"},
			wantScore:  0, wantMatched: 0, wantTotal: 0,
		},
		{
			name:       "invalid stored JSON returns zero result",
			storedJSON: "not-json",
			incoming:   map[string]string{"hostname": "host1"},
			wantScore:  0, wantMatched: 0, wantTotal: 0,
		},
		{
			name:       "all three stable fields match",
			storedJSON: `{"hostname":"host1","mac_address":"aa:bb:cc:dd:ee:ff","bios_uuid":"uuid-1"}`,
			incoming:   map[string]string{"hostname": "host1", "mac_address": "aa:bb:cc:dd:ee:ff", "bios_uuid": "uuid-1"},
			wantScore:  1.0, wantMatched: 3, wantTotal: 3,
		},
		{
			name:       "no fields match",
			storedJSON: `{"hostname":"host1","mac_address":"aa:bb:cc:dd:ee:ff"}`,
			incoming:   map[string]string{"hostname": "other", "mac_address": "11:22:33:44:55:66"},
			wantScore:  0.0, wantMatched: 0, wantTotal: 2,
		},
		{
			name:       "60% boundary — 3 of 5 fields match",
			storedJSON: `{"hostname":"h1","mac_address":"aa","bios_uuid":"u1","cpu_serial":"c1","machine_id":"m1"}`,
			incoming: map[string]string{
				"hostname":    "h1",
				"mac_address": "aa",
				"bios_uuid":   "u1",
				"cpu_serial":  "DIFFERENT",
				"machine_id":  "DIFFERENT",
			},
			wantScore: 0.6, wantMatched: 3, wantTotal: 5,
		},
		{
			name:       "DNA fields excluded from scoring",
			storedJSON: `{"hostname":"host1","os_version":"5.15","kernel_version":"5.15.0"}`,
			incoming:   map[string]string{"hostname": "host1", "os_version": "CHANGED", "kernel_version": "CHANGED"},
			wantScore:  1.0, wantMatched: 1, wantTotal: 1,
		},
		{
			name:       "stored has only DNA fields — zero result",
			storedJSON: `{"os_version":"5.15","kernel_version":"5.15.0"}`,
			incoming:   map[string]string{"os_version": "5.15"},
			wantScore:  0, wantMatched: 0, wantTotal: 0,
		},
		{
			name:       "extra incoming fields ignored",
			storedJSON: `{"hostname":"host1"}`,
			incoming:   map[string]string{"hostname": "host1", "extra_field": "value"},
			wantScore:  1.0, wantMatched: 1, wantTotal: 1,
		},
		{
			name:       "stored field absent in incoming counts as mismatch",
			storedJSON: `{"hostname":"host1","mac_address":"aa:bb"}`,
			incoming:   map[string]string{"hostname": "host1"},
			wantScore:  0.5, wantMatched: 1, wantTotal: 2,
		},
		{
			name:       "empty incoming map — all stored fields are unmatched",
			storedJSON: `{"hostname":"host1","mac_address":"aa:bb"}`,
			incoming:   map[string]string{},
			wantScore:  0.0, wantMatched: 0, wantTotal: 2,
		},
	}

	pm := ProvenanceMatcher{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := pm.FuzzyMatch(tc.storedJSON, tc.incoming)
			assert.InDelta(t, tc.wantScore, result.Score, 0.001, "score")
			assert.Equal(t, tc.wantMatched, result.MatchedFields, "matched fields")
			assert.Equal(t, tc.wantTotal, result.TotalFields, "total fields")
		})
	}
}
