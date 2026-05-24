// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"testing"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/stretchr/testify/assert"
)

// TestApplyDriftModeDefault verifies the production defaulting function:
// an empty DriftMode (returned by FromProto when the proto does not carry
// drift_mode) becomes DriftModeApply; explicit modes pass through unchanged.
func TestApplyDriftModeDefault(t *testing.T) {
	cases := []struct {
		name  string
		input stewardconfig.DriftMode
		want  stewardconfig.DriftMode
	}{
		{
			name:  "empty_defaults_to_apply",
			input: "",
			want:  stewardconfig.DriftModeApply,
		},
		{
			name:  "explicit_apply_unchanged",
			input: stewardconfig.DriftModeApply,
			want:  stewardconfig.DriftModeApply,
		},
		{
			name:  "explicit_monitor_unchanged",
			input: stewardconfig.DriftModeMonitor,
			want:  stewardconfig.DriftModeMonitor,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyDriftModeDefault(tc.input)
			assert.Equal(t, tc.want, got,
				"applyDriftModeDefault(%q) must return %q", tc.input, tc.want)
		})
	}
}
