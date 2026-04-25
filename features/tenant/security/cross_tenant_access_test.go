// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsTimeInRange covers the HH:MM-HH:MM 24-hour time-range predicate.
func TestIsTimeInRange(t *testing.T) {
	v := NewCrossTenantAccessValidator()

	tests := []struct {
		name        string
		currentTime string
		timeRange   string
		wantInRange bool
		wantErr     bool
	}{
		// Normal (same-day) ranges
		{
			name:        "inside normal range",
			currentTime: "12:00",
			timeRange:   "09:00-17:00",
			wantInRange: true,
		},
		{
			name:        "at start boundary of normal range",
			currentTime: "09:00",
			timeRange:   "09:00-17:00",
			wantInRange: true,
		},
		{
			name:        "at end boundary of normal range",
			currentTime: "17:00",
			timeRange:   "09:00-17:00",
			wantInRange: true,
		},
		{
			name:        "before start of normal range",
			currentTime: "08:59",
			timeRange:   "09:00-17:00",
			wantInRange: false,
		},
		{
			name:        "after end of normal range",
			currentTime: "17:01",
			timeRange:   "09:00-17:00",
			wantInRange: false,
		},
		// Overnight (cross-midnight) ranges
		{
			name:        "inside overnight range - evening side",
			currentTime: "23:00",
			timeRange:   "22:00-06:00",
			wantInRange: true,
		},
		{
			name:        "inside overnight range - morning side",
			currentTime: "03:00",
			timeRange:   "22:00-06:00",
			wantInRange: true,
		},
		{
			name:        "at start boundary of overnight range",
			currentTime: "22:00",
			timeRange:   "22:00-06:00",
			wantInRange: true,
		},
		{
			name:        "at end boundary of overnight range",
			currentTime: "06:00",
			timeRange:   "22:00-06:00",
			wantInRange: true,
		},
		{
			name:        "outside overnight range - midday",
			currentTime: "12:00",
			timeRange:   "22:00-06:00",
			wantInRange: false,
		},
		{
			name:        "outside overnight range - just before start",
			currentTime: "21:59",
			timeRange:   "22:00-06:00",
			wantInRange: false,
		},
		{
			name:        "outside overnight range - just after end",
			currentTime: "06:01",
			timeRange:   "22:00-06:00",
			wantInRange: false,
		},
		// All-day range used in integration tests
		{
			name:        "all-day range covers any time",
			currentTime: "12:00",
			timeRange:   "00:00-23:59",
			wantInRange: true,
		},
		{
			name:        "all-day range at midnight",
			currentTime: "00:00",
			timeRange:   "00:00-23:59",
			wantInRange: true,
		},
		// Malformed input
		{
			name:        "missing separator dash",
			currentTime: "12:00",
			timeRange:   "09001700",
			wantInRange: false,
			wantErr:     true,
		},
		{
			name:        "empty time range",
			currentTime: "12:00",
			timeRange:   "",
			wantInRange: false,
			wantErr:     true,
		},
		{
			name:        "invalid start hour",
			currentTime: "12:00",
			timeRange:   "25:00-17:00",
			wantInRange: false,
			wantErr:     true,
		},
		{
			name:        "invalid end hour",
			currentTime: "12:00",
			timeRange:   "09:00-99:00",
			wantInRange: false,
			wantErr:     true,
		},
		{
			name:        "invalid current time",
			currentTime: "not-a-time",
			timeRange:   "09:00-17:00",
			wantInRange: false,
			wantErr:     true,
		},
		{
			name:        "malformed start time missing colon",
			currentTime: "12:00",
			timeRange:   "0900-17:00",
			wantInRange: false,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inRange, err := v.isTimeInRange(tc.currentTime, tc.timeRange)
			if tc.wantErr {
				require.Error(t, err, "expected an error for input (%q, %q)", tc.currentTime, tc.timeRange)
				assert.False(t, inRange)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantInRange, inRange)
			}
		})
	}
}

// TestMatchResourcePattern covers filepath.Match-based glob pattern evaluation.
func TestMatchResourcePattern(t *testing.T) {
	v := NewCrossTenantAccessValidator()

	tests := []struct {
		name       string
		resourceID string
		pattern    string
		wantMatch  bool
		wantErr    bool
	}{
		// Exact matches
		{
			name:       "exact match",
			resourceID: "config/database",
			pattern:    "config/database",
			wantMatch:  true,
		},
		{
			name:       "exact match no match",
			resourceID: "config/database",
			pattern:    "config/other",
			wantMatch:  false,
		},
		// Wildcard single-level (does not cross /)
		{
			name:       "single wildcard matches one path segment",
			resourceID: "config/database",
			pattern:    "config/*",
			wantMatch:  true,
		},
		{
			name:       "single wildcard does not cross slash",
			resourceID: "config/secrets/api-key",
			pattern:    "config/*",
			wantMatch:  false,
		},
		{
			name:       "wildcard matches any single segment",
			resourceID: "status/health",
			pattern:    "status/*",
			wantMatch:  true,
		},
		{
			name:       "wildcard at root level",
			resourceID: "anything",
			pattern:    "*",
			wantMatch:  true,
		},
		{
			name:       "wildcard at root does not cross slash",
			resourceID: "config/database",
			pattern:    "*",
			wantMatch:  false,
		},
		// No match scenarios
		{
			name:       "different prefix no match",
			resourceID: "config/database",
			pattern:    "status/*",
			wantMatch:  false,
		},
		// Malformed patterns
		{
			name:       "bad pattern unclosed bracket",
			resourceID: "config/db",
			pattern:    "config/[invalid",
			wantMatch:  false,
			wantErr:    true,
		},
		// Empty pattern
		{
			name:       "empty pattern returns error",
			resourceID: "config/database",
			pattern:    "",
			wantMatch:  false,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := v.matchResourcePattern(tc.resourceID, tc.pattern)
			if tc.wantErr {
				require.Error(t, err, "expected an error for pattern %q against %q", tc.pattern, tc.resourceID)
				assert.False(t, matched)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantMatch, matched)
			}
		})
	}
}

// TestValidateAccessConditionsContains covers the "contains" operator fix.
func TestValidateAccessConditionsContains(t *testing.T) {
	v := NewCrossTenantAccessValidator()

	tests := []struct {
		name       string
		conditions []AccessCondition
		ctx        map[string]string
		wantErr    bool
	}{
		{
			name: "context value contains one configured value",
			conditions: []AccessCondition{
				{Type: "user_group", Operator: "contains", Values: []string{"admin"}},
			},
			ctx:     map[string]string{"user_group": "admin_users"},
			wantErr: false,
		},
		{
			name: "context value contains second of multiple configured values",
			conditions: []AccessCondition{
				{Type: "user_group", Operator: "contains", Values: []string{"superuser", "admin"}},
			},
			ctx:     map[string]string{"user_group": "admin_users"},
			wantErr: false,
		},
		{
			name: "context value does not contain any configured value",
			conditions: []AccessCondition{
				{Type: "user_group", Operator: "contains", Values: []string{"admin"}},
			},
			ctx:     map[string]string{"user_group": "regular_users"},
			wantErr: true,
		},
		{
			name: "context value does not contain any of multiple configured values",
			conditions: []AccessCondition{
				{Type: "user_group", Operator: "contains", Values: []string{"superuser", "power_user"}},
			},
			ctx:     map[string]string{"user_group": "regular_users"},
			wantErr: true,
		},
		{
			name: "empty values list returns error",
			conditions: []AccessCondition{
				{Type: "user_group", Operator: "contains", Values: []string{}},
			},
			ctx:     map[string]string{"user_group": "admin_users"},
			wantErr: true,
		},
		{
			name: "missing context key returns error (empty string does not match non-empty values)",
			conditions: []AccessCondition{
				{Type: "user_group", Operator: "contains", Values: []string{"admin"}},
			},
			ctx:     map[string]string{},
			wantErr: true,
		},
		{
			name: "exact substring match",
			conditions: []AccessCondition{
				{Type: "role", Operator: "contains", Values: []string{"read"}},
			},
			ctx:     map[string]string{"role": "readonly_access"},
			wantErr: false,
		},
		// Ensure other operators still work after contains fix
		{
			name: "equals operator still works",
			conditions: []AccessCondition{
				{Type: "env", Operator: "equals", Values: []string{"production"}},
			},
			ctx:     map[string]string{"env": "production"},
			wantErr: false,
		},
		{
			name: "equals operator fails mismatch",
			conditions: []AccessCondition{
				{Type: "env", Operator: "equals", Values: []string{"production"}},
			},
			ctx:     map[string]string{"env": "staging"},
			wantErr: true,
		},
		{
			name: "in operator still works",
			conditions: []AccessCondition{
				{Type: "region", Operator: "in", Values: []string{"us-east-1", "us-west-2"}},
			},
			ctx:     map[string]string{"region": "us-east-1"},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.validateAccessConditions(tc.conditions, tc.ctx)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
