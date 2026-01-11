// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidatePermissions tests the permission validation function
func TestValidatePermissions(t *testing.T) {
	tests := []struct {
		name        string
		perms       interface{}
		expectError bool
	}{
		{
			name:        "valid 644",
			perms:       0644,
			expectError: false,
		},
		{
			name:        "valid 755",
			perms:       0755,
			expectError: false,
		},
		{
			name:        "valid 600",
			perms:       0600,
			expectError: false,
		},
		{
			name:        "valid 777",
			perms:       0777,
			expectError: false,
		},
		{
			name:        "valid 000",
			perms:       0,
			expectError: false,
		},
		{
			name:        "invalid 999999",
			perms:       999999,
			expectError: true,
		},
		{
			name:        "invalid negative",
			perms:       -1,
			expectError: true,
		},
		{
			name:        "invalid 1000 (out of octal range)",
			perms:       01000,
			expectError: true,
		},
		{
			name:        "valid int64",
			perms:       int64(0755),
			expectError: false,
		},
		{
			name:        "valid float64 (from YAML)",
			perms:       float64(0644),
			expectError: false,
		},
		{
			name:        "invalid type string",
			perms:       "644",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePermissions(tt.perms)
			if tt.expectError {
				assert.Error(t, err, "Expected error for permissions: %v", tt.perms)
			} else {
				assert.NoError(t, err, "Expected no error for permissions: %v", tt.perms)
			}
		})
	}
}
