// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt_quic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateContainerName tests the container name validation function
func TestValidateContainerName(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		expectError   bool
	}{
		{
			name:          "valid steward-standalone",
			containerName: "steward-standalone",
			expectError:   false,
		},
		{
			name:          "valid controller-standalone",
			containerName: "controller-standalone",
			expectError:   false,
		},
		{
			name:          "valid mqtt-broker",
			containerName: "mqtt-broker",
			expectError:   false,
		},
		{
			name:          "invalid container name",
			containerName: "malicious-container",
			expectError:   true,
		},
		{
			name:          "empty container name",
			containerName: "",
			expectError:   true,
		},
		{
			name:          "container name with injection attempt",
			containerName: "steward; rm -rf /",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContainerName(tt.containerName)
			if tt.expectError {
				assert.Error(t, err, "Expected error for container name: %s", tt.containerName)
			} else {
				assert.NoError(t, err, "Expected no error for container name: %s", tt.containerName)
			}
		})
	}
}
