// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package push_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStewardConfigurationJSONRoundTrip(t *testing.T) {
	appliedAt := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	original := push.StewardConfiguration{
		ConfigID: "cfg-001",
		Version:  "1.2.3",
		TenantID: "tenant-abc",
		Policies: map[string]interface{}{
			"security": map[string]interface{}{
				"enabled": true,
				"level":   "high",
			},
		},
		Modules:   []string{"file", "directory", "script"},
		AppliedAt: appliedAt,
		Source:    "controller-east",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var result push.StewardConfiguration
	require.NoError(t, json.Unmarshal(data, &result))

	assert.Equal(t, original.ConfigID, result.ConfigID)
	assert.Equal(t, original.Version, result.Version)
	assert.Equal(t, original.TenantID, result.TenantID)
	assert.Equal(t, original.Modules, result.Modules)
	assert.True(t, original.AppliedAt.Equal(result.AppliedAt))
	assert.Equal(t, original.Source, result.Source)
	// Verify full Policies map round-trips, not just a single nested key.
	require.NotNil(t, result.Policies)
	security, ok := result.Policies["security"].(map[string]interface{})
	require.True(t, ok, "policies.security must be a map")
	assert.Equal(t, true, security["enabled"])
	assert.Equal(t, "high", security["level"])
}

func TestStewardConfigurationZeroValue(t *testing.T) {
	var cfg push.StewardConfiguration

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var result push.StewardConfiguration
	require.NoError(t, json.Unmarshal(data, &result))

	assert.Empty(t, result.ConfigID)
	assert.Empty(t, result.Version)
	assert.Empty(t, result.TenantID)
	assert.Nil(t, result.Policies)
	assert.Nil(t, result.Modules)
	assert.True(t, result.AppliedAt.IsZero())
	assert.Empty(t, result.Source)
}
