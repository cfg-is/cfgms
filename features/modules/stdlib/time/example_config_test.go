// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package timemodule

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestExampleTimeSyncConfig_Validates loads the shipped time-sync role config
// and checks its time resource against TimeConfig.
func TestExampleTimeSyncConfig_Validates(t *testing.T) {
	data, err := os.ReadFile("../../../../docs/examples/role-configs/time-sync.cfg")
	require.NoError(t, err)

	var doc struct {
		Resources []struct {
			Name   string    `yaml:"name"`
			Module string    `yaml:"module"`
			Config yaml.Node `yaml:"config"`
		} `yaml:"resources"`
	}
	require.NoError(t, yaml.Unmarshal(data, &doc))

	found := false
	for _, r := range doc.Resources {
		if r.Module != "time" {
			continue
		}
		found = true
		raw, err := yaml.Marshal(&r.Config)
		require.NoError(t, err)

		var cfg TimeConfig
		require.NoError(t, cfg.FromYAML(raw))
		require.NoError(t, cfg.Validate())
		require.True(t, cfg.NTPSyncEnabled)
		require.NotEmpty(t, cfg.NTPServers)
		// The shipped example must not opt in to any Windows-only behaviour:
		// reliable is never implied, and the new fields stay at their defaults.
		require.Equal(t, "manual", cfg.AsMap()["ntp_source"])
		require.Equal(t, false, cfg.AsMap()["ntp_reliable"])
		require.Equal(t, "", cfg.AsMap()["hyperv_host_time_provider"])
	}
	require.True(t, found, "no resource with module \"time\" in example")
}
