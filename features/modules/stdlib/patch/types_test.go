// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

func TestConfig_Validate_MaintenanceWindowRejected(t *testing.T) {
	t.Run("maintenance.window is rejected", func(t *testing.T) {
		cfg := &Config{
			PatchType: "security",
			Maintenance: struct {
				Window   string        `yaml:"window"`
				Schedule string        `yaml:"schedule"`
				Duration time.Duration `yaml:"duration"`
				Timezone string        `yaml:"timezone"`
			}{
				Window: "sunday_3am",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMaintenanceWindowUnsupported)
		assert.NotErrorIs(t, err, ErrMaintenanceWindowNotActive,
			"must not be misreported as 'outside the window'")
	})

	t.Run("maintenance.schedule is rejected", func(t *testing.T) {
		cfg := &Config{
			PatchType: "security",
			Maintenance: struct {
				Window   string        `yaml:"window"`
				Schedule string        `yaml:"schedule"`
				Duration time.Duration `yaml:"duration"`
				Timezone string        `yaml:"timezone"`
			}{
				Schedule: "0 3 * * 0",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMaintenanceWindowUnsupported)
		assert.NotErrorIs(t, err, ErrMaintenanceWindowNotActive,
			"must not be misreported as 'outside the window'")
	})

	t.Run("both window and schedule rejected", func(t *testing.T) {
		cfg := &Config{
			PatchType: "security",
			Maintenance: struct {
				Window   string        `yaml:"window"`
				Schedule string        `yaml:"schedule"`
				Duration time.Duration `yaml:"duration"`
				Timezone string        `yaml:"timezone"`
			}{
				Window:   "sunday_3am",
				Schedule: "0 3 * * 0",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMaintenanceWindowUnsupported)
	})

	t.Run("no maintenance fields passes validation", func(t *testing.T) {
		cfg := &Config{
			PatchType:  "security",
			AutoReboot: false,
		}
		err := cfg.Validate()
		assert.NoError(t, err, "common case with no maintenance fields must not regress")
	})
}

func TestConfig_Validate_InvalidPatchID(t *testing.T) {
	badIDs := []struct {
		name  string
		patch string
	}{
		{"empty string", ""},
		{"contains space", "KB 123456"},
		{"contains semicolon", "KB123;DROP"},
		{"contains pipe", "KB123|evil"},
		{"contains newline", "KB123\n456"},
	}
	for _, tc := range badIDs {
		t.Run("include_patches/"+tc.name, func(t *testing.T) {
			cfg := &Config{
				PatchType:      "security",
				IncludePatches: []string{tc.patch},
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidPatchID)
		})
		t.Run("exclude_patches/"+tc.name, func(t *testing.T) {
			cfg := &Config{
				PatchType:      "security",
				ExcludePatches: []string{tc.patch},
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidPatchID)
		})
	}
}

// TestConfig_Validate_ContractHook verifies that ErrMaintenanceWindowUnsupported
// surfaces through the ConfigState.Validate() method defined by the module contract
// (features/modules/module.go:60), so a declared window is refused at cfg-apply
// time rather than being discovered at reboot time.
func TestConfig_Validate_ContractHook(t *testing.T) {
	var state modules.ConfigState = &Config{
		PatchType: "security",
		Maintenance: struct {
			Window   string        `yaml:"window"`
			Schedule string        `yaml:"schedule"`
			Duration time.Duration `yaml:"duration"`
			Timezone string        `yaml:"timezone"`
		}{
			Window: "daily_2am",
		},
	}

	err := state.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMaintenanceWindowUnsupported),
		"ErrMaintenanceWindowUnsupported must be reachable via the ConfigState contract")
}
