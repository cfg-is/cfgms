// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// TestConfig_Validate_MaintenanceWindowAccepted verifies that maintenance.window
// and maintenance.schedule pass validation now that the real WindowManager
// (GateWindowAdapter) is implemented. The former ErrMaintenanceWindowUnsupported
// guard has been removed; enforcement is done at Set() time by the Gate.
func TestConfig_Validate_MaintenanceWindowAccepted(t *testing.T) {
	t.Run("maintenance.window passes validation", func(t *testing.T) {
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
		assert.NoError(t, err, "maintenance.window must now pass validation")
	})

	t.Run("maintenance.schedule passes validation", func(t *testing.T) {
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
		assert.NoError(t, err, "maintenance.schedule must now pass validation")
	})

	t.Run("both window and schedule pass validation", func(t *testing.T) {
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
		assert.NoError(t, err, "both maintenance fields together must pass validation")
	})

	t.Run("no maintenance fields passes validation", func(t *testing.T) {
		cfg := &Config{
			PatchType:  "security",
			AutoReboot: false,
		}
		err := cfg.Validate()
		assert.NoError(t, err, "config with no maintenance fields must pass validation")
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

// TestConfig_Validate_ContractHook verifies that maintenance.window passes through
// the ConfigState.Validate() method defined by the module contract
// (features/modules/module.go). Enforcement moves from validation time to
// Set()-time via the Gate (ADR-026 story 4).
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
	assert.NoError(t, err,
		"maintenance.window must pass ConfigState.Validate(); enforcement is at Set() time via the Gate")
}
