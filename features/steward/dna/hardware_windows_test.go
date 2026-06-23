//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWindowsHyperVCollector runs the real Windows motherboard collector and
// asserts the shape of the Hyper-V host-capability and guest-detection
// attributes added by #1950. Values are host-dependent, so only their shape is
// asserted. Crucially it verifies that NO VM inventory / running-VM count / VM
// name attribute is emitted (those belong to the module Get()/Monitor path, not
// DNA).
func TestWindowsHyperVCollector(t *testing.T) {
	col := &WindowsHardwareCollector{}
	attrs := make(map[string]string)
	require.NoError(t, col.CollectMotherboard(context.Background(), attrs))

	// hyperv_role_installed is read from the registry (no elevation) and must
	// always be present as a strict boolean.
	role, ok := attrs["hyperv_role_installed"]
	require.True(t, ok, "hyperv_role_installed must be set")
	assert.Contains(t, []string{"true", "false"}, role,
		"hyperv_role_installed must be 'true' or 'false', got %q", role)

	// hyperv_enabled requires elevation (DISM). It is set when queryable and
	// omitted (not stubbed) otherwise — but when present it must be a strict
	// boolean.
	if enabled, ok := attrs["hyperv_enabled"]; ok {
		assert.Contains(t, []string{"true", "false"}, enabled,
			"hyperv_enabled, when present, must be 'true' or 'false', got %q", enabled)
	}

	// virtualization_type must be a non-empty string.
	vt, ok := attrs["virtualization_type"]
	require.True(t, ok, "virtualization_type must be set")
	assert.NotEmpty(t, vt, "virtualization_type must be non-empty")

	// virtualization_role must be one of the three allowed roles.
	role2, ok := attrs["virtualization_role"]
	require.True(t, ok, "virtualization_role must be set")
	assert.Contains(t, []string{"guest", "host", "baremetal"}, role2,
		"virtualization_role must be guest/host/baremetal, got %q", role2)

	// No VM inventory / count / name attribute may ever be emitted as DNA.
	assertNoVMInventoryKeys(t, attrs)
}

// assertNoVMInventoryKeys verifies that none of the forbidden VM-inventory /
// volatile-runtime keys are present (#1950 Out of Scope).
func assertNoVMInventoryKeys(t *testing.T, attrs map[string]string) {
	t.Helper()
	for _, forbidden := range []string{
		"hyperv_vm_running_count",
		"vm_inventory",
		"vm_count",
		"vm_running_count",
		"vm_names",
		"hyperv_vm_names",
	} {
		_, present := attrs[forbidden]
		assert.False(t, present, "forbidden VM-inventory key %q must not be emitted as DNA", forbidden)
	}
}
