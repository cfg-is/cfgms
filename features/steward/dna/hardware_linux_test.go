//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLinuxVirtualizationCollector runs the real Linux motherboard collector and
// asserts the shape of the virtualization guest/host attributes added by #1950.
// Values are host-dependent (bare metal vs guest), so only their shape is
// asserted. It also verifies no VM inventory / running-VM count is emitted.
func TestLinuxVirtualizationCollector(t *testing.T) {
	col := &LinuxHardwareCollector{}
	attrs := make(map[string]string)
	require.NoError(t, col.CollectMotherboard(context.Background(), attrs))

	// virtualization_type must be a non-empty string (at least "none").
	vt, ok := attrs["virtualization_type"]
	require.True(t, ok, "virtualization_type must be set")
	assert.NotEmpty(t, vt, "virtualization_type must be non-empty")

	// virtualization_role must be one of the three allowed roles.
	role, ok := attrs["virtualization_role"]
	require.True(t, ok, "virtualization_role must be set")
	assert.Contains(t, []string{"guest", "host", "baremetal"}, role,
		"virtualization_role must be guest/host/baremetal, got %q", role)

	// hyperv_host must be a strict boolean.
	hh, ok := attrs["hyperv_host"]
	require.True(t, ok, "hyperv_host must be set")
	assert.Contains(t, []string{"true", "false"}, hh,
		"hyperv_host must be 'true' or 'false', got %q", hh)

	// No VM inventory / count / name attribute may ever be emitted as DNA
	// (#1950 Out of Scope — VM presence is observed via the module path).
	for _, forbidden := range []string{
		"hyperv_vm_running_count", "vm_inventory", "vm_count",
		"vm_running_count", "vm_names", "hyperv_vm_names",
	} {
		_, present := attrs[forbidden]
		assert.False(t, present, "forbidden VM-inventory key %q must not be emitted as DNA", forbidden)
	}
	// Defense in depth: no DNA key may reference per-VM inventory/state/identity,
	// regardless of exact spelling (tenant-sensitive).
	for k := range attrs {
		lk := strings.ToLower(k)
		vmRef := strings.HasPrefix(lk, "vm_") || strings.Contains(lk, "_vm_") ||
			strings.Contains(lk, "vm_inventory") || strings.Contains(lk, "vm_count") ||
			strings.Contains(lk, "vm_running") || strings.Contains(lk, "vm_name")
		assert.Falsef(t, vmRef, "no DNA key may reference per-VM inventory/state; got %q", k)
	}
}
