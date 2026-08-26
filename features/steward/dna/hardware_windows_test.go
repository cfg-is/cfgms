//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"strings"
	"testing"
	"time"

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
	// Defense in depth: no DNA key may reference per-VM inventory/state/identity,
	// regardless of exact spelling (tenant-sensitive — #1950 Out of Scope).
	for k := range attrs {
		assert.Falsef(t, keyReferencesVMInventory(k),
			"no DNA key may reference per-VM inventory/state; got %q", k)
	}
}

// keyReferencesVMInventory reports whether an attribute key names per-VM
// inventory, count, or identity (which must never enter DNA).
func keyReferencesVMInventory(key string) bool {
	k := strings.ToLower(key)
	return strings.HasPrefix(k, "vm_") ||
		strings.Contains(k, "_vm_") ||
		strings.Contains(k, "vm_inventory") ||
		strings.Contains(k, "vm_count") ||
		strings.Contains(k, "vm_running") ||
		strings.Contains(k, "vm_name")
}

// TestRunCommand_StuckGrandchildDoesNotHang is the regression guard for
// Issue #3600 (mirroring exec_darwin_test.go's TestDarwinRunCmd_StuckChildDoesNotHang
// for the identical root cause, Issue #2361). It reproduces the failure mode
// directly: cmd.exe backgrounds a long-lived grandchild (ping, 60s) via
// `start /b`, which inherits the stdout pipe Go redirected for Output(), then
// cmd.exe itself exits almost immediately. The grandchild keeps the pipe's
// write end open, so without WaitDelay, Output() cannot see EOF and blocks
// for the grandchild's full lifetime regardless of context cancellation.
//
// The passed-in context has a 2-second timeout — well under both
// commandTimeout (30s) and the grandchild's 60s lifetime — so a hang here is
// unmistakable: a regression blocks for ~60s (until the grandchild exits or
// the test's own -timeout fires), while the fixed path returns within
// roughly commandWaitDelay once the timer starts.
func TestRunCommand_StuckGrandchildDoesNotHang(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_, err := runCommand(ctx, "cmd", "/c", "start /b ping -n 60 127.0.0.1 >nul & exit")
	elapsed := time.Since(start)

	require.Error(t, err, "a call whose grandchild outlives it must return an error, not silently succeed with truncated output")
	require.Less(t, elapsed, 30*time.Second,
		"runCommand must return within WaitDelay when a grandchild holds the stdout pipe open, not block on it")
}

// TestRunCommand_NormalCommandSucceeds confirms the WaitDelay fix does not
// disturb ordinary fast commands: output is returned intact with no error.
func TestRunCommand_NormalCommandSucceeds(t *testing.T) {
	out, err := runCommand(context.Background(), "cmd", "/c", "echo cfgms")
	require.NoError(t, err)
	assert.Contains(t, out, "cfgms")
}
