// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package-internal tests for the module-type convention (Issue #1903):
// parseModuleRef and getResourceIdentifier are unexported, so these tests live
// in package execution. They assert the bundle/type split and the typed
// resourceID construction that the steward executor performs before dispatch.
package execution

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/steward/config"
)

// TestParseModuleRef covers the bundle/resource-type split on the first dot.
func TestParseModuleRef(t *testing.T) {
	cases := []struct {
		module       string
		wantBundle   string
		wantResource string
	}{
		{"hyperv.vm", "hyperv", "vm"},
		{"hyperv.vswitch", "hyperv", "vswitch"},
		{"hyperv.snapshot", "hyperv", "snapshot"},
		{"directory", "directory", ""},
		{"file", "file", ""},
		{"", "", ""},
		// Only the FIRST dot splits — a hypothetical multi-segment type is
		// preserved intact as the resource-type component.
		{"hyperv.vm.extra", "hyperv", "vm.extra"},
	}

	for _, tc := range cases {
		t.Run(tc.module, func(t *testing.T) {
			bundle, resourceType := parseModuleRef(tc.module)
			assert.Equal(t, tc.wantBundle, bundle, "bundle component")
			assert.Equal(t, tc.wantResource, resourceType, "resource-type component")
		})
	}
}

// TestGetResourceIdentifier_TypedHyperv verifies the typed resourceID construction
// for the three hyperv shapes, including the snapshot compound special-case.
func TestGetResourceIdentifier_TypedHyperv(t *testing.T) {
	e := newTestExecutor(t, config.ErrorHandlingConfig{})

	cases := []struct {
		name     string
		resource config.ResourceConfig
		wantID   string
	}{
		{
			name: "vm builds vm:<name>",
			resource: config.ResourceConfig{
				Name:   "m2-test-vm",
				Module: "hyperv.vm",
				Config: map[string]interface{}{"memory_mb": 2048},
			},
			wantID: "vm:m2-test-vm",
		},
		{
			name: "vswitch builds vswitch:<name>",
			resource: config.ResourceConfig{
				Name:   "m2-test-vsw",
				Module: "hyperv.vswitch",
				Config: map[string]interface{}{"switch_type": "external"},
			},
			wantID: "vswitch:m2-test-vsw",
		},
		{
			name: "snapshot with vm_name builds compound snapshot:<vm>/<name>",
			resource: config.ResourceConfig{
				Name:   "nightly",
				Module: "hyperv.snapshot",
				Config: map[string]interface{}{"vm_name": "m2-test-vm", "state": "present"},
			},
			wantID: "snapshot:m2-test-vm/nightly",
		},
		{
			name: "snapshot without vm_name falls back to snapshot:<name>",
			resource: config.ResourceConfig{
				Name:   "nightly",
				Module: "hyperv.snapshot",
				Config: map[string]interface{}{"state": "present"},
			},
			wantID: "snapshot:nightly",
		},
		{
			name: "snapshot with empty vm_name falls back to snapshot:<name>",
			resource: config.ResourceConfig{
				Name:   "nightly",
				Module: "hyperv.snapshot",
				Config: map[string]interface{}{"vm_name": "", "state": "present"},
			},
			wantID: "snapshot:nightly",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantID, e.getResourceIdentifier(tc.resource))
		})
	}
}

// TestGetResourceIdentifier_UntypedBackCompat verifies that untyped module refs
// keep their legacy path/name behaviour (file/directory/script), unchanged by #1903.
func TestGetResourceIdentifier_UntypedBackCompat(t *testing.T) {
	e := newTestExecutor(t, config.ErrorHandlingConfig{})

	t.Run("path config wins for filesystem modules", func(t *testing.T) {
		r := config.ResourceConfig{
			Name:   "app-config-dir",
			Module: "directory",
			Config: map[string]interface{}{"path": "/etc/myapp"},
		}
		assert.Equal(t, "/etc/myapp", e.getResourceIdentifier(r))
	})

	t.Run("falls back to name when path absent", func(t *testing.T) {
		r := config.ResourceConfig{
			Name:   "some-resource",
			Module: "file",
			Config: map[string]interface{}{},
		}
		assert.Equal(t, "some-resource", e.getResourceIdentifier(r))
	})

	t.Run("empty path falls back to name", func(t *testing.T) {
		r := config.ResourceConfig{
			Name:   "some-resource",
			Module: "file",
			Config: map[string]interface{}{"path": ""},
		}
		assert.Equal(t, "some-resource", e.getResourceIdentifier(r))
	})
}
