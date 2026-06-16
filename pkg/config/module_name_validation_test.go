// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for the module-name validator that accepts the #1903 module-type
// convention (e.g. "hyperv.vm") on the controller upload path, while leaving
// resource-NAME validation (isValidResourceName) strict and unchanged.
package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestIsValidModuleName_AcceptsBundleAndType covers the accepted module values,
// including the hyperv.<type> convention, and rejects malformed ones.
func TestIsValidModuleName_AcceptsBundleAndType(t *testing.T) {
	cases := []struct {
		module string
		want   bool
	}{
		// Plain bundles (back-compat).
		{"file", true},
		{"directory", true},
		{"hyperv", true},
		{"my-bundle", true},
		{"my_bundle", true},
		// bundle.type convention (#1903). isValidModuleName validates FORMAT
		// only — any well-formed bundle.type passes regardless of whether the
		// bundle actually defines that resource type.
		{"hyperv.vm", true},
		{"hyperv.vswitch", true},
		{"some-bundle.some-type", true},
		// Rejected: empty, uppercase, more than one dot, leading/trailing dot,
		// path separators, injection characters.
		{"", false},
		{"Hyperv.vm", false},
		{"hyperv.VM", false},
		{"hyperv.vm.extra", false},
		{".vm", false},
		{"hyperv.", false},
		{"hyperv..vm", false},
		{"hyperv/vm", false},
		{"hyperv:vm", false},
		{"hyperv vm", false},
		{"hyperv.vm;rm", false},
	}

	for _, tc := range cases {
		t.Run(tc.module, func(t *testing.T) {
			assert.Equal(t, tc.want, isValidModuleName(tc.module), "module %q", tc.module)
		})
	}
}

// TestValidateConfiguration_AcceptsHypervModuleType is the controller-side
// acceptance check: a fleet config carrying module: hyperv.vm (plus the other
// hyperv shapes) with strict plain names must pass validation — no
// INVALID_MODULE_NAME or INVALID_RESOURCE_NAME errors.
func TestValidateConfiguration_AcceptsHypervModuleType(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	vm := NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())

	cfg := minimalValidConfig()
	cfg.Resources = []stewardconfig.ResourceConfig{
		{
			Name:   "m2-test-vm",
			Module: "hyperv.vm",
			Config: map[string]interface{}{
				"memory_mb":   2048,
				"cpu_count":   2,
				"switch_name": "m2-test-vsw",
				"vhd_path":    "C:\\VMs\\m2.vhdx",
				"state":       "running",
			},
		},
		{
			Name:   "m2-test-vsw",
			Module: "hyperv.vswitch",
			Config: map[string]interface{}{
				"switch_type":      "external",
				"net_adapter_name": "Ethernet",
			},
		},
	}

	result := vm.ValidateConfiguration(context.Background(), "", "steward-1", cfg)

	// Assert full acceptance, not merely the absence of the two codes — a
	// rejection via any other validation path must fail this test.
	assert.True(t, result.Valid,
		"controller must fully accept the hyperv module-type config; errors: %v", result.Errors)
	for _, e := range result.Errors {
		assert.NotEqual(t, "INVALID_MODULE_NAME", e.Code,
			"module: hyperv.<type> must be accepted, got error: %s", e.Message)
		assert.NotEqual(t, "INVALID_RESOURCE_NAME", e.Code,
			"plain names must pass strict validation, got error: %s", e.Message)
	}
}

// TestValidateConfiguration_RejectsMalformedModule confirms the validator still
// rejects a structurally invalid module value.
func TestValidateConfiguration_RejectsMalformedModule(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	vm := NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())

	cfg := minimalValidConfig()
	cfg.Resources = []stewardconfig.ResourceConfig{
		{
			Name:   "bad-mod",
			Module: "hyperv:vm", // colon is not a valid module separator
			Config: map[string]interface{}{"state": "present"},
		},
	}

	result := vm.ValidateConfiguration(context.Background(), "", "steward-1", cfg)

	var found bool
	for _, e := range result.Errors {
		if e.Code == "INVALID_MODULE_NAME" {
			found = true
		}
	}
	assert.True(t, found, "malformed module value must produce INVALID_MODULE_NAME")
	assert.False(t, result.Valid, "config with malformed module must be invalid")
}
