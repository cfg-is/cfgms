// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// End-to-end test for the #1903 module-type convention spanning two real
// components: the controller's config ValidationManager (the upload gate) and
// the steward executor's resource-identifier construction (the dispatch path).
//
// It builds a fleet config containing the two hyperv shapes (hyperv.vm,
// hyperv.vswitch), asserts the controller ACCEPTS it, and asserts the executor
// builds the exact module-internal resource IDs the hyperv module's Get/Set
// expect (vm:m2-test-vm, vswitch:m2-test-vsw).
//
// Real components only: pkgconfig.ValidationManager wired to real test storage,
// and the production (*Executor).getResourceIdentifier / parseModuleRef. The
// test lives in package execution because getResourceIdentifier is unexported;
// it carries no transport protocol in its filename per the test taxonomy.
package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// hypervFleetConfig returns a StewardConfig with one resource of each hyperv
// shape, using the module-type convention with plain, strictly-valid names.
func hypervFleetConfig() *stewardconfig.StewardConfig {
	return &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:      "m2-host",
			Mode:    stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{Level: "info"},
		},
		Resources: []stewardconfig.ResourceConfig{
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
		},
	}
}

// TestHypervModuleTypeConvention_E2E exercises controller validation and the
// steward executor's identifier construction for all three hyperv shapes.
func TestHypervModuleTypeConvention_E2E(t *testing.T) {
	cfg := hypervFleetConfig()

	// ── Stage 1: controller validation must ACCEPT the config ──────────────
	sm := pkgtesting.SetupTestStorage(t)
	vmgr := pkgconfig.NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())

	result := vmgr.ValidateConfiguration(context.Background(), "", "m2-host", cfg)

	// The config must be FULLY accepted — not merely free of the two codes we
	// care about. Asserting Valid catches a rejection via any other path.
	assert.True(t, result.Valid,
		"controller must fully accept the hyperv module-type fleet config; errors: %v", result.Errors)
	for _, e := range result.Errors {
		assert.NotEqual(t, "INVALID_MODULE_NAME", e.Code,
			"module: hyperv.<type> must be accepted by the controller, got: %s", e.Message)
		assert.NotEqual(t, "INVALID_RESOURCE_NAME", e.Code,
			"plain names must pass strict validation, got: %s", e.Message)
	}

	// ── Stage 2: executor builds the module-internal typed resource IDs ────
	e := newTestExecutor(t, stewardconfig.ErrorHandlingConfig{})

	wantIDs := map[string]string{
		"m2-test-vm":  "vm:m2-test-vm",
		"m2-test-vsw": "vswitch:m2-test-vsw",
	}
	wantBundle := map[string]string{
		"m2-test-vm":  "hyperv",
		"m2-test-vsw": "hyperv",
	}

	for _, r := range cfg.Resources {
		t.Run(r.Name, func(t *testing.T) {
			gotID := e.getResourceIdentifier(r)
			assert.Equal(t, wantIDs[r.Name], gotID,
				"executor must build the module-internal resource ID")

			// The module LOADED must be the bundle ("hyperv"), never the full
			// "hyperv.<type>" — one signed bundle per ADR-006.
			bundle, _ := parseModuleRef(r.Module)
			assert.Equal(t, wantBundle[r.Name], bundle,
				"module loading must use the bundle component only")
		})
	}
}
