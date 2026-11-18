// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"testing"

	"github.com/cfgis/cfgms/test/e2e/fleet/fleetkit"
)

// fleetScenarioSuite is the fleet suite the scenario methods in this package are
// defined on. The shared helpers live in fleetkit.FleetTestSuite; methods can only
// be declared on a type of this package, so the scenarios embed it.
type fleetScenarioSuite struct {
	*fleetkit.FleetTestSuite
}

// newFleetScenarioSuite starts the fleet suite (skipping unless CFGMS_FLEET_TEST=1)
// and wraps it for the scenario methods.
func newFleetScenarioSuite(t *testing.T) *fleetScenarioSuite {
	t.Helper()
	return &fleetScenarioSuite{FleetTestSuite: fleetkit.SetupFleetSuite(t)}
}

// TestFleetWalkthrough is the single ordered entry point for all fleet walkthrough scenarios.
// Scenarios execute in definition order via t.Run so each is individually identified in output.
func TestFleetWalkthrough(t *testing.T) {
	suite := newFleetScenarioSuite(t)
	cfg := "configs/fleet-config.yaml"

	t.Run("VanillaState", func(t *testing.T) { suite.testVanillaState(t) })
	t.Run("ConfigUploadAndConvergence", func(t *testing.T) { suite.testConfigUploadAndConvergence(t, cfg) })
	t.Run("IdempotentReUpload", func(t *testing.T) { suite.testIdempotentReUpload(t, cfg) })
	t.Run("PerModuleConvergence", func(t *testing.T) { suite.testPerModuleConvergence(t) })
	t.Run("ControllerRestart", func(t *testing.T) { suite.testControllerRestart(t, cfg) })
	t.Run("StewardRestart", func(t *testing.T) { suite.testStewardRestart(t, cfg) })
	t.Run("DeferredConfig", func(t *testing.T) { suite.testDeferredConfig(t, cfg) })
	t.Run("DriftAutoCorrection", func(t *testing.T) { suite.testDriftAutoCorrection(t, cfg) })
	t.Run("ConfigCascade", func(t *testing.T) { suite.testConfigCascade(t) })
}
