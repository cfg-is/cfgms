// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward

import (
	"context"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/execution"
)

// RunConvergence exposes the unexported runConvergence method for black-box tests.
var RunConvergence = (*Steward).runConvergence

// DetectUnmanagedDNADrift exposes the unexported detectUnmanagedDNADrift method for black-box tests.
var DetectUnmanagedDNADrift = (*Steward).detectUnmanagedDNADrift

// SetPreviousDNA sets the previousDNA field under its mutex for test setup.
var SetPreviousDNA = func(s *Steward, d *commonpb.DNA) {
	s.previousDNAMu.Lock()
	s.previousDNA = d
	s.previousDNAMu.Unlock()
}

// GetPreviousDNA reads the previousDNA field under its mutex for test assertions.
var GetPreviousDNA = func(s *Steward) *commonpb.DNA {
	s.previousDNAMu.Lock()
	defer s.previousDNAMu.Unlock()
	return s.previousDNA
}

// SetDNACollector replaces the dnaCollector field for test injection (e.g. nil-safety tests).
var SetDNACollector = func(s *Steward, c *dna.Collector) {
	s.dnaCollector = c
}

// SetDriftDetector replaces the driftDetector field for test injection (e.g. nil-safety tests).
var SetDriftDetector = func(s *Steward, d drift.Detector) {
	s.driftDetector = d
}

// RunTargetedReconcile exposes the executor's targeted reconcile for black-box tests
// that need to exercise the reconcile path directly (e.g. unmanaged-resource early-exit).
var RunTargetedReconcile = func(s *Steward, ctx context.Context, resourceID string) {
	s.executor.RunTargetedReconcile(ctx, resourceID)
}

// SetDebounceWindowForTest overrides the per-resource monitor debounce window on a
// specific Steward instance. Tests set a short window (e.g. 20ms) so they don't
// wait the production 1500ms before a coalesced reconcile fires.
// Delegates to the executor's monitor engine (Issue #2435).
var SetDebounceWindowForTest = func(s *Steward, d time.Duration) {
	s.executor.SetMonitorDebounceWindow(d)
}

// SetMonitorFanInCapForTest overrides the fan-in channel capacity for a specific
// Steward instance. Tests set a small value (e.g. 2) to guarantee queue overflow
// without relying on scheduler timing when testing shed-to-poll behavior.
// Delegates to the executor's monitor engine (Issue #2435).
var SetMonitorFanInCapForTest = func(s *Steward, cap int) {
	s.executor.SetMonitorFanInCap(cap)
}

// RegisterTestModule injects a module instance into the steward's factory cache.
// Subsequent calls to LoadModule or CreateModuleInstance for name will return mod.
var RegisterTestModule = func(s *Steward, name string, mod modules.Module) {
	s.moduleFactory.RegisterModule(name, mod)
}

// GetMonitorDNARefreshCount reports how many DNA snapshot refreshes were
// triggered by monitor-driven targeted reconciles that applied changes. In
// controller mode the same post-reconcile path updates the heartbeat
// currentDNAHash before the next scheduled tick; standalone tests read this
// counter to assert the change is reflected early (AC3).
var GetMonitorDNARefreshCount = func(s *Steward) int64 {
	return s.monitorDNARefreshes.Load()
}

// SetDriftModeForTest sets the executor's drift mode for tests that need to
// exercise monitor-mode reconcile paths.
var SetDriftModeForTest = func(s *Steward, mode config.DriftMode) {
	s.executor.SetDriftMode(mode)
}

// SetDriftEventHandlerForTest sets the executor's drift event handler for tests
// that need to capture drift events (e.g. to assert EventType in monitor mode).
var SetDriftEventHandlerForTest = func(s *Steward, handler execution.DriftEventHandler) {
	s.executor.SetDriftEventHandler(handler)
}
