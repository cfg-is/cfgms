// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"time"

	maintinterfaces "github.com/cfgis/cfgms/pkg/maintenance/interfaces"
)

// compile-time assertion that *GateWindowAdapter satisfies the WindowManager contract.
var _ WindowManager = (*GateWindowAdapter)(nil)

// GateWindowAdapter adapts the central pkg/maintenance/interfaces.Gate to the
// patch module's WindowManager interface.
//
// For the patch module, "in window" and "can reboot" collapse to the same check
// (ADR-026 decision 1): the patch module only ever gates reboots, so
// IsInWindow and CanPerformMaintenance both delegate to Gate.CanReboot.
type GateWindowAdapter struct {
	gate     maintinterfaces.Gate
	deviceID string
}

// NewGateWindowAdapter constructs a GateWindowAdapter backed by the given Gate.
// deviceID is the steward's own registered identity, passed through to Gate calls.
func NewGateWindowAdapter(gate maintinterfaces.Gate, deviceID string) *GateWindowAdapter {
	return &GateWindowAdapter{gate: gate, deviceID: deviceID}
}

// CanReboot delegates to Gate.CanReboot.
func (a *GateWindowAdapter) CanReboot(ctx context.Context, deviceID string) (bool, error) {
	return a.gate.CanReboot(ctx, deviceID)
}

// CanPerformMaintenance delegates to Gate.CanReboot — for the patch module,
// maintenance permission and reboot permission are the same check.
func (a *GateWindowAdapter) CanPerformMaintenance(ctx context.Context, deviceID string) (bool, error) {
	return a.gate.CanReboot(ctx, deviceID)
}

// GetNextWindow delegates to Gate.NextWindow.
func (a *GateWindowAdapter) GetNextWindow(ctx context.Context, deviceID string) (time.Time, error) {
	return a.gate.NextWindow(ctx, deviceID)
}

// IsInWindow delegates to Gate.CanReboot — for the patch module, "in window"
// and "can reboot" are equivalent.
func (a *GateWindowAdapter) IsInWindow(ctx context.Context, deviceID string) (bool, error) {
	return a.gate.CanReboot(ctx, deviceID)
}
