// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"

	cpsignaltypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// Control-plane test doubles that do not exercise the tamper-state and repair
// signals implement them as no-ops so they keep satisfying ControlPlaneProvider.

func (c *capturingControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error {
	return nil
}

func (c *capturingControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (c *recordingControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error {
	return nil
}

func (c *recordingControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (c *syncedControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error { return nil }

func (c *syncedControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}
