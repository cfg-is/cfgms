// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"

	cpsignaltypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// Control-plane test doubles that do not exercise the tamper-state and repair
// signals implement them as no-ops so they keep satisfying ControlPlaneProvider.

func (n *noopControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error { return nil }

func (n *noopControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (e *eventCapture) SendTamperState(_ context.Context, _ string, _ bool) error { return nil }

func (e *eventCapture) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}
