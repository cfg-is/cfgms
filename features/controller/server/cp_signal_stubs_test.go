// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"

	cpsignaltypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// Control-plane test doubles that do not exercise the tamper-state and repair
// signals implement them as no-ops so they keep satisfying ControlPlaneProvider.

func (p *testDNAWiringControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error {
	return nil
}

func (p *testDNAWiringControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (c *recordingControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error {
	return nil
}

func (c *recordingControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (p *hbTestControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error { return nil }

func (p *hbTestControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (p *bulkWiringCP) SendTamperState(_ context.Context, _ string, _ bool) error { return nil }

func (p *bulkWiringCP) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}

func (p *inObserveSweepControlPlane) SendTamperState(_ context.Context, _ string, _ bool) error {
	return nil
}

func (p *inObserveSweepControlPlane) SendRepair(_ context.Context, _ string, _ cpsignaltypes.RepairRequest) error {
	return nil
}
