// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/telemetry"
)

// TestTelemetryToProto_ServiceAndProcessDetail verifies the service display
// name, start type and PID, and the process status and description, reach the
// proto; a stopped service keeps PID 0 and its start type.
func TestTelemetryToProto_ServiceAndProcessDetail(t *testing.T) {
	snap := telemetryToProto(telemetry.Telemetry{
		Processes: []telemetry.ProcessSnapshot{{PID: 9, Name: "p", Status: "suspended", Description: "desc"}},
		Services: []telemetry.ServiceSnapshot{
			{Name: "a.service", State: "running", DisplayName: "A", StartType: "auto", PID: 55},
			{Name: "b.service", State: "dead", DisplayName: "B", StartType: "manual"},
		},
	}, "s1")

	require.Len(t, snap.GetProcesses(), 1)
	assert.Equal(t, "suspended", snap.GetProcesses()[0].GetStatus())
	assert.Equal(t, "desc", snap.GetProcesses()[0].GetDescription())
	require.Len(t, snap.GetServices(), 2)
	assert.Equal(t, "A", snap.GetServices()[0].GetDisplayName())
	assert.Equal(t, "auto", snap.GetServices()[0].GetStartType())
	assert.EqualValues(t, 55, snap.GetServices()[0].GetPid())
	assert.EqualValues(t, 0, snap.GetServices()[1].GetPid())
	assert.Equal(t, "manual", snap.GetServices()[1].GetStartType())
}
