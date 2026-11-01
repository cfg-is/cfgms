// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/telemetry"
)

// TestTelemetryToProto_HostTotals verifies host totals are copied into the proto
// and that a collector which reports none leaves Host nil.
func TestTelemetryToProto_HostTotals(t *testing.T) {
	with := telemetryToProto(telemetry.Telemetry{Host: &telemetry.HostTotals{
		CPUPercent: 7, MemoryUsedBytes: 1, MemoryTotalBytes: 2,
		DiskReadBytesPerSec: 3, DiskWriteBytesPerSec: 4, DiskUsedBytes: 5, DiskTotalBytes: 6,
		NetRxBytesPerSec: 8, NetTxBytesPerSec: 9,
	}}, "s1")
	require.NotNil(t, with.GetHost())
	h := with.GetHost()
	assert.Equal(t, 7.0, h.GetCpuPercent())
	assert.Equal(t, uint64(2), h.GetMemoryTotalBytes())
	assert.Equal(t, uint64(6), h.GetDiskTotalBytes())
	assert.Equal(t, 8.0, h.GetNetRxBytesPerSec())
	assert.Equal(t, 9.0, h.GetNetTxBytesPerSec())

	assert.Nil(t, telemetryToProto(telemetry.Telemetry{}, "s1").GetHost())
}
