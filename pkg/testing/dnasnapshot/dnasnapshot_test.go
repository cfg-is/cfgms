// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dnasnapshot

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/dna"
)

// Compile-time interface conformance: each snapshot-backed type must satisfy
// the real dna sub-collector interface it stands in for.
var (
	_ dna.HardwareCollector = (*HardwareCollector)(nil)
	_ dna.SoftwareCollector = (*SoftwareCollector)(nil)
	_ dna.NetworkCollector  = (*NetworkCollector)(nil)
	_ dna.SecurityCollector = (*SecurityCollector)(nil)
)

const fixturePath = "../../../features/steward/dna/testdata/dna_snapshot.json"

func TestLoad(t *testing.T) {
	snap, err := Load(fixturePath)
	require.NoError(t, err)
	require.NotNil(t, snap)

	assert.NotEmpty(t, snap.Hardware, "fixture must carry captured hardware attributes")
	assert.NotEmpty(t, snap.Software, "fixture must carry captured software attributes")
	assert.NotEmpty(t, snap.Network, "fixture must carry captured network attributes")
	assert.NotEmpty(t, snap.Security, "fixture must carry captured security attributes")
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("testdata/does-not-exist.json")
	assert.Error(t, err)
}

func TestHardwareCollector_ReplaysSnapshotAndCountsCalls(t *testing.T) {
	snap, err := Load(fixturePath)
	require.NoError(t, err)

	hw := NewHardwareCollector(snap.Hardware)
	attrs := make(map[string]string)
	ctx := context.Background()

	require.NoError(t, hw.CollectCPU(ctx, attrs))
	require.NoError(t, hw.CollectMemory(ctx, attrs))
	require.NoError(t, hw.CollectDisk(ctx, attrs))
	require.NoError(t, hw.CollectMotherboard(ctx, attrs))

	assert.EqualValues(t, 4, hw.Calls())
	for k, v := range snap.Hardware {
		assert.Equal(t, v, attrs[k])
	}
}

func TestSoftwareCollector_ReplaysSnapshot(t *testing.T) {
	snap, err := Load(fixturePath)
	require.NoError(t, err)

	sw := NewSoftwareCollector(snap.Software)
	attrs := make(map[string]string)
	ctx := context.Background()

	require.NoError(t, sw.CollectOS(ctx, attrs))
	require.NoError(t, sw.CollectPackages(ctx, attrs))
	require.NoError(t, sw.CollectServices(ctx, attrs))
	require.NoError(t, sw.CollectProcesses(ctx, attrs))

	for k, v := range snap.Software {
		assert.Equal(t, v, attrs[k])
	}
}

func TestNetworkCollector_ReplaysSnapshot(t *testing.T) {
	snap, err := Load(fixturePath)
	require.NoError(t, err)

	n := NewNetworkCollector(snap.Network)
	attrs := make(map[string]string)
	ctx := context.Background()

	require.NoError(t, n.CollectInterfaces(ctx, attrs))
	require.NoError(t, n.CollectRouting(ctx, attrs))
	require.NoError(t, n.CollectDNS(ctx, attrs))
	require.NoError(t, n.CollectFirewall(ctx, attrs))

	for k, v := range snap.Network {
		assert.Equal(t, v, attrs[k])
	}
}

func TestSecurityCollector_ReplaysSnapshot(t *testing.T) {
	snap, err := Load(fixturePath)
	require.NoError(t, err)

	sec := NewSecurityCollector(snap.Security)
	attrs := make(map[string]string)
	ctx := context.Background()

	require.NoError(t, sec.CollectUsers(ctx, attrs))
	require.NoError(t, sec.CollectGroups(ctx, attrs))
	require.NoError(t, sec.CollectPermissions(ctx, attrs))
	require.NoError(t, sec.CollectCertificates(ctx, attrs))

	for k, v := range snap.Security {
		assert.Equal(t, v, attrs[k])
	}
}
