// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/dnasnapshot"
)

// dnaSnapshotFixturePath is the captured DNA sub-collector fixture, relative
// to this package's directory (the working directory `go test` uses).
const dnaSnapshotFixturePath = "testdata/dna_snapshot.json"

// newSnapshotCollector builds a Collector wired to snapshot-backed
// implementations of HardwareCollector, SoftwareCollector, NetworkCollector
// and SecurityCollector, loaded from dnaSnapshotFixturePath. They are real
// components that implement the sub-collector interfaces and replay data
// captured once from a real collector run, rather than probing live hardware
// on every test — the multi-second-per-test cost Issue #4222 removes from
// tests that assert on Collector's assembly, caching and partitioning logic
// rather than on how deeply a given OS can be inspected.
//
// Tests that exist to prove per-OS collection works (TestCollectHardwareInfo,
// TestCollectSoftwareInfo, hardware_linux_test.go, hardware_windows_test.go,
// software_windows_test.go, network_windows_test.go, security_windows_test.go)
// keep using the platform default and must not be switched to this helper.
//
// Additional opts (e.g. WithOsquerySource) are applied after the sub-collector
// options, so a caller can still override any of them.
func newSnapshotCollector(t testing.TB, logger logging.Logger, opts ...CollectorOption) *Collector {
	t.Helper()
	snap, err := dnasnapshot.Load(dnaSnapshotFixturePath)
	require.NoError(t, err, "load DNA snapshot fixture")

	base := []CollectorOption{
		WithHardwareCollector(dnasnapshot.NewHardwareCollector(snap.Hardware)),
		WithSoftwareCollector(dnasnapshot.NewSoftwareCollector(snap.Software)),
		WithNetworkCollector(dnasnapshot.NewNetworkCollector(snap.Network)),
		WithSecurityCollector(dnasnapshot.NewSecurityCollector(snap.Security)),
	}
	return NewCollector(logger, append(base, opts...)...)
}
