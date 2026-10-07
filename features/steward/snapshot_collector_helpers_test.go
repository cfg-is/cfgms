// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/dnasnapshot"
)

// dnaSnapshotFixturePath is the captured DNA sub-collector fixture, relative
// to this package's directory (the working directory `go test` uses).
const dnaSnapshotFixturePath = "dna/testdata/dna_snapshot.json"

// newSnapshotDNACollector builds a dna.Collector wired to snapshot-backed
// sub-collectors loaded from dnaSnapshotFixturePath — real components that
// implement dna's HardwareCollector/SoftwareCollector/NetworkCollector/
// SecurityCollector interfaces and replay data captured once from a real
// collector run, instead of probing the live host on every test. This is the
// multi-second-per-test cost Issue #4222 removes.
//
// Inject with steward.SetDNACollector so a Standalone steward's convergence
// and drift-detection paths run real DNA assembly without paying that cost.
// Tests that exist to prove per-OS collection works (monitor_e2e_windows_test.go)
// keep the platform default and must not use this helper.
func newSnapshotDNACollector(t testing.TB, logger logging.Logger) *dna.Collector {
	t.Helper()
	snap, err := dnasnapshot.Load(dnaSnapshotFixturePath)
	require.NoError(t, err, "load DNA snapshot fixture")

	return dna.NewCollector(logger,
		dna.WithHardwareCollector(dnasnapshot.NewHardwareCollector(snap.Hardware)),
		dna.WithSoftwareCollector(dnasnapshot.NewSoftwareCollector(snap.Software)),
		dna.WithNetworkCollector(dnasnapshot.NewNetworkCollector(snap.Network)),
		dna.WithSecurityCollector(dnasnapshot.NewSecurityCollector(snap.Security)),
	)
}
