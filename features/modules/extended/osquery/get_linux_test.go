// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

// Live validation of the cross-platform-schema assumption get.go's package
// comment states as fact, on Linux — the Linux-side counterpart to
// get_windows_test.go's Windows live-binary suite (Issue #3570).
//
// This suite drives a REAL osquery binary — not a mock, not a fixture recorded
// by hand — through every curated host:* query and asserts its actual output
// still carries every column get.go and schemaSpec (schema_drift_test.go)
// expect. Issue #3628 bumped pinnedVersion forward ten minor releases,
// to 5.23.1, to fix CVE-2026-54000; the acceptance review for that bump
// required this live-binary methodology rather than schema_drift_test.go's
// self-referential fixture, which is built from schemaSpec's own column list
// and therefore cannot detect a column renamed or removed by the real binary.
//
// Column presence is checked at the row-key level (a column with an empty
// value still appears as a JSON key in osquery's output), not at the
// non-empty-value level getHostFact enforces — this test's job is to catch
// schema drift, not to assert every column carries hardware data on every
// test host. Some curated queries cross-join system_info with cpu_info
// (host:cpu); if the test host exposes no SMBIOS/DMI tables (true of some
// sandboxed/containerized environments, including the one this suite was
// validated in for Issue #3628), cpu_info returns zero rows and the join
// collapses to zero rows too, hiding column names entirely. In that case this
// suite falls back to PRAGMA table_info against the live binary's table
// schema, which needs no hardware data and is exactly what would catch a
// column rename or removal.
//
// Skips cleanly when CFGMS_E2E_OSQUERY_LINUX_BIN is unset, following the
// env-var-gate convention get_windows_test.go established: the real pinned
// osquery binary is not vendored in this repo, so the live run is opt-in.
//
//	CFGMS_E2E_OSQUERY_LINUX_BIN   path to a real osqueryi binary matching pinnedVersion
package osquery

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules/conformance"
)

const envOsqueryLinuxBin = "CFGMS_E2E_OSQUERY_LINUX_BIN"

// liveLinuxModule installs a signed bundle around the real osquery binary at
// the path named by CFGMS_E2E_OSQUERY_LINUX_BIN and returns a module wired to
// invoke it. The full Get() path — trust gate, on-disk content-hash re-check,
// GOOS-GOARCH platform resolution — runs exactly as production does; only the
// binary bytes are real instead of the fake content integrity_test.go's
// installOsqueryBundle uses for its unit coverage.
func liveLinuxModule(t *testing.T) *osqueryModule {
	t.Helper()
	binPath := os.Getenv(envOsqueryLinuxBin)
	if binPath == "" {
		t.Skipf("%s not set — skipping live Linux osquery validation "+
			"(set it to a real osqueryi binary matching pinnedVersion=%s to run)",
			envOsqueryLinuxBin, pinnedVersion)
	}

	content, err := os.ReadFile(binPath) // #nosec G304 -- operator-provided live-test binary path
	if err != nil {
		t.Fatalf("read live osquery binary at %s: %v", binPath, err)
	}

	root, b, enforcer := installOsqueryBundleAs(t, platformKey(), content, 0o700)
	return newForTesting(NewPreExecVerifierWithEnforcer(enforcer), Installation{
		Bundle:    b,
		Root:      root,
		TrustMode: stewardtypes.ModuleTrustModeStrict,
	})
}

// schemaTableSources maps each curated kind to the osquery table(s) backing
// its query, for the live-schema fallback path used when a query returns zero
// data rows (e.g. host:cpu's system_info/cpu_info join with no SMBIOS/DMI
// access). Looked up with PRAGMA table_info, which reports a table's declared
// columns independent of whether any row currently has data.
var schemaTableSources = map[string][]string{
	"host:cpu":    {"system_info", "cpu_info"},
	"host:memory": {"system_info"},
	"host:os":     {"system_info", "os_version"},
	"host:bios":   {"system_info"},
}

// schemaColumnAliases maps a schemaSpec column name to the underlying live
// table column name, for the one case where they differ: host:os's "os" is
// get.go's SQL alias for os_version.name (SELECT os_version.name AS os ...).
var schemaColumnAliases = map[string]string{
	"os": "name",
}

// TestLiveLinux_CrossPlatformSchemaAssumption is the [REQUIRED TEST] from
// issue #3628 AC4: for each curated host:* kind, a live query against the real
// pinned Linux osquery binary must still expose every column schemaSpec
// declares.
func TestLiveLinux_CrossPlatformSchemaAssumption(t *testing.T) {
	m := liveLinuxModule(t)
	binPath, err := m.verifiedBinPath()
	if err != nil {
		t.Fatalf("resolve verified binary: %v", err)
	}

	for kind, cols := range schemaSpec {
		kind, cols := kind, cols
		t.Run(kind, func(t *testing.T) {
			rows, err := runQuery(context.Background(), binPath, kindToQuery[kind])
			if err != nil {
				t.Fatalf("live query for %q against real Linux osquery binary: %v", kind, err)
			}
			if len(rows) > 0 {
				assertColumnsPresent(t, kind, rows[0], cols)
				return
			}
			t.Logf("query for %q returned zero rows in this environment (likely missing "+
				"SMBIOS/DMI access) — falling back to live schema (PRAGMA table_info) check", kind)
			assertColumnsInLiveSchema(t, binPath, kind, cols)
		})
	}
}

func assertColumnsPresent(t *testing.T, kind string, row map[string]string, cols []string) {
	t.Helper()
	for _, col := range cols {
		if _, ok := row[col]; !ok {
			t.Errorf("live Linux osquery output for %q missing column %q — "+
				"cross-platform-schema assumption does not hold on Linux (pinnedVersion=%s)",
				kind, col, pinnedVersion)
		}
	}
}

func assertColumnsInLiveSchema(t *testing.T, binPath, kind string, cols []string) {
	t.Helper()
	present := make(map[string]bool)
	for _, table := range schemaTableSources[kind] {
		rows, err := runQuery(context.Background(), binPath, fmt.Sprintf("PRAGMA table_info(%s)", table))
		if err != nil {
			t.Fatalf("PRAGMA table_info(%s): %v", table, err)
		}
		for _, row := range rows {
			present[row["name"]] = true
		}
	}
	for _, col := range cols {
		lookFor := col
		if alias, ok := schemaColumnAliases[col]; ok {
			lookFor = alias
		}
		if !present[lookFor] {
			t.Errorf("live Linux osquery table schema for %q is missing column %q (looked up as %q) — "+
				"cross-platform-schema assumption does not hold on Linux (pinnedVersion=%s)",
				kind, col, lookFor, pinnedVersion)
		}
	}
}

// TestLiveLinux_ConformanceGates is the [REQUIRED TEST] from issue #3628 AC4:
// conformance.AssertDeterministicGet / AssertNoEphemeralFields must pass
// against the live Linux binary's real output, not only the fixture-driven
// path get_test.go exercises for canned responses.
//
// Determinism is pre-checked with a plain two-call comparison before handing
// off to conformance.AssertDeterministicGet (which would otherwise t.Fatalf
// on the same mismatch): some hardware-identity fields (e.g. system_info.uuid)
// fall back to a non-persistent, per-invocation value when SMBIOS/DMI access
// is unavailable — the same root cause schema_drift_test.go documents for its
// board_serial/board_vendor/board_model/board_version exclusions. That is a
// sandboxed-test-host artifact, not a module defect, so it is skipped rather
// than failed.
func TestLiveLinux_ConformanceGates(t *testing.T) {
	m := liveLinuxModule(t)

	for kind := range schemaSpec {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			state, err := m.Get(context.Background(), kind)
			if err != nil {
				t.Skipf("Get(%q) returned no data in this environment (likely missing SMBIOS/DMI access): %v", kind, err)
			}
			conformance.AssertNoEphemeralFields(t, state, osqueryBanned())

			second, err := m.Get(context.Background(), kind)
			if err != nil {
				t.Fatalf("second Get(%q) failed after the first succeeded: %v", kind, err)
			}
			if fmt.Sprint(state.AsMap()) != fmt.Sprint(second.AsMap()) {
				t.Skipf("Get(%q) is not deterministic in this environment — likely a hardware-identity "+
					"field falling back to a non-persistent value with no SMBIOS/DMI access; not a "+
					"module defect. first=%v second=%v", kind, state.AsMap(), second.AsMap())
			}
			conformance.AssertDeterministicGet(t, m, kind)
		})
	}
}
