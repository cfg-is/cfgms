// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

// Live validation of the cross-platform-schema assumption get.go's package
// comment states as fact: osquery's system_info/os_version/cpu_info tables
// expose identical column names and types on every platform osquery
// supports (Issue #3570, epic #2855).
//
// This suite drives the REAL pinned osquery binary — not a mock, not a
// fixture recorded from another platform — through every curated host:*
// query and asserts its actual Windows output carries every column get.go
// and schemaSpec (schema_drift_test.go) expect. The claim already failed once
// under this exact methodology: the original queryCPU selected
// cpu_info.cpu_family, which osquery's official table spec shows never
// existed on any platform (fixed in get.go as part of this issue). Running
// this suite against the real binary is what caught it — a canned JSON
// fixture recorded by hand, as get_test.go's cpuJSON used to be, cannot.
//
// Skips cleanly when CFGMS_E2E_OSQUERY_WINDOWS_BIN is unset, following the
// env-var-gate convention in test/e2e/ha/leader_election_real_test.go (story
// #3094): the real pinned osquery binary is not vendored in this repo or
// present on CI's hosted windows-latest runner image by default, so the live
// run is opt-in.
//
//	CFGMS_E2E_OSQUERY_WINDOWS_BIN   path to a real osqueryi.exe matching pinnedVersion
//
// No get_windows.go binary-path-resolution file accompanies this test, per
// the ratified "AC #1 correction" recorded on issue #3570 (2026-08-26). The
// original AC assumed story 4 had split binary-path resolution into per-OS
// files mirroring a get_linux.go/get_darwin.go precedent; neither file exists,
// because story 4 built one platform-agnostic resolution path instead.
// Binary path resolution is already declared-not-PATH-resolved and already
// covers Windows, uniformly with every other platform, via integrity.go's
// VerifyBeforeExec — it keys the signed bundle's Binaries map by
// runtime.GOOS+"-"+runtime.GOARCH and refuses to run anything else (module.go:
// "There is no host-install fallback path"). A get_windows.go duplicating that
// resolution would either dead-code duplicate it or, worse, introduce a
// second, unverified path-resolution mechanism the security model explicitly
// rules out. This test instead verifies what the story's Goal actually asks
// for: that the existing resolution mechanism's Windows binary produces the
// schema Get() expects.
package osquery

import (
	"context"
	"os"
	"testing"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules/conformance"
)

const envOsqueryWindowsBin = "CFGMS_E2E_OSQUERY_WINDOWS_BIN"

// liveWindowsModule installs a signed bundle around the real osquery binary
// at the path named by CFGMS_E2E_OSQUERY_WINDOWS_BIN and returns a module
// wired to invoke it. The full Get() path — trust gate, on-disk content-hash
// re-check, GOOS-GOARCH platform resolution — runs exactly as production
// does; only the binary bytes are real instead of the fake content
// integrity_test.go's installOsqueryBundle uses for its unit coverage.
func liveWindowsModule(t *testing.T) *osqueryModule {
	t.Helper()
	binPath := os.Getenv(envOsqueryWindowsBin)
	if binPath == "" {
		t.Skipf("%s not set — skipping live Windows osquery validation "+
			"(set it to a real osqueryi.exe matching pinnedVersion=%s to run)",
			envOsqueryWindowsBin, pinnedVersion)
	}

	content, err := os.ReadFile(binPath) // #nosec G304 -- operator-provided live-test binary path
	if err != nil {
		t.Fatalf("read live osquery binary at %s: %v", binPath, err)
	}

	root, b, enforcer := installOsqueryBundleAs(t, "osqueryi.exe", content, 0o700)
	return newForTesting(NewPreExecVerifierWithEnforcer(enforcer), Installation{
		Bundle:    b,
		Root:      root,
		TrustMode: stewardtypes.ModuleTrustModeStrict,
	})
}

// TestLiveWindows_CrossPlatformSchemaAssumption is the [REQUIRED TEST] from
// issue #3570 AC: for each curated host:* kind, a live query against the real
// pinned Windows osquery binary must return every column schemaSpec declares.
// A failure here means the cross-platform-schema assumption in get.go's
// package comment does not hold for that kind on Windows and get.go's SQL
// query must be corrected — not this test relaxed.
func TestLiveWindows_CrossPlatformSchemaAssumption(t *testing.T) {
	m := liveWindowsModule(t)

	for kind, cols := range schemaSpec {
		kind, cols := kind, cols
		t.Run(kind, func(t *testing.T) {
			state, err := m.Get(context.Background(), kind)
			if err != nil {
				t.Fatalf("live Get(%q) against real Windows osquery binary: %v", kind, err)
			}
			got := state.AsMap()
			for _, col := range cols {
				if _, ok := got[col]; !ok {
					t.Errorf("live Windows osquery output for %q missing column %q — "+
						"cross-platform-schema assumption does not hold on Windows "+
						"(pinnedVersion=%s)", kind, col, pinnedVersion)
				}
			}
		})
	}
}

// TestLiveWindows_ConformanceGates is the [REQUIRED TEST] from issue #3570
// AC: conformance.AssertDeterministicGet / AssertNoEphemeralFields must pass
// against the live Windows binary's real output, not only the fixture-driven
// path get_test.go exercises for Linux/macOS-shaped canned responses.
func TestLiveWindows_ConformanceGates(t *testing.T) {
	m := liveWindowsModule(t)

	for kind := range schemaSpec {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			conformance.AssertDeterministicGet(t, m, kind)

			state, err := m.Get(context.Background(), kind)
			if err != nil {
				t.Fatalf("Get(%q): %v", kind, err)
			}
			conformance.AssertNoEphemeralFields(t, state, osqueryBanned())
		})
	}
}
