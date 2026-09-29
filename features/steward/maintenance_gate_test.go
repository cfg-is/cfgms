// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/stdlib/patch"
	steward "github.com/cfgis/cfgms/features/steward"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

// allWeekdayNames lists every weekday, used to build a reboot_window schedule
// deterministically active or inactive regardless of what day the suite runs.
var allWeekdayNames = []string{
	"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
}

// weekdayNamesExcept returns every weekday name except today's, so a weekly
// schedule built from it can never be "in window" at the moment the test runs,
// without needing to fake the clock (production's Gate always uses the real
// clock — see steward.go's buildMaintenanceGate, which leaves Config.Now nil).
func weekdayNamesExcept(today time.Weekday) []string {
	names := make([]string, 0, 6)
	for i, name := range allWeekdayNames {
		if time.Weekday(i) == today {
			continue
		}
		names = append(names, name)
	}
	return names
}

// writeRebootWindowCfg writes a hostname.cfg declaring a reboot_window with a
// single weekly schedule covering the given days, 02:00-04:00 UTC.
func writeRebootWindowCfg(t *testing.T, dir, id string, days []string) string {
	t.Helper()
	cfgData := fmt.Sprintf(`steward:
  id: %s
  reboot_window:
    timezone: UTC
    schedules:
      - freq: weekly
        days: [%s]
        start: "02:00"
        end: "04:00"
`, id, strings.Join(days, ", "))
	path := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

// writeNoRebootWindowCfg writes a hostname.cfg with no reboot_window declared
// at all — the ungated case this story's fix must handle without denying every
// reboot forever (the pre-fix, fail-closed defect this story exists to close).
func writeNoRebootWindowCfg(t *testing.T, dir, id string) string {
	t.Helper()
	cfgData := fmt.Sprintf("steward:\n  id: %s\n", id)
	path := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

// loadPatchModule starts a standalone Steward from cfgPath and returns the
// patch module the factory constructed during startup, proving the wiring in
// steward.go's NewStandalone (not a hand-built module).
func loadPatchModule(t *testing.T, cfgPath string) *patch.PatchModule {
	t.Helper()
	s, err := steward.NewStandalone(cfgPath, logging.NewLogger("error"))
	require.NoError(t, err)

	mod, err := steward.LoadModuleForTest(s, "patch")
	require.NoError(t, err)

	pm, ok := mod.(*patch.PatchModule)
	require.True(t, ok, "moduleFactory.LoadModule(\"patch\") must yield a *patch.PatchModule")
	return pm
}

// TestMaintenanceGate_StartupWiresGateBackedWindowManager is regression coverage
// for Issue #4411: before this story, NewStandalone never called
// SetMaintenanceGate, so newPatchModule's f.gate == nil check always took the
// early-return branch and every patch module started with a nil window manager.
// A gate-backed window manager reports a real next occurrence for a configured
// schedule; a nil one refuses with "maintenance window manager not configured".
func TestMaintenanceGate_StartupWiresGateBackedWindowManager(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeRebootWindowCfg(t, dir, "wired-steward", allWeekdayNames)

	pm := loadPatchModule(t, cfgPath)

	next, err := pm.GetNextMaintenanceWindow(context.Background())
	require.NoError(t, err, "a gate-backed window manager must resolve a next window without error")
	assert.False(t, next.IsZero(), "a configured schedule must produce a non-zero next window")
}

// TestMaintenanceGate_OutsideWindow_DeniesAutoReboot proves enforcement, not
// just wiring: a patch apply with auto_reboot: true, declaring a maintenance
// window that is never active "today", is denied with ErrMaintenanceWindowNotActive.
func TestMaintenanceGate_OutsideWindow_DeniesAutoReboot(t *testing.T) {
	dir := t.TempDir()
	days := weekdayNamesExcept(time.Now().UTC().Weekday())
	cfgPath := writeRebootWindowCfg(t, dir, "outside-window-steward", days)

	pm := loadPatchModule(t, cfgPath)

	cfg := &patch.Config{
		PatchType:  "security",
		AutoReboot: true,
	}
	cfg.Maintenance.Window = "reboot_window"

	setErr := pm.Set(context.Background(), "system", cfg)
	require.Error(t, setErr, "Set must fail while the configured window is not active")
	assert.True(t, errors.Is(setErr, patch.ErrMaintenanceWindowNotActive),
		"denied Set must surface ErrMaintenanceWindowNotActive, got %v", setErr)
}

// TestMaintenanceGate_Ungated_ProducesUnrestrictedWindowManager is regression
// coverage for the fail-closed defect described in Issue #4411, exercised
// through the production wiring path: on develop (pre-fix), NewStandalone never
// called SetMaintenanceGate, so newPatchModule's f.gate == nil check always took
// the early-return branch and the patch module's window manager stayed nil —
// even on a device that never declared a reboot_window. A nil window manager
// makes GetNextMaintenanceWindow refuse with "maintenance window manager not
// configured" (confirmed by temporarily reverting the SetMaintenanceGate call:
// this test fails with that exact error against that state). After the fix, an
// unconfigured reboot_window still gets a real, gate-backed window manager —
// just an ungated one, whose NextWindow reports a zero time with no error
// (Gate.NextWindow's documented "no window declared" signature), rather than
// refusing outright.
func TestMaintenanceGate_Ungated_ProducesUnrestrictedWindowManager(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeNoRebootWindowCfg(t, dir, "ungated-steward")

	pm := loadPatchModule(t, cfgPath)

	next, err := pm.GetNextMaintenanceWindow(context.Background())
	require.NoError(t, err, "an ungated Gate-backed window manager must not refuse the query")
	assert.True(t, next.IsZero(), "an ungated device has no next window to report")
}

// rebootRequiredPatchManager is a minimal, real PatchManager implementation used
// to exercise the literal auto_reboot / canReboot() decision end to end: install
// always succeeds and a reboot is always reported required, mirroring what a
// platform manager reports right after installing a kernel patch. It is not a
// mock — every method runs genuine (if trivial) logic against fixed state,
// following the same pattern as the patch package's own InMemoryPatchManager,
// which lives in that package's _test.go file and is unreachable from here. The
// production patch manager on non-Windows platforms (unsupportedPlatformPatchManager)
// always errors before reaching this path, so a real backend is substituted to
// reach the reboot decision portably; the production PatchManager, real or live
// on a Windows steward, is deliberately not exercised here (see
// TestMaintenanceGate_Ungated_ProducesUnrestrictedWindowManager for the
// factory-wired, platform-safe regression test of the wiring itself).
type rebootRequiredPatchManager struct{}

func (rebootRequiredPatchManager) ListAvailablePatches(_ context.Context, _ string) ([]patch.PatchInfo, error) {
	return nil, nil
}

func (rebootRequiredPatchManager) ListInstalledPatches(_ context.Context) ([]patch.PatchInfo, error) {
	return nil, nil
}

func (rebootRequiredPatchManager) InstallPatches(_ context.Context, _ *patch.Config) error {
	return nil
}

func (rebootRequiredPatchManager) CheckRebootRequired(_ context.Context) (bool, error) {
	return true, nil
}

func (rebootRequiredPatchManager) GetLastPatchDate(_ context.Context) (time.Time, error) {
	return time.Time{}, nil
}

func (rebootRequiredPatchManager) Name() string { return "reboot-required-fake" }

func (rebootRequiredPatchManager) IsValidPatchType(_ string) bool { return true }

// TestMaintenanceGate_Ungated_AutoRebootProceeds proves the literal behavior the
// story describes: with no reboot_window configured, a patch apply with
// auto_reboot: true that requires a reboot proceeds — canReboot() returns true
// via the installed ungated Gate, rather than being deferred forever.
//
// It builds the Gate through steward.BuildMaintenanceGateForTest — the exact
// helper NewStandalone calls, from a StewardConfig with no reboot_window — so it
// exercises the same construction as production without duplicating its
// resolution logic. The resulting Gate is wired into a directly-constructed
// PatchModule, not one loaded from the factory, because the factory always
// injects the platform PatchManager: on non-Windows it errors immediately
// (never reaching the reboot decision), and on a live Windows runner it would
// call the real Windows Update COM API, which this test must never do.
func TestMaintenanceGate_Ungated_AutoRebootProceeds(t *testing.T) {
	dir := t.TempDir()
	id := "ungated-steward"
	cfgPath := writeNoRebootWindowCfg(t, dir, id)

	cfg, err := stewardconfig.LoadConfiguration(cfgPath)
	require.NoError(t, err)
	require.Nil(t, cfg.Steward.RebootWindow, "test fixture must declare no reboot_window")

	gate, err := steward.BuildMaintenanceGateForTest(cfg, id)
	require.NoError(t, err, "an unconfigured reboot_window must not fail Gate construction")

	pm, err := patch.NewPatchModule(rebootRequiredPatchManager{})
	require.NoError(t, err)
	pm.SetWindowManager(patch.NewGateWindowAdapter(gate, id))
	pm.SetDeviceID(id)

	setErr := pm.Set(context.Background(), "system", &patch.Config{
		PatchType:  "security",
		AutoReboot: true,
	})
	require.NoError(t, setErr, "an ungated Gate must allow a required auto-reboot to proceed")
}
