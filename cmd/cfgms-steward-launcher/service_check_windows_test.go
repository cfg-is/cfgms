// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc/mgr"
)

// These tests exercise the real Windows Service Control Manager (CLAUDE.md
// forbids mocks). Creating/deleting a service requires Administrator, so they
// skip when the process is not elevated — the same mgr.Connect()-succeeds gate
// cmd/steward/service's windowsManager.IsElevated uses. They ALWAYS operate on
// a unique throwaway service name, never the real CFGMSSteward registration, so
// a run on the live lab host cannot disturb the running steward.

// requireSCM skips the test when the SCM is not writable (non-elevated), and
// otherwise returns a connected manager closed at test end.
func requireSCM(t *testing.T) *mgr.Mgr {
	t.Helper()
	scm, err := mgr.Connect()
	if err != nil {
		t.Skipf("skipping — requires Administrator (SCM connect failed: %v)", err)
	}
	t.Cleanup(func() { _ = scm.Disconnect() })
	return scm
}

// uniqueTestServiceName returns a throwaway service name distinct from the real
// CFGMSSteward registration and scoped to this test so parallel packages can't
// collide. It also registers cleanup that force-deletes the service if a test
// leaves it behind.
func uniqueTestServiceName(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("CFGMSSelfRepairTest_%d_%s", os.Getpid(), t.Name())
	// Sanitize: service names may not contain '/' (t.Name() uses it for subtests).
	safe := make([]rune, 0, len(name))
	for _, r := range name {
		if r == '/' || r == ' ' {
			r = '_'
		}
		safe = append(safe, r)
	}
	name = string(safe)
	t.Cleanup(func() { deleteServiceIfPresent(name) })
	return name
}

// deleteServiceIfPresent removes a service if it exists, ignoring all errors —
// used only for test cleanup.
func deleteServiceIfPresent(name string) {
	scm, err := mgr.Connect()
	if err != nil {
		return
	}
	defer func() { _ = scm.Disconnect() }()
	s, err := scm.OpenService(name)
	if err != nil {
		return
	}
	defer func() { _ = s.Close() }()
	_ = s.Delete()
}

const testRepairExePath = `C:\Program Files\CFGMS\cfgms-steward-launcher.exe`

// TestServiceRegistrationOK_DetectsMissingService (REQUIRED, #2465): the check
// reports true while the service exists and (false, nil) — the definite
// "missing" verdict — after it is deleted.
func TestServiceRegistrationOK_DetectsMissingService(t *testing.T) {
	scm := requireSCM(t)
	name := uniqueTestServiceName(t)

	// Absent to start with → (false, nil).
	ok, err := serviceRegistrationOK(name)
	require.NoError(t, err)
	assert.False(t, ok, "a never-created service must read as missing")

	// Create it → present → (true, nil).
	s, err := scm.CreateService(name, testRepairExePath, mgr.Config{StartType: mgr.StartAutomatic})
	require.NoError(t, err)
	require.NoError(t, s.Close())

	ok, err = serviceRegistrationOK(name)
	require.NoError(t, err)
	assert.True(t, ok, "an existing service must read as present")

	// Delete it → missing again → (false, nil). DeleteService only marks the
	// service for deletion; the SCM purges the registration once every open
	// handle to it has closed, asynchronously relative to CloseServiceHandle
	// returning (Issue #4159, which evicted an unrelated PR on this exact
	// race). Poll for the real, observable deleted state rather than
	// asserting on a state the SCM has not necessarily reached yet.
	existing, err := scm.OpenService(name)
	require.NoError(t, err)
	require.NoError(t, existing.Delete())
	require.NoError(t, existing.Close())

	require.Eventually(t, func() bool {
		ok, err := serviceRegistrationOK(name)
		return err == nil && !ok
	}, 5*time.Second, 10*time.Millisecond, "a deleted service must read as missing (the repair trigger)")
}

// TestRepairServiceRegistration_RecreatesService (REQUIRED, #2465): recreate a
// missing registration with the same start type, binary path, args, and
// recovery actions as the install path.
func TestRepairServiceRegistration_RecreatesService(t *testing.T) {
	requireSCM(t)
	name := uniqueTestServiceName(t)

	// Precondition: absent.
	ok, err := serviceRegistrationOK(name)
	require.NoError(t, err)
	require.False(t, ok)

	args := []string{"run", "--root", `C:\Program Files\CFGMS`, "--child-args", `--regtoken-file C:\token`}
	require.NoError(t, repairServiceRegistration(name, testRepairExePath, args))

	// Now present with the expected config.
	scm, err := mgr.Connect()
	require.NoError(t, err)
	defer func() { _ = scm.Disconnect() }()
	s, err := scm.OpenService(name)
	require.NoError(t, err, "repaired service must exist")
	defer func() { _ = s.Close() }()

	cfg, err := s.Config()
	require.NoError(t, err)
	assert.Equal(t, uint32(mgr.StartAutomatic), cfg.StartType, "start type must match install")
	assert.Equal(t, launcherServiceDisplayName, cfg.DisplayName)
	assert.Equal(t, launcherServiceDescription, cfg.Description)
	assert.Contains(t, cfg.BinaryPathName, testRepairExePath,
		"repaired service must point at the launcher install path")
	assert.Contains(t, cfg.BinaryPathName, `--regtoken-file C:\token`,
		"repaired service must carry the original launcher args")

	recovery, err := s.RecoveryActions()
	require.NoError(t, err)
	require.Len(t, recovery, 3, "install-parity recovery actions (3 escalating restarts)")
	// Full parity with cmd/steward/service/manager_windows.go:254-256 — same
	// action type and the same escalating 10s/30s/60s delays.
	assert.Equal(t, mgr.ServiceRestart, recovery[0].Type)
	assert.Equal(t, mgr.ServiceRestart, recovery[1].Type)
	assert.Equal(t, mgr.ServiceRestart, recovery[2].Type)
	assert.Equal(t, 10*time.Second, recovery[0].Delay)
	assert.Equal(t, 30*time.Second, recovery[1].Delay)
	assert.Equal(t, 60*time.Second, recovery[2].Delay)

	nonCrash, err := s.RecoveryActionsOnNonCrashFailures()
	require.NoError(t, err)
	assert.True(t, nonCrash, "recovery must apply to non-crash failures")
}

// TestRepairServiceRegistration_RefusesRegtokenValue: arguments carrying a
// token value are refused and no service is created.
func TestRepairServiceRegistration_RefusesRegtokenValue(t *testing.T) {
	requireSCM(t)
	name := uniqueTestServiceName(t)

	args := []string{"run", "--root", `C:\Program Files\CFGMS`, "--child-args", "--regtoken abc"}
	err := repairServiceRegistration(name, testRepairExePath, args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--regtoken-file")
	assert.NotContains(t, err.Error(), "abc")

	ok, err := serviceRegistrationOK(name)
	require.NoError(t, err)
	assert.False(t, ok, "no service may be created for arguments carrying a token value")
}

// TestRepairServiceIfMissing_CarriesTokenFilePathOnly (REQUIRED, #5623) is a
// regression guard on the launcher's service-repair path: the repair copies its
// own arguments, so a service re-created from arguments carrying
// --regtoken-file <path> must hold that path and no token value.
func TestRepairServiceIfMissing_CarriesTokenFilePathOnly(t *testing.T) {
	requireSCM(t)
	name := uniqueTestServiceName(t)

	tokenPath := `C:\ProgramData\cfgms\registration-token`
	args := []string{"run", "--root", `C:\Program Files\CFGMS`, "--child-args",
		"--regtoken-file " + tokenPath + " --controller-url https://ctrl.example.com:8443"}

	var out bytes.Buffer
	repairServiceIfMissing(&out, name, testRepairExePath, args)
	assert.Contains(t, out.String(), "service_registration_repaired",
		"the repair must run and log success for a missing service")

	scm, err := mgr.Connect()
	require.NoError(t, err)
	defer func() { _ = scm.Disconnect() }()
	s, err := scm.OpenService(name)
	require.NoError(t, err, "repaired service must exist")
	defer func() { _ = s.Close() }()

	cfg, err := s.Config()
	require.NoError(t, err)
	assert.Contains(t, cfg.BinaryPathName, "--regtoken-file "+tokenPath,
		"repaired service must carry the token file path")
	assert.NotContains(t, cfg.BinaryPathName, "--regtoken ",
		"repaired service must not carry a token value via the legacy flag")
	assert.Equal(t, 1, strings.Count(cfg.BinaryPathName, "--regtoken"),
		"the only token-related argument is --regtoken-file")
}

// TestRepairServiceRegistration_ErrorsOnConflict (#2465): repairServiceRegistration
// surfaces a CreateService failure as an error (rather than swallowing it) — the
// error that drives the event=service_registration_repair_failed WARN log in the
// per-tick repairServiceIfMissing path. Induced with a real name collision, since
// the no-mock rule rules out faulting the SCM directly.
func TestRepairServiceRegistration_ErrorsOnConflict(t *testing.T) {
	scm := requireSCM(t)
	name := uniqueTestServiceName(t)

	// Pre-create the service so a second create collides.
	s, err := scm.CreateService(name, testRepairExePath, mgr.Config{StartType: mgr.StartAutomatic})
	require.NoError(t, err)
	require.NoError(t, s.Close())

	err = repairServiceRegistration(name, testRepairExePath, nil)
	require.Error(t, err, "recreating an already-existing service must return an error, not silently succeed")
	assert.Contains(t, err.Error(), "create service", "the error must identify the failed CreateService step")
}
