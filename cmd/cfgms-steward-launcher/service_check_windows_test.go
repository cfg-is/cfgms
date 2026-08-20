// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"fmt"
	"os"
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

	// Delete it → missing again → (false, nil).
	existing, err := scm.OpenService(name)
	require.NoError(t, err)
	require.NoError(t, existing.Delete())
	require.NoError(t, existing.Close())

	ok, err = serviceRegistrationOK(name)
	require.NoError(t, err)
	assert.False(t, ok, "a deleted service must read as missing (the repair trigger)")
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

	args := []string{"run", "--root", `C:\Program Files\CFGMS`, "--child-args", "--regtoken abc"}
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
	assert.Equal(t, mgr.StartAutomatic, cfg.StartType, "start type must match install")
	assert.Equal(t, launcherServiceDisplayName, cfg.DisplayName)
	assert.Equal(t, launcherServiceDescription, cfg.Description)
	assert.Contains(t, cfg.BinaryPathName, testRepairExePath,
		"repaired service must point at the launcher install path")
	assert.Contains(t, cfg.BinaryPathName, "--regtoken abc",
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
