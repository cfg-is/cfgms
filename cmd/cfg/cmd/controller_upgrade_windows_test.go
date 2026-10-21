// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/controller/cutover"
	"github.com/cfgis/cfgms/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// grantUsers adds an ACL entry for BUILTIN\Users (S-1-5-32-545) on path.
func grantUsers(t *testing.T, path, perm string) {
	t.Helper()
	out, err := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:"+perm).CombinedOutput()
	require.NoError(t, err, "icacls: %s", out)
}

// A state file writable by BUILTIN\Users is refused by run, rollback and status.
func TestControllerUpgrade_RefusesUserWritableStateFile(t *testing.T) {
	saveRestartGlobals(t)
	bin := filepath.Join(t.TempDir(), "new-binary.exe")
	require.NoError(t, os.WriteFile(bin, []byte("x"), 0o700))
	upgradeBinaryPath = bin
	upgradeConfigPath = filepath.Join(t.TempDir(), "controller.cfg")
	upgradeStatusJSON = false

	upgradeStatePath = newStateFile(t, cutover.PersistedState{
		CanonicalBinary:   bin,
		QuarantinedBinary: bin,
	})
	grantUsers(t, upgradeStatePath, "(M)")

	err := runControllerUpgrade(controllerUpgradeRunCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state")
	err = runControllerUpgradeRollback(controllerUpgradeRollbackCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state")
	err = runControllerUpgradeStatus(controllerUpgradeStatusCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state")
}

func TestControllerUpgradeRollback_QuarantinedBinaryDACL(t *testing.T) {
	newBinary := func(t *testing.T) string {
		dir := filepath.Join(t.TempDir(), "bin")
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, security.EnsureAdminOnlyDir(dir))
		p := filepath.Join(dir, "quarantined.exe")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o700))
		return p
	}

	t.Run("users write refused", func(t *testing.T) {
		saveRestartGlobals(t)
		q := newBinary(t)
		grantUsers(t, q, "(M)")
		upgradeConfigPath = filepath.Join(t.TempDir(), "controller.cfg")
		upgradeStatePath = newStateFile(t, cutover.PersistedState{CanonicalBinary: q, QuarantinedBinary: q})

		err := runControllerUpgradeRollback(controllerUpgradeRollbackCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "QuarantinedBinary")
	})

	t.Run("users read+execute accepted by validation", func(t *testing.T) {
		q := newBinary(t)
		grantUsers(t, q, "(RX)")
		assert.NoError(t, validateStateBinary("QuarantinedBinary", q))
	})
}
