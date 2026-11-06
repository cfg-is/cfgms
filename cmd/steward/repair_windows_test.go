// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// A data directory owned by an unrelated principal, repaired with no loss: the
// owner and DACL come back through the rights reset, and the steward ID, the log
// files and the action-history file are byte-identical afterwards. Nothing is
// deleted.
func TestRepair_Windows_UnrelatedOwnerRestoredThroughTakeover_NothingLost(t *testing.T) {
	guest := winacct.StandardUser(t)
	f := newRepairFixture(t, repairFixtureOpts{})

	dir, _, _ := useStewardDataDir(t)
	logDir := filepath.Join(dir, "logs")
	require.NoError(t, os.Mkdir(logDir, 0o755))
	logFile := filepath.Join(logDir, "steward.log")
	require.NoError(t, os.WriteFile(logFile, []byte("log line one\nlog line two\n"), 0o600))
	f.paths = repairPaths{dataDir: dir, certStoreDir: f.env.f.dir, logDir: logDir}
	history := f.paths.actionHistory()
	require.NoError(t, os.WriteFile(history, []byte(`{"action":"first"}`+"\n"), 0o600))
	for _, p := range []string{logDir, logFile, history} {
		winacct.SetOwner(t, p, guest)
		require.Equal(t, guest.String(), winacct.Owner(t, p))
	}
	logBefore, historyBefore := readFile(t, logFile), readFile(t, history)
	idBefore, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)

	dataDirCheck = secureStewardDataDir // the real check, not the test seam
	f.start()
	f.ctrl.allow("repair-windows")
	f.send(f.request("repair-windows", requestOpts{}))
	awaitOutcome(t, f, cpTypes.ReasonCodeRepairCompleted)

	for _, p := range []string{dir, logDir, logFile, history} {
		assert.Equal(t, sidBuiltinAdministrators, winacct.Owner(t, p), "%s is owned by Administrators again", p)
	}
	require.NoError(t, security.EnsureAdminOnlyDir(dir), "the DACL passes the strict check")

	idAfter, err := loadIdentity(f.env.f.dir)
	require.NoError(t, err)
	assert.Equal(t, idBefore.StewardID, idAfter.StewardID)
	assert.Equal(t, logBefore, readFile(t, logFile))
	assert.Equal(t, historyBefore, readFile(t, history))
	assert.Empty(t, f.removedPaths(), "no file was deleted")
}
