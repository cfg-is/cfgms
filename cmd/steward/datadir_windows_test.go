// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

const sidBuiltinAdministrators = "S-1-5-32-544"

// useStewardDataDir points the start-up lockdown at a fresh data directory
// owned by Administrators, with a certs child and a file in it.
func useStewardDataDir(t *testing.T) (dir, child, file string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	child = filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(child, 0755))
	file = filepath.Join(child, "ca.crt")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	winacct.SetOwner(t, dir, admins)

	prev := stewardDataDirResolver
	stewardDataDirResolver = func() string { return dir }
	t.Cleanup(func() { stewardDataDirResolver = prev })
	return dir, child, file
}

func TestSecureStewardDataDir_TakesOverEntriesOwnedByAnotherAdministratorsMember(t *testing.T) {
	// Files an administrator other than the account running the steward wrote,
	// as on a host upgraded to this steward.
	member := winacct.OtherAdministratorsMember(t)
	dir, child, file := useStewardDataDir(t)
	winacct.SetOwner(t, child, member)
	winacct.SetOwner(t, file, member)
	require.Equal(t, member.String(), winacct.Owner(t, file))

	logger := logging.NewCapturingLogger()
	require.NoError(t, secureStewardDataDir(logger))

	for _, p := range []string{child, file} {
		assert.Equal(t, sidBuiltinAdministrators, winacct.Owner(t, p), "%s must be handed to Administrators", p)
	}
	summary, ok := logger.FindInfo("Assigned steward data entries to BUILTIN\\Administrators")
	require.True(t, ok, "the takeover must be logged at Info")
	assert.Equal(t, 2, summary["count"])
	assert.Equal(t, logging.SanitizeLogValue(dir), summary["path"])
	entry, ok := logger.FindInfo("Took over steward data entry owned by a member of Administrators")
	require.True(t, ok, "each taken-over entry must be logged at Info")
	assert.Equal(t, logging.SanitizeLogValue(child), entry["path"])
	require.NoError(t, security.EnsureAdminOnlyDir(dir), "the taken-over tree must pass the strict check")
}

func TestSecureStewardDataDir_RefusesEntryOwnedByStandardUser(t *testing.T) {
	guest := winacct.StandardUser(t)
	_, _, file := useStewardDataDir(t)
	winacct.SetOwner(t, file, guest)
	require.Equal(t, guest.String(), winacct.Owner(t, file))

	err := secureStewardDataDir(logging.NewCapturingLogger())
	assert.ErrorIs(t, err, security.ErrUntrustedDirOwner, "the steward must refuse to start")
	assert.Equal(t, guest.String(), winacct.Owner(t, file), "a standard user's entry must never be adopted")
}

func TestRunStewardInternal_LocksDataDirBeforeCreatingLogFiles(t *testing.T) {
	guest := winacct.StandardUser(t)
	dir, _, file := useStewardDataDir(t)
	winacct.SetOwner(t, file, guest)
	logDir := filepath.Join(dir, "logs")
	t.Setenv("CFGMS_LOG_DIR", logDir)
	prevStore := certStoreDirResolver
	certStoreDirResolver = func() string { return t.TempDir() }
	t.Cleanup(func() { certStoreDirResolver = prevStore })

	// The refusal no longer ends the process: with no stored identity the
	// steward holds the alarm locally until it is stopped.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, runStewardInternal(ctx, "", "", "", nil))

	_, statErr := os.Stat(logDir)
	assert.True(t, os.IsNotExist(statErr), "no log directory may be created in the tree before the lockdown")
}

// A data directory owned by an unrelated non-admin principal: the steward does
// not exit, connects report-only to a real controller and the heartbeat
// carries the data-directory tamper code. Reverting the change makes
// runStewardInternal return the error, which fails the done check.
func TestRunStewardInternal_UnrelatedOwner_ReportsDataDirTamper(t *testing.T) {
	guest := winacct.StandardUser(t)
	dir, _, file := useStewardDataDir(t)
	winacct.SetOwner(t, file, guest)

	e := newAlarmEnv(t, trustSourceCompileBaked)
	dataDirCheck = secureStewardDataDir // the real check, not the test seam
	t.Setenv("CFGMS_LOG_DIR", filepath.Join(dir, "logs"))

	stop, done := e.runSteward(t, "", e.cf())
	hb := tamperHeartbeat(t, e.f.srv, cpTypes.ReasonCodeTamperDataDir)
	assert.Equal(t, cpTypes.StatusError, hb.Status)
	assertAlive(t, done)
	assert.Zero(t, e.connect.Load(), "the normal connect is never attempted")
	assert.Equal(t, guest.String(), winacct.Owner(t, file), "a standard user's entry must never be adopted")
	require.NoError(t, stop())
}
