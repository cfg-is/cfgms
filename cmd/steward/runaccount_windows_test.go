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
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// ownAccountTree builds a data directory with a certs child and a file, all
// owned by account and protected by a DACL granting SYSTEM, Administrators and
// account (plus extraACE, an SDDL ACE string, when non-empty).
func ownAccountTree(t *testing.T, account *windows.SID, extraACE string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0o755))
	child := filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(child, 0o755))
	file := filepath.Join(child, "ca.crt")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + account.String() + ")" + extraACE
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	for _, p := range []string{file, child, dir} {
		require.NoError(t, windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil))
		winacct.SetOwner(t, p, account)
	}

	prev := stewardDataDirResolver
	stewardDataDirResolver = func() string { return dir }
	t.Cleanup(func() { stewardDataDirResolver = prev })
	return dir
}

// runAs makes the data directory check treat sid as the (non-default) account
// the steward runs as.
func runAs(t *testing.T, sid *windows.SID) {
	t.Helper()
	prev := processRunAccount
	processRunAccount = func() runAccount {
		return runAccount{Name: "test-account", SID: sid.String(), Missing: []string{"take ownership"}}
	}
	t.Cleanup(func() { processRunAccount = prev })
}

func TestSecureStewardDataDir_OwnNonSystemAccount_NoTamperAlarm(t *testing.T) {
	account := winacct.StandardUser(t)
	dir := ownAccountTree(t, account, "")
	runAs(t, account)

	class, err := classifyDataDir(dir, account.String())
	require.NoError(t, err)
	assert.Equal(t, dataDirOwnAccount, class)

	logger := logging.NewCapturingLogger()
	require.NoError(t, secureStewardDataDir(logger), "an own-account data directory must not raise the tamper alarm")
	_, own := logger.FindWarn("Steward data directory is owned by the run account; leaving ownership unchanged")
	assert.True(t, own, "the legitimate own-account case is logged as a warning, not refused")
	assert.Equal(t, account.String(), winacct.Owner(t, dir), "ownership must be left unchanged")
}

func TestSecureStewardDataDir_OwnAccountWithForeignWriteACE_RaisesTamperAlarm(t *testing.T) {
	account := winacct.StandardUser(t)
	// BUILTIN\Users: another non-admin principal with write access.
	dir := ownAccountTree(t, account, "(A;OICI;FA;;;BU)")
	runAs(t, account)

	class, err := classifyDataDir(dir, account.String())
	require.NoError(t, err)
	assert.Equal(t, dataDirTampered, class)

	logger := logging.NewCapturingLogger()
	err = secureStewardDataDir(logger)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUntrustedDirEntry)
	_, own := logger.FindWarn("Steward data directory is owned by the run account; leaving ownership unchanged")
	assert.False(t, own, "a tampered tree must not be accepted as the own-account case")
}

func TestClassifyDataDir_OwnedByAnotherPrincipalIsNotOwnAccount(t *testing.T) {
	account := winacct.StandardUser(t)
	dir := ownAccountTree(t, account, "")
	other := winacct.OtherAdministratorsMember(t)

	class, err := classifyDataDir(dir, other.String())
	require.NoError(t, err)
	assert.Equal(t, dataDirNotOwned, class, "another principal's directory is left to the regular lockdown")
}

func TestCurrentRunAccount_DefaultMatchesToken(t *testing.T) {
	acct := currentRunAccount()
	assert.NotEmpty(t, acct.SID)
	assert.Equal(t, acct.Default, len(acct.Missing) == 0)
}
