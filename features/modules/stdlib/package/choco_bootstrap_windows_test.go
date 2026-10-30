// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package package_module

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// requireElevated skips t unless the test runs elevated. Securing the
// chocolatey staging base assigns BUILTIN\Administrators as owner, and the
// tests hand directories to other principals; both need an elevated
// administrator, as the steward (a SYSTEM service) and the native Windows CI
// runners are.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: securing the chocolatey staging base assigns BUILTIN\\Administrators as owner")
	}
}

// chocoStagingBaseOwnedBy creates a staging base under t.TempDir() owned by
// the owner in sddl (e.g. "O:BA").
func chocoStagingBaseOwnedBy(t *testing.T, sddl string) string {
	t.Helper()
	requireElevated(t)
	base := filepath.Join(t.TempDir(), "choco-staging")
	require.NoError(t, os.Mkdir(base, 0o700))
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	winacct.SetOwner(t, base, owner)
	return base
}

// newTestChocoStagingBase returns an admin-owned staging base so tests that
// run the real bootstrap never extract under the real %ProgramData%.
func newTestChocoStagingBase(t *testing.T) string {
	t.Helper()
	return chocoStagingBaseOwnedBy(t, "O:BA")
}

// isUnderDir reports whether path lies inside dir, ignoring case.
func isUnderDir(path, dir string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Clean(path)),
		strings.ToLower(filepath.Clean(dir))+string(filepath.Separator))
}

// bootstrapModule returns a module that will run the full bootstrap from a
// verified test nupkg, staging under base, with rec as its command runner.
func bootstrapModule(t *testing.T, base string, rec *recordingRunner) *PackageModule {
	t.Helper()
	nupkgDir := t.TempDir()
	nupkgBytes := buildTestNupkg(t, map[string]string{
		"tools/chocolateyInstall.ps1": "Write-Host 'installing'",
	})
	require.NoError(t, os.WriteFile(filepath.Join(nupkgDir, "chocolatey.nupkg"), nupkgBytes, 0o600))
	return &PackageModule{
		chocoSource:          nupkgDir,
		chocoSourceName:      "org",
		chocoBootstrapSHA256: sha256Hex(nupkgBytes),
		chocoExeExists:       func() bool { return false },
		chocoTrust:           func(string) error { return nil },
		runCommand:           rec.run,
		chocoStagingBase:     base,
	}
}

// TestBootstrapChocoReal_ExtractsUnderSecuredBase (REQUIRED, #5639): the
// installer's -File argument lies under the configured staging base and not
// under os.TempDir().
func TestBootstrapChocoReal_ExtractsUnderSecuredBase(t *testing.T) {
	base := chocoStagingBaseOwnedBy(t, "O:BA")
	// Move the system temporary directory elsewhere so a regression to
	// os.MkdirTemp("", ...) would extract there and fail the assertions.
	fakeTemp := filepath.Join(t.TempDir(), "system-temp")
	require.NoError(t, os.Mkdir(fakeTemp, 0o700))
	t.Setenv("TMP", fakeTemp)
	t.Setenv("TEMP", fakeTemp)
	require.True(t, strings.EqualFold(filepath.Clean(os.TempDir()), filepath.Clean(fakeTemp)))

	rec := &recordingRunner{}
	m := bootstrapModule(t, base, rec)
	require.NoError(t, m.bootstrapChocoReal(context.Background()))

	require.NotEmpty(t, rec.calls)
	installer := rec.calls[0]
	require.Equal(t, "powershell.exe", installer.name)
	require.Len(t, installer.args, 3)
	require.Equal(t, "-File", installer.args[1])
	path := installer.args[2]
	assert.True(t, isUnderDir(path, base), "installer %q must be under the staging base %q", path, base)
	assert.False(t, isUnderDir(path, os.TempDir()), "installer %q must not be under the system temporary directory", path)
	extractDir := filepath.Dir(filepath.Dir(path)) // <base>\bootstrap-*\tools\chocolateyInstall.ps1
	assert.True(t, strings.EqualFold(filepath.Dir(extractDir), base) &&
		strings.HasPrefix(filepath.Base(extractDir), "bootstrap-"),
		"installer %q must be extracted into a fresh bootstrap-* subdirectory of the base", path)
}

// TestBootstrapChocoReal_RefusesBaseOwnedByUsers (REQUIRED, #5639): with a
// staging base owned by BUILTIN\Users, the bootstrap returns an error,
// extracts nothing and never calls the command runner.
func TestBootstrapChocoReal_RefusesBaseOwnedByUsers(t *testing.T) {
	base := chocoStagingBaseOwnedBy(t, "O:BU")

	rec := &recordingRunner{}
	m := bootstrapModule(t, base, rec)
	err := m.bootstrapChocoReal(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUntrustedDirOwner)
	assert.Empty(t, rec.calls, "the installer must not run when the staging base cannot be secured")

	entries, rerr := os.ReadDir(base)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "nothing may be extracted into a refused base")
}

// TestBootstrapChocoReal_RemovesExtractionDir (REQUIRED, #5639): after the
// bootstrap returns, on success or failure, no extraction subdirectory remains
// under the base.
func TestBootstrapChocoReal_RemovesExtractionDir(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		base := chocoStagingBaseOwnedBy(t, "O:BA")
		rec := &recordingRunner{}
		require.NoError(t, bootstrapModule(t, base, rec).bootstrapChocoReal(context.Background()))
		entries, err := os.ReadDir(base)
		require.NoError(t, err)
		assert.Empty(t, entries, "the extraction directory must be removed after a successful bootstrap")
	})

	t.Run("installer failure", func(t *testing.T) {
		base := chocoStagingBaseOwnedBy(t, "O:BA")
		rec := &recordingRunner{err: os.ErrPermission}
		err := bootstrapModule(t, base, rec).bootstrapChocoReal(context.Background())
		require.Error(t, err)
		require.Len(t, rec.calls, 1, "the installer ran and failed")
		entries, rerr := os.ReadDir(base)
		require.NoError(t, rerr)
		assert.Empty(t, entries, "the extraction directory must be removed after a failed bootstrap")
	})
}

func TestChocoStagingDir_Default(t *testing.T) {
	t.Setenv("ProgramData", `D:\PD`)
	assert.Equal(t, `D:\PD\cfgms\choco-staging`, (&PackageModule{}).chocoStagingDir())
	t.Setenv("ProgramData", "")
	assert.Equal(t, `C:\ProgramData\cfgms\choco-staging`, (&PackageModule{}).chocoStagingDir())
	assert.Equal(t, `E:\x`, (&PackageModule{chocoStagingBase: `E:\x`}).chocoStagingDir())
}
