// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package initialization

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

const (
	winSIDSystem         = "S-1-5-18"
	winSIDAdministrators = "S-1-5-32-544"
	winSIDUsers          = "S-1-5-32-545"
)

// aceSIDs returns the SIDs named by the ACEs of path's DACL.
func aceSIDs(t *testing.T, path string) []string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	var sids []string
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return sids
}

func windowsTestConfig(t *testing.T) (base string, caDir string, bundlePath string) {
	t.Helper()
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	base = ControllerBaseDir()
	require.Equal(t, filepath.Join(programData, "cfgms"), base)
	return base, filepath.Join(base, "ca"), filepath.Join(base, "admin.bundle.yaml")
}

func TestRun_Windows_LocksDataTreeToAdmins(t *testing.T) {
	base, caDir, bundlePath := windowsTestConfig(t)
	cfg := makeTestConfig(t, filepath.Dir(base), caDir, bundlePath)

	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	var caKey string
	require.NoError(t, filepath.WalkDir(caDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "ca.key" {
			caKey = p
		}
		return err
	}))
	require.NotEmpty(t, caKey, "CA key must have been written under %s", caDir)
	for _, p := range []string{caKey, bundlePath} {
		require.FileExists(t, p)
		sids := aceSIDs(t, p)
		assert.NotContains(t, sids, winSIDUsers, "%s must grant BUILTIN\\Users nothing", p)
		assert.ElementsMatch(t, []string{winSIDSystem, winSIDAdministrators}, sids, p)
	}
	assert.Equal(t, winSIDAdministrators, winacct.Owner(t, base))
}

func TestRun_Windows_RefusesTreeOwnedByStandardUser(t *testing.T) {
	base, caDir, bundlePath := windowsTestConfig(t)
	require.NoError(t, os.Mkdir(base, 0755))
	user := winacct.StandardUser(t)
	winacct.SetOwner(t, base, user)

	cfg := makeTestConfig(t, filepath.Dir(base), caDir, bundlePath)
	_, err := Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUntrustedDirOwner)
	assert.Equal(t, user.String(), winacct.Owner(t, base), "an untrusted owner must never be replaced")
	assert.NoFileExists(t, bundlePath)
}

func TestRun_Windows_AdoptsTreeOwnedByAdministratorsMember(t *testing.T) {
	base, caDir, bundlePath := windowsTestConfig(t)
	require.NoError(t, os.Mkdir(base, 0755))
	winacct.SetOwner(t, base, winacct.LocalAccountSID(t, windows.WinBuiltinAdministratorsSid))
	member := winacct.OtherAdministratorsMember(t)
	stray := filepath.Join(base, "stray.txt")
	require.NoError(t, os.WriteFile(stray, []byte("x"), 0600))
	winacct.SetOwner(t, stray, member)

	cfg := makeTestConfig(t, filepath.Dir(base), caDir, bundlePath)
	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	assert.Equal(t, winSIDAdministrators, winacct.Owner(t, stray))
	assert.Equal(t, winSIDAdministrators, winacct.Owner(t, base))
}

// A bundle path outside %ProgramData%\cfgms must be refused before anything in
// either tree is touched: adoption rewrites the owner and DACL of every entry
// below the directory, which on an operator's own folder removes their access.
func TestRun_Windows_RefusesBundlePathOutsideBase(t *testing.T) {
	base, caDir, _ := windowsTestConfig(t)
	outside := filepath.Join(t.TempDir(), "Desktop")
	require.NoError(t, os.Mkdir(outside, 0755))
	existing := filepath.Join(outside, "notes.txt")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0600))
	ownerBefore := winacct.Owner(t, outside)
	fileOwnerBefore := winacct.Owner(t, existing)
	aclBefore := aceSIDs(t, outside)

	cfg := makeTestConfig(t, filepath.Dir(base), caDir, filepath.Join(outside, "admin.bundle.yaml"))
	_, err := Run(cfg, logging.NewNoopLogger())
	require.ErrorIs(t, err, ErrDataDirOutsideBase)

	assert.Equal(t, ownerBefore, winacct.Owner(t, outside), "an out-of-base directory must not be taken over")
	assert.Equal(t, fileOwnerBefore, winacct.Owner(t, existing), "entries below an out-of-base directory must not be taken over")
	assert.ElementsMatch(t, aclBefore, aceSIDs(t, outside), "an out-of-base directory DACL must not be rewritten")
	assert.NoDirExists(t, caDir, "nothing may be written when the data tree is refused")
	assert.NoFileExists(t, filepath.Join(outside, "admin.bundle.yaml"))
}

func TestAdoptControllerDataTree_Windows_RefusesRelativeAndOutsidePaths(t *testing.T) {
	base, caDir, bundlePath := windowsTestConfig(t)
	cases := map[string]struct{ ca, bundle string }{
		"relative bundle path":       {caDir, "admin.bundle.yaml"},
		"relative CA path":           {`certs\ca`, bundlePath},
		"CA path outside the base":   {filepath.Join(t.TempDir(), "ca"), bundlePath},
		"bundle in a prefix sibling": {caDir, filepath.Join(base+"-other", "admin.bundle.yaml")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := makeTestConfig(t, filepath.Dir(base), tc.ca, tc.bundle)
			require.ErrorIs(t, AdoptControllerDataTree(cfg), ErrDataDirOutsideBase)
			assert.NoDirExists(t, base, "nothing may be created when the data tree is refused")
		})
	}
}
