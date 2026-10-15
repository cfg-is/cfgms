// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "modules")
	require.NoError(t, EnsureProtectedDir(root))
	mod := filepath.Join(root, "widget")
	require.NoError(t, EnsureProtectedDir(mod))
	require.NoError(t, os.WriteFile(filepath.Join(mod, "module.yaml"), []byte("name: widget\n"), 0o644)) // #nosec G306 -- test fixture
	return root
}

// [REQUIRED TEST] a created tree passes; a tree writable by non-administrators
// is refused.
func TestCheckProtectedTree_AcceptsCreatedTree(t *testing.T) {
	require.NoError(t, CheckProtectedTree(writeTree(t)))
}

func TestCheckProtectedTree_RefusesWritableTree(t *testing.T) {
	root := writeTree(t)
	file := filepath.Join(root, "widget", "module.yaml")

	if runtime.GOOS == "windows" {
		// Users (S-1-5-32-545) given write on a module directory.
		out, err := exec.Command("icacls", filepath.Join(root, "widget"), "/grant", "*S-1-5-32-545:(OI)(CI)W").CombinedOutput()
		require.NoError(t, err, string(out))
		assert.ErrorIs(t, CheckProtectedTree(root), ErrTreeNotProtected)
		return
	}

	require.NoError(t, os.Chmod(file, 0o666)) // #nosec G302 -- deliberately unsafe fixture
	assert.ErrorIs(t, CheckProtectedTree(root), ErrTreeNotProtected, "world-writable file")
	require.NoError(t, os.Chmod(file, 0o644)) // #nosec G302
	require.NoError(t, CheckProtectedTree(root))

	require.NoError(t, os.Chmod(filepath.Join(root, "widget"), 0o775)) // #nosec G302 -- deliberately unsafe fixture
	assert.ErrorIs(t, CheckProtectedTree(root), ErrTreeNotProtected, "group-writable directory")
	require.NoError(t, os.Chmod(filepath.Join(root, "widget"), 0o755)) // #nosec G302

	require.NoError(t, os.Symlink(file, filepath.Join(root, "widget", "link")))
	assert.ErrorIs(t, CheckProtectedTree(root), ErrTreeNotProtected, "symlink entry")
}

func TestEnsureProtectedDir_TightensExistingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits do not exist on Windows; the ACL path is covered by TestCheckProtectedTree_*")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	require.NoError(t, os.Mkdir(dir, 0o777)) // #nosec G301 -- deliberately unsafe fixture
	require.NoError(t, os.Chmod(dir, 0o777)) // #nosec G302
	require.NoError(t, EnsureProtectedDir(dir))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

// A root owned by a different non-root uid is refused. Creating such a root
// needs chown, which only root may do; as an unprivileged user that sub-case
// cannot be created and is skipped, while the owner rule itself is covered by
// TestOwnerAcceptable on every platform.
func TestCheckProtectedTree_RefusesForeignOwner(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("creating a directory owned by another non-root uid requires root on Unix")
	}
	root := writeTree(t)
	require.NoError(t, os.Chown(filepath.Join(root, "widget"), 12345, 12345))
	assert.ErrorIs(t, CheckProtectedTree(root), ErrTreeNotProtected)
}

func TestOwnerAcceptable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uid ownership is a Unix rule")
	}
	assert.True(t, ownerAcceptable(0, 1000))
	assert.True(t, ownerAcceptable(1000, 1000))
	assert.False(t, ownerAcceptable(2000, 1000))
}

func TestCheckSDDL(t *testing.T) {
	protected := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
	assert.NoError(t, checkSDDL(protected))
	assert.NoError(t, checkSDDL("O:BAG:SYD:P(A;OICI;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"))
	assert.NoError(t, checkSDDL(protected+"(D;;FA;;;WD)"), "deny entries do not widen access")

	assert.ErrorIs(t, checkSDDL("D:P(A;OICI;FA;;;SY)(A;OICI;GRGXGW;;;BU)"), ErrTreeNotProtected, "Users write")
	assert.ErrorIs(t, checkSDDL("D:P(A;OICI;0x1301bf;;;AU)"), ErrTreeNotProtected, "authenticated users modify")
	assert.ErrorIs(t, checkSDDL("D:(A;;FA;;;WD)"), ErrTreeNotProtected, "everyone full control")
	assert.ErrorIs(t, checkSDDL("D:P(A;OICI;WD;;;BU)"), ErrTreeNotProtected, "write DAC")
	assert.ErrorIs(t, checkSDDL("D:P(A;OICI;zzz;;;BU)"), ErrTreeNotProtected, "unparseable rights count as write")
	assert.ErrorIs(t, checkSDDL("D:P(A;OICI;FA"), ErrTreeNotProtected, "malformed ACE")
	assert.ErrorIs(t, checkSDDL("nodacl"), ErrTreeNotProtected)
	assert.ErrorIs(t, checkSDDL("D:P(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)"), ErrTreeNotProtected, "other NT SERVICE account is not TrustedInstaller")
	assert.ErrorIs(t, checkSDDL("D:P(XA;OICI;FA;;;BU;(@User.x==1))"), ErrTreeNotProtected, "callback allow entry")
	assert.ErrorIs(t, checkSDDL("D:P(Q;;FA;;;BU)"), ErrTreeNotProtected, "unknown ACE type fails closed")
}
