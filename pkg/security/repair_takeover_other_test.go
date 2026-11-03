// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package security

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// asCurrentUser lets the walk run without root: the owner it assigns becomes
// the caller, so the mode and link handling are exercised everywhere.
func asCurrentUser(t *testing.T) {
	t.Helper()
	old := repairOwnerUID
	repairOwnerUID = os.Geteuid()
	t.Cleanup(func() { repairOwnerUID = old })
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	return fi.Mode()
}

func TestTakeOverForRepair_ResetsModesAndKeepsContent(t *testing.T) {
	asCurrentUser(t)
	root := t.TempDir()
	sub := filepath.Join(root, "certs")
	require.NoError(t, os.Mkdir(sub, 0777))
	file := filepath.Join(sub, "ca.pem")
	require.NoError(t, os.WriteFile(file, []byte("pem-bytes"), 0666))
	require.NoError(t, os.Chmod(file, 0666))
	require.NoError(t, os.Chmod(sub, 0777))

	rep, err := TakeOverForRepair([]string{root})
	require.NoError(t, err)
	assert.Contains(t, rep.Secured, sub)
	assert.Contains(t, rep.Secured, file)
	assert.Equal(t, os.FileMode(0700), modeOf(t, sub).Perm())
	assert.Equal(t, os.FileMode(0600), modeOf(t, file).Perm())
	got, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, "pem-bytes", string(got))
}

func TestTakeOverForRepair_AssignsRootOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("assigning root ownership requires running as root; the walk is covered by the other tests")
	}
	root := t.TempDir()
	file := filepath.Join(root, "f")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0644))
	require.NoError(t, os.Chown(file, 4242, 4242))

	_, err := TakeOverForRepair([]string{root})
	require.NoError(t, err)
	var st syscall.Stat_t
	require.NoError(t, syscall.Stat(file, &st))
	assert.Equal(t, uint32(0), st.Uid)
}

func TestTakeOverForRepair_LinksToOutsideAreQuarantinedNotFollowed(t *testing.T) {
	asCurrentUser(t)
	outside := t.TempDir()
	targetFile := filepath.Join(outside, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("outside"), 0644))
	targetDir := filepath.Join(outside, "dir")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	inner := filepath.Join(targetDir, "inner")
	require.NoError(t, os.WriteFile(inner, []byte("i"), 0644))

	root := t.TempDir()
	fileLink := filepath.Join(root, "file-link")
	dirLink := filepath.Join(root, "dir-link")
	hard := filepath.Join(root, "hard")
	require.NoError(t, os.Symlink(targetFile, fileLink))
	require.NoError(t, os.Symlink(targetDir, dirLink))
	require.NoError(t, os.Link(targetFile, hard))

	beforeFile := modeOf(t, targetFile)
	beforeDir := modeOf(t, targetDir)
	beforeInner := modeOf(t, inner)

	rep, err := TakeOverForRepair([]string{root})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{fileLink, dirLink, hard}, rep.Quarantined)
	for _, p := range []string{fileLink, dirLink, hard} {
		_, err := os.Lstat(p)
		assert.True(t, os.IsNotExist(err), "%s must be removed", p)
	}
	assert.Equal(t, beforeFile, modeOf(t, targetFile))
	assert.Equal(t, beforeDir, modeOf(t, targetDir))
	assert.Equal(t, beforeInner, modeOf(t, inner))
	got, err := os.ReadFile(targetFile)
	require.NoError(t, err)
	assert.Equal(t, "outside", string(got))
}

func TestTakeOverForRepair_NeverTouchesPathsOutsideRoots(t *testing.T) {
	asCurrentUser(t)
	// Getwd reports the resolved path (/private/var on macOS), so resolve the
	// temp dir the same way before comparing paths.
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "root")
	sibling := filepath.Join(base, "sibling")
	require.NoError(t, os.Mkdir(root, 0755))
	require.NoError(t, os.Mkdir(sibling, 0755))
	sibFile := filepath.Join(sibling, "f")
	require.NoError(t, os.WriteFile(sibFile, []byte("s"), 0644))
	require.NoError(t, os.Symlink("../sibling", filepath.Join(root, "up")))

	before := modeOf(t, sibling)
	beforeFile := modeOf(t, sibFile)

	// A relative root with a ".." component still resolves to root only.
	wd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(wd) })
	require.NoError(t, os.Chdir(sibling))
	rep, err := TakeOverForRepair([]string{"../root"})
	require.NoError(t, err)

	assert.Equal(t, []string{filepath.Join(root, "up")}, rep.Quarantined)
	assert.Equal(t, before, modeOf(t, sibling))
	assert.Equal(t, beforeFile, modeOf(t, sibFile))
	assert.NotContains(t, rep.Secured, sibling)
}

func TestTakeOverForRepair_RootThatIsALinkIsRefused(t *testing.T) {
	asCurrentUser(t)
	outside := t.TempDir()
	require.NoError(t, os.Chmod(outside, 0755))
	link := filepath.Join(t.TempDir(), "root-link")
	require.NoError(t, os.Symlink(outside, link))

	rep, err := TakeOverForRepair([]string{link})
	require.ErrorIs(t, err, ErrTakeoverIncomplete)
	assert.Len(t, rep.Refused, 1)
	assert.Equal(t, os.FileMode(0755), modeOf(t, outside).Perm())
	_, lerr := os.Lstat(link)
	assert.NoError(t, lerr, "a declared root is refused, not removed")
}

func TestTakeOverForRepair_RejectsBadRoots(t *testing.T) {
	_, err := TakeOverForRepair(nil)
	assert.Error(t, err)
	_, err = TakeOverForRepair([]string{""})
	assert.Error(t, err)
}

func TestTakeOverForRepair_MissingRootIsSkipped(t *testing.T) {
	rep, err := TakeOverForRepair([]string{filepath.Join(t.TempDir(), "absent")})
	require.NoError(t, err)
	assert.Empty(t, rep.Secured)
}

func TestTakeOverForRepair_DoesNotChangeStartupBehavior(t *testing.T) {
	// Outside Windows the startup helpers are no-ops; the takeover must not
	// have changed that, nor be reachable from them.
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0777))
	require.NoError(t, EnsureAdminOnlyDir(dir))
	adopted, err := AdoptAdminOnlyDir(dir)
	require.NoError(t, err)
	assert.Empty(t, adopted)
	assert.Equal(t, os.FileMode(0777), modeOf(t, dir).Perm())
}
