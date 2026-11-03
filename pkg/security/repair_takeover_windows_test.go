// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// makeJunction plants a directory junction at link pointing at target.
func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestTakeOverForRepair_TakesTreeOwnedByNonAdmin(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	sub := filepath.Join(root, "certs")
	require.NoError(t, os.MkdirAll(sub, 0755))
	file := filepath.Join(sub, "ca.pem")
	require.NoError(t, os.WriteFile(file, []byte("pem-bytes"), 0644))

	user := winacct.StandardUser(t)
	for _, p := range []string{file, sub, root} {
		winacct.SetOwner(t, p, user)
		require.Equal(t, user.String(), winacct.Owner(t, p))
	}
	// The startup checks refuse this tree before and after the takeover is
	// available; they must not have learned to take it over.
	require.ErrorIs(t, EnsureAdminOnlyDir(root), ErrUntrustedDirOwner)
	_, err := AdoptAdminOnlyDir(root)
	require.ErrorIs(t, err, ErrUntrustedDirOwner)

	rep, err := TakeOverForRepair([]string{root})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{root, sub, file}, rep.Secured)

	for _, p := range []string{root, sub, file} {
		assert.Equal(t, sidAdministrators, winacct.Owner(t, p))
		sids, protected := daclSIDs(t, p)
		assert.True(t, protected, p)
		assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids, p)
	}
	require.NoError(t, checkTree(root, true))
	got, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, "pem-bytes", string(got))
}

func TestTakeOverForRepair_LinksToOutsideAreNotFollowed(t *testing.T) {
	outside := t.TempDir()
	targetFile := filepath.Join(outside, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("outside"), 0644))
	targetDir := filepath.Join(outside, "dir")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	inner := filepath.Join(targetDir, "inner")
	require.NoError(t, os.WriteFile(inner, []byte("i"), 0644))

	root := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.Mkdir(root, 0755))
	junction := filepath.Join(root, "junction")
	hard := filepath.Join(root, "hard")
	makeJunction(t, junction, targetDir)
	require.NoError(t, os.Link(targetFile, hard))

	paths := []string{targetFile, targetDir, inner}
	owners := map[string]string{}
	daclBefore := map[string][]string{}
	for _, p := range paths {
		owners[p] = winacct.Owner(t, p)
		daclBefore[p], _ = daclSIDs(t, p)
	}

	rep, err := TakeOverForRepair([]string{root})
	require.ErrorIs(t, err, ErrTakeoverIncomplete, "a hard-linked file is refused")

	assert.Equal(t, []string{junction}, rep.Quarantined)
	require.Len(t, rep.Refused, 1)
	assert.Contains(t, rep.Refused[0], hard)
	_, lerr := os.Lstat(junction)
	assert.True(t, os.IsNotExist(lerr), "junction must be removed")
	for _, p := range paths {
		assert.Equal(t, owners[p], winacct.Owner(t, p), p)
		after, _ := daclSIDs(t, p)
		assert.Equal(t, daclBefore[p], after, p)
	}
	got, err := os.ReadFile(inner)
	require.NoError(t, err, "the junction target must survive")
	assert.Equal(t, "i", string(got))
}

func TestTakeOverForRepair_NeverTouchesPathsOutsideRoots(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	sibling := filepath.Join(base, "sibling")
	require.NoError(t, os.Mkdir(root, 0755))
	require.NoError(t, os.Mkdir(sibling, 0755))
	makeJunction(t, filepath.Join(root, "up"), sibling)

	ownerBefore := winacct.Owner(t, sibling)
	daclBefore, _ := daclSIDs(t, sibling)

	wd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(wd) })
	require.NoError(t, os.Chdir(sibling))
	rep, err := TakeOverForRepair([]string{`..\root`})
	require.NoError(t, err)

	assert.Equal(t, []string{filepath.Join(root, "up")}, rep.Quarantined)
	assert.NotContains(t, rep.Secured, sibling)
	assert.Equal(t, ownerBefore, winacct.Owner(t, sibling))
	daclAfter, _ := daclSIDs(t, sibling)
	assert.Equal(t, daclBefore, daclAfter)
}

func TestTakeOverForRepair_RejectsBadRoots(t *testing.T) {
	_, err := TakeOverForRepair(nil)
	assert.Error(t, err)
	_, err = TakeOverForRepair([]string{""})
	assert.Error(t, err)
}
