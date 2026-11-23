// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build !windows

package package_module

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrewLocationFor(t *testing.T) {
	arm, err := brewLocationFor("arm64")
	require.NoError(t, err)
	assert.Equal(t, "/opt/homebrew/bin/brew", arm.BinPath)
	assert.Equal(t, "/opt/homebrew", arm.RepoDir)

	intel, err := brewLocationFor("amd64")
	require.NoError(t, err)
	assert.Equal(t, "/usr/local/bin/brew", intel.BinPath)
	// The owner comes from the repository dir; /usr/local is root-owned.
	assert.Equal(t, "/usr/local/Homebrew", intel.RepoDir)

	_, err = brewLocationFor("386")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported architecture")
}

// fakeLookup returns an account for any uid, like a populated passwd file.
func fakeLookup(uid string) (*user.User, error) {
	return &user.User{Uid: uid, Gid: "20", HomeDir: "/Users/brewowner"}, nil
}

// brewFixture creates a repository directory and an executable brew file under
// t.TempDir(). When the tests run as root, the files are owned by root, so
// ownerless refusals are exercised by chowning where possible.
type brewFixture struct {
	loc  brewLocation
	uid  uint32 // owner of the repository directory
	root bool
}

func newBrewFixture(t *testing.T) brewFixture {
	t.Helper()
	dir := t.TempDir()
	repo := filepath.Join(dir, "Homebrew")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	require.NoError(t, os.Mkdir(repo, 0o755))
	bin := filepath.Join(dir, "bin", "brew")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))
	f := brewFixture{loc: brewLocation{BinPath: bin, RepoDir: repo}, root: os.Geteuid() == 0}
	if f.root {
		// Root-owned repo is refused, so give it a non-root owner.
		f.uid = 501
		require.NoError(t, os.Chown(repo, 501, 20))
		require.NoError(t, os.Chown(bin, 501, 20))
	} else {
		f.uid = uint32(os.Geteuid())
	}
	return f
}

func TestResolveBrewAt_OK(t *testing.T) {
	f := newBrewFixture(t)
	got, err := resolveBrewAt(f.loc, fakeLookup)
	require.NoError(t, err)
	assert.Equal(t, f.uid, got.UID)
	assert.Equal(t, uint32(20), got.GID)
	assert.Equal(t, "/Users/brewowner", got.Home)
	assert.Equal(t, f.loc.BinPath, got.BinPath)
	assert.Equal(t, filepath.Dir(f.loc.BinPath), got.BinDir)
	assert.Equal(t, f.loc.RepoDir, got.RepoDir)
}

func TestResolveBrewAt_SymlinkedBinaryAndGroupWritable(t *testing.T) {
	f := newBrewFixture(t)
	// Real brew lives in the repository and bin/brew is a symlink to it.
	real := filepath.Join(f.loc.RepoDir, "brew-real")
	require.NoError(t, os.WriteFile(real, []byte("#!/bin/sh\n"), 0o775))
	require.NoError(t, os.Chmod(real, 0o775)) // group-writable is allowed
	if f.root {
		require.NoError(t, os.Chown(real, 501, 20))
	}
	link := filepath.Join(filepath.Dir(f.loc.BinPath), "brew-link")
	require.NoError(t, os.Symlink(real, link))
	f.loc.BinPath = link

	_, err := resolveBrewAt(f.loc, fakeLookup)
	require.NoError(t, err)

	// World-writable on the resolved file is refused even through the link.
	require.NoError(t, os.Chmod(real, 0o777))
	_, err = resolveBrewAt(f.loc, fakeLookup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "world-writable")
}

func TestResolveBrewAt_Refusals(t *testing.T) {
	t.Run("homebrew not installed (no repository)", func(t *testing.T) {
		f := newBrewFixture(t)
		f.loc.RepoDir = filepath.Join(t.TempDir(), "absent")
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not installed")
	})

	t.Run("brew binary missing", func(t *testing.T) {
		f := newBrewFixture(t)
		require.NoError(t, os.Remove(f.loc.BinPath))
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not installed")
	})

	t.Run("repository path is a file", func(t *testing.T) {
		f := newBrewFixture(t)
		file := filepath.Join(t.TempDir(), "repo")
		require.NoError(t, os.WriteFile(file, nil, 0o644))
		f.loc.RepoDir = file
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a directory")
	})

	t.Run("repository unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can traverse any directory; the unreadable-parent case needs an unprivileged user")
		}
		f := newBrewFixture(t)
		parent := t.TempDir()
		repo := filepath.Join(parent, "Homebrew")
		require.NoError(t, os.Mkdir(repo, 0o755))
		require.NoError(t, os.Chmod(parent, 0o000))
		t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
		f.loc.RepoDir = repo
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be determined")
	})

	t.Run("repository owned by root", func(t *testing.T) {
		// "/" is a real root-owned directory on every unix host.
		f := newBrewFixture(t)
		f.loc.RepoDir = "/"
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "owned by root")
	})

	t.Run("binary world-writable", func(t *testing.T) {
		f := newBrewFixture(t)
		require.NoError(t, os.Chmod(f.loc.BinPath, 0o757))
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "world-writable")
	})

	t.Run("binary not executable", func(t *testing.T) {
		f := newBrewFixture(t)
		require.NoError(t, os.Chmod(f.loc.BinPath, 0o644))
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not executable")
	})

	t.Run("binary is a directory", func(t *testing.T) {
		f := newBrewFixture(t)
		f.loc.BinPath = filepath.Dir(f.loc.BinPath)
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	})

	t.Run("binary owned by neither root nor the prefix owner", func(t *testing.T) {
		f := newBrewFixture(t)
		if f.root {
			require.NoError(t, os.Chown(f.loc.BinPath, 4242, 20))
		} else {
			// The binary stays owned by the current (non-root) user; make the
			// repository's owner look different by checking the binary rule directly.
			err := checkBrewBinary(f.loc.BinPath, f.uid+1)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "neither root nor the prefix owner")
			return
		}
		_, err := resolveBrewAt(f.loc, fakeLookup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "neither root nor the prefix owner")
	})

	t.Run("no account for the owner uid", func(t *testing.T) {
		f := newBrewFixture(t)
		_, err := resolveBrewAt(f.loc, func(string) (*user.User, error) {
			return nil, errors.New("user: unknown userid")
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be determined")
	})

	t.Run("account with bad gid", func(t *testing.T) {
		f := newBrewFixture(t)
		_, err := resolveBrewAt(f.loc, func(uid string) (*user.User, error) {
			return &user.User{Uid: uid, Gid: "staff", HomeDir: "/Users/x"}, nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid primary gid")
	})

	t.Run("account without home", func(t *testing.T) {
		f := newBrewFixture(t)
		_, err := resolveBrewAt(f.loc, func(uid string) (*user.User, error) {
			return &user.User{Uid: uid, Gid: "20"}, nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no home directory")
	})
}

func TestResolveBrewAt_RootOwnerNeverLooksUpAccount(t *testing.T) {
	// A root-owned repository is refused before any account lookup happens.
	f := newBrewFixture(t)
	f.loc.RepoDir = "/"
	called := false
	_, err := resolveBrewAt(f.loc, func(uid string) (*user.User, error) {
		called = true
		return fakeLookup(uid)
	})
	require.Error(t, err)
	assert.False(t, called)
}

func TestResolveBrew_UnsupportedArch(t *testing.T) {
	_, err := resolveBrew("riscv64")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported architecture")
}

func TestBuildBrewCmd(t *testing.T) {
	target := &brewTarget{
		BinPath: "/opt/homebrew/bin/brew",
		BinDir:  "/opt/homebrew/bin",
		RepoDir: "/opt/homebrew",
		UID:     501,
		GID:     20,
		Home:    "/Users/brewowner",
	}
	cmd := buildBrewCmd(context.Background(), target, "install", "wget")

	assert.Equal(t, "/opt/homebrew/bin/brew", cmd.Path)
	assert.Equal(t, []string{"/opt/homebrew/bin/brew", "install", "wget"}, cmd.Args)
	assert.Equal(t, "/opt/homebrew", cmd.Dir)
	require.NotNil(t, cmd.SysProcAttr)
	require.NotNil(t, cmd.SysProcAttr.Credential)
	assert.Equal(t, uint32(501), cmd.SysProcAttr.Credential.Uid)
	assert.Equal(t, uint32(20), cmd.SysProcAttr.Credential.Gid)
	assert.Equal(t, os.Geteuid() != 0, cmd.SysProcAttr.Credential.NoSetGroups)

	assert.Contains(t, cmd.Env, "HOME=/Users/brewowner")
	assert.Contains(t, cmd.Env, "PATH=/opt/homebrew/bin:/usr/bin:/bin")
	assert.Contains(t, cmd.Env, "HOMEBREW_NO_AUTO_UPDATE=1")
	assert.Len(t, cmd.Env, 3, "environment is explicit, nothing inherited")

	// No shell and no sudo: the program is brew itself and no argv is a
	// shell/sudo wrapper or command string.
	assert.NotContains(t, cmd.Path, "sh")
	for _, a := range cmd.Args {
		assert.NotContains(t, []string{"sh", "-c", "bash", "sudo", "su"}, a)
	}
	assert.Nil(t, cmd.Process, "the command is built, not started")
}

func TestBuildBrewCmd_NoShellMetacharacterExpansion(t *testing.T) {
	target := &brewTarget{BinPath: "/usr/local/bin/brew", BinDir: "/usr/local/bin", RepoDir: "/usr/local/Homebrew", UID: 501, GID: 20, Home: "/Users/x"}
	cmd := buildBrewCmd(context.Background(), target, "uninstall", "a;rm -rf /")
	assert.Equal(t, []string{"/usr/local/bin/brew", "uninstall", "a;rm -rf /"}, cmd.Args)
	assert.Equal(t, "PATH=/usr/local/bin:/usr/bin:/bin", cmd.Env[0])
}

func TestBrewManager_NotInstalledRunsNothing(t *testing.T) {
	// On a non-macOS host the fixed Homebrew paths are absent, so every
	// operation must fail with a clear cause and never start brew.
	if _, err := os.Stat("/opt/homebrew"); err == nil {
		t.Skip("a Homebrew installation is present on this host")
	}
	if _, err := os.Stat("/usr/local/Homebrew"); err == nil {
		t.Skip("a Homebrew installation is present on this host")
	}
	ctx := context.Background()
	m := &homebrewManager{}

	err := m.Install(ctx, "wget", "latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not installed")
	assert.Error(t, m.Remove(ctx, "wget"))
	assert.Error(t, m.Update(ctx, "wget"))
	_, err = m.ListInstalled(ctx)
	assert.Error(t, err)
	_, err = m.GetInstalledVersion(ctx, "wget")
	assert.Error(t, err)
	_, err = m.GetVersion(ctx, "wget")
	assert.Error(t, err)
	_, err = m.IsInstalled(ctx, "wget")
	assert.Error(t, err)

	require.Error(t, brewCheck(ctx))
	assert.False(t, brewProbe(ctx))
}

func TestSelectManager_BrewUnavailableNamesCause(t *testing.T) {
	if _, err := os.Stat("/opt/homebrew"); err == nil {
		t.Skip("a Homebrew installation is present on this host")
	}
	if _, err := os.Stat("/usr/local/Homebrew"); err == nil {
		t.Skip("a Homebrew installation is present on this host")
	}
	m := &PackageModule{}
	_, _, err := m.selectManager(context.Background(), []string{"brew"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no available package provider among [brew]")
	assert.True(t, strings.Contains(err.Error(), "not installed") || strings.Contains(err.Error(), "unsupported architecture"), err.Error())
}

func TestBrewCheckRunsAsOwnerSelf(t *testing.T) {
	// End to end against real files: a fake brew script in a temp prefix owned
	// by the current user runs through the built command (the only owner an
	// unprivileged test process may switch to is itself).
	if os.Geteuid() == 0 {
		t.Skip("running as root switches to the prefix owner uid, which needs a real account; covered by the post-merge live macOS check")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "Homebrew")
	require.NoError(t, os.Mkdir(repo, 0o755))
	bin := filepath.Join(dir, "brew")
	script := "#!/bin/sh\necho \"HOME=$HOME\"\necho \"ARGS=$*\"\n"
	require.NoError(t, os.WriteFile(bin, []byte(script), 0o755))

	acct, err := user.Current()
	require.NoError(t, err)
	target, err := resolveBrewAt(brewLocation{BinPath: bin, RepoDir: repo}, func(string) (*user.User, error) { return acct, nil })
	require.NoError(t, err)
	assert.Equal(t, uint32(os.Geteuid()), target.UID)

	out, err := buildBrewCmd(context.Background(), target, "list", "--versions").CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "HOME="+acct.HomeDir)
	assert.Contains(t, string(out), "ARGS=list --versions")

	st, ok := mustStat(t, repo).Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, strconv.Itoa(int(st.Uid)), acct.Uid)
}

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	require.NoError(t, err)
	return fi
}
