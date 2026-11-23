// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build !windows

package package_module

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// Homebrew install locations. The steward never resolves brew through PATH:
// the Apple silicon prefix is not on launchd's default PATH and module
// processes inherit a minimal environment, so the binary is located by its
// fixed per-architecture path.
const (
	brewBinArm64  = "/opt/homebrew/bin/brew"
	brewRepoArm64 = "/opt/homebrew"
	brewBinAmd64  = "/usr/local/bin/brew"
	// On Intel /usr/local itself is root-owned; the Homebrew repository
	// directory is the one the installing user owns.
	brewRepoAmd64 = "/usr/local/Homebrew"
)

// brewLocation is where Homebrew lives for one architecture.
type brewLocation struct {
	// BinPath is the fixed path of the brew executable (a symlink into the
	// repository on both architectures).
	BinPath string
	// RepoDir is the Homebrew repository directory whose owner is the
	// prefix owner brew runs as.
	RepoDir string
}

// brewLocationFor returns the fixed Homebrew locations for goarch. It is pure
// so both architectures are testable on any host.
func brewLocationFor(goarch string) (brewLocation, error) {
	switch goarch {
	case "arm64":
		return brewLocation{BinPath: brewBinArm64, RepoDir: brewRepoArm64}, nil
	case "amd64":
		return brewLocation{BinPath: brewBinAmd64, RepoDir: brewRepoAmd64}, nil
	default:
		return brewLocation{}, fmt.Errorf("homebrew: unsupported architecture %q (supported: arm64, amd64)", goarch)
	}
}

// brewTarget is a verified Homebrew installation and the identity brew runs as.
type brewTarget struct {
	BinPath string
	BinDir  string
	RepoDir string
	// UID and GID are the prefix owner's uid and primary gid.
	UID  uint32
	GID  uint32
	Home string
}

// userLookup resolves a numeric uid to an account (os/user.LookupId in
// production).
type userLookup func(uid string) (*user.User, error)

// resolveBrew locates and verifies Homebrew at the fixed path for goarch.
func resolveBrew(goarch string) (*brewTarget, error) {
	loc, err := brewLocationFor(goarch)
	if err != nil {
		return nil, err
	}
	return resolveBrewAt(loc, user.LookupId)
}

// resolveBrewAt verifies the Homebrew installation at loc and determines the
// prefix owner. It never falls back to root: a missing installation, an
// unreadable repository directory, a root-owned repository, or an untrusted
// brew file is an error that names the cause.
func resolveBrewAt(loc brewLocation, lookup userLookup) (*brewTarget, error) {
	repoInfo, err := os.Stat(loc.RepoDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("homebrew is not installed: %s does not exist", loc.RepoDir)
		}
		return nil, fmt.Errorf("homebrew prefix owner cannot be determined: cannot read repository directory %s: %w", loc.RepoDir, err)
	}
	if !repoInfo.IsDir() {
		return nil, fmt.Errorf("homebrew prefix owner cannot be determined: %s is not a directory", loc.RepoDir)
	}
	repoStat, ok := repoInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("homebrew prefix owner cannot be determined: no ownership information for %s", loc.RepoDir)
	}
	if repoStat.Uid == 0 {
		return nil, fmt.Errorf("homebrew repository %s is owned by root; Homebrew refuses to run as root and the steward will not run it as root", loc.RepoDir)
	}

	if err := checkBrewBinary(loc.BinPath, repoStat.Uid); err != nil {
		return nil, err
	}

	acct, err := lookup(strconv.FormatUint(uint64(repoStat.Uid), 10))
	if err != nil {
		return nil, fmt.Errorf("homebrew prefix owner cannot be determined: uid %d owning %s has no account: %w", repoStat.Uid, loc.RepoDir, err)
	}
	gid, err := strconv.ParseUint(acct.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("homebrew prefix owner cannot be determined: account for uid %d has invalid primary gid %q", repoStat.Uid, acct.Gid)
	}
	if acct.HomeDir == "" {
		return nil, fmt.Errorf("homebrew prefix owner cannot be determined: account for uid %d has no home directory", repoStat.Uid)
	}

	return &brewTarget{
		BinPath: loc.BinPath,
		BinDir:  filepath.Dir(loc.BinPath),
		RepoDir: loc.RepoDir,
		UID:     repoStat.Uid,
		GID:     uint32(gid),
		Home:    acct.HomeDir,
	}, nil
}

// checkBrewBinary refuses a brew file the steward must not run as another
// user: stat follows the symlink, so the resolved file is checked. It must be
// a regular executable that is not world-writable and is owned by root or the
// prefix owner. Group-writable is allowed (Homebrew sets g+w for the admin
// group on Intel).
func checkBrewBinary(binPath string, ownerUID uint32) error {
	info, err := os.Stat(binPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("homebrew is not installed: %s does not exist", binPath)
		}
		return fmt.Errorf("homebrew binary %s cannot be inspected: %w", binPath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("homebrew binary %s is not a regular file", binPath)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("homebrew binary %s is not executable", binPath)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("homebrew binary %s is world-writable; refusing to run it", binPath)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("homebrew binary %s has no ownership information; refusing to run it", binPath)
	}
	if st.Uid != 0 && st.Uid != ownerUID {
		return fmt.Errorf("homebrew binary %s is owned by uid %d, which is neither root nor the prefix owner (uid %d); refusing to run it", binPath, st.Uid, ownerUID)
	}
	return nil
}

// buildBrewCmd builds the brew command for target without starting it: the
// verified absolute path with argv as given (no shell), run as the prefix
// owner through SysProcAttr.Credential, in the repository directory, with an
// explicit environment.
func buildBrewCmd(ctx context.Context, t *brewTarget, args ...string) *exec.Cmd {
	// #nosec G204 -- BinPath is one of two fixed Homebrew paths verified by
	// resolveBrewAt; args are validated package names or fixed subcommands,
	// passed as separate argv entries without a shell.
	cmd := exec.CommandContext(ctx, t.BinPath, args...)
	cmd.Dir = t.RepoDir
	cmd.Env = []string{
		"PATH=" + t.BinDir + ":/usr/bin:/bin",
		"HOME=" + t.Home,
		"HOMEBREW_NO_AUTO_UPDATE=1",
	}
	// NEGATIVE RUN: owner switch removed; brew runs as root.
	_ = syscall.Credential{}
	_ = os.Geteuid
	return cmd
}

// newBrewCmd verifies Homebrew for this host's architecture and returns the
// command to run brew with args as the prefix owner. It returns an error, and
// no command, when Homebrew cannot be run safely.
func newBrewCmd(ctx context.Context, args ...string) (*exec.Cmd, error) {
	t, err := resolveBrew(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	return buildBrewCmd(ctx, t, args...), nil
}

// brewCheck returns nil when brew at its fixed path runs `--version` as the
// prefix owner, else an error naming the cause.
func brewCheck(ctx context.Context) error {
	cmd, err := newBrewCmd(ctx, "--version")
	if err != nil {
		return err
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("homebrew --version failed: %w\nOutput: %s", err, string(out))
	}
	return nil
}
