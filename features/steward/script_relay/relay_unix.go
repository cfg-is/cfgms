// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build !windows

package scriptrelay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// checkSocketDir refuses a socket directory that another local user could have
// prepared: a symlink, a non-directory, a directory owned by someone other than
// the effective user, or one whose mode is not exactly 0700. It uses Lstat so a
// symlink is never followed.
func checkSocketDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat socket dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket dir %q is a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("socket dir %q is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("socket dir %q: ownership unavailable", dir)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("socket dir %q is not owned by the current user", dir)
	}
	if info.Mode().Perm() != 0700 {
		return fmt.Errorf("socket dir %q has mode %o, want 0700", dir, info.Mode().Perm())
	}
	return nil
}

// initSocket creates the per-execution directory (mode 0700) and opens a
// unix socket inside it (mode 0600). The directory is created fresh and
// exclusively with an unpredictable name (os.MkdirTemp), so a path planted in
// the world-writable temp tree is never reused. It is verified before binding,
// and is created first so no window exists between bind and chmod where the
// socket is world-accessible.
func initSocket(r *Relay) error {
	sockDir, err := os.MkdirTemp("", "cfgms-")
	if err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := checkSocketDir(sockDir); err != nil {
		_ = os.Remove(sockDir)
		return err
	}

	sockPath := filepath.Join(sockDir, "api.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("listen unix socket: %w", err)
	}

	// Enforce 0600 on the socket file; the 0700 directory prevents access
	// during the brief window before chmod.
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Chown the directory and socket to the script's execution UID. With mode
	// 0700/0600, connecting requires write access to the socket inode, so a
	// script running under a different user (logged_in_user context, launched
	// via `sudo -u`) can only connect when it owns these files. When the
	// execution UID equals the steward process UID (system context) or is
	// unset (< 0), the chown is skipped as a no-op.
	if r.uid >= 0 && r.uid != os.Getuid() {
		if err := os.Chown(sockDir, r.uid, -1); err != nil {
			_ = ln.Close()
			_ = os.RemoveAll(sockDir)
			return fmt.Errorf("chown socket dir to uid %d: %w", r.uid, err)
		}
		// Lchown the socket itself: it is never a symlink, but Lchown avoids
		// following one if the path were ever swapped, matching the dir chown.
		if err := os.Lchown(sockPath, r.uid, -1); err != nil {
			_ = ln.Close()
			_ = os.RemoveAll(sockDir)
			return fmt.Errorf("chown socket to uid %d: %w", r.uid, err)
		}
	}

	r.socketPath = sockPath
	r.ln = ln
	return nil
}

// cleanupSocket removes the per-execution socket directory and its contents.
func cleanupSocket(r *Relay) {
	if r.socketPath == "" {
		return
	}
	sockDir := filepath.Dir(r.socketPath)
	_ = os.RemoveAll(sockDir)
}
