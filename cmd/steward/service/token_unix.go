// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// maxTokenFileSize bounds the read of a token file.
const maxTokenFileSize = 4096

// writeTokenFile writes the registration token to path. The content goes into
// a temp file in the same directory created O_EXCL with mode 0600, is synced,
// then renamed over the target, so the token is never in a file with a wider mode.
func writeTokenFile(path, token string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //#nosec G301 -- shared config dir also holds the CA cert
		return fmt.Errorf("create token directory: %w", err)
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", tokenFileName, os.Getpid()))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //#nosec G304 -- fixed platform path
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("sync token file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close token file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("install token file: %w", err)
	}
	return nil
}

// ReadTokenFile reads the registration token from path. It refuses a file that
// is not a regular file, is not owned by the current effective user, or has any
// group or other permission bit set. Errors never contain the token.
func ReadTokenFile(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //#nosec G304 -- operator-supplied path, validated below
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", tokenFileErr(TokenFileMissing, "registration token file %s does not exist", path)
		}
		return "", tokenFileErr(TokenFilePermissions, "open registration token file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", tokenFileErr(TokenFilePermissions, "inspect registration token file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", tokenFileErr(TokenFilePermissions, "registration token file %s is not a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", tokenFileErr(TokenFilePermissions, "cannot determine owner of registration token file %s", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return "", tokenFileErr(TokenFilePermissions, "registration token file %s is not owned by the current user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", tokenFileErr(TokenFilePermissions, "registration token file %s must not be accessible by group or others (mode %04o): use mode 0600", path, info.Mode().Perm())
	}
	return readTokenContent(f, path)
}

// tokenFileConfigured reports whether path is a non-empty regular file. A
// missing path reports false, not an error. It never returns the content.
func tokenFileConfigured(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect registration token file %s: %w", path, err)
	}
	return info.Mode().IsRegular() && info.Size() > 0, nil
}
