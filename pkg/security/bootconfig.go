// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// BootConfigFileName is the canonical steward boot-config file name. The
// steward config loader, the deployment docs and the file-module write guard
// all derive from this one constant.
const BootConfigFileName = "steward.cfg"

// BootConfigDirs returns the directories the steward config loader searches,
// highest priority first. It is the single source for both loading and the
// write guard, so a directory can never be read without also being protected.
func BootConfigDirs() []string {
	var dirs []string
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			dirs = append(dirs, filepath.Join(pd, "cfgms"))
		}
		if up := os.Getenv("USERPROFILE"); up != "" {
			dirs = append(dirs, filepath.Join(up, ".cfgms"))
		}
	case "darwin":
		dirs = append(dirs,
			filepath.Join("/Library", "Application Support", "cfgms"),
			filepath.Join("/usr", "local", "etc", "cfgms"))
		if h := os.Getenv("HOME"); h != "" {
			dirs = append(dirs,
				filepath.Join(h, "Library", "Application Support", "cfgms"),
				filepath.Join(h, ".cfgms"))
		}
	case "linux":
		dirs = append(dirs,
			filepath.Join("/etc", "cfgms"),
			filepath.Join("/usr", "local", "etc", "cfgms"))
		if h := os.Getenv("HOME"); h != "" {
			dirs = append(dirs,
				filepath.Join(h, ".config", "cfgms"),
				filepath.Join(h, ".cfgms"))
		}
	}
	return dirs
}

// BootConfigFileNames returns the file names the loader looks for in each
// directory: the host-specific "<hostname>.cfg" first, then steward.cfg.
func BootConfigFileNames() []string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	return []string{hostname + ".cfg", BootConfigFileName}
}

// IsProtectedBootConfigPath reports whether path is a boot-config file the
// steward loader may read, or one of the directories holding them. Local
// settings such as remote_terminal.enabled live there and must not be
// changeable by controller-delivered resources. Symlinks in the parent
// directory are resolved before comparing.
func IsProtectedBootConfigPath(path string) bool {
	target := resolveForCompare(path)
	for _, dir := range BootConfigDirs() {
		d := resolveForCompare(dir)
		if samePath(target, d) {
			return true
		}
		for _, name := range BootConfigFileNames() {
			if samePath(target, filepath.Join(d, name)) {
				return true
			}
		}
	}
	return false
}

// resolveForCompare cleans path and resolves symlinks in its parent
// directory (the leaf may not exist yet or may itself be the link target).
func resolveForCompare(path string) string {
	clean := filepath.Clean(path)
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return resolved
	}
	parent, leaf := filepath.Split(clean)
	if resolvedParent, err := filepath.EvalSymlinks(filepath.Clean(parent)); err == nil {
		return filepath.Join(resolvedParent, leaf)
	}
	return clean
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
