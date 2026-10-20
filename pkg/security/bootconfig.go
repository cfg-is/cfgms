// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security

import (
	"os"
	"path/filepath"
	"runtime"
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
// changeable by controller-delivered resources.
//
// The comparison is platform specific. On Windows it compares the canonical
// file identity (volume serial + file index) and fails closed when that
// identity cannot be established; elsewhere it compares cleaned paths with the
// parent directory's symlinks resolved.
func IsProtectedBootConfigPath(path string) bool {
	return isProtectedBootConfigPath(path)
}
