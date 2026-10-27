// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// hostnameFunc reads the host name; tests override it to model a rename.
var hostnameFunc = os.Hostname

// loadedBootConfig is the process-local, additive record of the boot configs
// the running steward loaded and the host names in force when it did so. A
// later rename of the host must not make those files writable, nor let a
// planted file for the new name be treated as an ordinary file.
var loadedBootConfig struct {
	sync.Mutex
	paths     []string
	hostnames []string
}

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
	return []string{currentHostname() + ".cfg", BootConfigFileName}
}

func currentHostname() string {
	hostname, err := hostnameFunc()
	if err != nil {
		return "localhost"
	}
	return hostname
}

// SetLoadedBootConfigPath records the boot config the steward loaded, and the
// host name at that moment, as protected for the life of the process. Calls
// only add to the set.
func SetLoadedBootConfigPath(path string) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		abs = filepath.Clean(path)
	}
	host := currentHostname()
	loadedBootConfig.Lock()
	defer loadedBootConfig.Unlock()
	loadedBootConfig.paths = appendUnique(loadedBootConfig.paths, abs)
	loadedBootConfig.hostnames = appendUnique(loadedBootConfig.hostnames, host)
}

// AddProtectedBootConfigHostname records name as a host name whose
// "<name>.cfg" must be protected in every boot-config directory for the life
// of the process. The hostname module calls it before applying a rename: on
// platforms where the rename is pending until reboot (Windows), os.Hostname
// keeps returning the old name, so without this record a delivered resource
// could plant the boot config the steward loads after the reboot. Calls only
// add to the set; an empty name is ignored.
func AddProtectedBootConfigHostname(name string) {
	if name == "" {
		return
	}
	loadedBootConfig.Lock()
	defer loadedBootConfig.Unlock()
	loadedBootConfig.hostnames = appendUnique(loadedBootConfig.hostnames, name)
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// loadedBootConfigSnapshot returns the recorded paths and host names.
func loadedBootConfigSnapshot() (paths, hostnames []string) {
	loadedBootConfig.Lock()
	defer loadedBootConfig.Unlock()
	return append([]string(nil), loadedBootConfig.paths...), append([]string(nil), loadedBootConfig.hostnames...)
}

// protectedCandidates lists every boot-config file path (not directory) the
// guard protects: the current names plus recorded host names in each boot
// config directory, and the recorded loaded paths.
func protectedCandidates() []string {
	paths, hosts := loadedBootConfigSnapshot()
	names := BootConfigFileNames()
	for _, h := range hosts {
		names = appendUnique(names, h+".cfg")
	}
	out := paths
	for _, dir := range BootConfigDirs() {
		for _, n := range names {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

// resetLoadedBootConfig clears the recorded state; tests only.
func resetLoadedBootConfig() {
	loadedBootConfig.Lock()
	defer loadedBootConfig.Unlock()
	loadedBootConfig.paths, loadedBootConfig.hostnames = nil, nil
}

// BootConfigExistsForHostname reports whether "<name>.cfg" exists in any boot
// config directory. A stat error other than not-exist fails closed (true).
func BootConfigExistsForHostname(name string) bool {
	for _, dir := range BootConfigDirs() {
		if _, err := os.Lstat(filepath.Join(dir, name+".cfg")); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
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
