// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package hostname

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// linuxExecutor manages host identity configuration on Linux.
//
// The current hostname is read from /etc/hostname (the durable config file).
// When /etc/hostname does not exist, os.Hostname() is used as a fallback so
// that hosts that have never been managed by this module still report a value.
//
// setState writes the desired hostname to /etc/hostname for persistence and
// calls the injected setHostname function (defaults to syscall.Sethostname)
// for runtime application without requiring a reboot.
//
// Both hostnameFile and setHostname are configurable so tests can substitute
// fixture paths and no-op functions, never mutating the CI runner's actual
// hostname or kernel state.
//
// Workgroup is a Windows-only concept; it is never read or written on Linux.
type linuxExecutor struct {
	hostnameFile string // default: /etc/hostname
	setHostname  func(name string) error
}

func newExecutor() hostnameExecutor {
	return &linuxExecutor{
		hostnameFile: "/etc/hostname",
		setHostname:  sysSetHostname,
	}
}

// sysSetHostname applies the hostname to the running kernel via syscall.Sethostname.
func sysSetHostname(name string) error {
	return syscall.Sethostname([]byte(name))
}

// getState reads the current hostname from /etc/hostname.
// Falls back to os.Hostname() when the file does not exist so that unmanaged
// hosts still return a meaningful value.
func (e *linuxExecutor) getState() (hostnameState, error) {
	data, err := os.ReadFile(e.hostnameFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File absent — read the runtime hostname from the kernel.
			h, herr := os.Hostname()
			if herr != nil {
				return hostnameState{}, fmt.Errorf("os.Hostname: %w", herr)
			}
			return hostnameState{Hostname: strings.TrimSpace(h)}, nil
		}
		return hostnameState{}, fmt.Errorf("read /etc/hostname: %w", err)
	}
	return hostnameState{Hostname: strings.TrimSpace(string(data))}, nil
}

// setState writes the desired hostname to /etc/hostname for persistence and
// applies it at runtime via the injected setHostname function.
// Parent directories are created if needed (handles missing /etc on bare containers).
func (e *linuxExecutor) setState(desired hostnameState) error {
	if err := os.MkdirAll(filepath.Dir(e.hostnameFile), 0o755); err != nil { // #nosec G301 - /etc is world-traversable by convention
		return fmt.Errorf("create hostname file parent: %w", err)
	}
	if err := os.WriteFile(e.hostnameFile, []byte(desired.Hostname+"\n"), 0o644); err != nil { // #nosec G306 - /etc/hostname is world-readable by convention
		return fmt.Errorf("write /etc/hostname: %w", err)
	}
	if err := e.setHostname(desired.Hostname); err != nil {
		return fmt.Errorf("syscall Sethostname: %w", err)
	}
	return nil
}
