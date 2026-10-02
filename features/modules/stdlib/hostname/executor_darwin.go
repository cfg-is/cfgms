// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package hostname

import (
	"fmt"
	"os/exec"
	"strings"
)

// darwinExecutor manages host identity configuration on macOS via the
// scutil command-line tool.
//
// ComputerName (friendly display name) and HostName (BSD/kernel hostname) are
// both managed. getHostNameFn returns HostName as the canonical value;
// setHostNamesFn writes both so the machine name is consistent in all macOS
// naming layers.
//
// Workgroup is a Windows-only concept; it is never read or written on macOS.
//
// getHostNameFn and setHostNamesFn are injected as function values so that
// tests can substitute fixtures without requiring a real macOS host or
// elevated privileges. The production defaults call scutil, which is declared
// in module.yaml behavioral_envelope as a shelling-out dependency (preferred
// over in-process APIs on macOS because Apple's System Configuration framework
// is not available without CGO).
type darwinExecutor struct {
	getHostNameFn  func() (string, error)
	setHostNamesFn func(name string) error
}

func newExecutor() hostnameExecutor {
	return &darwinExecutor{
		getHostNameFn:  scutilGetHostName,
		setHostNamesFn: scutilSetHostNames,
	}
}

// getState returns the current hostname from macOS via the injected getHostNameFn.
func (e *darwinExecutor) getState() (hostnameState, error) {
	h, err := e.getHostNameFn()
	if err != nil {
		return hostnameState{}, err
	}
	return hostnameState{Hostname: h}, nil
}

// setState sets the hostname via the injected setHostNamesFn.
func (e *darwinExecutor) setState(desired hostnameState) error {
	return e.setHostNamesFn(desired.Hostname)
}

// scutilGetHostName returns the current BSD hostname via scutil --get HostName.
func scutilGetHostName() (string, error) {
	out, err := exec.Command("scutil", "--get", "HostName").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil --get HostName: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// scutilSetHostNames sets both ComputerName and HostName via scutil to keep
// all macOS naming layers consistent.
func scutilSetHostNames(name string) error {
	if out, err := exec.Command("scutil", "--set", "ComputerName", name).CombinedOutput(); err != nil { // #nosec G204 - name matches hostnamePattern; no shell metacharacters
		return fmt.Errorf("scutil --set ComputerName: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("scutil", "--set", "HostName", name).CombinedOutput(); err != nil { // #nosec G204 - name matches hostnamePattern; no shell metacharacters
		return fmt.Errorf("scutil --set HostName: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
