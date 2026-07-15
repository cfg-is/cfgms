// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hostname

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// windowsExecutor manages host identity configuration on Windows via
// os.Hostname (read), wmic.exe (workgroup read/set), and netdom.exe (rename).
//
// Both getHostname and getWorkgroup are injected as function values so that
// tests can substitute fixture functions without touching the real host's
// identity or requiring elevated privileges on the CI runner.
//
// wmic.exe and netdom.exe are declared in module.yaml behavioral_envelope as
// shelling-out dependencies (preferred over native COM/WMI calls to avoid a
// CGO dependency for out-of-process modules).
type windowsExecutor struct {
	getHostname  func() (string, error)
	getWorkgroup func(computerName string) (string, error)
	setHostname  func(currentName, newName string) error
	setWorkgroup func(computerName, workgroup string) error
}

func newExecutor() hostnameExecutor {
	return &windowsExecutor{
		getHostname:  os.Hostname,
		getWorkgroup: wmicGetWorkgroup,
		setHostname:  netdomRename,
		setWorkgroup: wmicSetWorkgroup,
	}
}

// getState returns the current hostname and workgroup from Windows.
func (e *windowsExecutor) getState() (hostnameState, error) {
	hostname, err := e.getHostname()
	if err != nil {
		return hostnameState{}, fmt.Errorf("get hostname: %w", err)
	}
	hostname = strings.TrimSpace(hostname)

	workgroup, err := e.getWorkgroup(hostname)
	if err != nil {
		return hostnameState{}, fmt.Errorf("get workgroup: %w", err)
	}

	return hostnameState{
		Hostname:  hostname,
		Workgroup: workgroup,
	}, nil
}

// setState applies the desired hostname and workgroup on Windows.
// Each change is applied only when the desired value differs from the current.
func (e *windowsExecutor) setState(desired hostnameState) error {
	current, err := e.getState()
	if err != nil {
		return fmt.Errorf("get current state: %w", err)
	}

	if current.Hostname != desired.Hostname {
		if err := e.setHostname(current.Hostname, desired.Hostname); err != nil {
			return fmt.Errorf("rename computer: %w", err)
		}
	}

	if desired.Workgroup != "" && current.Workgroup != desired.Workgroup {
		if err := e.setWorkgroup(desired.Hostname, desired.Workgroup); err != nil {
			return fmt.Errorf("set workgroup: %w", err)
		}
	}

	return nil
}

// wmicGetWorkgroup reads the current workgroup via wmic computersystem.
// Output format: "Workgroup=WORKGROUPNAME" (one line after /format:list).
func wmicGetWorkgroup(computerName string) (string, error) {
	out, err := exec.Command("wmic", "computersystem", "get", "Workgroup", "/format:list").CombinedOutput() // #nosec G204 - no user-controlled values in arguments
	if err != nil {
		return "", fmt.Errorf("wmic computersystem get Workgroup: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "WORKGROUP=") {
			return strings.TrimSpace(line[len("WORKGROUP="):]), nil
		}
	}
	return "", nil
}

// netdomRename renames the computer via netdom.exe.
// /reboot:0 suppresses the automatic reboot — the rename takes effect on
// the next manual reboot scheduled by the operator.
func netdomRename(currentName, newName string) error {
	out, err := exec.Command("netdom", "renamecomputer", currentName, "/newname:"+newName, "/reboot:0", "/force").CombinedOutput() // #nosec G204 - names validated by Validate()
	if err != nil {
		return fmt.Errorf("netdom renamecomputer: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// wmicSetWorkgroup joins the computer to the specified workgroup via wmic.
func wmicSetWorkgroup(computerName, workgroup string) error {
	// wmic computersystem where name=... call JoinDomainOrWorkgroup WorkgroupName=...
	whereClause := fmt.Sprintf(`name="%s"`, computerName) // #nosec G204 - computerName validated by Validate()
	out, err := exec.Command("wmic", "computersystem", "where", whereClause,
		"call", "JoinDomainOrWorkgroup", fmt.Sprintf("WorkgroupName=%q", workgroup)).CombinedOutput() // #nosec G204 - workgroup validated by Validate()
	if err != nil {
		return fmt.Errorf("wmic JoinDomainOrWorkgroup: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
