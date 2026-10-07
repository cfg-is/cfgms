// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package timemodule

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// darwinExecutor manages host time configuration on macOS via the
// systemsetup command-line tool.
//
// Timezone is managed via systemsetup -gettimezone / -settimezone.
// NTP server is managed via systemsetup -getnetworktimeserver / -setnetworktimeserver.
// NTP sync state is managed via systemsetup -getusingnetworktime / -setusingnetworktime.
//
// Note: macOS systemsetup only supports a single NTP server (not a list).
// The module treats a single-element list as the canonical state; additional
// servers beyond the first are ignored on Set and not returned on Get.
type darwinExecutor struct{}

func newExecutor() timeExecutor {
	return &darwinExecutor{}
}

// getState returns the current timezone and NTP configuration from macOS.
func (e *darwinExecutor) getState() (timeState, error) {
	tz, err := e.getTimezone()
	if err != nil {
		return timeState{}, err
	}

	server, err := e.getNTPServer()
	if err != nil {
		return timeState{}, err
	}

	enabled, err := e.getNTPEnabled()
	if err != nil {
		return timeState{}, err
	}

	var servers []string
	if server != "" {
		servers = []string{server}
	}
	sort.Strings(servers)

	return timeState{
		Timezone:       tz,
		NTPServers:     servers,
		NTPSyncEnabled: enabled,
	}, nil
}

// setState applies the desired timezone and NTP configuration via systemsetup.
func (e *darwinExecutor) setState(desired timeState) error {
	if out, err := exec.Command("systemsetup", "-settimezone", desired.Timezone).CombinedOutput(); err != nil { // #nosec G204 - timezone matches ianaTimezonePattern; no shell metacharacters
		return fmt.Errorf("systemsetup -settimezone %s: %w (output: %s)", desired.Timezone, err, strings.TrimSpace(string(out)))
	}

	// macOS supports only a single NTP server; use the first if provided.
	server := ""
	if len(desired.NTPServers) > 0 {
		servers := make([]string, len(desired.NTPServers))
		copy(servers, desired.NTPServers)
		sort.Strings(servers)
		server = servers[0]
	}
	if server != "" {
		if out, err := exec.Command("systemsetup", "-setnetworktimeserver", server).CombinedOutput(); err != nil { // #nosec G204 - server matches ntpServerPattern; no shell metacharacters
			return fmt.Errorf("systemsetup -setnetworktimeserver %s: %w (output: %s)", server, err, strings.TrimSpace(string(out)))
		}
	}

	ntpArg := "off"
	if desired.NTPSyncEnabled {
		ntpArg = "on"
	}
	if out, err := exec.Command("systemsetup", "-setusingnetworktime", ntpArg).CombinedOutput(); err != nil { // #nosec G204 - ntpArg is a controlled literal
		return fmt.Errorf("systemsetup -setusingnetworktime %s: %w (output: %s)", ntpArg, err, strings.TrimSpace(string(out)))
	}

	return nil
}

// getTimezone returns the current IANA timezone identifier.
// Output format: "Time Zone: America/Chicago"
func (e *darwinExecutor) getTimezone() (string, error) {
	out, err := exec.Command("systemsetup", "-gettimezone").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemsetup -gettimezone: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(string(out))
	// Strip "Time Zone: " prefix.
	if idx := strings.Index(line, ":"); idx >= 0 {
		return strings.TrimSpace(line[idx+1:]), nil
	}
	return line, nil
}

// getNTPServer returns the configured NTP server hostname.
// Output format: "Network Time Server: time.apple.com"
func (e *darwinExecutor) getNTPServer() (string, error) {
	out, err := exec.Command("systemsetup", "-getnetworktimeserver").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemsetup -getnetworktimeserver: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(string(out))
	if idx := strings.Index(line, ":"); idx >= 0 {
		return strings.TrimSpace(line[idx+1:]), nil
	}
	return line, nil
}

// getNTPEnabled returns whether automatic network time synchronisation is on.
// Output format: "Using Network Time: On" or "Using Network Time: Off"
func (e *darwinExecutor) getNTPEnabled() (bool, error) {
	out, err := exec.Command("systemsetup", "-getusingnetworktime").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("systemsetup -getusingnetworktime: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	line := strings.ToLower(strings.TrimSpace(string(out)))
	return strings.HasSuffix(line, "on"), nil
}
