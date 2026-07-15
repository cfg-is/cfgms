// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package timemodule

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// windowsExecutor manages host time configuration on Windows via tzutil.exe
// and w32tm.exe.
//
// Timezone is managed via tzutil /s (set) and tzutil /g (get).
// Note: Windows timezone identifiers use Windows format (e.g. "Eastern Standard Time"),
// not IANA format. The module stores and returns Windows identifiers as-is.
//
// NTP servers are managed via w32tm /config /manualpeerlist.
// NTP sync enabled/disabled is managed via w32tm /config /syncfromflags.
type windowsExecutor struct{}

func newExecutor() timeExecutor {
	return &windowsExecutor{}
}

// getState returns the current timezone and NTP configuration from the Windows
// Time Service.
func (e *windowsExecutor) getState() (timeState, error) {
	tz, err := e.getTimezone()
	if err != nil {
		return timeState{}, err
	}

	servers, enabled, err := e.getNTPConfig()
	if err != nil {
		return timeState{}, err
	}

	sort.Strings(servers)
	return timeState{
		Timezone:       tz,
		NTPServers:     servers,
		NTPSyncEnabled: enabled,
	}, nil
}

// setState applies the desired timezone and NTP configuration via Windows tools.
func (e *windowsExecutor) setState(desired timeState) error {
	if out, err := exec.Command("tzutil", "/s", desired.Timezone).CombinedOutput(); err != nil { // #nosec G204 - timezone from Validate()
		return fmt.Errorf("tzutil /s %s: %w (output: %s)", desired.Timezone, err, strings.TrimSpace(string(out)))
	}

	servers := make([]string, len(desired.NTPServers))
	copy(servers, desired.NTPServers)
	sort.Strings(servers)

	peerList := strings.Join(servers, " ")
	if peerList == "" {
		peerList = "time.windows.com,0x9"
	}

	if out, err := exec.Command("w32tm", "/config", "/manualpeerlist:"+peerList, "/syncfromflags:manual", "/reliable:yes", "/update").CombinedOutput(); err != nil { // #nosec G204 - peer list from config
		return fmt.Errorf("w32tm /config: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	if desired.NTPSyncEnabled {
		if out, err := exec.Command("w32tm", "/config", "/syncfromflags:manual", "/update").CombinedOutput(); err != nil { // #nosec G204 - controlled literal
			return fmt.Errorf("w32tm enable sync: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	} else {
		if out, err := exec.Command("w32tm", "/config", "/syncfromflags:no", "/update").CombinedOutput(); err != nil { // #nosec G204 - controlled literal
			return fmt.Errorf("w32tm disable sync: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

// getTimezone returns the current Windows timezone identifier via tzutil /g.
func (e *windowsExecutor) getTimezone() (string, error) {
	out, err := exec.Command("tzutil", "/g").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tzutil /g: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// getNTPConfig returns the NTP peer list and sync-enabled state via w32tm.
func (e *windowsExecutor) getNTPConfig() (servers []string, enabled bool, err error) {
	out, runErr := exec.Command("w32tm", "/query", "/configuration").CombinedOutput()
	if runErr != nil {
		return nil, false, fmt.Errorf("w32tm /query /configuration: %w (output: %s)", runErr, strings.TrimSpace(string(out)))
	}

	output := string(out)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "NtpServer:") {
			// Format: "NtpServer: server1,0x9 server2,0x9 (Local)"
			val := strings.TrimPrefix(line, "NtpServer:")
			// Remove trailing parenthetical annotation.
			if idx := strings.Index(val, "("); idx >= 0 {
				val = val[:idx]
			}
			for _, s := range strings.Fields(val) {
				// Strip ,0x9 polling flags.
				if comma := strings.Index(s, ","); comma >= 0 {
					s = s[:comma]
				}
				if s != "" {
					servers = append(servers, s)
				}
			}
		}
		if strings.HasPrefix(line, "Type:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			// "NTP" or "NT5DS" means syncing; "NoSync" means disabled.
			enabled = !strings.EqualFold(val, "NoSync")
		}
	}

	return servers, enabled, nil
}
