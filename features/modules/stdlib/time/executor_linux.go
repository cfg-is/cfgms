// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package timemodule

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// linuxExecutor manages host time configuration on Linux.
//
// Timezone is stored in /etc/timezone (IANA name, one line).
// NTP server list and sync state are stored in /etc/systemd/timesyncd.conf;
// this module assumes systemd-timesyncd as the time-sync daemon.
//
// File paths are configurable so tests can point at fixture files in a temp
// directory (never mutating the CI host's real time configuration).
//
// setState shells out to timedatectl for runtime application; if timedatectl
// is unavailable (no running systemd) the file writes still persist and take
// effect on next boot or service start. Only genuine timedatectl failures on
// systems where systemd IS running are returned as errors.
type linuxExecutor struct {
	timezoneFile    string // default: /etc/timezone
	timesyncdConfig string // default: /etc/systemd/timesyncd.conf
}

func newExecutor() timeExecutor {
	return &linuxExecutor{
		timezoneFile:    "/etc/timezone",
		timesyncdConfig: "/etc/systemd/timesyncd.conf",
	}
}

// getState reads the current timezone and NTP configuration from disk.
// All reads are file-based to support fixture-isolated testing without
// requiring a running systemd instance.
func (e *linuxExecutor) getState() (timeState, error) {
	tz, err := e.readTimezone()
	if err != nil {
		return timeState{}, fmt.Errorf("read timezone: %w", err)
	}

	servers, enabled, err := e.readTimesyncd()
	if err != nil {
		return timeState{}, fmt.Errorf("read timesyncd config: %w", err)
	}

	sort.Strings(servers)
	return timeState{
		Timezone:       tz,
		NTPServers:     servers,
		NTPSyncEnabled: enabled,
	}, nil
}

// setState writes the desired time configuration to disk and attempts to
// apply it at runtime via timedatectl. File writes always succeed or return
// an error. timedatectl failures are ignored when systemd is not running.
func (e *linuxExecutor) setState(desired timeState) error {
	if err := e.writeTimezone(desired.Timezone); err != nil {
		return fmt.Errorf("write timezone: %w", err)
	}

	servers := make([]string, len(desired.NTPServers))
	copy(servers, desired.NTPServers)
	sort.Strings(servers)

	if err := e.writeTimesyncd(servers, desired.NTPSyncEnabled); err != nil {
		return fmt.Errorf("write timesyncd config: %w", err)
	}

	// Apply at runtime via timedatectl. Failures are silently ignored when
	// systemd is not running (e.g. containers, CI environments). On systems
	// where systemd IS the init, timedatectl failures are returned as errors.
	if err := e.applyTimezone(desired.Timezone); err != nil {
		return fmt.Errorf("timedatectl set-timezone: %w", err)
	}
	if err := e.applyNTPSync(desired.NTPSyncEnabled); err != nil {
		return fmt.Errorf("timedatectl set-ntp: %w", err)
	}

	return nil
}

// readTimezone reads the IANA timezone name from timezoneFile.
// Returns "UTC" when the file does not exist (system default before configuration).
func (e *linuxExecutor) readTimezone() (string, error) {
	data, err := os.ReadFile(e.timezoneFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "UTC", nil
		}
		return "", err
	}
	tz := strings.TrimSpace(string(data))
	if tz == "" {
		return "UTC", nil
	}
	return tz, nil
}

// writeTimezone writes the IANA timezone name to timezoneFile, creating the
// file and any parent directories that do not exist.
func (e *linuxExecutor) writeTimezone(timezone string) error {
	if err := os.MkdirAll(filepath.Dir(e.timezoneFile), 0o755); err != nil { // #nosec G301 - /etc is world-traversable by convention
		return err
	}
	return os.WriteFile(e.timezoneFile, []byte(timezone+"\n"), 0o644) // #nosec G306 - /etc/timezone is world-readable by convention
}

// ntpSyncEnabledMarker is the comment prefix written by this module in the
// timesyncd config file to track the desired NTP sync enabled state.
const ntpSyncEnabledMarker = "# cfgms:ntp_sync_enabled="

// readTimesyncd parses /etc/systemd/timesyncd.conf (or the configured path)
// for the NTP server list and the cfgms-managed sync-enabled state.
// Returns empty servers and enabled=true when the file does not exist.
func (e *linuxExecutor) readTimesyncd() (servers []string, enabled bool, err error) {
	f, err := os.Open(e.timesyncdConfig)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	enabled = true // default if no cfgms marker found
	inTimeSection := false
	markerFound := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// cfgms-managed marker for NTP sync enabled state.
		if strings.HasPrefix(trimmed, ntpSyncEnabledMarker) {
			val := strings.TrimPrefix(trimmed, ntpSyncEnabledMarker)
			enabled = strings.EqualFold(strings.TrimSpace(val), "true")
			markerFound = true
			continue
		}

		// Section header.
		if strings.HasPrefix(trimmed, "[") {
			inTimeSection = strings.EqualFold(trimmed, "[time]")
			continue
		}

		// NTP= line inside [Time] section.
		if inTimeSection && strings.HasPrefix(trimmed, "NTP=") {
			val := strings.TrimPrefix(trimmed, "NTP=")
			for _, s := range strings.Fields(val) {
				if s != "" {
					servers = append(servers, s)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	if !markerFound {
		// No cfgms marker: infer enabled from whether NTP servers are configured.
		enabled = len(servers) > 0
	}
	return servers, enabled, nil
}

// writeTimesyncd writes the NTP server list and sync-enabled state to the
// timesyncd config file. Parent directories are created if needed.
func (e *linuxExecutor) writeTimesyncd(servers []string, enabled bool) error {
	if err := os.MkdirAll(filepath.Dir(e.timesyncdConfig), 0o755); err != nil { // #nosec G301 - /etc/systemd is world-traversable by convention
		return err
	}

	enabledVal := "true"
	if !enabled {
		enabledVal = "false"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s%s\n", ntpSyncEnabledMarker, enabledVal)
	sb.WriteString("[Time]\n")
	sb.WriteString("NTP=")
	sb.WriteString(strings.Join(servers, " "))
	sb.WriteString("\n")
	sb.WriteString("FallbackNTP=\n")

	return os.WriteFile(e.timesyncdConfig, []byte(sb.String()), 0o644) // #nosec G306 - timesyncd.conf is world-readable by convention
}

// isTimedatectlUnavailable returns true when the error indicates that
// timedatectl is either not installed or systemd is not running — both are
// expected in containers and CI environments without a systemd init.
func isTimedatectlUnavailable(err error, output string) bool {
	// Binary not in PATH (exec error, not exit error).
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return true // exec.LookPath failed or similar — not a real failure
	}
	unavailableMarkers := []string{
		"Failed to connect to bus",
		"No such file or directory",
		"Connection refused",
		"Transport endpoint is not connected",
		"System has not been booted with systemd",
	}
	for _, m := range unavailableMarkers {
		if strings.Contains(output, m) {
			return true
		}
	}
	return false
}

// applyTimezone calls timedatectl to apply the timezone change at runtime.
// Returns nil when timedatectl is unavailable or systemd is not running;
// file writes are the durable change in those cases.
func (e *linuxExecutor) applyTimezone(timezone string) error {
	out, err := exec.Command("timedatectl", "set-timezone", timezone).CombinedOutput() // #nosec G204 - timezone matches ianaTimezonePattern: no shell metacharacters
	if err != nil {
		output := strings.TrimSpace(string(out))
		if isTimedatectlUnavailable(err, output) {
			return nil
		}
		return fmt.Errorf("%w (output: %s)", err, output)
	}
	return nil
}

// applyNTPSync calls timedatectl to enable or disable NTP sync at runtime.
// Returns nil when timedatectl is unavailable or systemd is not running;
// file writes are the durable change in those cases.
func (e *linuxExecutor) applyNTPSync(enabled bool) error {
	arg := "false"
	if enabled {
		arg = "true"
	}
	out, err := exec.Command("timedatectl", "set-ntp", arg).CombinedOutput() // #nosec G204 - arg is a controlled literal
	if err != nil {
		output := strings.TrimSpace(string(out))
		if isTimedatectlUnavailable(err, output) {
			return nil
		}
		return fmt.Errorf("%w (output: %s)", err, output)
	}
	return nil
}
