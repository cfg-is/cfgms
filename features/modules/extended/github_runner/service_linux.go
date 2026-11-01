// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package github_runner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// linuxRunnerService manages the runner's systemd unit. The GitHub runner's
// `svc.sh install` registers a unit named like
// "actions.runner.<owner>-<repo>.<name>.service"; this executor reports and
// converges that unit's run/enable state via systemctl. It never registers the
// unit (that is the provisioning workflow's token-bearing register step).
type linuxRunnerService struct{}

func newServiceExecutor() runnerServiceExecutor { return &linuxRunnerService{} }

// status reports the unit's registered/running/enabled state. A unit systemd
// does not know about is reported as not-installed (not an error).
func (s *linuxRunnerService) status(_ context.Context, serviceName string) (svcStatus, error) {
	enabledOut, enabledErr := runSystemctl("is-enabled", serviceName)
	// is-enabled prints "not-found" (exit non-zero) when the unit is unknown.
	if strings.Contains(enabledOut, "not-found") {
		return svcStatus{Installed: false}, nil
	}
	// A genuine systemd failure (daemon unreachable) surfaces an error only when
	// the output is not one of the recognised state words.
	enabled := strings.TrimSpace(enabledOut) == "enabled"
	if enabledErr != nil && !isKnownEnabledState(enabledOut) {
		return svcStatus{}, fmt.Errorf("systemctl is-enabled %s: %w (output: %s)", serviceName, enabledErr, strings.TrimSpace(enabledOut))
	}

	activeOut, _ := runSystemctl("is-active", serviceName)
	running := strings.TrimSpace(activeOut) == "active"

	return svcStatus{Installed: true, Running: running, Enabled: enabled}, nil
}

// ensure converges an already-registered unit to the desired running+enabled
// state. Enable/disable is applied before start/stop, matching systemd practice.
func (s *linuxRunnerService) ensure(ctx context.Context, serviceName string, running, enabled bool) error {
	st, err := s.status(ctx, serviceName)
	if err != nil {
		return err
	}
	if !st.Installed {
		return fmt.Errorf("%w: %s", ErrServiceNotRegistered, serviceName)
	}

	if enabled && !st.Enabled {
		if out, err := runSystemctl("enable", serviceName); err != nil {
			return fmt.Errorf("systemctl enable %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
		}
	} else if !enabled && st.Enabled {
		if out, err := runSystemctl("disable", serviceName); err != nil {
			return fmt.Errorf("systemctl disable %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
		}
	}

	if running && !st.Running {
		if out, err := runSystemctl("start", serviceName); err != nil {
			return fmt.Errorf("systemctl start %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
		}
	} else if !running && st.Running {
		if out, err := runSystemctl("stop", serviceName); err != nil {
			return fmt.Errorf("systemctl stop %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// runSystemctl runs `systemctl <verb> <name>` and returns trimmed combined
// output. systemctl is a declared LOLBIN (see module.yaml behavioral_envelope);
// the name is validated by RunnerConfig.Validate before reaching here.
func runSystemctl(verb, name string) (string, error) {
	out, err := exec.Command("systemctl", verb, name).CombinedOutput() // #nosec G204 - verb is a constant, name validated by RunnerConfig.Validate
	return string(out), err
}

// isKnownEnabledState reports whether out is one of systemd's normal
// is-enabled words (so a non-zero exit on those is not a real error).
func isKnownEnabledState(out string) bool {
	switch strings.TrimSpace(out) {
	case "enabled", "disabled", "static", "masked", "indirect", "linked", "generated", "transient":
		return true
	}
	return false
}
