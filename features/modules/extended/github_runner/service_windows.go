// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package github_runner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// windowsRunnerService manages the runner's Windows service via the SCM. The
// GitHub runner's `config.cmd --runasservice` registers a service named like
// "actions.runner.<owner>-<repo>.<name>"; this executor reports and converges
// that service's run/enable state via sc.exe. It never registers the service
// (that is the provisioning workflow's token-bearing register step).
type windowsRunnerService struct{}

func newServiceExecutor() runnerServiceExecutor { return &windowsRunnerService{} }

// status reports the service's registered/running/enabled state. A service the
// SCM does not know about is reported as not-installed (not an error).
func (s *windowsRunnerService) status(_ context.Context, serviceName string) (svcStatus, error) {
	out, err := runSC("query", serviceName)
	if err != nil {
		// sc query exits non-zero when the service does not exist (1060).
		if strings.Contains(out, "1060") || strings.Contains(out, "does not exist") {
			return svcStatus{Installed: false}, nil
		}
		return svcStatus{}, fmt.Errorf("sc query %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
	}
	running := strings.Contains(out, "RUNNING")

	qc, qcErr := runSC("qc", serviceName)
	if qcErr != nil {
		return svcStatus{}, fmt.Errorf("sc qc %s: %w (output: %s)", serviceName, qcErr, strings.TrimSpace(qc))
	}
	enabled := strings.Contains(qc, "AUTO_START")

	return svcStatus{Installed: true, Running: running, Enabled: enabled}, nil
}

// ensure converges an already-registered service to the desired running+enabled
// state via sc.exe. Start type is applied before start/stop.
func (s *windowsRunnerService) ensure(ctx context.Context, serviceName string, running, enabled bool) error {
	st, err := s.status(ctx, serviceName)
	if err != nil {
		return err
	}
	if !st.Installed {
		return fmt.Errorf("%w: %s", ErrServiceNotRegistered, serviceName)
	}

	if enabled != st.Enabled {
		startType := "demand"
		if enabled {
			startType = "auto"
		}
		if out, err := runSC("config", serviceName, "start=", startType); err != nil {
			return fmt.Errorf("sc config %s start=%s: %w (output: %s)", serviceName, startType, err, strings.TrimSpace(out))
		}
	}

	if running && !st.Running {
		if out, err := runSC("start", serviceName); err != nil {
			// 1056 = ERROR_SERVICE_ALREADY_RUNNING — benign.
			if !strings.Contains(out, "1056") {
				return fmt.Errorf("sc start %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
			}
		}
	} else if !running && st.Running {
		if out, err := runSC("stop", serviceName); err != nil {
			// 1062 = ERROR_SERVICE_NOT_ACTIVE — benign.
			if !strings.Contains(out, "1062") {
				return fmt.Errorf("sc stop %s: %w (output: %s)", serviceName, err, strings.TrimSpace(out))
			}
		}
	}
	return nil
}

// runSC runs sc.exe with the given args and returns combined output. sc.exe is a
// declared LOLBIN (see module.yaml behavioral_envelope); serviceName is
// validated by RunnerConfig.Validate and the other args are constants.
func runSC(args ...string) (string, error) {
	out, err := exec.Command("sc", args...).CombinedOutput() // #nosec G204 - args are constants except the validated service name
	return string(out), err
}
