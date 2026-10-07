// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// stewardWindowsServiceName is the SCM name the steward installer registers.
const stewardWindowsServiceName = "CFGMSSteward"

// serviceWaitInterval is how often a pending state change is polled.
const serviceWaitInterval = 250 * time.Millisecond

type scmServiceController struct{}

// newPlatformServiceController returns the Service Control Manager controller.
func newPlatformServiceController() ServiceController { return scmServiceController{} }

func connectSCM() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("%w: connect to service control manager: %v", ErrServiceUnsupported, err)
	}
	return m, nil
}

func openService(m *mgr.Mgr, name string) (*mgr.Service, error) {
	s, err := m.OpenService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, ErrServiceNotFound
		}
		return nil, fmt.Errorf("open service: %w", err)
	}
	return s, nil
}

func (scmServiceController) Control(ctx context.Context, op ServiceOp, name string) error {
	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := openService(m, name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	switch op {
	case ServiceOpStart:
		return startService(ctx, s)
	case ServiceOpStop:
		return stopService(ctx, s)
	case ServiceOpRestart:
		if err := stopService(ctx, s); err != nil {
			return err
		}
		return startService(ctx, s)
	default:
		return fmt.Errorf("unknown service op %q", op)
	}
}

func startService(ctx context.Context, s *mgr.Service) error {
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start: %w", err)
	}
	return waitForState(ctx, s, svc.Running)
}

func stopService(ctx context.Context, s *mgr.Service) error {
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop: %w", err)
	}
	return waitForState(ctx, s, svc.Stopped)
}

func waitForState(ctx context.Context, s *mgr.Service, want svc.State) error {
	ticker := time.NewTicker(serviceWaitInterval)
	defer ticker.Stop()
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query: %w", err)
		}
		if st.State == want {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// IsStewardService matches the target service's ServiceStatusProcess.ProcessId against
// this process (and its parent, which is the launcher when the steward runs under it),
// in addition to the steward's own SCM name. A service whose process is the steward is
// refused whatever it is named.
func (scmServiceController) IsStewardService(_ context.Context, name string) (bool, error) {
	if strings.EqualFold(name, stewardWindowsServiceName) {
		return true, nil
	}
	m, err := connectSCM()
	if err != nil {
		return false, err
	}
	defer func() { _ = m.Disconnect() }()

	s, err := openService(m, name)
	if err != nil {
		if errors.Is(err, ErrServiceNotFound) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("query: %w", err)
	}
	self, parent := uint32(os.Getpid()), uint32(os.Getppid()) // #nosec G115 -- pids fit uint32
	return st.ProcessId != 0 && (st.ProcessId == self || st.ProcessId == parent), nil
}
