// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import (
	"context"
	"errors"

	"github.com/cfgis/cfgms/features/modules"
)

// ErrNotSupported is returned by Monitor on non-Windows hosts. Hyper-V VM-state
// monitoring is implemented with a Windows Event Log subscription
// (monitor_windows.go), so there is no portable equivalent. The steward's
// scheduled poll remains the cross-platform backstop.
var ErrNotSupported = errors.New("hyperv: VM-state monitoring is only supported on Windows hosts")

// Monitor satisfies modules.Monitor on non-Windows builds by reporting that
// event-driven monitoring is unavailable. Callers fall back to polling.
func (m *hypervModule) Monitor(_ context.Context, _ string, _ modules.ConfigState) error {
	return ErrNotSupported
}

// Changes returns nil on non-Windows builds: there is no subscription, so there
// is no channel to receive on. A nil channel blocks forever on receive, which a
// caller must guard with the ErrNotSupported it got from Monitor.
func (m *hypervModule) Changes() <-chan modules.ChangeEvent {
	return nil
}

// Close is a no-op on non-Windows builds: no subscription handle is ever held.
func (m *hypervModule) Close() error {
	return nil
}
