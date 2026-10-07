// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"context"
	"errors"
)

// ServiceOp is one service-control operation of the steward_action allowlist.
type ServiceOp string

const (
	ServiceOpStart   ServiceOp = "start"
	ServiceOpStop    ServiceOp = "stop"
	ServiceOpRestart ServiceOp = "restart"
)

var (
	// ErrServiceUnsupported is returned when the platform has no in-process service
	// control implementation (macOS) or the service manager is unreachable.
	ErrServiceUnsupported = errors.New("service control unsupported on this platform")

	// ErrServiceNotFound is returned when the named service does not exist.
	ErrServiceNotFound = errors.New("service not found")

	// ErrServicePermissionDenied is returned when the service manager refuses the
	// caller (for example an unprivileged steward that polkit will not authorize).
	ErrServicePermissionDenied = errors.New("service control permission denied")
)

// ServiceController controls OS services through in-process OS APIs only (systemd
// D-Bus on Linux, the Service Control Manager on Windows). Implementations never
// shell out.
type ServiceController interface {
	// Control starts, stops or restarts the named service and returns once the
	// service manager reports the operation finished.
	Control(ctx context.Context, op ServiceOp, name string) error

	// IsStewardService reports whether name is the steward's own service: the one
	// whose main process is the steward, or whose control group contains it.
	IsStewardService(ctx context.Context, name string) (bool, error)
}
