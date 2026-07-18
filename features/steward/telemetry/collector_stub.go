// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows && !linux

package telemetry

import "context"

// stubCollector is the fallback for platforms with no telemetry implementation
// (currently macOS and any other non-Linux/non-Windows target). It compiles
// cleanly and every Snapshot returns ErrPlatformNotSupported — mirroring
// features/steward/dex/collector_stub.go.
type stubCollector struct{}

// NewCollector returns a no-op collector on unsupported platforms.
func NewCollector() Collector { return stubCollector{} }

// Snapshot always returns ErrPlatformNotSupported on unsupported platforms.
func (stubCollector) Snapshot(_ context.Context) (Telemetry, error) {
	return Telemetry{}, ErrPlatformNotSupported
}
