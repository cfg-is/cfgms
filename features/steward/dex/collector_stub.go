// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package dex

import "context"

// Collector is the top-level acquisition spike entry point.
// On non-Windows platforms all methods return ErrPlatformNotSupported.
type Collector struct {
	cfg  SpikeConfig
	sink *Sink
}

// NewCollector returns a no-op Collector on non-Windows platforms.
func NewCollector(cfg SpikeConfig, sink *Sink) *Collector {
	return &Collector{cfg: cfg, sink: sink}
}

// Run returns ErrPlatformNotSupported on non-Windows platforms.
// Windows 10/11 is required for ETW and WMI acquisition.
func (c *Collector) Run(_ context.Context) (SpikeReport, error) {
	return SpikeReport{}, ErrPlatformNotSupported
}
