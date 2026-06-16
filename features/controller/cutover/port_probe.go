// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"context"
	"fmt"
	"net"
	"time"
)

// waitForPortFree polls the OS until addr is no longer listening, or
// the timeout elapses. Used by PortSwapTarget between draining the old
// canonical and spawning the new canonical, so the new spawn doesn't
// race the kernel's TIME_WAIT lingering or a slow shutdown.
//
// Returns nil when a TCP dial to addr fails (port free); returns a
// non-nil error if the budget elapses with the port still accepting
// connections.
//
// addr may be ":4433" / "127.0.0.1:4433" / "0.0.0.0:4433". For
// shorthand ":PORT" we probe "127.0.0.1:PORT" which is sufficient for
// the loopback bind that the controller does in local-dev / single-host
// blue/green deployments.
func waitForPortFree(ctx context.Context, addr string, timeout time.Duration) error {
	probeAddr := normalizeProbeAddr(addr)
	deadline := time.Now().Add(timeout)
	pollInterval := 50 * time.Millisecond

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", probeAddr, 200*time.Millisecond)
		if err != nil {
			// Dial failed — port is free.
			return nil
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			return fmt.Errorf("waitForPortFree: %s still accepting connections after %s", addr, timeout)
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// waitForPortReady is the inverse: polls until addr DOES accept
// connections, or the timeout elapses. Used by spawn paths that need
// to confirm a freshly-started backend is actually listening before
// declaring it ready.
func waitForPortReady(ctx context.Context, addr string, timeout time.Duration) error {
	probeAddr := normalizeProbeAddr(addr)
	deadline := time.Now().Add(timeout)
	pollInterval := 50 * time.Millisecond

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", probeAddr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("waitForPortReady: %s not accepting connections after %s: %w", addr, timeout, err)
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// normalizeProbeAddr converts ":4433" → "127.0.0.1:4433" so net.Dial
// can resolve it. Other forms ("0.0.0.0:4433", "host:port") are
// returned as-is.
func normalizeProbeAddr(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "127.0.0.1" + addr
	}
	// "0.0.0.0:port" is not a valid Dial target on Windows; rewrite to
	// loopback.
	if len(addr) >= 8 && addr[:7] == "0.0.0.0" {
		return "127.0.0.1" + addr[7:]
	}
	return addr
}
