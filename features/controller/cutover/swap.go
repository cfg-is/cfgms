// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PortSwapTarget is the production SwapTarget for the port-ownership-
// swap design (epic #1917 story #1920). It transfers canonical-port
// ownership from `from` to `to` by:
//
//  1. Draining `from` (graceful signal, wait for in-flight requests to
//     finish, child exits, OS releases the canonical ports).
//  2. Waiting up to PortHandoffTimeout for the canonical ports to
//     actually be free at the OS level. Without this wait, a fast
//     spawn loop on the orchestrator side would TOCTOU itself against
//     the kernel's TIME_WAIT lingering.
//  3. Stopping `to` (it was running on candidate ports for smoketesting
//     and must release them before spawning the canonical instance).
//  4. Spawning a fresh instance via CandidateSpawner on the CANONICAL
//     ports.
//
// Stewards see ~1-3s of API unavailability, well under the 10s AC bound.
// gRPC-over-QUIC client reconnect handles the transient outage.
//
// Because Swap REPLACES `to` with a fresh handle, the orchestrator's
// `candidate` pointer would be stale. The Swap method publishes the
// freshly-bound handle via LastPromoted(); the orchestrator wiring
// fetches that after Swap returns nil and treats it as the new
// canonical.
type PortSwapTarget struct {
	// PortHandoffTimeout caps how long Swap waits between the old
	// process exiting and confirming the canonical ports are free.
	// Default 5s. Linux typically completes instantly; Windows
	// loopback may linger ~500ms.
	PortHandoffTimeout time.Duration

	// CandidateSpawner is the factory the swap uses to produce the
	// fresh post-swap handle. Same shape as Orchestrator.spawn — takes
	// a binary path, returns a ProcessHandle.
	CandidateSpawner func(binaryPath string) ProcessHandle

	// ReadinessProbe verifies the new canonical instance is actually
	// accepting connections before Swap returns. nil → swap returns
	// immediately after spawn. Production callers should always supply
	// a probe.
	ReadinessProbe Smoketester

	mu              sync.Mutex
	lastPromotedSet ProcessHandle
}

// Swap implements SwapTarget.
func (p *PortSwapTarget) Swap(ctx context.Context, from, to ProcessHandle, canonicalAPIAddr, canonicalTransportAddr string) (ProcessHandle, error) {
	if from == nil || to == nil {
		return nil, errors.New("cutover: Swap requires non-nil from and to handles")
	}
	if p.PortHandoffTimeout <= 0 {
		p.PortHandoffTimeout = 5 * time.Second
	}
	if p.CandidateSpawner == nil {
		return nil, errors.New("cutover: PortSwapTarget.CandidateSpawner is required")
	}

	// Step 1: drain the previous canonical.
	drainCtx, cancel := context.WithTimeout(ctx, p.PortHandoffTimeout)
	if err := from.Drain(drainCtx); err != nil {
		stopCtx, sc := context.WithTimeout(context.Background(), 5*time.Second)
		_ = from.Stop(stopCtx)
		sc()
	}
	cancel()

	// Step 2: wait for the canonical ports to actually free up.
	if err := waitForPortFree(ctx, canonicalAPIAddr, p.PortHandoffTimeout); err != nil {
		return nil, fmt.Errorf("cutover: canonical API port %s did not free: %w", canonicalAPIAddr, err)
	}
	if canonicalTransportAddr != "" {
		if err := waitForPortFree(ctx, canonicalTransportAddr, p.PortHandoffTimeout); err != nil {
			return nil, fmt.Errorf("cutover: canonical transport port %s did not free: %w", canonicalTransportAddr, err)
		}
	}

	// Step 3: stop the smoketest-time instance of `to` (it was bound on
	// candidate ports; we want a fresh canonical one).
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = to.Stop(stopCtx)
	stopCancel()

	// Step 4: spawn the fresh canonical instance.
	newCanonical := p.CandidateSpawner(to.BinaryPath())
	if err := newCanonical.Start(ctx, canonicalAPIAddr, canonicalTransportAddr); err != nil {
		return nil, fmt.Errorf("cutover: start canonical instance: %w", err)
	}

	// Step 5: probe readiness (optional but strongly recommended).
	if p.ReadinessProbe != nil {
		probeCtx, probeCancel := context.WithTimeout(ctx, 30*time.Second)
		defer probeCancel()
		if err := p.ReadinessProbe.Probe(probeCtx, newCanonical, canonicalAPIAddr, canonicalTransportAddr); err != nil {
			killCtx, kc := context.WithTimeout(context.Background(), 5*time.Second)
			_ = newCanonical.Stop(killCtx)
			kc()
			return nil, fmt.Errorf("cutover: post-swap readiness probe failed: %w", err)
		}
	}

	p.mu.Lock()
	p.lastPromotedSet = newCanonical
	p.mu.Unlock()
	return newCanonical, nil
}

// LastPromoted returns the ProcessHandle that became canonical during
// the most recent successful Swap. nil if no swap has succeeded yet.
// The orchestrator wiring fetches this after each Swap so its
// `canonical` pointer tracks the freshly-bound handle, not the stale
// `to` that the Swap call received.
func (p *PortSwapTarget) LastPromoted() ProcessHandle {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPromotedSet
}
