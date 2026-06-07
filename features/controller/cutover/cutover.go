// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package cutover orchestrates blue/green controller upgrades for epic
// #1917 / story #1920. The design uses the port-ownership-swap pattern
// (rather than gRPC-level reverse proxying) — see
// docs/architecture/operating-model.md "Concurrent Controller Execution
// (Blue/Green Pattern)" for the full architectural context.
//
// # The cutover state machine
//
//	idle ─▶ preparing ─▶ smoketesting ─▶ swapping ─▶ quarantined ─▶ idle
//	  │         │              │             │             │
//	  └─────────┴──────────────┴─────────────┴─────────────┘
//	          (any state can transition back to idle on failure /
//	           operator abort, with no partial state retained)
//
// Stages:
//
//   - idle         The single canonical backend is serving. No upgrade in
//                  progress. cfg controller upgrade can be invoked.
//   - preparing    The orchestrator has accepted an upgrade request,
//                  validated the new binary, and is about to spawn the
//                  candidate backend on the alternate listen addresses.
//   - smoketesting The candidate is running on alternate ports and the
//                  orchestrator is hitting it with health-probe RPCs
//                  before allowing it to take over the canonical ports.
//   - swapping     Smoketests passed. The orchestrator is in the middle
//                  of the port-ownership swap: canonical backend stops
//                  listening; candidate takes over canonical ports.
//                  This is the brief window of API unavailability for
//                  connected stewards (the gRPC-over-QUIC client already
//                  reconnects with exponential backoff so the window is
//                  invisible to module convergence).
//   - quarantined  Cutover completed. The newly-canonical backend is
//                  serving; the previously-canonical backend is parked
//                  on alternate ports for the configured quarantine
//                  window so cfg controller rollback can flip back
//                  instantly. After the window expires the old backend
//                  shuts down and the orchestrator returns to idle.
//
// Concurrent cfg controller upgrade attempts are rejected with
// ErrUpgradeInProgress while the state is anything other than idle.
//
// # What this package owns vs. defers
//
// This package owns ONLY the orchestrator state machine + the abstract
// ProcessHandle interface. It deliberately does NOT own:
//
//   - Bundle signature verification (Issue #1882; verifier is plugged in
//     via the Validator interface so signature work can land
//     independently)
//   - Actual subprocess execution (the production ProcessHandle impl
//     wraps exec.Cmd; the orchestrator never depends on the real exe)
//   - Smoketest RPC payloads (the production Smoketester sends real
//     control-plane probes against the candidate; we test against a
//     fake)
//
// Each of those is a clearly-scoped surface that can be filled in by
// follow-up work without touching this orchestrator.
package cutover

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is the lifecycle stage of a cutover.
type State string

const (
	StateIdle         State = "idle"
	StatePreparing    State = "preparing"
	StateSmoketesting State = "smoketesting"
	StateSwapping     State = "swapping"
	StateQuarantined  State = "quarantined"
)

// Errors surfaced by Orchestrator. Each maps to a specific operator-
// visible failure mode in `cfg controller upgrade`.
var (
	ErrUpgradeInProgress   = errors.New("cutover: an upgrade is already in progress")
	ErrNoQuarantinedBinary = errors.New("cutover: no quarantined binary available to roll back to")
	ErrValidationFailed    = errors.New("cutover: binary validation failed")
	ErrSmoketestFailed     = errors.New("cutover: candidate smoketest failed")
	ErrAborted             = errors.New("cutover: upgrade aborted by operator")
)

// Snapshot is a point-in-time view of the orchestrator's state. Returned
// by Status() and used by `cfg controller upgrade status` to render the
// operator-visible state line. Safe to log / serialise — no internal
// references escape.
type Snapshot struct {
	State                State     `json:"state"`
	CanonicalBinary      string    `json:"canonical_binary"`
	CanonicalStartedAt   time.Time `json:"canonical_started_at"`
	QuarantinedBinary    string    `json:"quarantined_binary,omitempty"`
	QuarantinedStartedAt time.Time `json:"quarantined_started_at,omitempty"`
	QuarantineExpiresAt  time.Time `json:"quarantine_expires_at,omitempty"`
}

// ProcessHandle is the subprocess abstraction the orchestrator depends
// on. The production impl wraps an exec.Cmd that spawns a controller
// binary in backend mode. Tests use a fake impl that records lifecycle
// calls.
//
// The orchestrator NEVER imports os/exec directly — all subprocess
// effects route through this interface so the state-machine logic is
// independently testable.
type ProcessHandle interface {
	// Start launches the backend process on the requested listen
	// addresses. Returns an error only if the spawn itself fails (binary
	// missing, permission denied, etc.). Successful return means the
	// process is starting up; readiness is detected separately via the
	// Smoketester.
	Start(ctx context.Context, listenAPIAddr, listenTransportAddr string) error

	// Drain asks the backend to stop accepting new requests and finish
	// in-flight requests. Used during port-ownership swap so connected
	// stewards finish their current RPCs cleanly before the canonical
	// listener disappears.
	Drain(ctx context.Context) error

	// Stop terminates the backend process. Always succeeds in the sense
	// that the orchestrator treats the handle as gone afterwards;
	// implementation may log on hard-kill paths.
	Stop(ctx context.Context) error

	// BinaryPath returns the on-disk path of the binary this handle
	// supervises. Used for Snapshot rendering and rollback decisions.
	BinaryPath() string
}

// Validator vets a candidate binary BEFORE the orchestrator spawns it.
// In production this verifies the bundle signature per #1882 and confirms
// the architecture matches the host. The orchestrator depends only on
// the (binary path → ok / not-ok) verdict so the signature surface can
// evolve without touching this package.
type Validator interface {
	Validate(ctx context.Context, binaryPath string) error
}

// Smoketester runs health probes against a candidate backend before the
// orchestrator allows it to take over the canonical ports. Returns nil
// when the backend is verified healthy; a non-nil error means the
// orchestrator refuses to swap and surfaces the reason to the operator.
type Smoketester interface {
	Probe(ctx context.Context, candidate ProcessHandle, listenAPIAddr, listenTransportAddr string) error
}

// SwapTarget is the abstract "this binary now owns the canonical ports"
// effect. The production impl signals both processes (drain old; rebind
// new) via the controller's local admin socket. Tests use a fake impl
// that just records the swap.
//
// Separating the swap mechanic from the orchestrator state machine lets
// us implement the actual port rebind however turns out to fit the
// platform (Linux SO_REUSEPORT swap, Windows alternate-port swap, etc.)
// without touching the state machine again.
type SwapTarget interface {
	// Swap atomically transfers canonical-port ownership from `from`
	// (currently listening on the canonical addrs) to `to` (currently
	// listening on the candidate addrs). After Swap returns nil, `to` is
	// the new canonical and `from` is the quarantined backend.
	Swap(ctx context.Context, from, to ProcessHandle, canonicalAPIAddr, canonicalTransportAddr string) error
}

// Config holds orchestrator-level knobs. Defaults are populated in
// NewOrchestrator if the caller leaves any zero-valued.
type Config struct {
	// CanonicalAPIAddr / CanonicalTransportAddr are the addresses the
	// canonical backend must listen on at the end of every cutover.
	// These come from controller.cfg (potentially overridden via Story B's
	// --listen-* flags) and are passed to Swap so it knows the target
	// state.
	CanonicalAPIAddr       string
	CanonicalTransportAddr string

	// CandidateAPIAddr / CandidateTransportAddr are where a freshly
	// spawned candidate binds while it's being smoketested. Operators
	// typically set these to canonical_port + 1 so they're predictable.
	CandidateAPIAddr       string
	CandidateTransportAddr string

	// QuarantineWindow is how long a previously-canonical backend stays
	// running on the candidate ports after a successful cutover, ready
	// for `cfg controller rollback` to flip back. After this expires the
	// orchestrator stops the quarantined process and transitions back to
	// idle. Default: 1 hour.
	QuarantineWindow time.Duration

	// SmoketestTimeout caps how long Probe() may run before the
	// orchestrator gives up. Default: 30s.
	SmoketestTimeout time.Duration
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.QuarantineWindow <= 0 {
		out.QuarantineWindow = 1 * time.Hour
	}
	if out.SmoketestTimeout <= 0 {
		out.SmoketestTimeout = 30 * time.Second
	}
	return out
}

// Orchestrator runs the cutover state machine for a single controller
// installation. There is exactly one Orchestrator per running controller
// process — concurrent upgrade attempts route through the same instance
// and the second one fails with ErrUpgradeInProgress.
//
// All public methods are safe to call concurrently.
type Orchestrator struct {
	cfg       Config
	validator Validator
	smoke     Smoketester
	swap      SwapTarget
	spawn     func(binaryPath string) ProcessHandle

	mu                   sync.Mutex
	state                State
	canonical            ProcessHandle
	canonicalStartedAt   time.Time
	quarantined          ProcessHandle
	quarantinedStartedAt time.Time
	quarantineExpiresAt  time.Time

	clock func() time.Time
}

// NewOrchestrator constructs an Orchestrator that supervises `initial` as
// the canonical backend. `spawn` is the factory used to produce
// ProcessHandle instances for candidate binaries (tests inject a fake
// that records calls; production wires it to a real exec.Cmd wrapper).
func NewOrchestrator(
	cfg Config,
	initial ProcessHandle,
	validator Validator,
	smoke Smoketester,
	swap SwapTarget,
	spawn func(binaryPath string) ProcessHandle,
) *Orchestrator {
	if spawn == nil {
		panic("cutover: spawn factory must not be nil")
	}
	o := &Orchestrator{
		cfg:                cfg.withDefaults(),
		validator:          validator,
		smoke:              smoke,
		swap:               swap,
		spawn:              spawn,
		state:              StateIdle,
		canonical:          initial,
		canonicalStartedAt: time.Now(),
		clock:              time.Now,
	}
	return o
}

// Status returns a point-in-time snapshot of the orchestrator state.
// Safe to call from any goroutine including during an in-progress
// upgrade.
func (o *Orchestrator) Status() Snapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.snapshotLocked()
}

func (o *Orchestrator) snapshotLocked() Snapshot {
	snap := Snapshot{
		State:              o.state,
		CanonicalStartedAt: o.canonicalStartedAt,
	}
	if o.canonical != nil {
		snap.CanonicalBinary = o.canonical.BinaryPath()
	}
	if o.quarantined != nil {
		snap.QuarantinedBinary = o.quarantined.BinaryPath()
		snap.QuarantinedStartedAt = o.quarantinedStartedAt
		snap.QuarantineExpiresAt = o.quarantineExpiresAt
	}
	return snap
}

// Upgrade is the operator-facing entry point. It runs the full
// preparing → smoketesting → swapping pipeline against `candidateBinary`
// and returns nil only after the new binary is serving as canonical and
// the previous binary is parked in the quarantine slot.
//
// Returns ErrUpgradeInProgress if another cutover is already running.
// Returns ErrValidationFailed / ErrSmoketestFailed / a wrapped swap
// error otherwise — each carries enough context for `cfg controller
// upgrade` to render an operator-actionable message.
//
// The state machine never leaves a partially-committed state: any
// failure rolls back to a clean idle/canonical-only state before
// returning.
func (o *Orchestrator) Upgrade(ctx context.Context, candidateBinary string) error {
	if err := o.beginUpgrade(); err != nil {
		return err
	}
	// On any error path, the orchestrator must end up in StateIdle with
	// the original canonical still serving (no quarantine slot set).
	// rollbackToIdle handles that.
	if err := o.runUpgrade(ctx, candidateBinary); err != nil {
		o.rollbackToIdle()
		return err
	}
	return nil
}

func (o *Orchestrator) beginUpgrade() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != StateIdle {
		return ErrUpgradeInProgress
	}
	o.state = StatePreparing
	return nil
}

func (o *Orchestrator) runUpgrade(ctx context.Context, candidateBinary string) error {
	// Validate first — cheapest gate; refuses unsigned / wrong-arch
	// binaries before any side effects.
	if o.validator != nil {
		if err := o.validator.Validate(ctx, candidateBinary); err != nil {
			return fmt.Errorf("%w: %v", ErrValidationFailed, err)
		}
	}

	candidate := o.spawn(candidateBinary)
	if err := candidate.Start(ctx, o.cfg.CandidateAPIAddr, o.cfg.CandidateTransportAddr); err != nil {
		return fmt.Errorf("cutover: start candidate: %w", err)
	}

	// On error past this point, the candidate is running on the
	// candidate ports and must be stopped before we return.
	stopCandidate := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = candidate.Stop(stopCtx)
	}

	o.transitionTo(StateSmoketesting)
	smokeCtx, cancel := context.WithTimeout(ctx, o.cfg.SmoketestTimeout)
	defer cancel()
	if o.smoke != nil {
		if err := o.smoke.Probe(smokeCtx, candidate, o.cfg.CandidateAPIAddr, o.cfg.CandidateTransportAddr); err != nil {
			stopCandidate()
			return fmt.Errorf("%w: %v", ErrSmoketestFailed, err)
		}
	}

	o.transitionTo(StateSwapping)
	o.mu.Lock()
	prevCanonical := o.canonical
	o.mu.Unlock()
	if o.swap == nil {
		stopCandidate()
		return errors.New("cutover: no SwapTarget configured")
	}
	if err := o.swap.Swap(ctx, prevCanonical, candidate, o.cfg.CanonicalAPIAddr, o.cfg.CanonicalTransportAddr); err != nil {
		stopCandidate()
		return fmt.Errorf("cutover: swap canonical ownership: %w", err)
	}

	// Promote candidate → canonical and park previous → quarantined.
	o.mu.Lock()
	o.canonical = candidate
	o.canonicalStartedAt = o.clock()
	o.quarantined = prevCanonical
	o.quarantinedStartedAt = o.clock()
	o.quarantineExpiresAt = o.clock().Add(o.cfg.QuarantineWindow)
	o.state = StateQuarantined
	o.mu.Unlock()

	return nil
}

// Rollback restores the previously-canonical backend if the operator
// regrets a recent upgrade. Only valid while the orchestrator is in
// StateQuarantined; outside that window the previous backend has already
// been stopped and ErrNoQuarantinedBinary is returned.
func (o *Orchestrator) Rollback(ctx context.Context) error {
	o.mu.Lock()
	if o.state != StateQuarantined || o.quarantined == nil {
		o.mu.Unlock()
		return ErrNoQuarantinedBinary
	}
	currentCanonical := o.canonical
	quarantined := o.quarantined
	o.state = StateSwapping
	o.mu.Unlock()

	if err := o.swap.Swap(ctx, currentCanonical, quarantined, o.cfg.CanonicalAPIAddr, o.cfg.CanonicalTransportAddr); err != nil {
		// Roll the state back to Quarantined so the operator can retry.
		o.mu.Lock()
		o.state = StateQuarantined
		o.mu.Unlock()
		return fmt.Errorf("cutover: rollback swap: %w", err)
	}

	// Stop the now-rolled-back backend (the binary the operator regretted).
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = currentCanonical.Stop(stopCtx)

	o.mu.Lock()
	o.canonical = quarantined
	o.canonicalStartedAt = o.clock()
	o.quarantined = nil
	o.quarantinedStartedAt = time.Time{}
	o.quarantineExpiresAt = time.Time{}
	o.state = StateIdle
	o.mu.Unlock()

	return nil
}

// FinalizeQuarantine stops the quarantined backend and returns the
// orchestrator to StateIdle. Called by the supervisor when the
// quarantine window has elapsed. Idempotent: a no-op if no quarantined
// backend is currently parked.
func (o *Orchestrator) FinalizeQuarantine(ctx context.Context) {
	o.mu.Lock()
	if o.state != StateQuarantined || o.quarantined == nil {
		o.mu.Unlock()
		return
	}
	quarantined := o.quarantined
	o.quarantined = nil
	o.quarantinedStartedAt = time.Time{}
	o.quarantineExpiresAt = time.Time{}
	o.state = StateIdle
	o.mu.Unlock()

	_ = quarantined.Stop(ctx)
}

// rollbackToIdle is the failure-cleanup path used by Upgrade when any
// stage errors out. It restores the orchestrator to StateIdle without
// touching the original canonical backend — it's still serving because
// we never swapped.
func (o *Orchestrator) rollbackToIdle() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.state = StateIdle
	// canonical / canonicalStartedAt are unchanged from before the
	// upgrade — that's the point: the original keeps serving.
	o.quarantined = nil
	o.quarantinedStartedAt = time.Time{}
	o.quarantineExpiresAt = time.Time{}
}

func (o *Orchestrator) transitionTo(s State) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.state = s
}
