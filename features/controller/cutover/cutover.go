// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package cutover orchestrates blue/green controller upgrades for epic
// #1917 / story #1920. The design uses the port-ownership-swap pattern
// (rather than gRPC-level reverse proxying) — see
// docs/architecture/operating-model.md "Concurrent Controller Execution
// (Blue/Green Pattern)" for the full architectural context.
//
// # Deprecation notice (Issue #2019, ADR-007)
//
// This port-swap orchestrator is EXPERIMENTAL and is not the supported
// production upgrade path. Per ADR-007
// (docs/architecture/decisions/007-controller-upgrade-and-state-externalization.md),
// investment in this path has stopped. The supported upgrade path is the
// smoketest-gated restart upgrade (Issue #2015, cfg controller upgrade
// restart). The /api/v1/ready real-state smoketest (HTTPSmoketester) and
// the keep-previous-binary rollback pattern from this package are reused by
// the restart-gated upgrade and remain maintained. Removal of the remaining
// port-swap orchestration is tracked for once the restart-gated path is the
// documented default. No new feature work should target this package.
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
//     progress. cfg controller upgrade can be invoked.
//   - preparing    The orchestrator has accepted an upgrade request,
//     validated the new binary, and is about to spawn the
//     candidate backend on the alternate listen addresses.
//   - smoketesting The candidate is running on alternate ports and the
//     orchestrator is hitting it with health-probe RPCs
//     before allowing it to take over the canonical ports.
//   - swapping     Smoketests passed. The orchestrator is in the middle
//     of the port-ownership swap: canonical backend stops
//     listening; candidate takes over canonical ports.
//     This is the brief window of API unavailability for
//     connected stewards (the gRPC-over-QUIC client already
//     reconnects with exponential backoff so the window is
//     invisible to module convergence).
//   - quarantined  Cutover completed. The newly-canonical backend is
//     serving; the previously-canonical backend is parked
//     on alternate ports for the configured quarantine
//     window so cfg controller rollback can flip back
//     instantly. After the window expires the old backend
//     shuts down and the orchestrator returns to idle.
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
// effect. The production impl (PortSwapTarget) drains the old, waits
// for the OS to release the canonical ports, then spawns a fresh
// instance of the new binary on those ports. Tests use a fake impl
// that just records the swap.
//
// # Why Swap returns a ProcessHandle
//
// Some swap implementations (notably PortSwapTarget) STOP the supplied
// `to` and spawn a fresh process on the canonical ports — the `to`
// handle the orchestrator passed in is dead by the time Swap returns
// nil. Returning the actual promoted handle keeps the orchestrator's
// canonical pointer consistent with what's truly serving traffic.
// Simple swap impls that don't respawn (e.g. tests) can return the
// input `to` unchanged.
type SwapTarget interface {
	// Swap atomically transfers canonical-port ownership from `from`
	// (currently listening on the canonical addrs) to a new instance
	// derived from `to` (currently listening on the candidate addrs).
	// On success the returned ProcessHandle is the one the orchestrator
	// should treat as the new canonical.
	Swap(ctx context.Context, from, to ProcessHandle, canonicalAPIAddr, canonicalTransportAddr string) (ProcessHandle, error)
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
	// The defer + recover guarantees the orchestrator never stays stuck
	// in a non-idle state even if runUpgrade panics — without this, a
	// panic in spawn / Start / Probe / Swap would leave the state
	// machine wedged in StatePreparing / StateSmoketesting / StateSwapping
	// forever and every subsequent Upgrade attempt would return
	// ErrUpgradeInProgress. Re-panic after restoring state so the caller
	// still sees the original crash; we just refuse to leave the
	// orchestrator broken.
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				o.rollbackToIdle()
				panic(r)
			}
		}()
		err = o.runUpgrade(ctx, candidateBinary)
	}()
	if err != nil {
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

	// Read the current canonical handle and transition to StateSwapping
	// in ONE locked section. The previous version released the lock
	// between transitionTo() and the prevCanonical read, opening a window
	// where Rollback / FinalizeQuarantine could mutate o.canonical
	// concurrently (review feedback from #1920).
	o.mu.Lock()
	o.state = StateSwapping
	prevCanonical := o.canonical
	o.mu.Unlock()

	if o.swap == nil {
		stopCandidate()
		return errors.New("cutover: no SwapTarget configured")
	}
	promoted, err := o.swap.Swap(ctx, prevCanonical, candidate, o.cfg.CanonicalAPIAddr, o.cfg.CanonicalTransportAddr)
	if err != nil {
		// Swap failed. The original canonical MAY have been drained by
		// the swap implementation before it returned the error, so its
		// "still serving" status is uncertain. Documented at the Swap
		// interface contract. The orchestrator surfaces the failure;
		// recovering the original canonical's listener (if it was
		// drained) is the swap implementation's responsibility.
		stopCandidate()
		return fmt.Errorf("cutover: swap canonical ownership: %w", err)
	}
	if promoted == nil {
		// Defensive: a SwapTarget that returns (nil, nil) violates
		// the contract; treat it as a failure rather than promoting
		// a nil pointer.
		stopCandidate()
		return errors.New("cutover: SwapTarget returned nil promoted handle on success")
	}

	// Promote (the swap-returned handle, NOT the original candidate
	// pointer — they may differ when the swap respawned) → canonical
	// and park previous → quarantined.
	o.mu.Lock()
	o.canonical = promoted
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
//
// Locking discipline (matters for the Rollback/FinalizeQuarantine race
// surfaced in review): on entry we atomically claim the quarantined
// handle by CLEARING o.quarantined while still under the lock, so any
// concurrent FinalizeQuarantine call observes a nil quarantined slot
// and returns immediately. The handle is owned by THIS Rollback for the
// remainder of the call. Double-Stop is no longer possible.
func (o *Orchestrator) Rollback(ctx context.Context) error {
	o.mu.Lock()
	if o.state != StateQuarantined || o.quarantined == nil {
		o.mu.Unlock()
		return ErrNoQuarantinedBinary
	}
	currentCanonical := o.canonical
	quarantined := o.quarantined
	// Claim the quarantined slot. Any concurrent FinalizeQuarantine will
	// see o.quarantined == nil and bail. The currentCanonical pointer is
	// kept locally and won't be touched by anyone else for the duration
	// of the call.
	o.quarantined = nil
	o.state = StateSwapping
	o.mu.Unlock()

	promoted, err := o.swap.Swap(ctx, currentCanonical, quarantined, o.cfg.CanonicalAPIAddr, o.cfg.CanonicalTransportAddr)
	if err != nil {
		// Swap failed — restore the quarantine slot so the operator can retry.
		o.mu.Lock()
		o.quarantined = quarantined
		o.state = StateQuarantined
		o.mu.Unlock()
		return fmt.Errorf("cutover: rollback swap: %w", err)
	}
	if promoted == nil {
		// Defensive (same as runUpgrade): refuse to promote a nil handle.
		o.mu.Lock()
		o.quarantined = quarantined
		o.state = StateQuarantined
		o.mu.Unlock()
		return errors.New("cutover: SwapTarget returned nil promoted handle on rollback")
	}

	// Stop the now-rolled-back backend (the binary the operator regretted).
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = currentCanonical.Stop(stopCtx)

	o.mu.Lock()
	o.canonical = promoted
	o.canonicalStartedAt = o.clock()
	o.quarantinedStartedAt = time.Time{}
	o.quarantineExpiresAt = time.Time{}
	o.state = StateIdle
	o.mu.Unlock()

	return nil
}

// FinalizeQuarantine stops the quarantined backend and returns the
// orchestrator to StateIdle. Called by the supervisor when the
// quarantine window has elapsed. Idempotent: a no-op if no quarantined
// backend is currently parked (e.g. because a concurrent Rollback
// already claimed it — see Rollback locking discipline above).
func (o *Orchestrator) FinalizeQuarantine(ctx context.Context) {
	o.mu.Lock()
	if o.state != StateQuarantined || o.quarantined == nil {
		o.mu.Unlock()
		return
	}
	// Claim the quarantined slot before releasing the lock so a
	// concurrent Rollback observes nil and bails (mirrors the Rollback
	// claim above; together these two CLAIM-before-Stop patterns
	// eliminate the double-Stop race a concurrent caller could
	// otherwise trigger).
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
