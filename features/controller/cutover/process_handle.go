// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ExecProcessHandle is the production ProcessHandle that wraps an
// exec.Cmd for the cfgms-controller binary. Lifecycle:
//
//   - Start spawns the binary with the supplied listen-addr overrides
//     applied via Story #1919's --listen-api-addr / --listen-transport-addr
//     flags. The child inherits the launcher's environment plus
//     CFGMS_CONTROLLER_CONFIG for the shared cfg path.
//   - Drain sends SIGTERM (or os.Interrupt on Windows where SIGTERM is
//     not delivered to console subsystems) and waits up to DrainTimeout
//     for the process to exit on its own. The controller's signal
//     handler in cmd/controller/main.go calls srv.Stop() which already
//     drains in-flight requests.
//   - Stop sends SIGKILL (TerminateProcess on Windows) and reaps the
//     process. Called only after Drain has timed out or the orchestrator
//     decided the process must die immediately.
//
// Safe to call from any goroutine — internal mutex serialises the
// lifecycle methods, and Stop is idempotent.
type ExecProcessHandle struct {
	// Binary is the on-disk path to the cfgms-controller binary this
	// handle supervises.
	Binary string

	// ConfigPath is the controller.cfg path passed to the spawned
	// process. Blue and green share the same config (per the Story B
	// substrate); listen-addr overrides come from the Start args.
	ConfigPath string

	// ExtraEnv is appended to the child's env after the launcher's own
	// os.Environ. Used by tests to control fake-child behaviour; in
	// production callers typically leave it empty.
	ExtraEnv []string

	// DrainTimeout caps how long Drain waits for graceful exit before
	// the caller is expected to escalate to Stop. Default 10s.
	DrainTimeout time.Duration

	// Stdout / Stderr are inherited by the child. nil → os.DevNull. In
	// production set to the launcher's logger writers so the child's
	// output rolls into the same log file.
	Stdout io.Writer
	Stderr io.Writer

	// ArgsOverride, when non-nil, replaces the argv that Start would
	// normally build via BuildArgs. Intended for tests that re-exec the
	// test binary as a fake child — the production argv (--config /
	// --listen-*) trips Go's testing.Main flag parser, so tests supply
	// "-test.run=..." here instead. Production callers leave this nil.
	ArgsOverride []string

	mu      sync.Mutex
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	exitCh  chan error // closed on Wait completion
	stopped bool
}

// NewExecProcessHandle constructs a handle that, when Started, will
// exec binaryPath. The handle does NOT spawn anything at construction
// time — Start is what fires the process.
func NewExecProcessHandle(binaryPath, configPath string) *ExecProcessHandle {
	return &ExecProcessHandle{
		Binary:       binaryPath,
		ConfigPath:   configPath,
		DrainTimeout: 10 * time.Second,
	}
}

// BinaryPath satisfies ProcessHandle.
func (h *ExecProcessHandle) BinaryPath() string { return h.Binary }

// BuildArgs returns the argv slice that Start will use to spawn the
// controller binary. Exposed publicly so tests can verify the flag
// wiring without actually exec'ing anything (real exec needs a real
// cfgms-controller binary, which is heavyweight for unit tests).
//
// Format: --config <ConfigPath> [--listen-api-addr <X>] [--listen-transport-addr <Y>]
// — matches the precedence contract established by Story B (#1919).
func (h *ExecProcessHandle) BuildArgs(listenAPIAddr, listenTransportAddr string) []string {
	args := []string{"--config", h.ConfigPath}
	if listenAPIAddr != "" {
		args = append(args, "--listen-api-addr", listenAPIAddr)
	}
	if listenTransportAddr != "" {
		args = append(args, "--listen-transport-addr", listenTransportAddr)
	}
	return args
}

// Start spawns the controller binary with the requested listen-addr
// overrides applied. Returns an error only if the spawn fails (binary
// missing, permission denied). Successful return means the process is
// starting up; readiness is detected separately via the Smoketester.
//
// If h.ArgsOverride is non-nil, those args are used VERBATIM instead of
// BuildArgs. This is for tests that re-exec the test binary as a fake
// child — the production argv (--config / --listen-*) is not tolerated
// by the Go testing.Main flag parser, but tests can supply their own
// argv (e.g. -test.run=TestHelperProcess) instead.
func (h *ExecProcessHandle) Start(ctx context.Context, listenAPIAddr, listenTransportAddr string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd != nil {
		return errors.New("cutover: ProcessHandle already started")
	}

	var args []string
	if h.ArgsOverride != nil {
		args = h.ArgsOverride
	} else {
		args = h.BuildArgs(listenAPIAddr, listenTransportAddr)
	}

	// We deliberately do NOT use exec.CommandContext here: cancelling
	// the orchestration ctx kills the child with SIGKILL on Linux and
	// TerminateProcess on Windows — neither calls our drain path. Drain
	// + Stop below handle signals explicitly. We DO carry the ctx into
	// the spawn purely so a cancellation before Start completes returns
	// promptly instead of hanging on a syscall.
	cmd := exec.Command(h.Binary, args...) //#nosec G204 -- caller validates Binary
	cmd.Env = append(os.Environ(), h.ExtraEnv...)
	cmd.Stdout = h.Stdout
	cmd.Stderr = h.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cutover: spawn %s: %w", h.Binary, err)
	}
	h.cmd = cmd

	// Reap the child asynchronously so Drain/Stop can wait on a single
	// channel regardless of whether the process exited on its own,
	// drained, or was killed.
	h.exitCh = make(chan error, 1)
	go func() {
		h.exitCh <- cmd.Wait()
		close(h.exitCh)
	}()

	// Honour context cancellation that happens AFTER Start returns by
	// arranging a cancellation watcher that calls Stop. This is a
	// belt-and-braces — the orchestrator never expects a child to die
	// just because its parent ctx fires; that should be Drain or Stop.
	cctx, ccancel := context.WithCancel(ctx)
	h.cancel = ccancel
	go func() {
		<-cctx.Done()
		// If ctx fired BEFORE the orchestrator called Stop, do an
		// immediate Stop to make sure we don't leak the child.
		_ = h.Stop(context.Background())
	}()
	return nil
}

// Drain sends a graceful shutdown signal and waits up to DrainTimeout
// for the child to exit. Returns nil if the child exits cleanly within
// the budget; returns a non-nil error if the budget elapses (caller
// typically escalates to Stop).
func (h *ExecProcessHandle) Drain(ctx context.Context) error {
	h.mu.Lock()
	if h.cmd == nil || h.stopped {
		h.mu.Unlock()
		return nil
	}
	process := h.cmd.Process
	exitCh := h.exitCh
	timeout := h.DrainTimeout
	h.mu.Unlock()

	if process == nil {
		return nil
	}
	if err := sendGracefulSignal(process); err != nil {
		// Best-effort: log and proceed to wait. A failed signal usually
		// means the process is already dead, in which case the wait
		// below returns immediately.
		_ = err
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-exitCh:
		return nil
	case <-waitCtx.Done():
		return fmt.Errorf("cutover: drain timeout after %s waiting for %s to exit", timeout, h.Binary)
	}
}

// Stop forcibly terminates the child and reaps it. Idempotent — a
// second call after the process has already been reaped is a no-op.
func (h *ExecProcessHandle) Stop(ctx context.Context) error {
	h.mu.Lock()
	if h.cmd == nil || h.stopped {
		h.mu.Unlock()
		return nil
	}
	h.stopped = true
	process := h.cmd.Process
	exitCh := h.exitCh
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	h.mu.Unlock()

	if process != nil {
		_ = process.Kill()
	}

	// Reap up to 5s even on forced kill so we don't leak goroutines.
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case <-exitCh:
		return nil
	case <-waitCtx.Done():
		return fmt.Errorf("cutover: stop timeout reaping %s", h.Binary)
	}
}

// sendGracefulSignal sends SIGTERM on Unix and os.Interrupt on Windows.
// On Windows, os.Process.Signal supports os.Interrupt (which is delivered
// as a Ctrl-Break to console processes); SIGTERM is not deliverable.
// The cfgms-controller signal handler treats both identically.
func sendGracefulSignal(p *os.Process) error {
	return p.Signal(gracefulSignal())
}

// gracefulSignal returns the platform-appropriate "please drain" signal.
// Split into a function so the Windows build constraint stays in
// process_handle_signal_windows.go / _unix.go.
func gracefulSignal() os.Signal {
	return defaultGracefulSignal
}

// defaultGracefulSignal is overridden in the per-platform files.
var defaultGracefulSignal os.Signal = syscall.SIGTERM
