// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Restricted run bounds and run guard (ADR-036 section 3).
//
// A restricted run is bounded in steps, loop iterations, fan-out and wall time,
// because delay and loops are a denial-of-service vector against the controller.
// It is also guarded: the engine calls the run guard before every step, so a
// revoked grant or an ended run reaches a running workflow at its next step.
// Unrestricted runs (ExecuteWorkflow) are neither bounded nor guarded.

const (
	// DefaultRestrictedMaxSteps bounds the steps one restricted run starts,
	// counting nested steps, loop-body steps and retries.
	DefaultRestrictedMaxSteps = 500
	// DefaultRestrictedMaxLoopIterations bounds the loop-body iterations one
	// restricted run starts, summed over every for, while and foreach loop in it.
	DefaultRestrictedMaxLoopIterations = 250
	// DefaultRestrictedMaxFanOut bounds the parallel branches a restricted run has
	// running at once, counting nested parallel steps.
	DefaultRestrictedMaxFanOut = 10
	// DefaultRestrictedMaxWallTime bounds the time from start to the end of a
	// restricted run.
	DefaultRestrictedMaxWallTime = 15 * time.Minute
)

var (
	// ErrRestrictedBoundExceeded is wrapped by the reason recorded when a
	// restricted run exceeds a step, iteration, fan-out or wall-time bound.
	ErrRestrictedBoundExceeded = errors.New("restricted run bound exceeded")
	// ErrRestrictedRunGuardStopped is wrapped by the reason recorded when the run
	// guard returns an error: the run has ended or its grant was revoked.
	ErrRestrictedRunGuardStopped = errors.New("restricted run stopped by the run guard")
)

// RunGuard reports whether a restricted run may continue. A non-nil error means
// the run has ended or its grant was revoked: the engine cancels the execution
// and records the error as the reason. The engine calls it before every step,
// possibly from concurrent parallel branches, so it must be safe for concurrent
// use and quick.
type RunGuard func(ctx context.Context) error

// RestrictedOptions are the per-run bounds and guard of a restricted execution.
// A zero or negative bound takes its default; a bound cannot be turned off.
type RestrictedOptions struct {
	// MaxSteps bounds the steps the run starts.
	MaxSteps int
	// MaxLoopIterations bounds the loop-body iterations the run starts in total.
	MaxLoopIterations int
	// MaxFanOut bounds the parallel branches the run has running at once.
	MaxFanOut int
	// MaxWallTime bounds the run's duration.
	MaxWallTime time.Duration
	// RunGuard is called before every step. Nil means no guard.
	RunGuard RunGuard
}

// withDefaults returns o with every unset bound replaced by its default.
func (o RestrictedOptions) withDefaults() RestrictedOptions {
	if o.MaxSteps <= 0 {
		o.MaxSteps = DefaultRestrictedMaxSteps
	}
	if o.MaxLoopIterations <= 0 {
		o.MaxLoopIterations = DefaultRestrictedMaxLoopIterations
	}
	if o.MaxFanOut <= 0 {
		o.MaxFanOut = DefaultRestrictedMaxFanOut
	}
	if o.MaxWallTime <= 0 {
		o.MaxWallTime = DefaultRestrictedMaxWallTime
	}
	return o
}

// restrictedState is the live accounting of one restricted run. It travels in the
// run's context, so every step, including those in parallel branches, reaches it.
type restrictedState struct {
	opts   RestrictedOptions
	cancel context.CancelFunc
	timer  *time.Timer

	mu         sync.Mutex
	steps      int
	iterations int
	fanOut     int
	stopErr    error
	stopStatus ExecutionStatus
}

type restrictedStateKey struct{}

// loopBodyKey marks the context a loop step runs its body in, so the engine can
// recognise each iteration of the body without a hook in the loop executors.
type loopBodyKey struct{}

// loopBody identifies a loop step's body by its first step: the loop executors
// pass step.Steps itself to executeSteps for every iteration.
type loopBody struct {
	first *Step
	n     int
}

// newRestrictedState starts the accounting for a run. cancel stops the run's
// execution; the wall-time timer stops it when MaxWallTime elapses.
func newRestrictedState(opts RestrictedOptions, cancel context.CancelFunc) *restrictedState {
	s := &restrictedState{opts: opts.withDefaults(), cancel: cancel}
	s.timer = time.AfterFunc(s.opts.MaxWallTime, func() {
		_ = s.exceeded("wall time %s", s.opts.MaxWallTime)
	})
	return s
}

// withRestrictedState returns ctx carrying the accounting of a restricted run,
// and the function that releases it once the run has ended. An unrestricted run
// gets ctx back unchanged and a release that does nothing.
func withRestrictedState(ctx context.Context, cancel context.CancelFunc, restricted bool, opts RestrictedOptions) (context.Context, func()) {
	if !restricted {
		return ctx, func() {}
	}
	state := newRestrictedState(opts, cancel)
	return context.WithValue(ctx, restrictedStateKey{}, state), state.release
}

func restrictedStateFrom(ctx context.Context) *restrictedState {
	s, _ := ctx.Value(restrictedStateKey{}).(*restrictedState)
	return s
}

// release stops the wall-time timer once the run has ended.
func (s *restrictedState) release() { s.timer.Stop() }

// stop records why the run ended and cancels its execution. The first reason
// wins; later calls change nothing.
func (s *restrictedState) stop(status ExecutionStatus, reason error) error {
	s.mu.Lock()
	first := s.stopErr == nil
	if first {
		s.stopErr, s.stopStatus = reason, status
	}
	recorded := s.stopErr
	s.mu.Unlock()
	if first {
		s.cancel()
	}
	return recorded
}

// stopped returns the recorded stop reason and the status the run ends in.
func (s *restrictedState) stopped() (ExecutionStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopStatus, s.stopErr
}

// exceeded records a bound violation and returns the recorded reason.
func (s *restrictedState) exceeded(format string, args ...interface{}) error {
	return s.stop(StatusFailed, fmt.Errorf("%w: %s", ErrRestrictedBoundExceeded, fmt.Sprintf(format, args...)))
}

// admitStep runs before every step of a restricted run: a run already stopped
// refuses the step, the guard is consulted, then the step is counted.
func (s *restrictedState) admitStep(ctx context.Context) error {
	if _, err := s.stopped(); err != nil {
		return err
	}
	if s.opts.RunGuard != nil {
		if err := s.opts.RunGuard(ctx); err != nil {
			return s.stop(StatusCancelled, fmt.Errorf("%w: %w", ErrRestrictedRunGuardStopped, err))
		}
	}
	s.mu.Lock()
	s.steps++
	over := s.steps > s.opts.MaxSteps
	s.mu.Unlock()
	if over {
		return s.exceeded("more than %d steps", s.opts.MaxSteps)
	}
	return nil
}

// admitIteration runs before every iteration of a loop body.
func (s *restrictedState) admitIteration() error {
	if _, err := s.stopped(); err != nil {
		return err
	}
	s.mu.Lock()
	s.iterations++
	over := s.iterations > s.opts.MaxLoopIterations
	s.mu.Unlock()
	if over {
		return s.exceeded("more than %d loop iterations", s.opts.MaxLoopIterations)
	}
	return nil
}

// enterFanOut reserves n parallel branches and returns the function that
// releases them.
func (s *restrictedState) enterFanOut(n int) (func(), error) {
	if _, err := s.stopped(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.fanOut += n
	over := s.fanOut > s.opts.MaxFanOut
	s.mu.Unlock()
	release := func() {
		s.mu.Lock()
		s.fanOut -= n
		s.mu.Unlock()
	}
	if over {
		release()
		return nil, s.exceeded("more than %d parallel branches at once", s.opts.MaxFanOut)
	}
	return release, nil
}

// restrictedStopError wraps a recorded stop reason as a workflow error no error
// policy retries.
func restrictedStopError(step Step, reason error) error {
	return NewWorkflowError(ErrorCodeCancellation, reason.Error(), step.Name, step.Type, reason)
}

// admitRestrictedStep is called before a step of a restricted execution runs.
func (e *Engine) admitRestrictedStep(ctx context.Context, step Step) error {
	state := restrictedStateFrom(ctx)
	if state == nil {
		// startWorkflow gives every restricted execution its state; only an
		// execution assembled by hand, outside the engine's start path, lacks one.
		return nil
	}
	if err := state.admitStep(ctx); err != nil {
		return restrictedStopError(step, err)
	}
	return nil
}

// markRestrictedLoopBody returns ctx marked with step's body when step is a loop.
func markRestrictedLoopBody(ctx context.Context, step Step) context.Context {
	switch step.Type {
	case StepTypeFor, StepTypeWhile, StepTypeForeach:
		if len(step.Steps) > 0 {
			return context.WithValue(ctx, loopBodyKey{}, loopBody{first: &step.Steps[0], n: len(step.Steps)})
		}
	}
	return ctx
}

// admitRestrictedIteration is called by executeSteps. When steps is the body of
// the loop the run is inside, the call is one iteration of that loop.
func (e *Engine) admitRestrictedIteration(ctx context.Context, steps []Step) error {
	if len(steps) == 0 {
		return nil
	}
	body, ok := ctx.Value(loopBodyKey{}).(loopBody)
	if !ok || body.first != &steps[0] || body.n != len(steps) {
		return nil
	}
	state := restrictedStateFrom(ctx)
	if state == nil {
		return nil
	}
	if err := state.admitIteration(); err != nil {
		return restrictedStopError(steps[0], err)
	}
	return nil
}

// restrictedFanOut reserves the branches of a parallel step of a restricted
// execution. The returned function releases them.
func (e *Engine) restrictedFanOut(ctx context.Context, step Step) (func(), error) {
	state := restrictedStateFrom(ctx)
	if state == nil {
		return func() {}, nil
	}
	release, err := state.enterFanOut(len(step.Steps))
	if err != nil {
		return nil, restrictedStopError(step, err)
	}
	return release, nil
}

// restrictedStop returns the reason and status a restricted execution was
// stopped with, or nil when it was not stopped.
func restrictedStop(execution *WorkflowExecution) (ExecutionStatus, error) {
	if execution.Restricted == nil || execution.Context == nil {
		return "", nil
	}
	if state := restrictedStateFrom(execution.Context); state != nil {
		return state.stopped()
	}
	return "", nil
}

// finishRestrictedStop ends execution in the status of its stop reason and
// records the reason as the execution's error. It reports whether the execution
// had been stopped.
func (e *Engine) finishRestrictedStop(execution *WorkflowExecution) bool {
	status, reason := restrictedStop(execution)
	if reason == nil {
		return false
	}
	details := NewWorkflowError(ErrorCodeCancellation, reason.Error(), execution.GetCurrentStep(), "", reason).
		WithVariableState(execution.Variables)
	endTime := time.Now()
	e.mutex.Lock()
	execution.SetEndTime(&endTime)
	execution.SetError(details.Error())
	execution.SetErrorDetails(details)
	e.mutex.Unlock()
	execution.SetStatus(status)
	e.logger.Warn("Restricted workflow execution stopped",
		"execution_id", execution.ID,
		"status", string(status),
		"reason", details.FullError())
	return true
}
