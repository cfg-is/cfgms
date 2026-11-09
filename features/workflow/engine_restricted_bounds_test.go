// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runBounded starts a restricted run with opts and waits for it to end.
func runBounded(t *testing.T, engine *Engine, wf Workflow, vars map[string]interface{}, opts RestrictedOptions) *WorkflowExecution {
	t.Helper()
	exec, err := engine.ExecuteRestrictedWorkflowWithOptions(restrictedCtx(), wf, vars,
		RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: restrictedTestTenant}, opts)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 10*time.Second)
	return exec
}

func scriptSteps(n int) []Step {
	steps := make([]Step, n)
	for i := range steps {
		steps[i] = scriptStep(fmt.Sprintf("s%d", i))
	}
	return steps
}

func assertStoppedWith(t *testing.T, exec *WorkflowExecution, status ExecutionStatus, sentinel error, reason string) {
	t.Helper()
	assert.Equal(t, status, exec.GetStatus())
	assert.Contains(t, exec.GetError(), sentinel.Error())
	assert.Contains(t, exec.GetError(), reason)
	details := exec.GetErrorDetails()
	require.NotNil(t, details, "the stop reason is recorded as error details")
	assert.Equal(t, ErrorCodeCancellation, details.Code)
	assert.Contains(t, details.Message, sentinel.Error())
	assert.NotNil(t, exec.GetEndTime())
}

func TestRestrictedBounds_StepBound(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	exec := runBounded(t, engine, Workflow{Name: "wf", Steps: scriptSteps(10)}, nil, RestrictedOptions{MaxSteps: 4})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 4 steps")
	assert.EqualValues(t, 4, scripts.runs.Load(), "the step over the bound never runs")
}

func TestRestrictedBounds_StepBoundCountsNestedSteps(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{
		{Name: "seq", Type: StepTypeSequential, Steps: scriptSteps(5)},
	}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxSteps: 3})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 3 steps")
	assert.EqualValues(t, 2, scripts.runs.Load(), "the sequential step counts as one of the three")
}

func TestRestrictedBounds_StepBoundSurvivesTryBlock(t *testing.T) {
	// A try block catching the step error does not let the run complete.
	engine, _ := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{{
		Name: "try", Type: StepTypeTry,
		Try: &TryConfig{
			Try:   scriptSteps(5),
			Catch: []CatchBlock{{Steps: []Step{restrictedDelayStep("recover")}}},
		},
	}}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxSteps: 3})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 3 steps")
}

func loopWorkflows() map[string]Workflow {
	body := func() []Step { return scriptSteps(1) }
	return map[string]Workflow{
		"for": {Name: "wf", Steps: []Step{{
			Name: "loop", Type: StepTypeFor, Steps: body(),
			Loop: &LoopConfig{Type: LoopTypeFor, Variable: "i", Start: 1, End: 10},
		}}},
		"foreach": {Name: "wf", Steps: []Step{{
			Name: "loop", Type: StepTypeForeach, Steps: body(),
			Loop: &LoopConfig{Type: LoopTypeForeach, Variable: "item", Items: []interface{}{1, 2, 3, 4, 5, 6}},
		}}},
		"while": {Name: "wf", Steps: []Step{{
			Name: "loop", Type: StepTypeWhile, Steps: body(),
			Loop: &LoopConfig{Type: LoopTypeWhile, Condition: &Condition{
				Type: ConditionTypeVariable, Variable: "go", Operator: OperatorEqual, Value: true,
			}},
		}}},
	}
}

func TestRestrictedBounds_LoopIterationBound(t *testing.T) {
	for name, wf := range loopWorkflows() {
		t.Run(name, func(t *testing.T) {
			engine, scripts := newRestrictedEngine(t)
			exec := runBounded(t, engine, wf, map[string]interface{}{"go": true},
				RestrictedOptions{MaxSteps: 1000, MaxLoopIterations: 3})

			assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 3 loop iterations")
			assert.EqualValues(t, 3, scripts.runs.Load(), "the iteration over the bound never runs")
		})
	}
}

func TestRestrictedBounds_LoopIterationsAreSummedOverLoops(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	loop := func(name string) Step {
		return Step{
			Name: name, Type: StepTypeFor, Steps: scriptSteps(1),
			Loop: &LoopConfig{Type: LoopTypeFor, Variable: "i", Start: 1, End: 2},
		}
	}
	exec := runBounded(t, engine, Workflow{Name: "wf", Steps: []Step{loop("a"), loop("b")}}, nil,
		RestrictedOptions{MaxSteps: 1000, MaxLoopIterations: 3})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 3 loop iterations")
	assert.EqualValues(t, 3, scripts.runs.Load())
}

func TestRestrictedBounds_StepsInsideALoopBodyAreNotIterations(t *testing.T) {
	// A conditional or sequential step in the body runs its own child list; only
	// the loop body itself counts as an iteration.
	engine, scripts := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{{
		Name: "loop", Type: StepTypeFor,
		Loop: &LoopConfig{Type: LoopTypeFor, Variable: "i", Start: 1, End: 2},
		Steps: []Step{{
			Name: "inner", Type: StepTypeSequential, Steps: scriptSteps(5),
		}},
	}}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxSteps: 1000, MaxLoopIterations: 2})

	assert.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.EqualValues(t, 10, scripts.runs.Load())
}

func TestRestrictedBounds_FanOutBound(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{{Name: "par", Type: StepTypeParallel, Steps: scriptSteps(4)}}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxFanOut: 3})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 3 parallel branches")
	assert.Zero(t, scripts.runs.Load(), "no branch of an over-wide parallel step starts")
}

func TestRestrictedBounds_FanOutWithinBoundRuns(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{{Name: "par", Type: StepTypeParallel, Steps: scriptSteps(3)}}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxFanOut: 3})

	assert.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.EqualValues(t, 3, scripts.runs.Load())
}

func TestRestrictedBounds_FanOutCountsNestedParallelSteps(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{{
		Name: "outer", Type: StepTypeParallel, Steps: []Step{
			{Name: "a", Type: StepTypeParallel, Steps: scriptSteps(2)},
			{Name: "b", Type: StepTypeParallel, Steps: scriptSteps(2)},
		},
	}}}
	// 2 outer branches + 2 + 2 inner branches running at once is 6.
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxFanOut: 5})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "more than 5 parallel branches")
}

func TestRestrictedBounds_FanOutIsReleasedWhenBranchesEnd(t *testing.T) {
	// Two parallel steps in sequence each fit the bound: the first one's branches
	// no longer count once it has finished.
	engine, scripts := newRestrictedEngine(t)
	par := func(name string) Step { return Step{Name: name, Type: StepTypeParallel, Steps: scriptSteps(3)} }
	exec := runBounded(t, engine, Workflow{Name: "wf", Steps: []Step{par("p1"), par("p2")}}, nil,
		RestrictedOptions{MaxFanOut: 3})

	assert.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.EqualValues(t, 6, scripts.runs.Load())
}

func TestRestrictedBounds_WallTimeBound(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{
		{Name: "wait", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Minute}},
	}}
	start := time.Now()
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxWallTime: 100 * time.Millisecond})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "wall time")
	assert.Less(t, time.Since(start), 10*time.Second, "the delay is cut short, not waited out")
}

func TestRestrictedBounds_WallTimeBoundSurvivesTryBlock(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{{
		Name: "try", Type: StepTypeTry,
		Try: &TryConfig{
			Try:   []Step{{Name: "wait", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Minute}}},
			Catch: []CatchBlock{{Steps: []Step{restrictedDelayStep("recover")}}},
		},
	}}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{MaxWallTime: 100 * time.Millisecond})

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, "wall time")
}

func TestRestrictedBounds_DefaultsApplyToEveryRestrictedRun(t *testing.T) {
	assert.Equal(t, RestrictedOptions{
		MaxSteps:          DefaultRestrictedMaxSteps,
		MaxLoopIterations: DefaultRestrictedMaxLoopIterations,
		MaxFanOut:         DefaultRestrictedMaxFanOut,
		MaxWallTime:       DefaultRestrictedMaxWallTime,
	}, RestrictedOptions{MaxSteps: -1, MaxFanOut: 0}.withDefaults(), "unset and negative bounds take the default")
	assert.Equal(t, 7, RestrictedOptions{MaxSteps: 7}.withDefaults().MaxSteps)

	// ExecuteRestrictedWorkflow, which takes no options, is bounded by the defaults.
	engine, scripts := newRestrictedEngine(t)
	exec, err := runRestricted(engine, Workflow{Name: "wf", Steps: scriptSteps(DefaultRestrictedMaxSteps + 1)}, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 10*time.Second)

	assertStoppedWith(t, exec, StatusFailed, ErrRestrictedBoundExceeded, fmt.Sprintf("more than %d steps", DefaultRestrictedMaxSteps))
	assert.EqualValues(t, DefaultRestrictedMaxSteps, scripts.runs.Load())
}

func TestRestrictedBounds_UnrestrictedRunIsNotBounded(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	steps := make([]Step, DefaultRestrictedMaxSteps+50)
	for i := range steps {
		steps[i] = Step{Name: fmt.Sprintf("d%d", i), Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Microsecond}}
	}
	exec, err := engine.ExecuteWorkflow(restrictedCtx(), Workflow{Name: "wf", Steps: steps}, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 30*time.Second)

	assert.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
}

func TestRestrictedBounds_GuardErrorStopsAtNextStep(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	errRevoked := errors.New("grant revoked")
	var calls atomic.Int32
	guard := func(context.Context) error {
		if calls.Add(1) > 2 {
			return errRevoked
		}
		return nil
	}
	exec := runBounded(t, engine, Workflow{Name: "wf", Steps: scriptSteps(6)}, nil, RestrictedOptions{RunGuard: guard})

	assertStoppedWith(t, exec, StatusCancelled, ErrRestrictedRunGuardStopped, "grant revoked")
	assert.Contains(t, exec.GetErrorDetails().Message, errRevoked.Error(), "the guard's own error is the reason")
	assert.EqualValues(t, 2, scripts.runs.Load(), "the third step never runs")
	assert.EqualValues(t, 3, calls.Load(), "no step is attempted after the guard fails")
}

func TestRestrictedBounds_GuardErrorStopsNestedAndLoopSteps(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	var revoked atomic.Bool
	guard := func(context.Context) error {
		if revoked.Load() {
			return errors.New("run ended")
		}
		return nil
	}
	// The guard fails once the second loop iteration's script step is reached.
	wf := Workflow{Name: "wf", Steps: []Step{{
		Name: "loop", Type: StepTypeFor,
		Loop: &LoopConfig{Type: LoopTypeFor, Variable: "i", Start: 1, End: 5},
		Steps: []Step{
			scriptStep("work"),
			{Name: "arm", Type: StepTypeConditional, Condition: &Condition{
				Type: ConditionTypeVariable, Variable: "i", Operator: OperatorEqual, Value: 1,
			}, Steps: []Step{restrictedDelayStep("revoke-after")}},
		},
	}}}
	go func() {
		for scripts.runs.Load() < 1 {
			time.Sleep(time.Millisecond)
		}
		revoked.Store(true)
	}()
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{RunGuard: guard})

	assertStoppedWith(t, exec, StatusCancelled, ErrRestrictedRunGuardStopped, "run ended")
	assert.Less(t, scripts.runs.Load(), int32(5), "the loop does not run to completion")
}

func TestRestrictedBounds_GuardErrorSurvivesTryBlock(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	guard := func(context.Context) error { return errors.New("grant revoked") }
	wf := Workflow{Name: "wf", Steps: []Step{{
		Name: "try", Type: StepTypeTry,
		Try: &TryConfig{
			Try:   scriptSteps(2),
			Catch: []CatchBlock{{Steps: scriptSteps(1)}},
		},
	}}}
	exec := runBounded(t, engine, wf, nil, RestrictedOptions{RunGuard: guard})

	assertStoppedWith(t, exec, StatusCancelled, ErrRestrictedRunGuardStopped, "grant revoked")
	assert.Zero(t, scripts.runs.Load(), "neither the try body nor the catch block runs")
}

func TestRestrictedBounds_GuardSeesEveryStepType(t *testing.T) {
	var calls atomic.Int32
	guard := func(context.Context) error { calls.Add(1); return nil }

	engine, scripts := newRestrictedEngine(t)

	delay := func(name string) Step { return restrictedDelayStep(name) }
	wf := Workflow{Name: "wf", Steps: []Step{
		// sequential: itself + 1 child
		{Name: "seq", Type: StepTypeSequential, Steps: []Step{delay("seq-a")}},
		// parallel: itself + 2 children
		{Name: "par", Type: StepTypeParallel, Steps: []Step{delay("par-a"), delay("par-b")}},
		// conditional (true): itself + 1 child
		{Name: "cond", Type: StepTypeConditional, Condition: &Condition{
			Type: ConditionTypeVariable, Variable: "status", Operator: OperatorEqual, Value: "active",
		}, Steps: []Step{delay("cond-a")}},
		// for, two iterations: itself + 2 children
		{Name: "for", Type: StepTypeFor, Loop: &LoopConfig{Type: LoopTypeFor, Variable: "i", Start: 1, End: 2},
			Steps: []Step{delay("for-a")}},
		// foreach, two items: itself + 2 children
		{Name: "foreach", Type: StepTypeForeach, Loop: &LoopConfig{Type: LoopTypeForeach, Variable: "x", Items: []interface{}{"p", "q"}},
			Steps: []Step{delay("foreach-a")}},
		// while, one iteration ended by break: itself + break
		{Name: "while", Type: StepTypeWhile, Loop: &LoopConfig{Type: LoopTypeWhile, Condition: &Condition{
			Type: ConditionTypeVariable, Variable: "status", Operator: OperatorEqual, Value: "active",
		}}, Steps: []Step{{Name: "brk", Type: StepTypeBreak}}},
		// for, two iterations of continue: itself + 2 children
		{Name: "for-continue", Type: StepTypeFor, Loop: &LoopConfig{Type: LoopTypeFor, Variable: "j", Start: 1, End: 2},
			Steps: []Step{{Name: "cont", Type: StepTypeContinue}}},
		// switch: itself + 1 child
		{Name: "switch", Type: StepTypeSwitch, Switch: &SwitchConfig{Variable: "status", Cases: []SwitchCase{
			{Value: "active", Steps: []Step{delay("switch-a")}},
		}}},
		// try: itself + try child + finally child
		{Name: "try", Type: StepTypeTry, Try: &TryConfig{Try: []Step{delay("try-a")}, Finally: []Step{delay("finally-a")}}},
		scriptStep("script"),
	}}
	const wantSteps = 2 + 3 + 2 + 3 + 3 + 2 + 3 + 2 + 3 + 1

	exec := runBounded(t, engine, wf, map[string]interface{}{"status": "active"}, RestrictedOptions{RunGuard: guard})

	assert.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.EqualValues(t, 1, scripts.runs.Load())
	assert.EqualValues(t, wantSteps, calls.Load(), "the guard runs before every step, of every type")
}

func TestRestrictedBounds_GuardRunsBeforeEveryAllowedStepType(t *testing.T) {
	// Whatever the step type, a failing guard stops the run before the step's
	// executor runs: each allowed type, alone, is stopped after one guard call.
	allowed := 0
	for stepType, policy := range restrictedStepPolicies {
		if !policy.allowed {
			continue
		}
		allowed++
		t.Run(string(stepType), func(t *testing.T) {
			engine, scripts := newRestrictedEngine(t)
			var calls atomic.Int32
			guard := func(context.Context) error { calls.Add(1); return errors.New("grant revoked") }

			step := Step{Name: "only", Type: stepType}
			if stepType == StepTypeNotify {
				step = notifyStep("only", configuredChannelURL)
			}
			exec := runBounded(t, engine, Workflow{Name: "wf", Steps: []Step{step}}, nil, RestrictedOptions{RunGuard: guard})

			assertStoppedWith(t, exec, StatusCancelled, ErrRestrictedRunGuardStopped, "grant revoked")
			assert.EqualValues(t, 1, calls.Load())
			assert.Zero(t, scripts.runs.Load())
		})
	}
	assert.NotZero(t, allowed)
}

func TestRestrictedBounds_RunWithoutGuardRuns(t *testing.T) {
	// A nil guard means no guard: the run is bounded but nothing is consulted. (The
	// unrestricted path has no guard at all.)
	engine, _ := newRestrictedEngine(t)
	exec := runBounded(t, engine, Workflow{Name: "wf", Steps: []Step{restrictedDelayStep("d")}}, nil, RestrictedOptions{})
	assert.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.Empty(t, exec.GetError())
}

func TestRestrictedBounds_FirstStopReasonWins(t *testing.T) {
	state := newRestrictedState(RestrictedOptions{MaxSteps: 1}.withDefaults(), func() {})
	defer state.release()

	first := state.stop(StatusCancelled, errors.New("first"))
	second := state.stop(StatusFailed, errors.New("second"))

	assert.EqualError(t, first, "first")
	assert.EqualError(t, second, "first", "a later stop returns the reason already recorded")
	status, reason := state.stopped()
	assert.Equal(t, StatusCancelled, status)
	assert.EqualError(t, reason, "first")
}
