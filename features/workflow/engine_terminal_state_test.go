// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// terminalReader polls GetExecution in a tight loop until done closes and
// records the first snapshot that carries an end time without a terminal status.
type terminalReader struct {
	wg      sync.WaitGroup
	reads   int
	torn    int
	example string
}

func startTerminalReader(engine *Engine, execution *WorkflowExecution) *terminalReader {
	r := &terminalReader{}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			if snap, err := engine.GetExecution(context.Background(), "", execution.ID); err == nil {
				r.reads++
				if snap.EndTime != nil && !snap.Status.IsTerminal() {
					r.torn++
					if r.example == "" {
						r.example = string(snap.Status)
					}
				}
			}
			select {
			case <-execution.Done:
				return
			default:
			}
		}
	}()
	return r
}

func (r *terminalReader) stop(t *testing.T) {
	t.Helper()
	r.wg.Wait()
	assert.Zero(t, r.torn, "%d of %d snapshots had an end time with non-terminal status %q", r.torn, r.reads, r.example)
}

func TestGetExecution_EndTimeImpliesTerminalStatus(t *testing.T) {
	cases := []struct {
		name   string
		steps  []Step
		cancel bool
		want   ExecutionStatus
	}{
		{
			name:  "completed",
			steps: []Step{{Name: "noop", Type: StepTypeConditional, Condition: &Condition{Type: ConditionTypeVariable, Variable: "x", Operator: OperatorExists}, Steps: []Step{}}},
			want:  StatusCompleted,
		},
		{
			name:  "failed",
			steps: []Step{{Name: "bad", Type: StepType("no-such-step-type")}},
			want:  StatusFailed,
		},
		{
			name:   "cancelled",
			steps:  []Step{{Name: "block", Type: StepTypeDelay, Delay: &DelayConfig{Duration: 30 * time.Second}}},
			cancel: true,
			want:   StatusCancelled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each iteration is a fresh run so the terminal write races a live reader.
			for i := 0; i < 200; i++ {
				engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
				execution, err := engine.ExecuteWorkflow(context.Background(), Workflow{Name: "terminal-" + tc.name, Steps: tc.steps}, nil)
				require.NoError(t, err)

				reader := startTerminalReader(engine, execution)
				if tc.cancel {
					waitForWorkflowRunning(t, execution, 2*time.Second)
					require.NoError(t, engine.CancelExecution(execution.ID))
				}
				waitForWorkflowCompletion(t, execution, 5*time.Second)
				reader.stop(t)

				final, err := engine.GetExecution(context.Background(), "", execution.ID)
				require.NoError(t, err)
				assert.Equal(t, tc.want, final.Status)
				assert.NotNil(t, final.EndTime)
				if t.Failed() {
					return
				}
			}
		})
	}
}

func TestWorkflowExecution_FinishNeverOverwritesTerminalStatus(t *testing.T) {
	end := time.Now()
	later := end.Add(time.Minute)

	t.Run("cancel then goroutine exit keeps cancelled and first end time", func(t *testing.T) {
		execution := &WorkflowExecution{Status: StatusRunning}
		require.True(t, execution.Finish(StatusCancelled, end, "", nil))
		assert.False(t, execution.Finish(StatusFailed, later, "late failure", &WorkflowError{}))
		assert.False(t, execution.Finish(StatusCancelled, later, "", nil))

		snap := execution.snapshotTerminal()
		assert.Equal(t, StatusCancelled, snap.Status)
		require.NotNil(t, snap.EndTime)
		assert.True(t, snap.EndTime.Equal(end))
		assert.Empty(t, snap.Error)
		assert.Nil(t, snap.ErrorDetails)
	})

	t.Run("writes error fields together with status", func(t *testing.T) {
		execution := &WorkflowExecution{Status: StatusRunning}
		details := &WorkflowError{}
		require.True(t, execution.Finish(StatusFailed, end, "boom", details))

		snap := execution.snapshotTerminal()
		assert.Equal(t, StatusFailed, snap.Status)
		assert.Equal(t, "boom", snap.Error)
		assert.Same(t, details, snap.ErrorDetails)
		require.NotNil(t, snap.EndTime)
	})

	t.Run("rejects a non-terminal status", func(t *testing.T) {
		execution := &WorkflowExecution{Status: StatusRunning}
		assert.False(t, execution.Finish(StatusRunning, end, "", nil))
		snap := execution.snapshotTerminal()
		assert.Equal(t, StatusRunning, snap.Status)
		assert.Nil(t, snap.EndTime)
	})

	t.Run("snapshot end time is a copy", func(t *testing.T) {
		execution := &WorkflowExecution{Status: StatusRunning}
		require.True(t, execution.Finish(StatusCompleted, end, "", nil))
		snap := execution.snapshotTerminal()
		*snap.EndTime = later
		assert.True(t, execution.GetEndTime().Equal(end))
	})
}
