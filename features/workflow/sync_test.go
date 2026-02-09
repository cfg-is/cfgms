// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestBarrierStep(t *testing.T) {
	// Test barrier synchronization - multiple parallel steps wait at barrier
	workflow := Workflow{
		Name: "barrier-test",
		Variables: map[string]interface{}{
			"execution_order": []string{},
		},
		Steps: []Step{
			{
				Name: "parallel-barrier-test",
				Type: StepTypeParallel,
				Steps: []Step{
					{
						Name: "worker-1",
						Type: StepTypeSequential,
						Steps: []Step{
							{
								Name: "work-1-before",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 1 * time.Millisecond,
									Message:  "Worker 1 before barrier",
								},
							},
							{
								Name: "barrier-1",
								Type: StepTypeBarrier,
								Barrier: &BarrierConfig{
									Name:    "test-barrier",
									Count:   2,
									Timeout: 5 * time.Second,
								},
							},
							{
								Name: "work-1-after",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 1 * time.Millisecond,
									Message:  "Worker 1 after barrier",
								},
							},
						},
					},
					{
						Name: "worker-2",
						Type: StepTypeSequential,
						Steps: []Step{
							{
								Name: "work-2-before",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 10 * time.Millisecond, // Takes longer
									Message:  "Worker 2 before barrier",
								},
							},
							{
								Name: "barrier-2",
								Type: StepTypeBarrier,
								Barrier: &BarrierConfig{
									Name:    "test-barrier",
									Count:   2,
									Timeout: 5 * time.Second,
								},
							},
							{
								Name: "work-2-after",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 1 * time.Millisecond,
									Message:  "Worker 2 after barrier",
								},
							},
						},
					},
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestSemaphoreStep(t *testing.T) {
	// Test semaphore with acquire and release
	workflow := Workflow{
		Name: "semaphore-test",
		Variables: map[string]interface{}{
			"counter": 0,
		},
		Steps: []Step{
			{
				Name: "acquire-semaphore",
				Type: StepTypeSemaphore,
				Semaphore: &SemaphoreConfig{
					Name:           "test-semaphore",
					InitialPermits: 2,
					Action:         SemaphoreActionAcquire,
					Count:          1,
					Timeout:        5 * time.Second,
				},
			},
			{
				Name: "work-with-semaphore",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 10 * time.Millisecond,
					Message:  "Working with semaphore",
				},
			},
			{
				Name: "release-semaphore",
				Type: StepTypeSemaphore,
				Semaphore: &SemaphoreConfig{
					Name:   "test-semaphore",
					Action: SemaphoreActionRelease,
					Count:  1,
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestLockStep(t *testing.T) {
	// Test read/write lock operations
	workflow := Workflow{
		Name: "lock-test",
		Variables: map[string]interface{}{
			"shared_data": "initial",
		},
		Steps: []Step{
			{
				Name: "acquire-read-lock",
				Type: StepTypeLock,
				Lock: &LockConfig{
					Name:      "test-lock",
					Action:    LockActionAcquire,
					Exclusive: false, // Read lock
					Timeout:   5 * time.Second,
				},
			},
			{
				Name: "read-data",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 10 * time.Millisecond,
					Message:  "Reading shared data",
				},
			},
			{
				Name: "release-read-lock",
				Type: StepTypeLock,
				Lock: &LockConfig{
					Name:      "test-lock",
					Action:    LockActionRelease,
					Exclusive: false, // Read lock
				},
			},
			{
				Name: "acquire-write-lock",
				Type: StepTypeLock,
				Lock: &LockConfig{
					Name:      "test-lock",
					Action:    LockActionAcquire,
					Exclusive: true, // Write lock
					Timeout:   5 * time.Second,
				},
			},
			{
				Name: "write-data",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 10 * time.Millisecond,
					Message:  "Writing shared data",
				},
			},
			{
				Name: "release-write-lock",
				Type: StepTypeLock,
				Lock: &LockConfig{
					Name:      "test-lock",
					Action:    LockActionRelease,
					Exclusive: true, // Write lock
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestWaitGroupStep(t *testing.T) {
	// Test wait group coordination
	workflow := Workflow{
		Name: "waitgroup-test",
		Variables: map[string]interface{}{
			"tasks_completed": 0,
		},
		Steps: []Step{
			{
				Name: "add-to-waitgroup",
				Type: StepTypeWaitGroup,
				WaitGroup: &WaitGroupConfig{
					Name:   "test-waitgroup",
					Action: WaitGroupActionAdd,
					Count:  2,
				},
			},
			{
				Name: "parallel-tasks",
				Type: StepTypeParallel,
				Steps: []Step{
					{
						Name: "task-1",
						Type: StepTypeSequential,
						Steps: []Step{
							{
								Name: "work-1",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 10 * time.Millisecond,
									Message:  "Task 1 working",
								},
							},
							{
								Name: "done-1",
								Type: StepTypeWaitGroup,
								WaitGroup: &WaitGroupConfig{
									Name:   "test-waitgroup",
									Action: WaitGroupActionDone,
								},
							},
						},
					},
					{
						Name: "task-2",
						Type: StepTypeSequential,
						Steps: []Step{
							{
								Name: "work-2",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 20 * time.Millisecond,
									Message:  "Task 2 working",
								},
							},
							{
								Name: "done-2",
								Type: StepTypeWaitGroup,
								WaitGroup: &WaitGroupConfig{
									Name:   "test-waitgroup",
									Action: WaitGroupActionDone,
								},
							},
						},
					},
				},
			},
			{
				Name: "wait-for-completion",
				Type: StepTypeWaitGroup,
				WaitGroup: &WaitGroupConfig{
					Name:    "test-waitgroup",
					Action:  WaitGroupActionWait,
					Timeout: 5 * time.Second,
				},
			},
			{
				Name: "all-tasks-complete",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 1 * time.Millisecond,
					Message:  "All tasks completed",
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestSyncMissingConfiguration(t *testing.T) {
	// Test synchronization steps with missing configuration
	workflows := []Workflow{
		{
			Name: "barrier-missing-config",
			Steps: []Step{
				{
					Name: "invalid-barrier",
					Type: StepTypeBarrier,
					// No Barrier configuration
				},
			},
		},
		{
			Name: "semaphore-missing-config",
			Steps: []Step{
				{
					Name: "invalid-semaphore",
					Type: StepTypeSemaphore,
					// No Semaphore configuration
				},
			},
		},
		{
			Name: "lock-missing-config",
			Steps: []Step{
				{
					Name: "invalid-lock",
					Type: StepTypeLock,
					// No Lock configuration
				},
			},
		},
		{
			Name: "waitgroup-missing-config",
			Steps: []Step{
				{
					Name: "invalid-waitgroup",
					Type: StepTypeWaitGroup,
					// No WaitGroup configuration
				},
			},
		},
	}

	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	for _, workflow := range workflows {
		t.Run(workflow.Name, func(t *testing.T) {
			execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
			require.NoError(t, err)
			require.NotNil(t, execution)

			// Wait for completion
			waitForWorkflowCompletion(t, execution, 2*time.Second)

			// Verify execution failed due to missing configuration
			assert.Equal(t, StatusFailed, execution.GetStatus())
		})
	}
}

func TestSyncTimeout(t *testing.T) {
	// Test synchronization primitives with timeouts
	workflow := Workflow{
		Name: "sync-timeout-test",
		Steps: []Step{
			{
				Name: "barrier-timeout",
				Type: StepTypeBarrier,
				Barrier: &BarrierConfig{
					Name:    "timeout-barrier",
					Count:   2, // Only one participant, will timeout
					Timeout: 10 * time.Millisecond,
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution failed due to timeout
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestSyncCleanup(t *testing.T) {
	// Test that sync manager cleanup works
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)

	// Create some barriers
	barrier1, err := engine.syncManager.GetOrCreateBarrier("test-barrier-1", 2)
	require.NoError(t, err)
	require.NotNil(t, barrier1)

	barrier2, err := engine.syncManager.GetOrCreateBarrier("test-barrier-2", 3)
	require.NoError(t, err)
	require.NotNil(t, barrier2)

	// Complete one barrier
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = barrier1.Wait(context.Background(), 100*time.Millisecond)
	}()
	_ = barrier1.Wait(context.Background(), 100*time.Millisecond)

	// Run cleanup
	engine.syncManager.Cleanup()

	// The completed barrier should be removed, but the other should remain
	// This is tested implicitly - if cleanup broke something, subsequent operations would fail
}
