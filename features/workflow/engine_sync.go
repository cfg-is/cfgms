// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"time"
)

// executeBarrierStep executes a barrier synchronization step
func (e *Engine) executeBarrierStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Barrier == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"barrier configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("barrier configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	barrierName := step.Barrier.Name
	if barrierName == "" {
		barrierName = step.Name
	}

	barrier, err := e.syncManager.GetOrCreateBarrier(barrierName, step.Barrier.Count)
	if err != nil {
		return fmt.Errorf("step %s: failed to get barrier: %w", step.Name, err)
	}

	e.logger.Info("Waiting at barrier", "step", step.Name, "barrier", barrierName, "count", step.Barrier.Count)

	timeout := step.Barrier.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	err = barrier.Wait(ctx, timeout)
	if err != nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			fmt.Sprintf("barrier wait failed: %v", err),
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.GetVariables())
	}

	e.logger.Info("Barrier released", "step", step.Name, "barrier", barrierName)
	return nil
}

// executeSemaphoreStep executes a semaphore synchronization step
func (e *Engine) executeSemaphoreStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Semaphore == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"semaphore configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("semaphore configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	semaphoreName := step.Semaphore.Name
	if semaphoreName == "" {
		semaphoreName = step.Name
	}

	permits := step.Semaphore.InitialPermits
	if permits <= 0 {
		permits = 1 // Default to 1 permit
	}

	semaphore, err := e.syncManager.GetOrCreateSemaphore(semaphoreName, permits)
	if err != nil {
		return fmt.Errorf("step %s: failed to get semaphore: %w", step.Name, err)
	}

	acquireCount := step.Semaphore.Count
	if acquireCount <= 0 {
		acquireCount = 1
	}

	timeout := step.Semaphore.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	switch step.Semaphore.Action {
	case SemaphoreActionAcquire:
		e.logger.Info("Acquiring semaphore", "step", step.Name, "semaphore", semaphoreName, "count", acquireCount)
		err = semaphore.Acquire(ctx, acquireCount, timeout)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("semaphore acquire failed: %v", err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		e.logger.Info("Semaphore acquired", "step", step.Name, "semaphore", semaphoreName)

	case SemaphoreActionRelease:
		e.logger.Info("Releasing semaphore", "step", step.Name, "semaphore", semaphoreName, "count", acquireCount)
		semaphore.Release(acquireCount)
		e.logger.Info("Semaphore released", "step", step.Name, "semaphore", semaphoreName)

	default:
		return fmt.Errorf("step %s: invalid semaphore action: %s", step.Name, step.Semaphore.Action)
	}

	return nil
}

// executeLockStep executes a lock synchronization step
func (e *Engine) executeLockStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Lock == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"lock configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("lock configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	lockName := step.Lock.Name
	if lockName == "" {
		lockName = step.Name
	}

	lock, err := e.syncManager.GetOrCreateLock(lockName)
	if err != nil {
		return fmt.Errorf("step %s: failed to get lock: %w", step.Name, err)
	}

	timeout := step.Lock.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	switch step.Lock.Action {
	case LockActionAcquire:
		if step.Lock.Exclusive {
			e.logger.Info("Acquiring write lock", "step", step.Name, "lock", lockName)
			err = lock.AcquireWrite(ctx, timeout)
			if err != nil {
				return NewWorkflowError(
					ErrorCodeValidation,
					fmt.Sprintf("write lock acquire failed: %v", err),
					step.Name,
					step.Type,
					err,
				).WithVariableState(execution.GetVariables())
			}
			e.logger.Info("Write lock acquired", "step", step.Name, "lock", lockName)
		} else {
			e.logger.Info("Acquiring read lock", "step", step.Name, "lock", lockName)
			err = lock.AcquireRead(ctx, timeout)
			if err != nil {
				return NewWorkflowError(
					ErrorCodeValidation,
					fmt.Sprintf("read lock acquire failed: %v", err),
					step.Name,
					step.Type,
					err,
				).WithVariableState(execution.GetVariables())
			}
			e.logger.Info("Read lock acquired", "step", step.Name, "lock", lockName)
		}

	case LockActionRelease:
		if step.Lock.Exclusive {
			e.logger.Info("Releasing write lock", "step", step.Name, "lock", lockName)
			lock.ReleaseWrite()
			e.logger.Info("Write lock released", "step", step.Name, "lock", lockName)
		} else {
			e.logger.Info("Releasing read lock", "step", step.Name, "lock", lockName)
			lock.ReleaseRead()
			e.logger.Info("Read lock released", "step", step.Name, "lock", lockName)
		}

	default:
		return fmt.Errorf("step %s: invalid lock action: %s", step.Name, step.Lock.Action)
	}

	return nil
}

// executeWaitGroupStep executes a wait group synchronization step
func (e *Engine) executeWaitGroupStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.WaitGroup == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"wait group configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("wait group configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	waitGroupName := step.WaitGroup.Name
	if waitGroupName == "" {
		waitGroupName = step.Name
	}

	waitGroup, err := e.syncManager.GetOrCreateWaitGroup(waitGroupName)
	if err != nil {
		return fmt.Errorf("step %s: failed to get wait group: %w", step.Name, err)
	}

	timeout := step.WaitGroup.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	switch step.WaitGroup.Action {
	case WaitGroupActionAdd:
		count := step.WaitGroup.Count
		if count == 0 {
			count = 1 // Default to 1
		}
		e.logger.Info("Adding to wait group", "step", step.Name, "waitGroup", waitGroupName, "count", count)
		waitGroup.Add(count)
		e.logger.Info("Wait group updated", "step", step.Name, "waitGroup", waitGroupName)

	case WaitGroupActionDone:
		e.logger.Info("Marking wait group done", "step", step.Name, "waitGroup", waitGroupName)
		waitGroup.Done()
		e.logger.Info("Wait group done", "step", step.Name, "waitGroup", waitGroupName)

	case WaitGroupActionWait:
		e.logger.Info("Waiting for wait group", "step", step.Name, "waitGroup", waitGroupName)
		err = waitGroup.Wait(ctx, timeout)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("wait group wait failed: %v", err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		e.logger.Info("Wait group completed", "step", step.Name, "waitGroup", waitGroupName)

	default:
		return fmt.Errorf("step %s: invalid wait group action: %s", step.Name, step.WaitGroup.Action)
	}

	return nil
}
