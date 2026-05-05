// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contextCapturingTrigger records the deadline of each context passed to TriggerWorkflow.
// It fails the first failCount calls, then succeeds, simulating transient errors.
type contextCapturingTrigger struct {
	mu        sync.Mutex
	deadlines []time.Time
	failCount int
	calls     int
}

func (c *contextCapturingTrigger) TriggerWorkflow(ctx context.Context, t *trigger.Trigger, data map[string]interface{}) (*workflow.WorkflowExecution, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline, _ := ctx.Deadline()
	c.deadlines = append(c.deadlines, deadline)
	c.calls++

	if c.calls <= c.failCount {
		return nil, errors.New("transient error")
	}
	return &workflow.WorkflowExecution{
		ID:           "exec-1",
		WorkflowName: t.WorkflowName,
		Status:       "running",
		StartTime:    time.Now(),
	}, nil
}

func (c *contextCapturingTrigger) ValidateTrigger(_ context.Context, _ *trigger.Trigger) error {
	return nil
}

func (c *contextCapturingTrigger) getDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]time.Time, len(c.deadlines))
	copy(result, c.deadlines)
	return result
}

// newTestWorkflowIntegration creates a WorkflowIntegration for executeTrigger unit tests.
// executeTrigger never calls TriggerManager, so nil is passed for that argument.
func newTestWorkflowIntegration(wt trigger.WorkflowTrigger, cfg WorkflowIntegrationConfig) *WorkflowIntegration {
	cfg.EnableWorkflowTriggers = true
	return NewWorkflowIntegration(nil, wt, cfg)
}

func testSecurityEvent() *SecurityEvent {
	return &SecurityEvent{
		ID:        "test-event",
		EventType: "test",
		TenantID:  "test-tenant",
	}
}

// TestExecuteTrigger_SingleTimeoutContextAcrossRetries verifies that executeTrigger
// creates exactly one context.WithTimeout before the retry loop and passes that same
// context (same deadline) to every attempt, preventing timer goroutine leaks.
func TestExecuteTrigger_SingleTimeoutContextAcrossRetries(t *testing.T) {
	const triggerTimeout = 10 * time.Second

	captor := &contextCapturingTrigger{failCount: 2} // fail first 2, succeed on 3rd

	wi := newTestWorkflowIntegration(captor, WorkflowIntegrationConfig{
		DefaultTimeout: 5 * time.Second,
		RetryAttempts:  2,
		RetryDelay:     time.Millisecond,
	})

	triggerConfig := &trigger.Trigger{
		ID:           "test-trigger",
		WorkflowName: "test-workflow",
		Timeout:      triggerTimeout,
	}

	err := wi.executeTrigger(context.Background(), triggerConfig, testSecurityEvent())
	require.NoError(t, err)

	deadlines := captor.getDeadlines()
	// 2 failures + 1 success = 3 total attempts
	require.Len(t, deadlines, 3, "expected 3 trigger attempts (2 failures + 1 success)")

	// All attempts must share the same deadline — proves a single context was created.
	for i := 1; i < len(deadlines); i++ {
		assert.Equal(t, deadlines[0], deadlines[i],
			"attempt %d had a different deadline than attempt 0 — multiple contexts were created", i)
	}

	// The deadline must be non-zero, proving a timeout was applied.
	assert.False(t, deadlines[0].IsZero(), "context should have a non-zero deadline")
}

// TestExecuteTrigger_DefaultTimeoutUsedWhenTriggerTimeoutIsZero verifies that when
// triggerConfig.Timeout == 0, executeTrigger falls back to WorkflowIntegrationConfig.DefaultTimeout.
func TestExecuteTrigger_DefaultTimeoutUsedWhenTriggerTimeoutIsZero(t *testing.T) {
	const defaultTimeout = 5 * time.Second

	captor := &contextCapturingTrigger{failCount: 0} // succeed on first attempt

	wi := newTestWorkflowIntegration(captor, WorkflowIntegrationConfig{
		DefaultTimeout: defaultTimeout,
		RetryAttempts:  1,
		RetryDelay:     time.Millisecond,
	})

	triggerConfig := &trigger.Trigger{
		ID:           "test-trigger-notime",
		WorkflowName: "test-workflow",
		Timeout:      0, // should fall back to DefaultTimeout
	}

	before := time.Now()
	err := wi.executeTrigger(context.Background(), triggerConfig, testSecurityEvent())
	require.NoError(t, err)

	deadlines := captor.getDeadlines()
	require.Len(t, deadlines, 1)
	assert.False(t, deadlines[0].IsZero(), "context should have a deadline when Timeout==0")

	// Deadline must be within the expected window based on DefaultTimeout.
	expectedDeadline := before.Add(defaultTimeout)
	assert.WithinDuration(t, expectedDeadline, deadlines[0], time.Second,
		"deadline should reflect DefaultTimeout, not zero or trigger-specific timeout")
}

// TestExecuteTrigger_AllAttemptsExhaustedReturnsError verifies that when every retry
// attempt fails, executeTrigger returns a wrapped error describing the exhaustion.
func TestExecuteTrigger_AllAttemptsExhaustedReturnsError(t *testing.T) {
	// failCount exceeds total attempts to ensure all fail
	captor := &contextCapturingTrigger{failCount: 10}

	wi := newTestWorkflowIntegration(captor, WorkflowIntegrationConfig{
		DefaultTimeout: 5 * time.Second,
		RetryAttempts:  2,
		RetryDelay:     time.Millisecond,
	})

	triggerConfig := &trigger.Trigger{
		ID:           "test-trigger-exhausted",
		WorkflowName: "test-workflow",
		Timeout:      time.Second,
	}

	err := wi.executeTrigger(context.Background(), triggerConfig, testSecurityEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all trigger attempts failed")
	assert.Contains(t, err.Error(), "transient error")

	// All 3 attempts (RetryAttempts+1) must have run, each with the same context deadline.
	deadlines := captor.getDeadlines()
	require.Len(t, deadlines, 3, "expected RetryAttempts+1 attempts before giving up")

	for i := 1; i < len(deadlines); i++ {
		assert.Equal(t, deadlines[0], deadlines[i],
			"exhausted-retry attempt %d had a different deadline — multiple contexts were created", i)
	}
}
