// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func makeRule(id string, minEvents int, window time.Duration) *CorrelationRule {
	return &CorrelationRule{
		ID:         id,
		Name:       id,
		EventTypes: []string{"test"},
		TimeWindow: window,
		MinEvents:  minEvents,
		Enabled:    true,
	}
}

func makeEvent(ruleID string) *SecurityEvent {
	return &SecurityEvent{
		ID:        "e-" + ruleID + "-" + time.Now().Format("150405.000000000"),
		Timestamp: time.Now(),
		EventType: "test",
		Severity:  SeverityLow,
		TenantID:  "tenant-1",
		RuleID:    ruleID,
		Fields:    map[string]interface{}{},
	}
}

// TestCorrelator_ExactMinEvents verifies that a window reaching exactly MinEvents
// produces exactly one CorrelatedEvent.
func TestCorrelator_ExactMinEvents(t *testing.T) {
	ec := NewEventCorrelator(0)
	rule := makeRule("rule-exact", 3, 5*time.Second)
	require.NoError(t, ec.AddCorrelationRule(rule))

	ctx := context.Background()
	events := []*SecurityEvent{makeEvent("rule-exact"), makeEvent("rule-exact"), makeEvent("rule-exact")}

	result, err := ec.CorrelateEvents(ctx, events, rule.TimeWindow)
	require.NoError(t, err)
	require.Len(t, result, 1, "exactly one CorrelatedEvent for a window that hits MinEvents")
}

// TestCorrelator_ExtraEventsStillOneCorrelation verifies that receiving more than
// MinEvents within the same window still produces exactly one CorrelatedEvent.
func TestCorrelator_ExtraEventsStillOneCorrelation(t *testing.T) {
	ec := NewEventCorrelator(0)
	rule := makeRule("rule-extra", 3, 5*time.Second)
	require.NoError(t, ec.AddCorrelationRule(rule))

	ctx := context.Background()

	var total []*CorrelatedEvent
	for i := 0; i < 10; i++ {
		result, err := ec.CorrelateEvents(ctx, []*SecurityEvent{makeEvent("rule-extra")}, rule.TimeWindow)
		require.NoError(t, err)
		total = append(total, result...)
	}

	require.Len(t, total, 1, "exactly one CorrelatedEvent regardless of how many events arrive in the same window")
}

// TestCorrelator_FreshWindowAfterExpiry verifies that after the original window
// expires, a new window can fire once more when it reaches MinEvents.
func TestCorrelator_FreshWindowAfterExpiry(t *testing.T) {
	ec := NewEventCorrelator(0)
	rule := makeRule("rule-expiry", 3, 100*time.Millisecond)
	require.NoError(t, ec.AddCorrelationRule(rule))

	ctx := context.Background()

	// First window: send 5 events — should produce exactly 1 correlated event.
	var firstPass []*CorrelatedEvent
	for i := 0; i < 5; i++ {
		result, err := ec.CorrelateEvents(ctx, []*SecurityEvent{makeEvent("rule-expiry")}, rule.TimeWindow)
		require.NoError(t, err)
		firstPass = append(firstPass, result...)
	}
	require.Len(t, firstPass, 1, "first window should produce exactly one CorrelatedEvent")

	// Wait for the window to expire.
	time.Sleep(150 * time.Millisecond)

	// Second window: send another MinEvents worth of events — should produce exactly 1 new event.
	var secondPass []*CorrelatedEvent
	for i := 0; i < 3; i++ {
		result, err := ec.CorrelateEvents(ctx, []*SecurityEvent{makeEvent("rule-expiry")}, rule.TimeWindow)
		require.NoError(t, err)
		secondPass = append(secondPass, result...)
	}
	require.Len(t, secondPass, 1, "fresh window after expiry should produce exactly one new CorrelatedEvent")
}
