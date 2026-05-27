// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package monitoring_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// contextCapturingLogger records contexts received by Ctx-aware log methods.
// It implements logging.Logger for test instrumentation only.
type contextCapturingLogger struct {
	captured []context.Context
}

func (l *contextCapturingLogger) Debug(_ string, _ ...interface{}) {}
func (l *contextCapturingLogger) Info(_ string, _ ...interface{})  {}
func (l *contextCapturingLogger) Warn(_ string, _ ...interface{})  {}
func (l *contextCapturingLogger) Error(_ string, _ ...interface{}) {}
func (l *contextCapturingLogger) Fatal(_ string, _ ...interface{}) {}
func (l *contextCapturingLogger) DebugCtx(ctx context.Context, _ string, _ ...interface{}) {
	l.captured = append(l.captured, ctx)
}
func (l *contextCapturingLogger) InfoCtx(ctx context.Context, _ string, _ ...interface{}) {
	l.captured = append(l.captured, ctx)
}
func (l *contextCapturingLogger) WarnCtx(ctx context.Context, _ string, _ ...interface{}) {
	l.captured = append(l.captured, ctx)
}
func (l *contextCapturingLogger) ErrorCtx(ctx context.Context, _ string, _ ...interface{}) {
	l.captured = append(l.captured, ctx)
}
func (l *contextCapturingLogger) FatalCtx(ctx context.Context, _ string, _ ...interface{}) {
	l.captured = append(l.captured, ctx)
}

func (l *contextCapturingLogger) lastContext() context.Context {
	if len(l.captured) == 0 {
		return nil
	}
	return l.captured[len(l.captured)-1]
}

// contextCapturingAlerter records contexts received by SendAlert.
// It implements monitoring.AlertSender for test instrumentation only.
type contextCapturingAlerter struct {
	captured  []context.Context
	name      string
	sendError error
}

func (a *contextCapturingAlerter) SendAlert(ctx context.Context, _ monitoring.SystemEvent) error {
	a.captured = append(a.captured, ctx)
	return a.sendError
}

func (a *contextCapturingAlerter) GetSenderName() string { return a.name }

func (a *contextCapturingAlerter) lastContext() context.Context {
	if len(a.captured) == 0 {
		return nil
	}
	return a.captured[len(a.captured)-1]
}

// LoggingWatcher tests

// TestLoggingWatcherCorrelationIDInContext verifies that OnSystemEvent stores the
// CorrelationID under ctxkeys.CorrelationIDKey so telemetry.GetCorrelationID can read it.
func TestLoggingWatcherCorrelationIDInContext(t *testing.T) {
	logger := &contextCapturingLogger{}
	watcher := monitoring.NewLoggingWatcher(logger, "test-watcher")

	const wantCorrelationID = "test-corr-id-abc123"

	event := monitoring.SystemEvent{
		ID:            "evt-1",
		Type:          monitoring.EventSystemStartup,
		Source:        "test",
		Component:     "test-component",
		CorrelationID: wantCorrelationID,
		Severity:      monitoring.SeverityInfo,
	}

	watcher.OnSystemEvent(event)

	ctx := logger.lastContext()
	require.NotNil(t, ctx, "logger must receive a non-nil context")

	got := telemetry.GetCorrelationID(ctx)
	assert.Equal(t, wantCorrelationID, got,
		"context passed to logger must carry correlation ID under ctxkeys.CorrelationIDKey")
}

// TestLoggingWatcherCorrelationIDAbsent verifies that when CorrelationID is empty
// the context does not receive a spurious entry.
func TestLoggingWatcherCorrelationIDAbsent(t *testing.T) {
	logger := &contextCapturingLogger{}
	watcher := monitoring.NewLoggingWatcher(logger, "test-watcher")

	event := monitoring.SystemEvent{
		ID:        "evt-2",
		Type:      monitoring.EventSystemStartup,
		Source:    "test",
		Component: "test-component",
		Severity:  monitoring.SeverityInfo,
		// CorrelationID intentionally empty
	}

	watcher.OnSystemEvent(event)

	ctx := logger.lastContext()
	require.NotNil(t, ctx, "logger must receive a non-nil context even without correlation ID")

	got := telemetry.GetCorrelationID(ctx)
	assert.Empty(t, got, "context should not contain a correlation ID when none was provided")
}

// MetricsWatcher tests

func TestMetricsWatcherOnSystemEvent(t *testing.T) {
	watcher := monitoring.NewMetricsWatcher(logging.NewNoopLogger(), "test-metrics")

	t.Run("increments event count", func(t *testing.T) {
		event := monitoring.SystemEvent{
			ID:        "evt-1",
			Type:      monitoring.EventSystemStartup,
			Source:    "test",
			Severity:  monitoring.SeverityInfo,
			Timestamp: time.Now(),
		}
		watcher.OnSystemEvent(event)

		counts := watcher.GetEventCounts()
		assert.Equal(t, int64(1), counts[monitoring.EventSystemStartup])
	})

	t.Run("accumulates counts for repeated event type", func(t *testing.T) {
		event := monitoring.SystemEvent{
			ID:        "evt-2",
			Type:      monitoring.EventSystemStartup,
			Source:    "test",
			Severity:  monitoring.SeverityInfo,
			Timestamp: time.Now(),
		}
		watcher.OnSystemEvent(event)

		counts := watcher.GetEventCounts()
		assert.Equal(t, int64(2), counts[monitoring.EventSystemStartup])
	})

	t.Run("tracks multiple event types independently", func(t *testing.T) {
		event := monitoring.SystemEvent{
			ID:        "evt-3",
			Type:      monitoring.EventStewardDisconnected,
			Source:    "test",
			Severity:  monitoring.SeverityWarning,
			Timestamp: time.Now(),
		}
		watcher.OnSystemEvent(event)

		counts := watcher.GetEventCounts()
		assert.Equal(t, int64(2), counts[monitoring.EventSystemStartup])
		assert.Equal(t, int64(1), counts[monitoring.EventStewardDisconnected])
	})

	t.Run("records last event timestamps", func(t *testing.T) {
		times := watcher.GetLastEventTimes()
		assert.NotZero(t, times[monitoring.EventSystemStartup])
		assert.NotZero(t, times[monitoring.EventStewardDisconnected])
	})
}

// AlertingWatcher tests

func TestAlertingWatcherCorrelationIDInContext(t *testing.T) {
	logger := logging.NewNoopLogger()
	alerter := &contextCapturingAlerter{name: "test-alerter"}
	watcher := monitoring.NewAlertingWatcher(logger, "test-alerting", alerter)

	const wantCorrelationID = "alert-corr-id-xyz"

	// EventStewardDisconnected has a default threshold of SeverityWarning,
	// so a Warning event must trigger SendAlert.
	event := monitoring.SystemEvent{
		ID:            "evt-4",
		Type:          monitoring.EventStewardDisconnected,
		Source:        "test",
		Component:     "test",
		CorrelationID: wantCorrelationID,
		Severity:      monitoring.SeverityWarning,
	}

	watcher.OnSystemEvent(event)

	ctx := alerter.lastContext()
	require.NotNil(t, ctx, "alerter must receive a non-nil context")

	got := telemetry.GetCorrelationID(ctx)
	assert.Equal(t, wantCorrelationID, got,
		"context passed to alerter must carry correlation ID under ctxkeys.CorrelationIDKey")
}

func TestAlertingWatcherBelowThresholdNoAlert(t *testing.T) {
	logger := logging.NewNoopLogger()
	alerter := &contextCapturingAlerter{name: "test-alerter"}
	watcher := monitoring.NewAlertingWatcher(logger, "test-alerting", alerter)

	// EventStewardDisconnected threshold is SeverityWarning; Info is below it.
	event := monitoring.SystemEvent{
		ID:       "evt-5",
		Type:     monitoring.EventStewardDisconnected,
		Source:   "test",
		Severity: monitoring.SeverityInfo,
	}

	watcher.OnSystemEvent(event)

	assert.Nil(t, alerter.lastContext(), "SendAlert must not be called when event is below threshold")
}

func TestAlertingWatcherSendAlertError(t *testing.T) {
	captLog := &contextCapturingLogger{}
	alerter := &contextCapturingAlerter{
		name:      "failing-alerter",
		sendError: errors.New("network unreachable"),
	}
	watcher := monitoring.NewAlertingWatcher(captLog, "test-alerting", alerter)

	event := monitoring.SystemEvent{
		ID:       "evt-6",
		Type:     monitoring.EventConfigurationFailed,
		Source:   "test",
		Severity: monitoring.SeverityError,
	}

	// Must not panic; error is logged internally.
	watcher.OnSystemEvent(event)

	// alerter was called (error path exercised)
	require.NotNil(t, alerter.lastContext(), "alerter must be called even on error path")

	// watcher logged the failure
	require.NotNil(t, captLog.lastContext(), "watcher must log the send failure")
}
