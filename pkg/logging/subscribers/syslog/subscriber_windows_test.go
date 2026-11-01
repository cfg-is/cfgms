//go:build windows
// +build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package syslog

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// Compile-time interface conformance: the Windows subscriber must satisfy the
// same contract as the Unix one, so the logging provider can hold it without
// build-tagged special cases.
var _ interfaces.LoggingSubscriber = (*SyslogSubscriber)(nil)

// testEntry returns a fully populated RFC5424 log entry for the contract tests.
func testEntry(level string) interfaces.LogEntry {
	entry := interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       level,
		Message:     "windows syslog contract check",
		ServiceName: "cfgms-steward",
		Component:   "logging",
		TenantID:    "root/msp-a/client-1",
		SessionID:   "test-session",
		Fields:      map[string]interface{}{"test_field": "test_value"},
	}
	interfaces.PopulateRFC5424Fields(&entry, "test-host", "cfgms-test", "12345", interfaces.FacilityDaemon)
	return entry
}

func TestWindowsSubscriberIdentity(t *testing.T) {
	s := NewSyslogSubscriber()
	require.NotNil(t, s)

	assert.Equal(t, "syslog", s.Name(),
		"name must match the Unix subscriber so config selects the same subscriber on every platform")
	assert.NotEmpty(t, s.Description())
	assert.Contains(t, s.Description(), "Windows",
		"description must tell an operator why this subscriber does nothing here")
}

func TestWindowsSubscriberConstructorDefaults(t *testing.T) {
	s := NewSyslogSubscriber()
	require.NotNil(t, s)

	require.NotNil(t, s.config)
	assert.Equal(t, DefaultSyslogConfig(), s.config)
	require.NotNil(t, s.enabledLevels, "enabledLevels must be allocated, not nil")
	assert.Empty(t, s.enabledLevels)

	assert.NotEmpty(t, s.hostname, "hostname must fall back to a non-empty value")
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		assert.Equal(t, hostname, s.hostname)
	}
	assert.Equal(t, strconv.Itoa(os.Getpid()), s.procID)
}

func TestWindowsDefaultSyslogConfig(t *testing.T) {
	cfg := DefaultSyslogConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, "udp", cfg.Network)
	assert.Equal(t, "localhost:514", cfg.Address)
	assert.Equal(t, "daemon", cfg.Facility)
	assert.Equal(t, "cfgms", cfg.Tag)
	assert.Empty(t, cfg.Levels)
	assert.False(t, cfg.EnableTLS)

	assert.NotSame(t, cfg, DefaultSyslogConfig(),
		"each call must return a fresh config so callers cannot mutate a shared default")
}

// TestWindowsSubscriberInitializeNotSupported pins the central behavior of this
// file: initialization must fail loudly with ErrNotSupported so the logging
// provider drops the subscriber at startup rather than registering a sink that
// silently discards every entry.
func TestWindowsSubscriberInitializeNotSupported(t *testing.T) {
	s := NewSyslogSubscriber()

	cases := map[string]map[string]interface{}{
		"nil config":   nil,
		"empty config": {},
		"full config": {
			"network":  "tcp",
			"address":  "syslog.example.test:514",
			"facility": "daemon",
			"tag":      "cfgms",
			"levels":   []string{"INFO", "ERROR"},
		},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			err := s.Initialize(cfg)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrNotSupported)
			assert.Contains(t, err.Error(), "Windows Event Log",
				"the error must point the operator at the supported alternative")
		})
	}
}

func TestWindowsSubscriberAvailable(t *testing.T) {
	s := NewSyslogSubscriber()

	ok, err := s.Available()
	assert.False(t, ok, "syslog is never available on Windows")
	assert.ErrorIs(t, err, ErrNotSupported)
}

// TestWindowsSubscriberShouldHandleAlwaysFalse verifies the filter rejects every
// entry regardless of level, so a subscriber that slipped past Initialize still
// routes nothing here.
func TestWindowsSubscriberShouldHandleAlwaysFalse(t *testing.T) {
	s := NewSyslogSubscriber()

	for _, level := range []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL", ""} {
		assert.False(t, s.ShouldHandle(testEntry(level)),
			"level %q must not be handled on Windows", level)
	}
}

// TestWindowsSubscriberHandleLogEntryDrops verifies dropped entries are reported
// as success: HandleLogEntry is called asynchronously by the logging provider,
// and returning an error per entry would flood the provider's error path.
func TestWindowsSubscriberHandleLogEntryDrops(t *testing.T) {
	s := NewSyslogSubscriber()
	ctx := context.Background()

	assert.NoError(t, s.HandleLogEntry(ctx, testEntry("ERROR")))

	// A failed Initialize must not change the drop behavior.
	require.Error(t, s.Initialize(nil))
	assert.NoError(t, s.HandleLogEntry(ctx, testEntry("INFO")))

	// A cancelled context must not turn a no-op into an error.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	assert.NoError(t, s.HandleLogEntry(cancelled, testEntry("WARN")))
}

func TestWindowsSubscriberCloseIdempotent(t *testing.T) {
	s := NewSyslogSubscriber()

	assert.NoError(t, s.Close())
	assert.NoError(t, s.Close(), "Close must be safe to call more than once")

	// Closing without initializing, and handling after close, must both be safe.
	assert.NoError(t, s.HandleLogEntry(context.Background(), testEntry("INFO")))
}

// TestWindowsSubscriberConcurrentUse runs the subscriber under -race the way the
// logging provider drives it: many goroutines calling ShouldHandle and
// HandleLogEntry at once while another closes it. The Windows subscriber holds
// no mutable state, so this must be data-race free without locking.
func TestWindowsSubscriberConcurrentUse(t *testing.T) {
	s := NewSyslogSubscriber()
	ctx := context.Background()

	const goroutines = 16
	const iterations = 50

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				entry := testEntry("INFO")
				if s.ShouldHandle(entry) {
					errs <- errors.New("ShouldHandle returned true on Windows")
					continue
				}
				if err := s.HandleLogEntry(ctx, entry); err != nil {
					errs <- err
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < iterations; j++ {
			if err := s.Close(); err != nil {
				errs <- err
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent use failed: %v", err)
	}
}
