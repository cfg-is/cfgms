// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package syslog

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

func TestNewSyslogSubscriber(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	assert.NotNil(t, subscriber)
	assert.Equal(t, "syslog", subscriber.Name())
	assert.Equal(t, "RFC5424 syslog subscriber for enterprise log aggregation", subscriber.Description())
	assert.NotEmpty(t, subscriber.hostname)
	assert.NotEmpty(t, subscriber.procID)
}

func TestSyslogSubscriber_Initialize(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	config := map[string]interface{}{
		"network":         "",
		"facility":        "daemon",
		"tag":             "test-cfgms",
		"levels":          []string{"INFO", "ERROR"},
		"structured_data": true,
	}

	err := subscriber.Initialize(config)
	assert.NoError(t, err)

	// Check configuration was applied
	assert.Equal(t, "daemon", subscriber.config.Facility)
	assert.Equal(t, "test-cfgms", subscriber.config.Tag)
	assert.Equal(t, []string{"INFO", "ERROR"}, subscriber.config.Levels)
	assert.True(t, subscriber.config.StructuredData)

	// Check level filtering was set up
	assert.True(t, subscriber.enabledLevels["INFO"])
	assert.True(t, subscriber.enabledLevels["ERROR"])
	assert.False(t, subscriber.enabledLevels["DEBUG"])

	// Cleanup
	_ = subscriber.Close()
}

func TestSyslogSubscriber_Initialize_InvalidConfig(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	// Test double initialization
	config := map[string]interface{}{"facility": "daemon"}
	err := subscriber.Initialize(config)
	assert.NoError(t, err)

	err = subscriber.Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already initialized")

	_ = subscriber.Close()
}

func TestSyslogSubscriber_ShouldHandle(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	// Test with no level filtering (should handle all)
	config := map[string]interface{}{"facility": "daemon"}
	err := subscriber.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = subscriber.Close() }()

	entry1 := interfaces.LogEntry{Level: "INFO", Message: "Test"}
	entry2 := interfaces.LogEntry{Level: "DEBUG", Message: "Test"}

	assert.True(t, subscriber.ShouldHandle(entry1))
	assert.True(t, subscriber.ShouldHandle(entry2))

	// Test with level filtering
	subscriber2 := NewSyslogSubscriber()
	config2 := map[string]interface{}{
		"facility": "daemon",
		"levels":   []string{"ERROR", "WARN"},
	}
	err = subscriber2.Initialize(config2)
	require.NoError(t, err)
	defer func() { _ = subscriber2.Close() }()

	assert.False(t, subscriber2.ShouldHandle(entry1)) // INFO not in filter
	assert.False(t, subscriber2.ShouldHandle(entry2)) // DEBUG not in filter

	errorEntry := interfaces.LogEntry{Level: "ERROR", Message: "Error"}
	assert.True(t, subscriber2.ShouldHandle(errorEntry))
}

func TestSyslogSubscriber_Available(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	// Test with default configuration (should be available as local syslog)
	available, err := subscriber.Available()
	// Default config uses local syslog which reports as available
	assert.True(t, available)
	assert.NoError(t, err)

	// Test after initialization with local syslog
	config := map[string]interface{}{
		"network":  "", // Local syslog
		"facility": "daemon",
	}

	err = subscriber.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = subscriber.Close() }()

	available, err = subscriber.Available()
	// Local syslog (empty network) always reports as available by design
	// This is because local syslog availability is difficult to test reliably
	assert.True(t, available)
	assert.NoError(t, err)
}

func TestSyslogSubscriber_Available_NetworkSyslog(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	// Test with unreachable network address (should fail availability check)
	config := map[string]interface{}{
		"network":  "udp",
		"address":  "192.0.2.1:514", // RFC5737 test address - unreachable
		"facility": "daemon",
	}

	err := subscriber.Initialize(config)
	if err != nil {
		// Initialization might fail on some systems - that's ok for this test
		t.Skipf("Network syslog initialization failed (system dependent): %v", err)
		return
	}
	defer func() { _ = subscriber.Close() }()

	available, err := subscriber.Available()
	// This should fail because the test address is unreachable
	// But network behavior may vary by system/environment
	if available {
		t.Logf("Note: test address unexpectedly reported as available")
	} else {
		assert.Error(t, err, "Should have error when address is unreachable")
	}
}

func TestSyslogSubscriber_HandleLogEntry(t *testing.T) {
	// Skip this test if not running in an environment with syslog
	if os.Getenv("CFGMS_TEST_SYSLOG") != "1" {
		t.Skip("Syslog tests disabled - set CFGMS_TEST_SYSLOG=1 to enable")
	}

	subscriber := NewSyslogSubscriber()

	config := map[string]interface{}{
		"network":         "", // Local syslog
		"facility":        "daemon",
		"tag":             "cfgms-test",
		"structured_data": true,
	}

	err := subscriber.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = subscriber.Close() }()

	// Create test log entry
	entry := interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       "INFO",
		Message:     "Test syslog subscriber",
		ServiceName: "cfgms-controller",
		Component:   "test-component",
		TenantID:    "test-tenant",
		SessionID:   "test-session",
		Fields: map[string]interface{}{
			"test_field": "test_value",
		},
	}

	// Populate RFC5424 fields
	interfaces.PopulateRFC5424Fields(&entry, "test-host", "cfgms-test", "12345", interfaces.FacilityDaemon)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = subscriber.HandleLogEntry(ctx, entry)
	assert.NoError(t, err)
}

func TestSyslogSubscriber_HandleLogEntry_NotInitialized(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	entry := interfaces.LogEntry{
		Level:   "INFO",
		Message: "Test",
	}

	ctx := context.Background()
	err := subscriber.HandleLogEntry(ctx, entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSyslogSubscriber_HandleLogEntry_Filtered(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	config := map[string]interface{}{
		"facility": "daemon",
		"levels":   []string{"ERROR"}, // Only ERROR level
	}

	err := subscriber.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = subscriber.Close() }()

	// INFO entry should be silently skipped (not error)
	entry := interfaces.LogEntry{
		Level:   "INFO",
		Message: "This should be filtered out",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = subscriber.HandleLogEntry(ctx, entry)
	assert.NoError(t, err) // Should not error, just skip
}

func TestSyslogSubscriber_Close(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	// Test closing uninitialized subscriber
	err := subscriber.Close()
	assert.NoError(t, err)

	// Test closing initialized subscriber
	config := map[string]interface{}{"facility": "daemon"}
	err = subscriber.Initialize(config)
	require.NoError(t, err)

	err = subscriber.Close()
	assert.NoError(t, err)

	// Test double close (should be safe)
	err = subscriber.Close()
	assert.NoError(t, err)
}

func TestSyslogSubscriber_ParseConfig(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	config := map[string]interface{}{
		"network":         "", // Use local syslog to avoid network dependency
		"facility":        "local0",
		"tag":             "custom-tag",
		"write_timeout":   "10s",
		"structured_data": false,
		"include_pid":     false,
		"levels":          []string{"WARN", "ERROR"},
		"buffer_size":     200,
	}

	err := subscriber.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = subscriber.Close() }()

	// Verify configuration was parsed correctly
	assert.Equal(t, "", subscriber.config.Network)
	assert.Equal(t, "localhost:514", subscriber.config.Address) // Default address
	assert.False(t, subscriber.config.EnableTLS)                // Default value
	assert.Equal(t, "local0", subscriber.config.Facility)
	assert.Equal(t, "custom-tag", subscriber.config.Tag)
	assert.Equal(t, "10s", subscriber.config.WriteTimeout)
	assert.False(t, subscriber.config.StructuredData)
	assert.False(t, subscriber.config.IncludePID)
	assert.Equal(t, []string{"WARN", "ERROR"}, subscriber.config.Levels)
	assert.Equal(t, 200, subscriber.config.BufferSize)
}

func TestSyslogSubscriber_ParseConfig_TypeConversion(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	config := map[string]interface{}{
		"facility":    "daemon",
		"buffer_size": 150.0,                          // float64 from JSON parsing
		"levels":      []interface{}{"INFO", "ERROR"}, // []interface{} from JSON
	}

	err := subscriber.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = subscriber.Close() }()

	assert.Equal(t, 150, subscriber.config.BufferSize)
	assert.Equal(t, []string{"INFO", "ERROR"}, subscriber.config.Levels)
}

func TestDefaultSyslogConfig(t *testing.T) {
	config := DefaultSyslogConfig()

	assert.Equal(t, "udp", config.Network)
	assert.Equal(t, "localhost:514", config.Address)
	assert.False(t, config.EnableTLS)
	assert.Equal(t, "daemon", config.Facility)
	assert.Equal(t, "cfgms", config.Tag)
	assert.Empty(t, config.Levels) // All levels
	assert.Equal(t, "5s", config.WriteTimeout)
	assert.Equal(t, 100, config.BufferSize)
	assert.True(t, config.StructuredData)
	assert.True(t, config.IncludePID)
}

func TestSyslogSubscriber_ParseFacility(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	tests := []struct {
		input    string
		expected interfaces.SyslogFacility
	}{
		{"kern", interfaces.FacilityKernel},
		{"kernel", interfaces.FacilityKernel},
		{"user", interfaces.FacilityUser},
		{"mail", interfaces.FacilityMail},
		{"daemon", interfaces.FacilityDaemon},
		{"syslog", interfaces.FacilitySyslog},
		{"local0", interfaces.FacilityLocal0},
		{"local7", interfaces.FacilityLocal7},
		{"unknown", interfaces.FacilityDaemon}, // Default
		{"", interfaces.FacilityDaemon},        // Default
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := subscriber.parseFacility(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestSyslogSubscriber_SetupLevelFiltering(t *testing.T) {
	subscriber := NewSyslogSubscriber()

	// Test with empty levels (should enable all)
	subscriber.config = &SyslogConfig{Levels: []string{}}
	subscriber.setupLevelFiltering()

	assert.Empty(t, subscriber.enabledLevels)

	// Test with specific levels
	subscriber.config = &SyslogConfig{Levels: []string{"info", "ERROR", "warn"}}
	subscriber.setupLevelFiltering()

	assert.True(t, subscriber.enabledLevels["INFO"]) // Uppercase conversion
	assert.True(t, subscriber.enabledLevels["ERROR"])
	assert.True(t, subscriber.enabledLevels["WARN"]) // Uppercase conversion
	assert.False(t, subscriber.enabledLevels["DEBUG"])
}

// Benchmark tests for performance validation
func BenchmarkSyslogSubscriber_ShouldHandle(b *testing.B) {
	subscriber := NewSyslogSubscriber()
	config := map[string]interface{}{
		"facility": "daemon",
		"levels":   []string{"INFO", "WARN", "ERROR"},
	}
	_ = subscriber.Initialize(config)
	defer func() { _ = subscriber.Close() }()

	entry := interfaces.LogEntry{
		Level:   "INFO",
		Message: "Benchmark message",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subscriber.ShouldHandle(entry)
	}
}

func BenchmarkSyslogSubscriber_ParseFacility(b *testing.B) {
	subscriber := NewSyslogSubscriber()

	facilities := []string{"daemon", "local0", "kern", "user", "mail"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		facility := facilities[i%len(facilities)]
		subscriber.parseFacility(facility)
	}
}
