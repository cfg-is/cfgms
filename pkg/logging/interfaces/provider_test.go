package interfaces

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogLevelToSyslogSeverity(t *testing.T) {
	tests := []struct {
		level    string
		expected SyslogSeverity
	}{
		{"FATAL", SeverityEmergency},
		{"ERROR", SeverityError},
		{"WARN", SeverityWarning},
		{"INFO", SeverityInformational},
		{"DEBUG", SeverityDebug},
		{"UNKNOWN", SeverityInformational}, // Default case
		{"", SeverityInformational},        // Empty string
	}

	for _, test := range tests {
		t.Run(test.level, func(t *testing.T) {
			result := LogLevelToSyslogSeverity(test.level)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestCalculateSyslogPriority(t *testing.T) {
	tests := []struct {
		facility SyslogFacility
		severity SyslogSeverity
		expected int
	}{
		{FacilityDaemon, SeverityInformational, 30}, // 3*8 + 6
		{FacilityLocal0, SeverityError, 131},        // 16*8 + 3
		{FacilityKernel, SeverityEmergency, 0},      // 0*8 + 0
		{FacilityLocal7, SeverityDebug, 191},        // 23*8 + 7
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			result := CalculateSyslogPriority(test.facility, test.severity)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestPopulateRFC5424Fields(t *testing.T) {
	entry := LogEntry{
		Level:   "INFO",
		Message: "Test message",
	}

	hostname := "test-host"
	appName := "test-app"
	procID := "12345"
	facility := FacilityDaemon

	PopulateRFC5424Fields(&entry, hostname, appName, procID, facility)

	// Check populated fields
	assert.Equal(t, 1, entry.Version)
	assert.Equal(t, hostname, entry.Hostname)
	assert.Equal(t, appName, entry.AppName)
	assert.Equal(t, procID, entry.ProcID)
	assert.Equal(t, 30, entry.Priority) // daemon(3)*8 + info(6) = 30
	
	// Test that existing fields are not overwritten
	existingEntry := LogEntry{
		Level:    "ERROR",
		Message:  "Test message",
		Version:  2,
		Hostname: "existing-host",
		AppName:  "existing-app",
		ProcID:   "99999",
	}

	PopulateRFC5424Fields(&existingEntry, hostname, appName, procID, facility)

	// Existing fields should not be overwritten
	assert.Equal(t, 2, existingEntry.Version)
	assert.Equal(t, "existing-host", existingEntry.Hostname)
	assert.Equal(t, "existing-app", existingEntry.AppName)
	assert.Equal(t, "99999", existingEntry.ProcID)
	assert.Equal(t, 27, existingEntry.Priority) // daemon(3)*8 + error(3) = 27
}

func TestPopulateRFC5424Fields_WithComponent(t *testing.T) {
	entry := LogEntry{
		Level:     "WARN",
		Message:   "Test message",
		Component: "test-component",
	}

	PopulateRFC5424Fields(&entry, "host", "app", "123", FacilityLocal0)

	// Check that MsgID is generated from component and level
	assert.Equal(t, "test-component_WARN", entry.MsgID)
}

func TestLogEntry_ToSyslogFormat(t *testing.T) {
	timestamp := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	
	entry := LogEntry{
		Timestamp:     timestamp,
		Level:         "INFO",
		Message:       "Test syslog message",
		Priority:      30,  // daemon.info
		Version:       1,
		Hostname:      "test-host",
		AppName:       "cfgms",
		ProcID:        "12345",
		MsgID:         "TEST_INFO",
		ServiceName:   "cfgms-controller",
		Component:     "test-component",
		TenantID:      "tenant-123",
		SessionID:     "session-456",
		CorrelationID: "corr-789",
		TraceID:       "trace-abc",
		Fields: map[string]interface{}{
			"request_id": "req-999",
			"duration":   150,
		},
	}

	result := entry.ToSyslogFormat()

	// Check RFC5424 format components - fields are sorted alphabetically for deterministic output
	expected := "<30>1 2024-01-15T10:30:00Z test-host cfgms 12345 TEST_INFO [cfgms tenant_id=\"tenant-123\" session_id=\"session-456\" correlation_id=\"corr-789\" trace_id=\"trace-abc\" duration=\"150\" request_id=\"req-999\"] Test syslog message"
	
	assert.Equal(t, expected, result)
}

func TestLogEntry_ToSyslogFormat_WithDefaults(t *testing.T) {
	timestamp := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	
	entry := LogEntry{
		Timestamp:   timestamp,
		Level:       "ERROR",
		Message:     "Error message",
		Priority:    27, // daemon.error
		Version:     1,
		ServiceName: "cfgms-controller",
	}

	result := entry.ToSyslogFormat()

	// Check that missing fields are replaced with defaults
	expected := "<27>1 2024-01-15T10:30:00Z - cfgms-controller - - [cfgms] Error message"
	
	assert.Equal(t, expected, result)
}

func TestLogEntry_ToSyslogFormat_EmptyFields(t *testing.T) {
	timestamp := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	
	entry := LogEntry{
		Timestamp: timestamp,
		Level:     "INFO",
		Message:   "Simple message",
		Priority:  30,
		Version:   1,
	}

	result := entry.ToSyslogFormat()

	// Check minimal format
	expected := "<30>1 2024-01-15T10:30:00Z - - - - [cfgms] Simple message"
	
	assert.Equal(t, expected, result)
}

func TestLogEntry_ToSyslogFormat_OnlyTenant(t *testing.T) {
	timestamp := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	
	entry := LogEntry{
		Timestamp: timestamp,
		Level:     "WARN",
		Message:   "Warning with tenant",
		Priority:  28, // daemon.warning
		Version:   1,
		Hostname:  "server1",
		TenantID:  "tenant-456",
	}

	result := entry.ToSyslogFormat()

	// Check structured data with only tenant
	expected := "<28>1 2024-01-15T10:30:00Z server1 - - - [cfgms tenant_id=\"tenant-456\"] Warning with tenant"
	
	assert.Equal(t, expected, result)
}

func TestSyslogFacilityConstants(t *testing.T) {
	// Verify facility constants match RFC5424 values
	assert.Equal(t, SyslogFacility(0), FacilityKernel)
	assert.Equal(t, SyslogFacility(1), FacilityUser)
	assert.Equal(t, SyslogFacility(3), FacilityDaemon)
	assert.Equal(t, SyslogFacility(16), FacilityLocal0)
	assert.Equal(t, SyslogFacility(23), FacilityLocal7)
}

func TestSyslogSeverityConstants(t *testing.T) {
	// Verify severity constants match RFC5424 values
	assert.Equal(t, SyslogSeverity(0), SeverityEmergency)
	assert.Equal(t, SyslogSeverity(1), SeverityAlert)
	assert.Equal(t, SyslogSeverity(3), SeverityError)
	assert.Equal(t, SyslogSeverity(4), SeverityWarning)
	assert.Equal(t, SyslogSeverity(6), SeverityInformational)
	assert.Equal(t, SyslogSeverity(7), SeverityDebug)
}

func TestLogEntry_StructureValidation(t *testing.T) {
	// Test that LogEntry has all required fields for RFC5424
	entry := LogEntry{}
	
	// Core fields
	require.IsType(t, time.Time{}, entry.Timestamp)
	require.IsType(t, "", entry.Level)
	require.IsType(t, "", entry.Message)
	
	// RFC5424 fields
	require.IsType(t, 0, entry.Priority)
	require.IsType(t, 0, entry.Version)
	require.IsType(t, "", entry.Hostname)
	require.IsType(t, "", entry.AppName)
	require.IsType(t, "", entry.ProcID)
	require.IsType(t, "", entry.MsgID)
	
	// CFGMS context fields
	require.IsType(t, "", entry.ServiceName)
	require.IsType(t, "", entry.Component)
	require.IsType(t, "", entry.TenantID)
	require.IsType(t, "", entry.SessionID)
	require.IsType(t, "", entry.CorrelationID)
	require.IsType(t, "", entry.TraceID)
	require.IsType(t, "", entry.SpanID)
	
	// Structured fields
	require.IsType(t, map[string]interface{}(nil), entry.Fields)
}

// Benchmark tests for performance validation
func BenchmarkPopulateRFC5424Fields(b *testing.B) {
	entry := LogEntry{
		Level:     "INFO",
		Message:   "Benchmark message",
		Component: "benchmark-component",
	}
	
	hostname := "benchmark-host"
	appName := "benchmark-app"
	procID := "12345"
	facility := FacilityDaemon
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PopulateRFC5424Fields(&entry, hostname, appName, procID, facility)
	}
}

func BenchmarkToSyslogFormat(b *testing.B) {
	entry := LogEntry{
		Timestamp:     time.Now(),
		Level:         "INFO",
		Message:       "Benchmark syslog formatting",
		Priority:      30,
		Version:       1,
		Hostname:      "benchmark-host",
		AppName:       "cfgms",
		ProcID:        "12345",
		MsgID:         "BENCH_INFO",
		TenantID:      "tenant-123",
		SessionID:     "session-456",
		CorrelationID: "corr-789",
		Fields: map[string]interface{}{
			"benchmark": true,
			"iteration": 0,
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry.Fields["iteration"] = i
		_ = entry.ToSyslogFormat()
	}
}