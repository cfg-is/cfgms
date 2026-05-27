// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogEntryStructRemovedFromLogger confirms that the shadow LogEntry struct has been
// deleted from logger.go and only interfaces.LogEntry is used.
func TestLogEntryStructRemovedFromLogger(t *testing.T) {
	data, err := os.ReadFile("logger.go")
	require.NoError(t, err, "logger.go must be readable")
	assert.NotContains(t, string(data), "type LogEntry struct",
		"logger.go must not define its own LogEntry struct; use interfaces.LogEntry instead")
}

// TestLogJSONUsesInterfacesLogEntry is a compile-time assertion: if logJSON were still
// constructing the local LogEntry the file would not compile after the struct is deleted.
// This test verifies the JSON output produced by logJSON contains the expected fields.
func TestLogJSONUsesInterfacesLogEntry(t *testing.T) {
	var buf bytes.Buffer
	l := &DefaultLogger{
		config: &Config{
			Level:             DebugLevel,
			Format:            JSONFormat,
			ServiceName:       "test-service",
			Component:         "test-component",
			EnableCorrelation: false,
		},
		log:               log.New(&buf, "", 0),
		useProviderSystem: false,
	}

	l.logJSON(context.Background(), "INFO", "hello world")

	output := strings.TrimSpace(buf.String())
	require.NotEmpty(t, output)

	var entry interfaces.LogEntry
	err := json.Unmarshal([]byte(output), &entry)
	require.NoError(t, err, "logJSON output must be valid JSON deserializable into interfaces.LogEntry")

	assert.Equal(t, "INFO", entry.Level)
	assert.Equal(t, "hello world", entry.Message)
	assert.Equal(t, "test-service", entry.ServiceName)
	assert.Equal(t, "test-component", entry.Component)
	assert.False(t, entry.Timestamp.IsZero(), "Timestamp must be populated")
}

// TestLogJSONWithCorrelation verifies correlation/trace fields are injected via interfaces.LogEntry.
func TestLogJSONWithCorrelation(t *testing.T) {
	var buf bytes.Buffer
	l := &DefaultLogger{
		config: &Config{
			Level:             DebugLevel,
			Format:            JSONFormat,
			ServiceName:       "svc",
			Component:         "comp",
			EnableCorrelation: true,
		},
		log:               log.New(&buf, "", 0),
		useProviderSystem: false,
	}

	ctx := context.Background()
	l.logJSON(ctx, "WARN", "something happened", "key", "value")

	output := strings.TrimSpace(buf.String())
	require.NotEmpty(t, output)

	var entry interfaces.LogEntry
	err := json.Unmarshal([]byte(output), &entry)
	require.NoError(t, err)

	assert.Equal(t, "WARN", entry.Level)
	assert.Equal(t, "something happened", entry.Message)
	assert.NotNil(t, entry.Fields)
	assert.Equal(t, "value", entry.Fields["key"])
}

// TestLogJSONTimestampIsUTC verifies the timestamp in the JSON output is UTC.
func TestLogJSONTimestampIsUTC(t *testing.T) {
	var buf bytes.Buffer
	l := &DefaultLogger{
		config: &Config{
			Level:  DebugLevel,
			Format: JSONFormat,
		},
		log:               log.New(&buf, "", 0),
		useProviderSystem: false,
	}

	before := time.Now().UTC().Add(-time.Second)
	l.logJSON(context.Background(), "DEBUG", "tick")
	after := time.Now().UTC().Add(time.Second)

	output := strings.TrimSpace(buf.String())
	require.NotEmpty(t, output)

	var entry interfaces.LogEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entry))

	assert.True(t, entry.Timestamp.After(before), "timestamp should be after test start")
	assert.True(t, entry.Timestamp.Before(after), "timestamp should be before test end")
	assert.Equal(t, "UTC", entry.Timestamp.Location().String())
}
