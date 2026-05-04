//go:build !windows && integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package syslog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

func TestSyslogSubscriber_HandleLogEntry(t *testing.T) {
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
