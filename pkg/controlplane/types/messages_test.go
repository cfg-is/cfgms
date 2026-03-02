// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommand_Marshaling(t *testing.T) {
	tests := []struct {
		name string
		cmd  *Command
	}{
		{
			name: "basic command",
			cmd: &Command{
				ID:        "cmd-123",
				Type:      CommandSyncConfig,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
				Timestamp: time.Now(),
				Params: map[string]interface{}{
					"version": "1.0.0",
				},
				Priority: 5,
			},
		},
		{
			name: "broadcast command without steward ID",
			cmd: &Command{
				ID:        "cmd-456",
				Type:      CommandExecuteTask,
				TenantID:  "tenant-2",
				Timestamp: time.Now(),
				Params: map[string]interface{}{
					"task": "update",
				},
			},
		},
		{
			name: "minimal command",
			cmd: &Command{
				ID:        "cmd-789",
				Type:      CommandShutdown,
				Timestamp: time.Now(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.cmd)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Unmarshal back
			var decoded Command
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Verify fields match
			assert.Equal(t, tt.cmd.ID, decoded.ID)
			assert.Equal(t, tt.cmd.Type, decoded.Type)
			assert.Equal(t, tt.cmd.StewardID, decoded.StewardID)
			assert.Equal(t, tt.cmd.TenantID, decoded.TenantID)
			assert.Equal(t, tt.cmd.Priority, decoded.Priority)
		})
	}
}

func TestEvent_Marshaling(t *testing.T) {
	event := &Event{
		ID:        "evt-123",
		Type:      EventConfigApplied,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		CommandID: "cmd-123",
		Details: map[string]interface{}{
			"duration_ms": 150,
		},
		Severity: "info",
	}

	// Marshal to JSON
	data, err := json.Marshal(event)
	require.NoError(t, err)

	// Unmarshal back
	var decoded Event
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, event.ID, decoded.ID)
	assert.Equal(t, event.Type, decoded.Type)
	assert.Equal(t, event.StewardID, decoded.StewardID)
	assert.Equal(t, event.CommandID, decoded.CommandID)
	assert.Equal(t, event.Severity, decoded.Severity)
}

func TestHeartbeat_Marshaling(t *testing.T) {
	hb := &Heartbeat{
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Status:    StatusHealthy,
		Timestamp: time.Now(),
		Metrics: map[string]interface{}{
			"cpu_percent": 25.5,
			"memory_mb":   512,
		},
		Version: "v0.9.0",
	}

	// Marshal to JSON
	data, err := json.Marshal(hb)
	require.NoError(t, err)

	// Unmarshal back
	var decoded Heartbeat
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, hb.StewardID, decoded.StewardID)
	assert.Equal(t, hb.Status, decoded.Status)
	assert.Equal(t, hb.Version, decoded.Version)
}

func TestResponse_Marshaling(t *testing.T) {
	resp := &Response{
		CommandID: "cmd-123",
		StewardID: "steward-1",
		Success:   true,
		Message:   "Command accepted",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"estimated_duration": "30s",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Unmarshal back
	var decoded Response
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, resp.CommandID, decoded.CommandID)
	assert.Equal(t, resp.Success, decoded.Success)
	assert.Equal(t, resp.Message, decoded.Message)
}

func TestEventFilter_Match(t *testing.T) {
	tests := []struct {
		name     string
		filter   *EventFilter
		event    *Event
		expected bool
	}{
		{
			name:   "empty filter matches all",
			filter: &EventFilter{},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: true,
		},
		{
			name: "steward ID filter matches",
			filter: &EventFilter{
				StewardIDs: []string{"steward-1", "steward-2"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: true,
		},
		{
			name: "steward ID filter no match",
			filter: &EventFilter{
				StewardIDs: []string{"steward-2", "steward-3"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: false,
		},
		{
			name: "tenant ID filter matches",
			filter: &EventFilter{
				TenantIDs: []string{"tenant-1", "tenant-2"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: true,
		},
		{
			name: "tenant ID filter no match",
			filter: &EventFilter{
				TenantIDs: []string{"tenant-2", "tenant-3"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: false,
		},
		{
			name: "event type filter matches",
			filter: &EventFilter{
				EventTypes: []EventType{EventConfigApplied, EventDNASynced},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: true,
		},
		{
			name: "event type filter no match",
			filter: &EventFilter{
				EventTypes: []EventType{EventDNASynced, EventTaskCompleted},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: false,
		},
		{
			name: "multiple filters all match",
			filter: &EventFilter{
				StewardIDs: []string{"steward-1"},
				TenantIDs:  []string{"tenant-1"},
				EventTypes: []EventType{EventConfigApplied},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: true,
		},
		{
			name: "multiple filters one doesn't match",
			filter: &EventFilter{
				StewardIDs: []string{"steward-1"},
				TenantIDs:  []string{"tenant-2"}, // Different tenant
				EventTypes: []EventType{EventConfigApplied},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCommandTypes(t *testing.T) {
	// Verify all command types are distinct
	types := []CommandType{
		CommandSyncConfig,
		CommandSyncDNA,
		CommandConnectDataPlane,
		CommandValidateConfig,
		CommandExecuteTask,
		CommandShutdown,
	}

	seen := make(map[CommandType]bool)
	for _, typ := range types {
		assert.False(t, seen[typ], "Duplicate command type: %s", typ)
		seen[typ] = true
	}
}

func TestEventTypes(t *testing.T) {
	// Verify all event types are distinct
	types := []EventType{
		EventConfigApplied,
		EventDNASynced,
		EventTaskCompleted,
		EventTaskFailed,
		EventError,
		EventCommandReceived,
		EventCommandCompleted,
		EventCommandFailed,
		EventDNAChanged,
	}

	seen := make(map[EventType]bool)
	for _, typ := range types {
		assert.False(t, seen[typ], "Duplicate event type: %s", typ)
		seen[typ] = true
	}
}

func TestHeartbeatStatus(t *testing.T) {
	// Verify all heartbeat statuses are distinct
	statuses := []HeartbeatStatus{
		StatusHealthy,
		StatusDegraded,
		StatusError,
		StatusDisconnected,
	}

	seen := make(map[HeartbeatStatus]bool)
	for _, status := range statuses {
		assert.False(t, seen[status], "Duplicate heartbeat status: %s", status)
		seen[status] = true
	}
}
