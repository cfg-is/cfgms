// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond) // proto truncates to microseconds

	tests := []struct {
		name string
		cmd  *types.Command
	}{
		{
			name: "full command",
			cmd: &types.Command{
				ID:        "cmd-123",
				Type:      types.CommandSyncConfig,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
				Timestamp: now,
				Params: map[string]interface{}{
					"version":  "1.2.3",
					"priority": float64(10),
					"nested":   map[string]interface{}{"key": "val"},
				},
				Priority: 5,
			},
		},
		{
			name: "minimal command",
			cmd: &types.Command{
				ID:        "cmd-456",
				Type:      types.CommandShutdown,
				Timestamp: now,
			},
		},
		{
			name: "nil params",
			cmd: &types.Command{
				ID:        "cmd-789",
				Type:      types.CommandExecuteTask,
				StewardID: "steward-2",
				Timestamp: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := commandToProto(tt.cmd)
			require.NotNil(t, pb)

			result := commandFromProto(pb)
			require.NotNil(t, result)

			assert.Equal(t, tt.cmd.ID, result.ID)
			assert.Equal(t, tt.cmd.Type, result.Type)
			assert.Equal(t, tt.cmd.StewardID, result.StewardID)
			assert.Equal(t, tt.cmd.TenantID, result.TenantID)
			assert.Equal(t, tt.cmd.Timestamp.UTC(), result.Timestamp.UTC())
			assert.Equal(t, tt.cmd.Priority, result.Priority)

			if tt.cmd.Params != nil {
				require.NotNil(t, result.Params)
				// String values round-trip exactly
				if v, ok := tt.cmd.Params["version"]; ok {
					assert.Equal(t, v, result.Params["version"])
				}
			} else {
				assert.Nil(t, result.Params)
			}
		})
	}
}

func TestCommandNil(t *testing.T) {
	assert.Nil(t, commandToProto(nil))
	assert.Nil(t, commandFromProto(nil))
}

func TestCommandTypeRoundTrip(t *testing.T) {
	allTypes := []types.CommandType{
		types.CommandSyncConfig,
		types.CommandSyncDNA,
		types.CommandConnectDataPlane,
		types.CommandValidateConfig,
		types.CommandExecuteTask,
		types.CommandShutdown,
	}
	for _, ct := range allTypes {
		t.Run(string(ct), func(t *testing.T) {
			pb := commandTypeToProto[ct]
			result := protoToCommandType[pb]
			assert.Equal(t, ct, result)
		})
	}
}

func TestEventRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond)

	tests := []struct {
		name  string
		event *types.Event
	}{
		{
			name: "full event",
			event: &types.Event{
				ID:        "evt-123",
				Type:      types.EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
				Timestamp: now,
				CommandID: "cmd-123",
				Details:   map[string]interface{}{"modules": float64(5)},
				Severity:  "warning",
			},
		},
		{
			name: "minimal event",
			event: &types.Event{
				ID:        "evt-456",
				Type:      types.EventError,
				StewardID: "steward-2",
				Timestamp: now,
				Severity:  "error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := eventToProto(tt.event)
			require.NotNil(t, pb)

			result := eventFromProto(pb)
			require.NotNil(t, result)

			assert.Equal(t, tt.event.ID, result.ID)
			assert.Equal(t, tt.event.Type, result.Type)
			assert.Equal(t, tt.event.StewardID, result.StewardID)
			assert.Equal(t, tt.event.TenantID, result.TenantID)
			assert.Equal(t, tt.event.Timestamp.UTC(), result.Timestamp.UTC())
			assert.Equal(t, tt.event.CommandID, result.CommandID)
			assert.Equal(t, tt.event.Severity, result.Severity)
		})
	}
}

func TestEventNil(t *testing.T) {
	assert.Nil(t, eventToProto(nil))
	assert.Nil(t, eventFromProto(nil))
}

func TestEventTypeRoundTrip(t *testing.T) {
	allTypes := []types.EventType{
		types.EventConfigApplied,
		types.EventDNASynced,
		types.EventTaskCompleted,
		types.EventTaskFailed,
		types.EventError,
	}
	for _, et := range allTypes {
		t.Run(string(et), func(t *testing.T) {
			pb := eventTypeToProto[et]
			result := protoToEventType[pb]
			assert.Equal(t, et, result)
		})
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	allSeverities := []string{"info", "warning", "error", "critical"}
	for _, s := range allSeverities {
		t.Run(s, func(t *testing.T) {
			pb := severityToProto[s]
			result := protoToSeverity[pb]
			assert.Equal(t, s, result)
		})
	}
}

func TestHeartbeatRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond)

	tests := []struct {
		name string
		hb   *types.Heartbeat
	}{
		{
			name: "full heartbeat",
			hb: &types.Heartbeat{
				StewardID: "steward-1",
				TenantID:  "tenant-1",
				Status:    types.StatusHealthy,
				Timestamp: now,
				Metrics: map[string]interface{}{
					"cpu":    "45.2",
					"memory": "1024",
				},
				Version: "2.1.0",
			},
		},
		{
			name: "degraded no metrics",
			hb: &types.Heartbeat{
				StewardID: "steward-2",
				Status:    types.StatusDegraded,
				Timestamp: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := heartbeatToProto(tt.hb)
			require.NotNil(t, pb)

			result := heartbeatFromProto(pb)
			require.NotNil(t, result)

			assert.Equal(t, tt.hb.StewardID, result.StewardID)
			assert.Equal(t, tt.hb.TenantID, result.TenantID)
			assert.Equal(t, tt.hb.Status, result.Status)
			assert.Equal(t, tt.hb.Timestamp.UTC(), result.Timestamp.UTC())
			assert.Equal(t, tt.hb.Version, result.Version)

			if tt.hb.Metrics != nil {
				require.NotNil(t, result.Metrics)
			} else {
				assert.Nil(t, result.Metrics)
			}
		})
	}
}

func TestHeartbeatNil(t *testing.T) {
	assert.Nil(t, heartbeatToProto(nil))
	assert.Nil(t, heartbeatFromProto(nil))
}

func TestHeartbeatStatusRoundTrip(t *testing.T) {
	allStatuses := []types.HeartbeatStatus{
		types.StatusHealthy,
		types.StatusDegraded,
		types.StatusError,
		types.StatusDisconnected,
	}
	for _, s := range allStatuses {
		t.Run(string(s), func(t *testing.T) {
			pb := heartbeatStatusToProto[s]
			result := protoToHeartbeatStatus[pb]
			assert.Equal(t, s, result)
		})
	}
}

func TestResponseRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond)

	tests := []struct {
		name string
		resp *types.Response
	}{
		{
			name: "success response",
			resp: &types.Response{
				CommandID: "cmd-123",
				StewardID: "steward-1",
				Success:   true,
				Message:   "command accepted",
				Timestamp: now,
				Details:   map[string]interface{}{"eta": "5s"},
			},
		},
		{
			name: "failure response",
			resp: &types.Response{
				CommandID: "cmd-456",
				StewardID: "steward-2",
				Success:   false,
				Message:   "insufficient permissions",
				Timestamp: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := responseToProto(tt.resp)
			require.NotNil(t, pb)

			result := responseFromProto(pb)
			require.NotNil(t, result)

			assert.Equal(t, tt.resp.CommandID, result.CommandID)
			assert.Equal(t, tt.resp.StewardID, result.StewardID)
			assert.Equal(t, tt.resp.Success, result.Success)
			assert.Equal(t, tt.resp.Message, result.Message)
			assert.Equal(t, tt.resp.Timestamp.UTC(), result.Timestamp.UTC())

			if tt.resp.Details != nil {
				require.NotNil(t, result.Details)
			} else {
				assert.Nil(t, result.Details)
			}
		})
	}
}

func TestResponseNil(t *testing.T) {
	assert.Nil(t, responseToProto(nil))
	assert.Nil(t, responseFromProto(nil))
}

func TestInterfaceMapToStringMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]string
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: map[string]string{},
		},
		{
			name:     "string values",
			input:    map[string]interface{}{"a": "hello", "b": "world"},
			expected: map[string]string{"a": "hello", "b": "world"},
		},
		{
			name:     "numeric values",
			input:    map[string]interface{}{"count": float64(42), "pi": 3.14},
			expected: map[string]string{"count": "42", "pi": "3.14"},
		},
		{
			name:     "boolean values",
			input:    map[string]interface{}{"enabled": true, "debug": false},
			expected: map[string]string{"enabled": "true", "debug": "false"},
		},
		{
			name:  "nested object",
			input: map[string]interface{}{"nested": map[string]interface{}{"key": "val"}},
			expected: map[string]string{
				"nested": `{"key":"val"}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interfaceMapToStringMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStringMapToInterfaceMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]interface{}
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: map[string]interface{}{},
		},
		{
			name:     "plain strings",
			input:    map[string]string{"a": "hello", "b": "world"},
			expected: map[string]interface{}{"a": "hello", "b": "world"},
		},
		{
			name:     "numeric JSON",
			input:    map[string]string{"count": "42", "pi": "3.14"},
			expected: map[string]interface{}{"count": float64(42), "pi": 3.14},
		},
		{
			name:     "boolean JSON",
			input:    map[string]string{"enabled": "true"},
			expected: map[string]interface{}{"enabled": true},
		},
		{
			name:  "nested JSON object",
			input: map[string]string{"nested": `{"key":"val"}`},
			expected: map[string]interface{}{
				"nested": map[string]interface{}{"key": "val"},
			},
		},
		{
			name:     "non-JSON string kept as-is",
			input:    map[string]string{"msg": "hello world"},
			expected: map[string]interface{}{"msg": "hello world"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringMapToInterfaceMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapRoundTrip(t *testing.T) {
	original := map[string]interface{}{
		"string_val": "hello",
		"int_val":    float64(42),
		"bool_val":   true,
		"nested":     map[string]interface{}{"inner": "value"},
	}

	stringMap := interfaceMapToStringMap(original)
	result := stringMapToInterfaceMap(stringMap)

	assert.Equal(t, original, result)
}
