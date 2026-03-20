// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCommand_Construction(t *testing.T) {
	tests := []struct {
		name        string
		cmdType     CommandType
		wantDefault bool
	}{
		{"sync config command", CommandType_COMMAND_TYPE_SYNC_CONFIG, false},
		{"sync dna command", CommandType_COMMAND_TYPE_SYNC_DNA, false},
		{"execute task command", CommandType_COMMAND_TYPE_EXECUTE_TASK, false},
		{"shutdown command", CommandType_COMMAND_TYPE_SHUTDOWN, false},
		{"zero value is unspecified", CommandType_COMMAND_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &Command{
				Id:    "cmd-001",
				Type:  tt.cmdType,
				Params: map[string]string{"key": "value"},
			}
			assert.Equal(t, tt.cmdType, cmd.GetType())
			if tt.wantDefault {
				assert.Equal(t, CommandType(0), cmd.GetType())
			}
		})
	}
}

func TestCommand_ZeroValueDefault(t *testing.T) {
	cmd := &Command{}
	assert.Equal(t, CommandType_COMMAND_TYPE_UNSPECIFIED, cmd.GetType())
}

func TestEvent_Construction(t *testing.T) {
	tests := []struct {
		name     string
		evtType  EventType
		severity Severity
	}{
		{"config applied info", EventType_EVENT_TYPE_CONFIG_APPLIED, Severity_SEVERITY_INFO},
		{"task failed error", EventType_EVENT_TYPE_TASK_FAILED, Severity_SEVERITY_ERROR},
		{"dna synced warning", EventType_EVENT_TYPE_DNA_SYNCED, Severity_SEVERITY_WARNING},
		{"error critical", EventType_EVENT_TYPE_ERROR, Severity_SEVERITY_CRITICAL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := &Event{
				Id:        "evt-001",
				Type:      tt.evtType,
				StewardId: "steward-1",
				Severity:  tt.severity,
				Timestamp: timestamppb.Now(),
			}
			assert.Equal(t, tt.evtType, evt.GetType())
			assert.Equal(t, tt.severity, evt.GetSeverity())
		})
	}
}

func TestEvent_ZeroValueDefaults(t *testing.T) {
	evt := &Event{}
	assert.Equal(t, EventType_EVENT_TYPE_UNSPECIFIED, evt.GetType())
	assert.Equal(t, Severity_SEVERITY_UNSPECIFIED, evt.GetSeverity())
}

func TestHeartbeat_Construction(t *testing.T) {
	tests := []struct {
		name   string
		status StewardStatus
	}{
		{"healthy steward", StewardStatus_STEWARD_STATUS_HEALTHY},
		{"degraded steward", StewardStatus_STEWARD_STATUS_DEGRADED},
		{"error steward", StewardStatus_STEWARD_STATUS_ERROR},
		{"disconnected steward", StewardStatus_STEWARD_STATUS_DISCONNECTED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hb := &Heartbeat{
				StewardId: "steward-1",
				TenantId:  "tenant-1",
				Status:    tt.status,
				Timestamp: timestamppb.Now(),
				Version:   "1.0.0",
			}
			assert.Equal(t, tt.status, hb.GetStatus())
		})
	}
}

func TestHeartbeat_ZeroValueDefault(t *testing.T) {
	hb := &Heartbeat{}
	assert.Equal(t, StewardStatus_STEWARD_STATUS_UNSPECIFIED, hb.GetStatus())
}

func TestControlMessage_OneofPayload(t *testing.T) {
	cmd := &Command{Id: "cmd-001", Type: CommandType_COMMAND_TYPE_SYNC_CONFIG}
	msg := &ControlMessage{
		Payload: &ControlMessage_Command{Command: cmd},
	}

	assert.NotNil(t, msg.GetCommand())
	assert.Equal(t, "cmd-001", msg.GetCommand().GetId())
	assert.Nil(t, msg.GetEvent())
	assert.Nil(t, msg.GetHeartbeat())
	assert.Nil(t, msg.GetResponse())

	evt := &Event{Id: "evt-001", Type: EventType_EVENT_TYPE_CONFIG_APPLIED}
	msgEvt := &ControlMessage{
		Payload: &ControlMessage_Event{Event: evt},
	}
	assert.Nil(t, msgEvt.GetCommand())
	assert.NotNil(t, msgEvt.GetEvent())
	assert.Equal(t, "evt-001", msgEvt.GetEvent().GetId())
}

func TestBulkChunk_TransferType(t *testing.T) {
	tests := []struct {
		name         string
		transferType TransferType
	}{
		{"package transfer", TransferType_TRANSFER_TYPE_PACKAGE},
		{"script transfer", TransferType_TRANSFER_TYPE_SCRIPT},
		{"log batch transfer", TransferType_TRANSFER_TYPE_LOG_BATCH},
		{"binary transfer", TransferType_TRANSFER_TYPE_BINARY},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunk := &BulkChunk{
				TransferId:   "xfer-001",
				TransferType: tt.transferType,
				Data:         []byte("payload"),
			}
			assert.Equal(t, tt.transferType, chunk.GetTransferType())
		})
	}
}

func TestBulkChunk_ZeroValueDefault(t *testing.T) {
	chunk := &BulkChunk{}
	assert.Equal(t, TransferType_TRANSFER_TYPE_UNSPECIFIED, chunk.GetTransferType())
}

func TestTaskMessage_Type(t *testing.T) {
	tests := []struct {
		name    string
		msgType TaskMessageType
	}{
		{"start task", TaskMessageType_TASK_MESSAGE_TYPE_START},
		{"progress update", TaskMessageType_TASK_MESSAGE_TYPE_PROGRESS},
		{"output chunk", TaskMessageType_TASK_MESSAGE_TYPE_OUTPUT},
		{"complete task", TaskMessageType_TASK_MESSAGE_TYPE_COMPLETE},
		{"cancel task", TaskMessageType_TASK_MESSAGE_TYPE_CANCEL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &TaskMessage{
				TaskId:    "task-001",
				Type:      tt.msgType,
				Timestamp: timestamppb.Now(),
			}
			assert.Equal(t, tt.msgType, msg.GetType())
		})
	}
}

func TestTaskMessage_ZeroValueDefault(t *testing.T) {
	msg := &TaskMessage{}
	assert.Equal(t, TaskMessageType_TASK_MESSAGE_TYPE_UNSPECIFIED, msg.GetType())
}

func TestLogEntry_Severity(t *testing.T) {
	// LogEntry.level reuses Severity from control.proto (same package)
	tests := []struct {
		name     string
		severity Severity
	}{
		{"info log", Severity_SEVERITY_INFO},
		{"warning log", Severity_SEVERITY_WARNING},
		{"error log", Severity_SEVERITY_ERROR},
		{"critical log", Severity_SEVERITY_CRITICAL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &LogEntry{
				StewardId: "steward-1",
				Level:     tt.severity,
				Message:   "test log message",
				Timestamp: timestamppb.Now(),
			}
			assert.Equal(t, tt.severity, entry.GetLevel())
		})
	}
}

func TestLogEntry_ZeroValueDefault(t *testing.T) {
	entry := &LogEntry{}
	assert.Equal(t, Severity_SEVERITY_UNSPECIFIED, entry.GetLevel())
}

func TestEnumStringValues(t *testing.T) {
	t.Run("CommandType string round-trips", func(t *testing.T) {
		assert.Equal(t, "COMMAND_TYPE_UNSPECIFIED", CommandType_COMMAND_TYPE_UNSPECIFIED.String())
		assert.Equal(t, "COMMAND_TYPE_SYNC_CONFIG", CommandType_COMMAND_TYPE_SYNC_CONFIG.String())
		assert.Equal(t, "COMMAND_TYPE_SHUTDOWN", CommandType_COMMAND_TYPE_SHUTDOWN.String())

		assert.Equal(t, int32(0), CommandType_value["COMMAND_TYPE_UNSPECIFIED"])
		assert.Equal(t, int32(1), CommandType_value["COMMAND_TYPE_SYNC_CONFIG"])
		assert.Equal(t, int32(5), CommandType_value["COMMAND_TYPE_SHUTDOWN"])
	})

	t.Run("EventType string round-trips", func(t *testing.T) {
		assert.Equal(t, "EVENT_TYPE_UNSPECIFIED", EventType_EVENT_TYPE_UNSPECIFIED.String())
		assert.Equal(t, "EVENT_TYPE_CONFIG_APPLIED", EventType_EVENT_TYPE_CONFIG_APPLIED.String())
		assert.Equal(t, "EVENT_TYPE_ERROR", EventType_EVENT_TYPE_ERROR.String())
	})

	t.Run("Severity string round-trips", func(t *testing.T) {
		assert.Equal(t, "SEVERITY_UNSPECIFIED", Severity_SEVERITY_UNSPECIFIED.String())
		assert.Equal(t, "SEVERITY_INFO", Severity_SEVERITY_INFO.String())
		assert.Equal(t, "SEVERITY_CRITICAL", Severity_SEVERITY_CRITICAL.String())
	})

	t.Run("StewardStatus string round-trips", func(t *testing.T) {
		assert.Equal(t, "STEWARD_STATUS_UNSPECIFIED", StewardStatus_STEWARD_STATUS_UNSPECIFIED.String())
		assert.Equal(t, "STEWARD_STATUS_HEALTHY", StewardStatus_STEWARD_STATUS_HEALTHY.String())
		assert.Equal(t, "STEWARD_STATUS_DISCONNECTED", StewardStatus_STEWARD_STATUS_DISCONNECTED.String())
	})

	t.Run("TransferType string round-trips", func(t *testing.T) {
		assert.Equal(t, "TRANSFER_TYPE_UNSPECIFIED", TransferType_TRANSFER_TYPE_UNSPECIFIED.String())
		assert.Equal(t, "TRANSFER_TYPE_PACKAGE", TransferType_TRANSFER_TYPE_PACKAGE.String())
		assert.Equal(t, "TRANSFER_TYPE_BINARY", TransferType_TRANSFER_TYPE_BINARY.String())
	})

	t.Run("TaskMessageType string round-trips", func(t *testing.T) {
		assert.Equal(t, "TASK_MESSAGE_TYPE_UNSPECIFIED", TaskMessageType_TASK_MESSAGE_TYPE_UNSPECIFIED.String())
		assert.Equal(t, "TASK_MESSAGE_TYPE_START", TaskMessageType_TASK_MESSAGE_TYPE_START.String())
		assert.Equal(t, "TASK_MESSAGE_TYPE_CANCEL", TaskMessageType_TASK_MESSAGE_TYPE_CANCEL.String())
	})
}
