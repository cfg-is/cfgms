// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"encoding/json"
	"fmt"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Command conversion ---

// commandTypeToProto maps semantic CommandType to proto enum.
var commandTypeToProto = map[types.CommandType]transportpb.CommandType{
	types.CommandSyncConfig:       transportpb.CommandType_COMMAND_TYPE_SYNC_CONFIG,
	types.CommandSyncDNA:          transportpb.CommandType_COMMAND_TYPE_SYNC_DNA,
	types.CommandConnectDataPlane: transportpb.CommandType_COMMAND_TYPE_CONNECT_DATAPLANE, //nolint:staticcheck // backward compat
	types.CommandValidateConfig:   transportpb.CommandType_COMMAND_TYPE_VALIDATE_CONFIG,
	types.CommandExecuteTask:      transportpb.CommandType_COMMAND_TYPE_EXECUTE_TASK,
	types.CommandShutdown:         transportpb.CommandType_COMMAND_TYPE_SHUTDOWN,
}

// protoToCommandType maps proto enum to semantic CommandType.
var protoToCommandType = map[transportpb.CommandType]types.CommandType{
	transportpb.CommandType_COMMAND_TYPE_SYNC_CONFIG:       types.CommandSyncConfig,
	transportpb.CommandType_COMMAND_TYPE_SYNC_DNA:          types.CommandSyncDNA,
	transportpb.CommandType_COMMAND_TYPE_CONNECT_DATAPLANE: types.CommandConnectDataPlane, //nolint:staticcheck // backward compat
	transportpb.CommandType_COMMAND_TYPE_VALIDATE_CONFIG:   types.CommandValidateConfig,
	transportpb.CommandType_COMMAND_TYPE_EXECUTE_TASK:      types.CommandExecuteTask,
	transportpb.CommandType_COMMAND_TYPE_SHUTDOWN:          types.CommandShutdown,
}

func commandToProto(cmd *types.Command) *transportpb.Command {
	if cmd == nil {
		return nil
	}
	pb := &transportpb.Command{
		Id:        cmd.ID,
		Type:      commandTypeToProto[cmd.Type],
		StewardId: cmd.StewardID,
		TenantId:  cmd.TenantID,
		Timestamp: timestamppb.New(cmd.Timestamp),
		Priority:  int32(cmd.Priority),
	}
	if len(cmd.Params) > 0 {
		pb.Params = interfaceMapToStringMap(cmd.Params)
	}
	return pb
}

func commandFromProto(pb *transportpb.Command) *types.Command {
	if pb == nil {
		return nil
	}
	cmd := &types.Command{
		ID:        pb.GetId(),
		Type:      protoToCommandType[pb.GetType()],
		StewardID: pb.GetStewardId(),
		TenantID:  pb.GetTenantId(),
		Timestamp: protoTimestampToTime(pb.GetTimestamp()),
		Priority:  int(pb.GetPriority()),
	}
	if len(pb.GetParams()) > 0 {
		cmd.Params = stringMapToInterfaceMap(pb.GetParams())
	}
	return cmd
}

// --- Event conversion ---

// eventTypeToProto maps semantic EventType to proto enum.
var eventTypeToProto = map[types.EventType]transportpb.EventType{
	types.EventConfigApplied: transportpb.EventType_EVENT_TYPE_CONFIG_APPLIED,
	types.EventDNASynced:     transportpb.EventType_EVENT_TYPE_DNA_SYNCED,
	types.EventTaskCompleted: transportpb.EventType_EVENT_TYPE_TASK_COMPLETED,
	types.EventTaskFailed:    transportpb.EventType_EVENT_TYPE_TASK_FAILED,
	types.EventError:         transportpb.EventType_EVENT_TYPE_ERROR,
}

// protoToEventType maps proto enum to semantic EventType.
var protoToEventType = map[transportpb.EventType]types.EventType{
	transportpb.EventType_EVENT_TYPE_CONFIG_APPLIED: types.EventConfigApplied,
	transportpb.EventType_EVENT_TYPE_DNA_SYNCED:     types.EventDNASynced,
	transportpb.EventType_EVENT_TYPE_TASK_COMPLETED: types.EventTaskCompleted,
	transportpb.EventType_EVENT_TYPE_TASK_FAILED:    types.EventTaskFailed,
	transportpb.EventType_EVENT_TYPE_ERROR:          types.EventError,
}

// severityToProto maps semantic severity string to proto enum.
var severityToProto = map[string]transportpb.Severity{
	"info":     transportpb.Severity_SEVERITY_INFO,
	"warning":  transportpb.Severity_SEVERITY_WARNING,
	"error":    transportpb.Severity_SEVERITY_ERROR,
	"critical": transportpb.Severity_SEVERITY_CRITICAL,
}

// protoToSeverity maps proto enum to semantic severity string.
var protoToSeverity = map[transportpb.Severity]string{
	transportpb.Severity_SEVERITY_INFO:     "info",
	transportpb.Severity_SEVERITY_WARNING:  "warning",
	transportpb.Severity_SEVERITY_ERROR:    "error",
	transportpb.Severity_SEVERITY_CRITICAL: "critical",
}

func eventToProto(event *types.Event) *transportpb.Event {
	if event == nil {
		return nil
	}
	pb := &transportpb.Event{
		Id:        event.ID,
		Type:      eventTypeToProto[event.Type],
		StewardId: event.StewardID,
		TenantId:  event.TenantID,
		Timestamp: timestamppb.New(event.Timestamp),
		CommandId: event.CommandID,
		Severity:  severityToProto[event.Severity],
	}
	if len(event.Details) > 0 {
		pb.Details = interfaceMapToStringMap(event.Details)
	}
	return pb
}

func eventFromProto(pb *transportpb.Event) *types.Event {
	if pb == nil {
		return nil
	}
	event := &types.Event{
		ID:        pb.GetId(),
		Type:      protoToEventType[pb.GetType()],
		StewardID: pb.GetStewardId(),
		TenantID:  pb.GetTenantId(),
		Timestamp: protoTimestampToTime(pb.GetTimestamp()),
		CommandID: pb.GetCommandId(),
		Severity:  protoToSeverity[pb.GetSeverity()],
	}
	if len(pb.GetDetails()) > 0 {
		event.Details = stringMapToInterfaceMap(pb.GetDetails())
	}
	return event
}

// --- Heartbeat conversion ---

// heartbeatStatusToProto maps semantic HeartbeatStatus to proto enum.
var heartbeatStatusToProto = map[types.HeartbeatStatus]transportpb.StewardStatus{
	types.StatusHealthy:      transportpb.StewardStatus_STEWARD_STATUS_HEALTHY,
	types.StatusDegraded:     transportpb.StewardStatus_STEWARD_STATUS_DEGRADED,
	types.StatusError:        transportpb.StewardStatus_STEWARD_STATUS_ERROR,
	types.StatusDisconnected: transportpb.StewardStatus_STEWARD_STATUS_DISCONNECTED,
}

// protoToHeartbeatStatus maps proto enum to semantic HeartbeatStatus.
var protoToHeartbeatStatus = map[transportpb.StewardStatus]types.HeartbeatStatus{
	transportpb.StewardStatus_STEWARD_STATUS_HEALTHY:      types.StatusHealthy,
	transportpb.StewardStatus_STEWARD_STATUS_DEGRADED:     types.StatusDegraded,
	transportpb.StewardStatus_STEWARD_STATUS_ERROR:        types.StatusError,
	transportpb.StewardStatus_STEWARD_STATUS_DISCONNECTED: types.StatusDisconnected,
}

func heartbeatToProto(hb *types.Heartbeat) *transportpb.Heartbeat {
	if hb == nil {
		return nil
	}
	pb := &transportpb.Heartbeat{
		StewardId: hb.StewardID,
		TenantId:  hb.TenantID,
		Status:    heartbeatStatusToProto[hb.Status],
		Timestamp: timestamppb.New(hb.Timestamp),
		Version:   hb.Version,
	}
	if len(hb.Metrics) > 0 {
		pb.Metrics = interfaceMapToStringMap(hb.Metrics)
	}
	return pb
}

func heartbeatFromProto(pb *transportpb.Heartbeat) *types.Heartbeat {
	if pb == nil {
		return nil
	}
	hb := &types.Heartbeat{
		StewardID: pb.GetStewardId(),
		TenantID:  pb.GetTenantId(),
		Status:    protoToHeartbeatStatus[pb.GetStatus()],
		Timestamp: protoTimestampToTime(pb.GetTimestamp()),
		Version:   pb.GetVersion(),
	}
	if len(pb.GetMetrics()) > 0 {
		hb.Metrics = stringMapToInterfaceMap(pb.GetMetrics())
	}
	return hb
}

// --- Response conversion ---

func responseToProto(resp *types.Response) *transportpb.Response {
	if resp == nil {
		return nil
	}
	pb := &transportpb.Response{
		CommandId: resp.CommandID,
		StewardId: resp.StewardID,
		Success:   resp.Success,
		Message:   resp.Message,
		Timestamp: timestamppb.New(resp.Timestamp),
	}
	if len(resp.Details) > 0 {
		pb.Details = interfaceMapToStringMap(resp.Details)
	}
	return pb
}

func responseFromProto(pb *transportpb.Response) *types.Response {
	if pb == nil {
		return nil
	}
	resp := &types.Response{
		CommandID: pb.GetCommandId(),
		StewardID: pb.GetStewardId(),
		Success:   pb.GetSuccess(),
		Message:   pb.GetMessage(),
		Timestamp: protoTimestampToTime(pb.GetTimestamp()),
	}
	if len(pb.GetDetails()) > 0 {
		resp.Details = stringMapToInterfaceMap(pb.GetDetails())
	}
	return resp
}

// --- Map conversion helpers ---

// interfaceMapToStringMap converts map[string]interface{} to map[string]string.
// String values are kept as-is; non-string values are JSON-serialized.
func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			result[k] = val
		default:
			data, err := json.Marshal(val)
			if err != nil {
				result[k] = fmt.Sprintf("%v", val)
			} else {
				result[k] = string(data)
			}
		}
	}
	return result
}

// stringMapToInterfaceMap converts map[string]string to map[string]interface{}.
// Values that are valid JSON are deserialized; plain strings are kept as-is.
func stringMapToInterfaceMap(m map[string]string) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		var parsed interface{}
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			// Only use parsed value if it's not a plain string (avoids
			// double-wrapping strings that happen to be valid JSON like "true").
			if _, isString := parsed.(string); !isString {
				result[k] = parsed
				continue
			}
		}
		result[k] = v
	}
	return result
}

// --- Timestamp helpers ---

func protoTimestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
