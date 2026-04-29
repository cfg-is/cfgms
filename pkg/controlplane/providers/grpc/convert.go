// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"encoding/json"
	"fmt"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// sigParamKey is the reserved params key used to carry the signature through
// the existing proto Command.params wire field without requiring a proto change.
// Two leading underscores prevent collision with user-defined command params.
const sigParamKey = "__sig"

// --- Command conversion ---

// commandTypeToProto maps semantic CommandType to proto enum.
// The proto enum retains COMMAND_TYPE_CONNECT_DATAPLANE, COMMAND_TYPE_VALIDATE_CONFIG,
// COMMAND_TYPE_EXECUTE_TASK, and COMMAND_TYPE_SHUTDOWN for wire compatibility with older
// stewards. The corresponding Go constants were removed (Issue #831); unknown types received
// over the wire map to the zero value and are ignored by handlers.
var commandTypeToProto = map[types.CommandType]transportpb.CommandType{
	types.CommandSyncConfig: transportpb.CommandType_COMMAND_TYPE_SYNC_CONFIG,
	types.CommandSyncDNA:    transportpb.CommandType_COMMAND_TYPE_SYNC_DNA,
}

// protoToCommandType maps proto enum to semantic CommandType.
var protoToCommandType = map[transportpb.CommandType]types.CommandType{
	transportpb.CommandType_COMMAND_TYPE_SYNC_CONFIG: types.CommandSyncConfig,
	transportpb.CommandType_COMMAND_TYPE_SYNC_DNA:    types.CommandSyncDNA,
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
	}
	if len(pb.GetParams()) > 0 {
		cmd.Params = stringMapToInterfaceMap(pb.GetParams())
	}
	return cmd
}

// signedCommandToProto serialises a SignedCommand to the wire proto Command.
//
// The signature (when present) is JSON-encoded and embedded in the proto params
// map under sigParamKey so no proto schema change is required.
func signedCommandToProto(sc *types.SignedCommand) *transportpb.Command {
	if sc == nil {
		return nil
	}
	pb := commandToProto(&sc.Command)
	if pb == nil {
		return nil
	}
	if sc.Signature != nil {
		sigJSON, err := json.Marshal(sc.Signature)
		if err == nil {
			if pb.Params == nil {
				pb.Params = make(map[string]string)
			}
			pb.Params[sigParamKey] = string(sigJSON)
		}
	}
	return pb
}

// signedCommandFromProto reconstructs a SignedCommand from the wire proto Command.
//
// It extracts the signature from the reserved sigParamKey entry (if present)
// and strips that key from the params so it does not appear in Command.Params.
func signedCommandFromProto(pb *transportpb.Command) *types.SignedCommand {
	if pb == nil {
		return nil
	}

	var sig *signature.ConfigSignature
	filteredParams := make(map[string]string, len(pb.GetParams()))
	for k, v := range pb.GetParams() {
		if k == sigParamKey {
			var s signature.ConfigSignature
			if err := json.Unmarshal([]byte(v), &s); err == nil {
				sig = &s
			}
			continue
		}
		filteredParams[k] = v
	}

	// Rebuild the proto Command without the sig key so commandFromProto sees
	// only the real user params.
	pbClean := &transportpb.Command{
		Id:        pb.GetId(),
		Type:      pb.GetType(),
		StewardId: pb.GetStewardId(),
		TenantId:  pb.GetTenantId(),
		Timestamp: pb.GetTimestamp(),
		Params:    filteredParams,
	}
	cmd := commandFromProto(pbClean)
	if cmd == nil {
		return nil
	}
	sc := &types.SignedCommand{
		Command:   *cmd,
		Signature: sig,
	}
	// Preserve the proto-wire string map for signature verification. The handler
	// must verify against this form, not cmd.Params, because stringMapToInterfaceMap
	// JSON-decodes numeric-looking strings (e.g. "1.0" → float64) making the bytes
	// differ from what the controller signed.
	if len(filteredParams) > 0 {
		sc.RawParams = filteredParams
	}
	return sc
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
