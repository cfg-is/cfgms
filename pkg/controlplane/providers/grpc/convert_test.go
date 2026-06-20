// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"encoding/base64"
	"testing"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
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
					"version": "1.2.3",
					"nested":  map[string]interface{}{"key": "val"},
				},
			},
		},
		{
			name: "minimal command",
			cmd: &types.Command{
				ID:        "cmd-456",
				Type:      types.CommandSyncDNA,
				Timestamp: now,
			},
		},
		{
			name: "nil params",
			cmd: &types.Command{
				ID:        "cmd-789",
				Type:      types.CommandSyncConfig,
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

// allCommandTypes enumerates every types.Command* constant that must survive
// the proto round-trip. Add new constants here as they are defined in
// pkg/controlplane/types/messages.go. The guard test below asserts this list
// stays in sync with commandTypeToProto (Issue #1994).
var allCommandTypes = []types.CommandType{
	types.CommandSyncConfig,
	types.CommandSyncDNA,
	types.CommandReconnect,
	types.CommandExecuteScript,
	types.CommandRelayResponse,
	types.CommandPushSigningCert,
	types.CommandPushStewardBinary,
}

func TestCommandTypeRoundTrip(t *testing.T) {
	// Every command type the controller can dispatch must survive the
	// semantic→proto→semantic round-trip. A type missing from either map
	// serialises to the zero enum value, which mutates the signed Type field
	// and makes steward-side signature verification fail (Issue #1943/#1948).
	for _, ct := range allCommandTypes {
		t.Run(string(ct), func(t *testing.T) {
			pb, ok := commandTypeToProto[ct]
			require.True(t, ok, "command type %q missing from commandTypeToProto", ct)
			require.NotEqual(t, transportpb.CommandType_COMMAND_TYPE_UNSPECIFIED, pb,
				"command type %q maps to the zero enum value", ct)
			result := protoToCommandType[pb]
			assert.Equal(t, ct, result)
		})
	}
}

// TestCommandTypeConvertMapsComplete guards against the class of omission from
// Issue #1992 and #1994: a Command* constant is added to messages.go but never
// added to the convert maps, causing silent Type-collapse to UNSPECIFIED on the
// wire. The slice length pin fails the test at compile-time if allCommandTypes
// and commandTypeToProto diverge.
func TestCommandTypeConvertMapsComplete(t *testing.T) {
	require.Len(t, allCommandTypes, len(commandTypeToProto),
		"allCommandTypes is out of sync with commandTypeToProto — "+
			"add the new Command* constant to both the slice and the convert maps")

	for _, ct := range allCommandTypes {
		_, inToProto := commandTypeToProto[ct]
		assert.True(t, inToProto, "command type %q missing from commandTypeToProto", ct)

		pbVal := commandTypeToProto[ct]
		_, inFromProto := protoToCommandType[pbVal]
		assert.True(t, inFromProto, "proto value for command type %q missing from protoToCommandType", ct)
	}
}

// TestCommandTypeProtoDescriptorComplete verifies that the embedded proto file
// descriptor (rawDesc) carries every CommandType enum value, so String(),
// gRPC reflection, and protojson render the symbolic name rather than the bare
// integer. Before the proto regen for Issue #1992, the hand-added values
// (7/8/9/10) were present only as Go constants and name/value maps — the
// descriptor blob still lacked them, so CommandType(8).String() rendered "8".
func TestCommandTypeProtoDescriptorComplete(t *testing.T) {
	cases := map[transportpb.CommandType]string{
		transportpb.CommandType_COMMAND_TYPE_RECONNECT:           "COMMAND_TYPE_RECONNECT",
		transportpb.CommandType_COMMAND_TYPE_EXECUTE_SCRIPT:      "COMMAND_TYPE_EXECUTE_SCRIPT",
		transportpb.CommandType_COMMAND_TYPE_PUSH_SIGNING_CERT:   "COMMAND_TYPE_PUSH_SIGNING_CERT",
		transportpb.CommandType_COMMAND_TYPE_PUSH_STEWARD_BINARY: "COMMAND_TYPE_PUSH_STEWARD_BINARY",
		transportpb.CommandType_COMMAND_TYPE_RELAY_RESPONSE:      "COMMAND_TYPE_RELAY_RESPONSE",
	}
	for ct, name := range cases {
		t.Run(name, func(t *testing.T) {
			// String() resolves through the descriptor; a missing descriptor value
			// would yield the decimal number instead of the symbolic name.
			assert.Equal(t, name, ct.String())
			// The descriptor must expose the value by number.
			vd := ct.Descriptor().Values().ByNumber(ct.Number())
			require.NotNil(t, vd, "enum value %d missing from proto descriptor", ct)
			assert.Equal(t, name, string(vd.Name()))
		})
	}
}

// newTestSigner returns a real Signer + Verifier pair backed by a fresh
// in-process CA. No mocks — real cryptographic operations.
func newTestSigner(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "controller.test",
		DNSNames:     []string{"controller.test"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  sc.PrivateKeyPEM,
		CertificatePEM: sc.CertificatePEM,
	})
	require.NoError(t, err)

	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: sc.CertificatePEM,
	})
	require.NoError(t, err)

	return signer, verifier
}

// TestExecuteScriptSignedRoundTrip is the end-to-end regression for Issue #1992.
//
// The controller signs CommandSigningBytes over the execute_script command, the
// signed command is serialised to the wire proto, then reconstructed on the steward
// side. Before the fix, CommandExecuteScript was absent from both command-type
// conversion maps, so the proto Type collapsed to COMMAND_TYPE_UNSPECIFIED and the
// reconstructed Command.Type became "" — making the signing bytes (which include
// Type) differ and the steward-side signature verification fail.
//
// This test proves byte-for-byte signing-payload equality across the wire and that
// the real verifier accepts the reconstructed command.
func TestExecuteScriptSignedRoundTrip(t *testing.T) {
	signer, verifier := newTestSigner(t)

	cmd := &types.Command{
		ID:        "cmd-exec-1",
		Type:      types.CommandExecuteScript,
		StewardID: "steward-7",
		TenantID:  "root/msp-a/client-1",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Params: map[string]interface{}{
			"script_content": base64.StdEncoding.EncodeToString([]byte("Write-Output 'hello'")),
			"execution_id":   "exec-abc-123",
			"shell":          "powershell",
			"run_id":         "run-42",
		},
	}

	// Controller side: sign the canonical bytes using the proto-wire-stable param map.
	rawParams := types.InterfaceParamsToStringMap(cmd.Params)
	signingBytes, err := types.CommandSigningBytes(cmd, rawParams)
	require.NoError(t, err)
	sig, err := signer.Sign(signingBytes)
	require.NoError(t, err)

	sc := &types.SignedCommand{Command: *cmd, Signature: sig}

	// Serialise to the wire proto and reconstruct on the steward side.
	pb := signedCommandToProto(sc)
	require.NotNil(t, pb)
	require.Equal(t, transportpb.CommandType_COMMAND_TYPE_EXECUTE_SCRIPT, pb.GetType(),
		"execute_script must not collapse to UNSPECIFIED on the wire")

	reconstructed := signedCommandFromProto(pb)
	require.NotNil(t, reconstructed)
	require.NotNil(t, reconstructed.Signature)

	// The Type must survive the round-trip — this is the field whose collapse
	// broke the signature in Issue #1992.
	require.Equal(t, types.CommandExecuteScript, reconstructed.Command.Type)

	// The signing bytes computed from the reconstructed command must equal the
	// original signing bytes byte-for-byte.
	reconstructedBytes, err := types.CommandSigningBytes(&reconstructed.Command, reconstructed.RawParams)
	require.NoError(t, err)
	assert.Equal(t, signingBytes, reconstructedBytes,
		"signing payload must be identical across the wire")

	// And the real verifier must accept the reconstructed command's signature.
	require.NoError(t, verifier.Verify(reconstructedBytes, reconstructed.Signature),
		"steward-side verification must succeed after the round-trip")
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

// wireCrossingEventTypes lists every types.Event* constant that is published over
// the control plane (steward->controller) and therefore must survive the proto
// codec with its Type preserved. Each entry was confirmed against a real emit site
// (steward) and/or a type-routed handler (controller):
//
//   - EventConfigApplied, EventDNASynced, EventTaskCompleted, EventTaskFailed,
//     EventError                                  — pre-existing config/task/error reporting
//   - EventCommandReceived/Completed/Failed       — command lifecycle (Issue #1948)
//   - EventScriptCompleted                        — execute_script.go:212; dispatcher.go:158 (Issue #1997)
//   - EventDNAChanged                             — client_transport.go:991; server.go:1810
//   - EventRelayRequest                           — script_relay/relay.go:188; api/relay_handler.go:79
//   - EventStewardUpgradeDownloaded/Swapped/Committed/RolledBack
//     — client_transport_upgrade.go / PublishUpgradeLifecycleEvent
//
// Deliberately EXCLUDED:
//   - EventStewardUpgradeDispatched — documented as a controller-side label, but it
//     has no emit site (never passed to PublishEvent/publishEventWithQueue) and is
//     never serialized over the transport, so it needs no proto enum. If a controller
//     ever publishes it over the wire, add it here and to the proto enum.
var wireCrossingEventTypes = []types.EventType{
	types.EventConfigApplied,
	types.EventDNASynced,
	types.EventTaskCompleted,
	types.EventTaskFailed,
	types.EventError,
	types.EventCommandReceived,
	types.EventCommandCompleted,
	types.EventCommandFailed,
	types.EventScriptCompleted,
	types.EventDNAChanged,
	types.EventRelayRequest,
	types.EventStewardUpgradeDownloaded,
	types.EventStewardUpgradeSwapped,
	types.EventStewardUpgradeCommitted,
	types.EventStewardUpgradeRolledBack,
}

func TestEventTypeRoundTrip(t *testing.T) {
	// Every wire-crossing event type must survive the semantic→proto→semantic
	// round-trip. A type missing from either map serialises to the zero enum
	// value, decodes to "" on the far side, and type-routed handlers never fire —
	// e.g. the dispatcher's script_completed filter, leaving `cfg steward exec`
	// runs stuck 0/1 (Issue #1997; same class as #1948).
	//
	// Guard against drift: if a new event type is added to the convert maps but
	// not to wireCrossingEventTypes, this list would silently stop being
	// exhaustive. Pin the slice length to the map size so the omission fails here.
	require.Len(t, wireCrossingEventTypes, len(eventTypeToProto),
		"wireCrossingEventTypes is out of sync with eventTypeToProto — add the new type to the slice")
	for _, et := range wireCrossingEventTypes {
		t.Run(string(et), func(t *testing.T) {
			pb, ok := eventTypeToProto[et]
			require.True(t, ok, "event type %q missing from eventTypeToProto", et)
			require.NotEqual(t, transportpb.EventType_EVENT_TYPE_UNSPECIFIED, pb,
				"event type %q maps to the zero enum value", et)
			result := protoToEventType[pb]
			assert.Equal(t, et, result)
		})
	}
}

// TestEventFullRoundTrip exercises the actual codec path (eventToProto ->
// eventFromProto) for every wire-crossing event type and asserts the Type is
// preserved. This is the guard that would have caught Issue #1997: building an
// Event{Type: EventScriptCompleted} and running it through the real conversion
// functions, rather than injecting it directly into a handler.
func TestEventFullRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond)
	for _, et := range wireCrossingEventTypes {
		t.Run(string(et), func(t *testing.T) {
			ev := &types.Event{
				ID:        "evt-" + string(et),
				Type:      et,
				StewardID: "steward-1",
				TenantID:  "root/msp-a/client-1",
				Timestamp: now,
				CommandID: "cmd-1",
				Severity:  "info",
			}
			pb := eventToProto(ev)
			require.NotNil(t, pb)
			require.NotEqual(t, transportpb.EventType_EVENT_TYPE_UNSPECIFIED, pb.GetType(),
				"event type %q collapsed to UNSPECIFIED on the wire", et)

			result := eventFromProto(pb)
			require.NotNil(t, result)
			assert.Equal(t, et, result.Type,
				"event type %q did not survive eventToProto->eventFromProto", et)
		})
	}
}

// TestEventTypeProtoDescriptorComplete verifies the embedded proto file
// descriptor (rawDesc) carries the EventType enum values added for Issue #1997,
// so String(), gRPC reflection, and protojson render the symbolic name rather
// than the bare integer.
func TestEventTypeProtoDescriptorComplete(t *testing.T) {
	cases := map[transportpb.EventType]string{
		transportpb.EventType_EVENT_TYPE_SCRIPT_COMPLETED:    "EVENT_TYPE_SCRIPT_COMPLETED",
		transportpb.EventType_EVENT_TYPE_DNA_CHANGED:         "EVENT_TYPE_DNA_CHANGED",
		transportpb.EventType_EVENT_TYPE_RELAY_REQUEST:       "EVENT_TYPE_RELAY_REQUEST",
		transportpb.EventType_EVENT_TYPE_UPGRADE_DOWNLOADED:  "EVENT_TYPE_UPGRADE_DOWNLOADED",
		transportpb.EventType_EVENT_TYPE_UPGRADE_SWAPPED:     "EVENT_TYPE_UPGRADE_SWAPPED",
		transportpb.EventType_EVENT_TYPE_UPGRADE_COMMITTED:   "EVENT_TYPE_UPGRADE_COMMITTED",
		transportpb.EventType_EVENT_TYPE_UPGRADE_ROLLED_BACK: "EVENT_TYPE_UPGRADE_ROLLED_BACK",
	}
	for et, name := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, name, et.String())
			vd := et.Descriptor().Values().ByNumber(et.Number())
			require.NotNil(t, vd, "enum value %d missing from proto descriptor", et)
			assert.Equal(t, name, string(vd.Name()))
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
		{
			name: "with active_sessions and connection_state",
			hb: &types.Heartbeat{
				StewardID:       "steward-3",
				Status:          types.StatusHealthy,
				Timestamp:       now,
				Version:         "3.0.0",
				ActiveSessions:  1,
				ConnectionState: "connected",
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
			assert.Equal(t, tt.hb.ActiveSessions, result.ActiveSessions)
			assert.Equal(t, tt.hb.ConnectionState, result.ConnectionState)

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
