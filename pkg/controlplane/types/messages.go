// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package types provides message types for the control plane communication layer.
//
// This package defines semantic message types for controller-steward communication,
// abstracting away transport-specific details (gRPC, WebSocket, etc.).
package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
)

// CommandType defines the type of command being sent.
type CommandType string

const (
	// CommandSyncConfig requests configuration synchronization via data plane
	CommandSyncConfig CommandType = "sync_config"

	// CommandSyncDNA requests DNA synchronization via data plane
	CommandSyncDNA CommandType = "sync_dna"
)

// Command represents a command sent from controller to steward.
//
// Commands are delivered via the control plane and typically trigger
// actions on the steward (execute task, sync config, etc.).
type Command struct {
	// ID is a unique identifier for this command
	ID string `json:"id"`

	// Type specifies what type of command this is
	Type CommandType `json:"type"`

	// StewardID identifies the target steward (empty for broadcasts)
	StewardID string `json:"steward_id,omitempty"`

	// TenantID identifies the tenant (for broadcast filtering)
	TenantID string `json:"tenant_id,omitempty"`

	// Timestamp when the command was created
	Timestamp time.Time `json:"timestamp"`

	// Params contains command-specific parameters
	Params map[string]interface{} `json:"params,omitempty"`
}

// EventType defines the type of event being reported.
type EventType string

const (
	// EventConfigApplied indicates configuration was successfully applied
	EventConfigApplied EventType = "config_applied"

	// EventDNASynced indicates DNA was successfully synchronized
	EventDNASynced EventType = "dna_synced"

	// EventTaskCompleted indicates a task completed successfully
	EventTaskCompleted EventType = "task_completed"

	// EventTaskFailed indicates a task failed
	EventTaskFailed EventType = "task_failed"

	// EventError indicates an error occurred
	EventError EventType = "error"

	// EventCommandReceived indicates command was received and processing started
	EventCommandReceived EventType = "command_received"

	// EventCommandCompleted indicates command completed successfully
	EventCommandCompleted EventType = "command_completed"

	// EventCommandFailed indicates command failed
	EventCommandFailed EventType = "command_failed"

	// EventDNAChanged indicates DNA attributes changed
	EventDNAChanged EventType = "dna_changed"
)

// Event represents an event published from steward to controller.
//
// Events notify the controller of steward state changes, command results,
// and other significant occurrences.
type Event struct {
	// ID is a unique identifier for this event
	ID string `json:"id"`

	// Type specifies what type of event this is
	Type EventType `json:"type"`

	// StewardID identifies which steward sent this event
	StewardID string `json:"steward_id"`

	// TenantID identifies the tenant
	TenantID string `json:"tenant_id,omitempty"`

	// Timestamp when the event was created
	Timestamp time.Time `json:"timestamp"`

	// CommandID references the command this event relates to (if applicable)
	CommandID string `json:"command_id,omitempty"`

	// Details contains event-specific information
	Details map[string]interface{} `json:"details,omitempty"`

	// Severity indicates event importance (info, warning, error)
	Severity string `json:"severity,omitempty"`
}

// HeartbeatStatus defines steward health status.
type HeartbeatStatus string

const (
	// StatusHealthy indicates steward is operating normally
	StatusHealthy HeartbeatStatus = "healthy"

	// StatusDegraded indicates steward is operational but with issues
	StatusDegraded HeartbeatStatus = "degraded"

	// StatusError indicates steward has errors but is still running
	StatusError HeartbeatStatus = "error"

	// StatusDisconnected indicates steward disconnected (sent via LWT)
	StatusDisconnected HeartbeatStatus = "disconnected"
)

// Heartbeat represents a periodic health check from steward to controller.
//
// Heartbeats allow the controller to monitor steward connectivity and health.
// If heartbeats stop, the controller can detect failures and take action.
type Heartbeat struct {
	// StewardID identifies which steward sent this heartbeat
	StewardID string `json:"steward_id"`

	// TenantID identifies the tenant
	TenantID string `json:"tenant_id,omitempty"`

	// Status indicates current health status
	Status HeartbeatStatus `json:"status"`

	// Timestamp when the heartbeat was created
	Timestamp time.Time `json:"timestamp"`

	// Metrics contains optional health metrics
	Metrics map[string]interface{} `json:"metrics,omitempty"`

	// Version is the steward software version
	Version string `json:"version,omitempty"`

	// DNAHash is a deterministic SHA-256 hash of the steward's current DNA attributes.
	// The controller uses this to detect drift without transmitting the full DNA dataset.
	// When the controller sees a hash it did not expect (e.g. after missed deltas) it
	// sends a CommandSyncDNA to request a full sync over the data plane.
	// Empty for older stewards that do not support hash-based sync.
	DNAHash string `json:"dna_hash,omitempty"`
}

// Response represents a command response/acknowledgment.
//
// Responses provide synchronous feedback about command acceptance/rejection.
// They are distinct from Events which provide asynchronous progress updates.
type Response struct {
	// CommandID references the command this responds to
	CommandID string `json:"command_id"`

	// StewardID identifies which steward sent this response
	StewardID string `json:"steward_id"`

	// Success indicates if the command was accepted
	Success bool `json:"success"`

	// Message provides human-readable response details
	Message string `json:"message,omitempty"`

	// Timestamp when the response was created
	Timestamp time.Time `json:"timestamp"`

	// Details contains response-specific data
	Details map[string]interface{} `json:"details,omitempty"`
}

// ModuleStatus represents the execution status of a single module.
//
// Used in ConfigStatusReport to provide per-module execution details
// after configuration application.
type ModuleStatus struct {
	// Name is the module name
	Name string `json:"name"`

	// Status indicates success/failure (OK, ERROR, WARNING)
	Status string `json:"status"`

	// Message contains human-readable status description
	Message string `json:"message"`

	// Timestamp when the module finished executing
	Timestamp time.Time `json:"timestamp"`

	// Details contains module-specific execution details
	Details map[string]interface{} `json:"details,omitempty"`
}

// ConfigStatusReport represents a detailed configuration status report from steward.
//
// This provides module-level execution details for MSP visibility,
// published as an Event via the control plane after configuration application.
type ConfigStatusReport struct {
	// StewardID identifies which steward sent this report
	StewardID string `json:"steward_id"`

	// ConfigVersion is the version of the configuration that was applied
	ConfigVersion string `json:"config_version"`

	// Status is the overall status (OK, ERROR, WARNING)
	Status string `json:"status"`

	// Message contains overall status message
	Message string `json:"message"`

	// Modules contains per-module execution status
	Modules map[string]ModuleStatus `json:"modules"`

	// Timestamp when the report was created
	Timestamp time.Time `json:"timestamp"`

	// ExecutionTimeMs is how long the configuration took to apply (milliseconds)
	ExecutionTimeMs int64 `json:"execution_time_ms,omitempty"`
}

// SignedCommand wraps a Command with a cryptographic signature for authenticated delivery.
//
// The Signature field contains the signature over CommandSigningBytes(Command, rawParams).
// The inner Command stays a pure value type; the wire envelope is SignedCommand.
// Verification happens in the steward handler before dispatch.
type SignedCommand struct {
	// Command is the inner command value.
	Command Command `json:"command"`

	// Signature is the cryptographic signature over CommandSigningBytes(Command, rawParams).
	// Nil when the controller is not configured with a signer (unsecured mode).
	Signature *signature.ConfigSignature `json:"signature,omitempty"`

	// RawParams holds the proto-wire string map of Command.Params, populated only
	// by the gRPC transport on receive. Used for signature verification to avoid
	// round-trip type mutations from stringMapToInterfaceMap.
	// Never transmitted on the wire or serialised to JSON.
	RawParams map[string]string `json:"-"`
}

// commandSigningPayload is the stable canonical form used when signing/verifying commands.
// Using map[string]string for Params avoids mutations from JSON-decoding proto string values,
// and UTC normalisation avoids timezone-dependent JSON output.
type commandSigningPayload struct {
	ID        string            `json:"id"`
	Type      CommandType       `json:"type"`
	StewardID string            `json:"steward_id,omitempty"`
	TenantID  string            `json:"tenant_id,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Params    map[string]string `json:"params,omitempty"`
}

// InterfaceParamsToStringMap converts map[string]interface{} command params to the
// proto-wire-stable map[string]string form. String values are stored as-is; other
// values are JSON-encoded to strings. This is identical to what the gRPC transport
// does in interfaceMapToStringMap, so signing with this form matches the wire form.
func InterfaceParamsToStringMap(m map[string]interface{}) map[string]string {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = s
		} else {
			data, err := json.Marshal(v)
			if err != nil {
				result[k] = fmt.Sprintf("%v", v)
			} else {
				result[k] = string(data)
			}
		}
	}
	return result
}

// CommandSigningBytes returns the canonical JSON bytes for signing or verifying a Command.
//
// rawParams must be the proto-wire string map of cmd.Params — either the map produced
// by the gRPC transport on receive (RawParams field of SignedCommand), or the result of
// InterfaceParamsToStringMap(cmd.Params) on the originating side. Using this canonical
// form ensures that both the signer (controller) and verifier (steward) produce identical
// bytes regardless of JSON-decode type coercions and timezone differences.
func CommandSigningBytes(cmd *Command, rawParams map[string]string) ([]byte, error) {
	payload := commandSigningPayload{
		ID:        cmd.ID,
		Type:      cmd.Type,
		StewardID: cmd.StewardID,
		TenantID:  cmd.TenantID,
		Timestamp: cmd.Timestamp.UTC(),
		Params:    rawParams,
	}
	return json.Marshal(payload)
}

// FanOutResult reports per-steward delivery status from a FanOutCommand.
type FanOutResult struct {
	// Succeeded contains steward IDs that received the command
	Succeeded []string

	// Failed maps steward IDs to their delivery errors
	Failed map[string]error
}

// EventFilter defines criteria for filtering events during subscription.
type EventFilter struct {
	// StewardIDs filters events to specific stewards (empty = all)
	StewardIDs []string

	// TenantIDs filters events to specific tenants (empty = all)
	TenantIDs []string

	// EventTypes filters to specific event types (empty = all)
	EventTypes []EventType

	// MinSeverity filters events below this severity
	MinSeverity string
}

// Match checks if an event matches this filter.
func (f *EventFilter) Match(event *Event) bool {
	// Check steward ID filter
	if len(f.StewardIDs) > 0 {
		matched := false
		for _, id := range f.StewardIDs {
			if id == event.StewardID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check tenant ID filter
	if len(f.TenantIDs) > 0 {
		matched := false
		for _, id := range f.TenantIDs {
			if id == event.TenantID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check event type filter
	if len(f.EventTypes) > 0 {
		matched := false
		for _, typ := range f.EventTypes {
			if typ == event.Type {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Severity filtering could be added here if needed

	return true
}
