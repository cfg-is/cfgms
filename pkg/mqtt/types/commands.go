// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package types provides common MQTT message types for CFGMS communication.
//
// Deprecated: Use pkg/controlplane/types instead. This package contains
// transport-specific types that have been superseded by the transport-agnostic
// control plane types (Story #267.5). The controlplane types support multiple
// transport implementations (MQTT, gRPC, WebSocket).
package types

import "time"

// CommandType defines the type of command being sent to a steward.
type CommandType string

const (
	// CommandSyncConfig requests configuration synchronization via QUIC
	CommandSyncConfig CommandType = "sync_config"

	// CommandSyncDNA requests DNA synchronization via QUIC
	CommandSyncDNA CommandType = "sync_dna"

	// CommandConnectQUIC requests QUIC connection establishment
	CommandConnectQUIC CommandType = "connect_quic"

	// CommandValidateConfig requests configuration validation (dry-run)
	CommandValidateConfig CommandType = "validate_config"

	// CommandExecuteTask requests execution of a specific task
	CommandExecuteTask CommandType = "execute_task"

	// CommandShutdown requests graceful shutdown
	CommandShutdown CommandType = "shutdown"
)

// Command represents a command sent from controller to steward.
type Command struct {
	// CommandID is a unique identifier for this command
	CommandID string `json:"command_id"`

	// Type specifies what type of command this is
	Type CommandType `json:"type"`

	// Timestamp when the command was created
	Timestamp time.Time `json:"timestamp"`

	// Params contains command-specific parameters
	Params map[string]interface{} `json:"params,omitempty"`
}

// StatusEvent defines types of status events from steward to controller.
type StatusEvent string

const (
	// EventConfigApplied indicates configuration was successfully applied
	EventConfigApplied StatusEvent = "config_applied"

	// EventDNASynced indicates DNA was successfully synchronized
	EventDNASynced StatusEvent = "dna_synced"

	// EventTaskCompleted indicates a task completed successfully
	EventTaskCompleted StatusEvent = "task_completed"

	// EventError indicates an error occurred
	EventError StatusEvent = "error"

	// EventCommandReceived indicates command was received and processing started
	EventCommandReceived StatusEvent = "command_received"

	// EventCommandCompleted indicates command completed successfully
	EventCommandCompleted StatusEvent = "command_completed"

	// EventCommandFailed indicates command failed
	EventCommandFailed StatusEvent = "command_failed"
)

// StatusUpdate represents a status update sent from steward to controller.
type StatusUpdate struct {
	// StewardID identifies which steward sent this status
	StewardID string `json:"steward_id"`

	// Timestamp when the status update was created
	Timestamp time.Time `json:"timestamp"`

	// Event type that occurred
	Event StatusEvent `json:"event"`

	// CommandID references the command this status relates to (if applicable)
	CommandID string `json:"command_id,omitempty"`

	// Details contains event-specific information
	Details map[string]interface{} `json:"details,omitempty"`
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

	// StatusDisconnected indicates steward disconnected (LWT)
	StatusDisconnected HeartbeatStatus = "disconnected"
)

// Heartbeat represents a heartbeat message from steward to controller.
type Heartbeat struct {
	// StewardID identifies which steward sent this heartbeat
	StewardID string `json:"steward_id"`

	// Status indicates current health status
	Status HeartbeatStatus `json:"status"`

	// Timestamp when the heartbeat was created
	Timestamp time.Time `json:"timestamp"`

	// Metrics contains optional health metrics
	Metrics map[string]string `json:"metrics,omitempty"`
}

// DNAUpdate represents a DNA update message from steward to controller.
// This is published by steward when DNA changes (e.g., hardware change, software install).
type DNAUpdate struct {
	// StewardID identifies which steward sent this update
	StewardID string `json:"steward_id"`

	// Timestamp when the DNA update was created
	Timestamp time.Time `json:"timestamp"`

	// DNA contains the updated DNA attributes
	DNA map[string]string `json:"dna"`

	// ConfigHash is the hash of the current configuration
	ConfigHash string `json:"config_hash,omitempty"`

	// SyncFingerprint is a combined hash of all sync-relevant data
	SyncFingerprint string `json:"sync_fingerprint,omitempty"`
}

// ModuleStatus represents the execution status of a single module.
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
// This provides module-level execution details for MSP visibility.
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

	// ExecutionTime is how long the configuration took to apply (milliseconds)
	ExecutionTimeMs int64 `json:"execution_time_ms,omitempty"`
}

// ValidationRequest represents a configuration validation request.
// Sent by steward to controller for pre-flight validation.
type ValidationRequest struct {
	// RequestID is a unique identifier for this validation request
	RequestID string `json:"request_id"`

	// StewardID identifies the requesting steward
	StewardID string `json:"steward_id"`

	// Config is the configuration to validate (JSON-encoded)
	Config []byte `json:"config"`

	// Version is the configuration version
	Version string `json:"version"`

	// Timestamp when the request was created
	Timestamp time.Time `json:"timestamp"`
}

// ValidationResponse represents a configuration validation response.
// Sent by controller to steward with validation results.
type ValidationResponse struct {
	// RequestID matches the ValidationRequest.RequestID
	RequestID string `json:"request_id"`

	// Valid indicates if the configuration passed validation
	Valid bool `json:"valid"`

	// Errors contains validation error messages
	Errors []string `json:"errors,omitempty"`

	// Timestamp when the response was created
	Timestamp time.Time `json:"timestamp"`
}
