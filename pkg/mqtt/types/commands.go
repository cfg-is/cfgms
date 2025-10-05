// Package types provides common MQTT message types for CFGMS communication.
//
// This package defines the message structures used for MQTT communication
// between controller and stewards (Story #198).
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
