// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package types provides message types for the control plane communication layer.
//
// This package defines semantic message types for controller-steward communication,
// abstracting away transport-specific details (MQTT, gRPC, etc.).
package types

import (
	"time"
)

// CommandType defines the type of command being sent.
type CommandType string

const (
	// CommandSyncConfig requests configuration synchronization via data plane
	CommandSyncConfig CommandType = "sync_config"

	// CommandSyncDNA requests DNA synchronization via data plane
	CommandSyncDNA CommandType = "sync_dna"

	// CommandConnectDataPlane requests data plane connection establishment
	CommandConnectDataPlane CommandType = "connect_dataplane"

	// CommandValidateConfig requests configuration validation (dry-run)
	CommandValidateConfig CommandType = "validate_config"

	// CommandExecuteTask requests execution of a specific task
	CommandExecuteTask CommandType = "execute_task"

	// CommandShutdown requests graceful shutdown
	CommandShutdown CommandType = "shutdown"
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

	// Priority allows prioritization (0 = normal, higher = more urgent)
	Priority int `json:"priority,omitempty"`
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
