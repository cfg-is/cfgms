// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules

import (
	"context"
)

// Module defines the core interface that all modules must implement.
//
// # ADR-016 Clause 4 — Canonical DNA Fragment Contract
//
// Every implementation of Get must return, for each resource it manages, a
// canonical, deterministically-serialisable DNA fragment. Concretely:
//
//   - ConfigState.AsMap() must produce byte-for-byte identical output on every
//     call against the same unchanged resource state. Implementations must not
//     rely on map-iteration order; callers use canonical encoding (e.g. JSON
//     with sorted keys) when comparing or hashing the result.
//   - Only stable desired-comparable fields are included. Ephemeral runtime
//     values must be omitted: live PIDs, current CPU/memory statistics,
//     timestamps, uptime counters, or any value that changes under the OS
//     without a cfg-driven configuration change.
//
// Use features/modules/conformance.AssertDeterministicGet and
// AssertNoEphemeralFields in a module's own test file to verify compliance.
type Module interface {
	// Get returns the current configuration of a resource.
	//
	// The returned ConfigState must satisfy the ADR-016 clause 4 canonical
	// fragment contract: deterministic AsMap() output, no ephemeral fields.
	Get(ctx context.Context, resourceID string) (ConfigState, error)

	// Set updates the resource configuration to match the desired state.
	Set(ctx context.Context, resourceID string, config ConfigState) error
}

// ConfigState defines the interface that all module configuration states must implement.
//
// # ADR-016 Clause 4 — Canonical Serialisation Requirements
//
// Implementations returned by Module.Get must produce deterministic output:
//   - AsMap() returns a stable map with no ephemeral keys; the same resource
//     state always produces the same key set and values across calls.
//   - ToYAML() serialises from the struct state; callers must not rely on key
//     ordering in the YAML output — use AsMap() for comparison operations.
type ConfigState interface {
	// AsMap returns the configuration as a map for efficient field-by-field comparison.
	// All keys and values must be stable across calls on the same resource state
	// (ADR-016 clause 4).
	AsMap() map[string]interface{}

	// ToYAML serializes the configuration to YAML for export/storage.
	ToYAML() ([]byte, error)

	// FromYAML deserializes YAML data into the configuration.
	FromYAML([]byte) error

	// Validate ensures the configuration is valid.
	Validate() error

	// GetManagedFields returns the list of fields this configuration manages.
	GetManagedFields() []string
}

// Configurable is implemented by modules that require initialization from
// operator config before Get() can safely read the current resource state.
// The execution engine calls Configure(desiredState) before Get() when the
// module implements this interface, allowing security boundaries to be
// established without modifying any files.
type Configurable interface {
	Configure(config ConfigState) error
}

// Monitor interface for modules that support real-time monitoring (optional)
type Monitor interface {
	// Monitor watches for changes to a resource and triggers events
	Monitor(ctx context.Context, resourceID string, config ConfigState) error

	// Changes returns a channel for receiving change notifications
	Changes() <-chan ChangeEvent

	// Close stops monitoring and releases resources
	Close() error
}

// ChangeEvent represents a configuration change event
type ChangeEvent struct {
	ResourceID string
	Timestamp  int64
	ChangeType ChangeType
	Details    ConfigState
}

// ChangeType represents the type of change that occurred
type ChangeType int

const (
	ChangeTypeCreated ChangeType = iota
	ChangeTypeModified
	ChangeTypeDeleted
	ChangeTypePermissions
)
