// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules

import (
	"context"
	"errors"
	"fmt"
	"time"
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

// ManagedElsewhere, when implemented by a ConfigState returned from Module.Get,
// tells the executor the resource is real and in its desired terminal state but
// managed by a DIFFERENT authority — e.g. a clustered HA VM owned by another
// failover-cluster node. The executor treats such a resource as compliant and
// performs no Compare/Set/Verify: field-level drift against THIS node's local
// view is not meaningful, because this node is not the resource's manager. The
// single accountable authority (the cluster's CNO for HA VMs) is responsible for
// the resource actually existing and having an owner — a non-owner only abstains
// (Story #2577).
type ManagedElsewhere interface {
	// ManagedElsewhere reports whether the resource is managed by another
	// authority and, if so, names it (the owning node/authority — used for logs
	// and DNA provenance). A false return means "this node IS the manager; apply
	// the normal Compare/Set/Verify flow."
	ManagedElsewhere() (managed bool, authority string)
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

// RebootDeferredError is returned by a module's Set when a reboot-gated action falls
// outside its reboot_window. The executor recognizes this error with errors.As and
// classifies the result as StatusDeferred, populating DeferredUntil from NextWindow.
//
// Use NewRebootDeferredError to construct and errors.As to extract:
//
//	var re *modules.RebootDeferredError
//	if errors.As(err, &re) {
//	    deferredUntil = re.NextWindow
//	}
type RebootDeferredError struct {
	// NextWindow is the next instant at which the reboot-gated action may proceed.
	// Zero means no upcoming window is known (ungated or schedule not yet computed).
	NextWindow time.Time
}

// Error implements the error interface.
func (e *RebootDeferredError) Error() string {
	if e.NextWindow.IsZero() {
		return "reboot deferred: no upcoming window scheduled"
	}
	return fmt.Sprintf("reboot deferred: next window opens at %s", e.NextWindow.Format(time.RFC3339))
}

// ErrRebootDeferred is a package-level sentinel for reboot deferral detection via errors.Is.
// Prefer errors.As when the next-window time is needed.
var ErrRebootDeferred = errors.New("reboot deferred outside reboot_window")

// NewRebootDeferredError constructs a RebootDeferredError with the given next window time.
// Pass a zero time.Time when the next window is not yet known.
func NewRebootDeferredError(nextWindow time.Time) *RebootDeferredError {
	return &RebootDeferredError{NextWindow: nextWindow}
}

// Is implements errors.Is support so that errors.Is(err, ErrRebootDeferred) returns true
// for any *RebootDeferredError, regardless of the wrapped NextWindow value.
func (e *RebootDeferredError) Is(target error) bool {
	return target == ErrRebootDeferred
}
