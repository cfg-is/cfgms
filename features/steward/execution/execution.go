// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package execution provides resource configuration orchestration for steward.
//
// This package implements the execution engine that orchestrates the complete
// Get→Compare→Set→Verify workflow for configuration management. It coordinates
// between modules, handles error policies, and provides detailed reporting.
//
// The execution engine follows this workflow for each resource:
//  1. Load the required module from the factory
//  2. Get the current state using module.Get()
//  3. Compare current vs desired state (drift detection)
//  4. If drift detected, apply changes using module.Set()
//  5. Verify changes by calling module.Get() again
//  6. Generate detailed execution report
//
// Basic usage:
//
//	// Create executor
//	executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logger})
//
//	// Execute complete configuration
//	report := executor.ExecuteConfiguration(ctx, stewardConfig)
//
//	// Check results
//	log.Printf("Executed %d resources: %d successful, %d failed, %d skipped",
//		report.TotalResources, report.SuccessfulCount,
//		report.FailedCount, report.SkippedCount)
//
// Error handling follows the steward's configured policies and provides
// detailed information for troubleshooting and monitoring.
package execution

import (
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
)

// DriftEventHandler is called when managed resource drift is detected during
// the Compare step of the Get→Compare→Set→Verify cycle, before Set corrects it.
// This provides the controller visibility into what drifted and when.
//
// Parameters:
//   - resourceName: the cfg resource name where drift was detected
//   - moduleName: the module managing the resource (e.g. "file", "package")
//   - diff: the state diff describing exactly what changed
type DriftEventHandler func(resourceName string, moduleName string, diff *stewardtesting.StateDiff)

// ExecutionReport contains the results of configuration execution
type ExecutionReport struct {
	StartTime           time.Time
	EndTime             time.Time
	TotalResources      int
	SuccessfulCount     int
	FailedCount         int
	SkippedCount        int
	NonCompliantCount   int
	DeferredCount       int
	RetryExhaustedCount int
	ResourceResults     []ResourceResult
	Errors              []string
}

// ResourceResult contains the result of executing a single resource
type ResourceResult struct {
	ResourceName   string
	ModuleName     string
	Status         ResourceStatus
	DriftDetected  bool
	ChangesApplied bool
	ExecutionTime  time.Duration
	Error          string
	StateDiff      *stewardtesting.StateDiff
	// DeferredUntil is the next instant at which a deferred reboot-gated action
	// may be retried. Zero when Status is not StatusDeferred.
	DeferredUntil time.Time
}

// ResourceStatus represents the execution status of a resource
type ResourceStatus int

const (
	StatusSuccess ResourceStatus = iota
	StatusFailed
	StatusSkipped
	StatusNoChange
	// StatusNonCompliant indicates drift was detected in monitor mode.
	// module.Set() and module.Verify() were NOT called; the drift is reported but not corrected.
	StatusNonCompliant
	// StatusTimeout indicates a per-resource module call (Get, Set, or verifyChanges)
	// exceeded the configured per-call timeout. Treated as a failure in all aggregation
	// paths. The emitted outcome event carries action=did-not-finish(timeout) (ADR-012 §7).
	StatusTimeout
	// StatusDeferred indicates a reboot-gated action was withheld because the current
	// time falls outside the resource's reboot_window. The deferred action will be retried
	// on the next convergence pass; ResourceResult.DeferredUntil carries the next window
	// open time when known. Distinct from StatusFailed (the action is not in error — it is
	// intentionally deferred) and StatusSkipped (the module did run but could not proceed).
	StatusDeferred
	// StatusRetryExhausted indicates a module's Set() returned a
	// *modules.RetryExhaustedError: a provably-safe, bounded auto-retry has used up its
	// attempt budget and the resource has settled into a terminal, operator-actionable
	// state. Distinct from StatusDeferred (which retries automatically on the next
	// convergence pass) and from StatusFailed (an unclassified failure that may or may
	// not be safe to keep retrying) — this status is the queryable signal that automatic
	// remediation already gave up and will not be retried again on its own.
	StatusRetryExhausted
)

// NewConfigState creates a ConfigState from a raw configuration map.
// Used by the steward to build the desired-state argument for Monitor() calls
// without duplicating the executor's internal createConfigState logic.
func NewConfigState(data map[string]interface{}) modules.ConfigState {
	return &genericConfigState{data: data}
}

// genericConfigState is a simple map-backed ConfigState implementation used
// when no module-specific state type is needed.
type genericConfigState struct {
	data map[string]interface{}
}

func (g *genericConfigState) AsMap() map[string]interface{} {
	return g.data
}

func (g *genericConfigState) ToYAML() ([]byte, error) {
	return yaml.Marshal(g.data)
}

func (g *genericConfigState) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, &g.data)
}

func (g *genericConfigState) Validate() error {
	return nil
}

func (g *genericConfigState) GetManagedFields() []string {
	// Exclude fields that aren't part of the actual configuration state:
	//   - identifier fields (path, name) — used to select the resource, not
	//     compared as state.
	//   - module-operational keys (transport, tenant_id, steward_id,
	//     audit_manager, and winrm_* credential pointers) — consumed by the
	//     module's Configure to wire its transport/identity; never reported
	//     by a module's Get response, so leaving them in the comparison
	//     produces false-positive drift on every convergence cycle (the
	//     desired state has them, the current state can't).
	//
	// These keys are pan-module by convention: any module that needs to be
	// told how to talk to its backend (the hyperv module needs `transport`
	// and `tenant_id`; future modules may add their own) plumbs them in
	// through resource.config and consumes them at Configure-time only.
	excludedFields := map[string]bool{
		"path":                     true, // resourceID, not state
		"name":                     true, // resource identifier
		"transport":                true, // module operational: which client to use
		"tenant_id":                true, // module operational: namespace prefix
		"steward_id":               true, // module operational: audit subject
		"audit_manager":            true, // module operational: pointer, never serialised
		"winrm_host":               true, // module operational: WinRM endpoint
		"winrm_user_secret":        true, // module operational: SecretStore key
		"winrm_pass_secret":        true, // module operational: SecretStore key
		"source":                   true, // create-time provisioning directive (existence-gated, ADR-009); never reported by getVM (source: nil), so comparing it drifts every cycle on a provisioned VM
		"old_name":                 true, // #2776 in-place rename directive: consumed by setVM to locate the source VM, never reported by getVM (which returns the VM under its NEW name), so comparing it drifts every cycle after a completed rename. The rename still triggers — the VM under the new name is absent, so its other fields drift.
		"enroll_token":             true, // module operational: hyperv create-from-source join token (ADR-010)
		"enroll_ca_fingerprint":    true, // module operational: controller CA fingerprint for guest TOFU
		"enroll_steward_path":      true, // module operational: host path to steward binary staged on seed
		"enroll_launcher_path":     true, // module operational: host path to launcher staged on seed (sibling of enroll_steward_path; ADR-010/#2346)
		"enroll_ca_path":           true, // module operational: host path to CA cert staged on seed
		"debug_ssh_authorized_key": true, // create-time: SSH public key injected into a provisioned guest; never observable on the VM
		"seed_dir":                 true, // module operational: local dir for the provisioning seed VHDX
	}

	fields := make([]string, 0, len(g.data))
	for key := range g.data {
		if !excludedFields[key] {
			fields = append(fields, key)
		}
	}
	return fields
}
