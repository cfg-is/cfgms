// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/workflow"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ringHealthConfig holds the parsed configuration for a query_ring_health step.
type ringHealthConfig struct {
	Ring           string `yaml:"ring"`
	DesiredVersion string `yaml:"desired_version"`
	TenantID       string `yaml:"tenant_id"` // required to scope fleet queries to a single tenant
}

// RingHealthNodeExecutor implements workflow.RingHealthStepExecutor.
// It queries the fleet for stewards in a deployment ring and classifies each
// steward as on-version, failed, or pending based on their running version
// and upgrade record status.
type RingHealthNodeExecutor struct {
	fleetQuery   fleet.FleetQuery
	upgradeStore business.UpgradeStore
}

// NewRingHealthNodeExecutor constructs a RingHealthNodeExecutor.
// upgradeStore may be nil; when nil, all non-on-version stewards are counted as pending.
func NewRingHealthNodeExecutor(fleetQuery fleet.FleetQuery, upgradeStore business.UpgradeStore) *RingHealthNodeExecutor {
	return &RingHealthNodeExecutor{
		fleetQuery:   fleetQuery,
		upgradeStore: upgradeStore,
	}
}

// ExecuteRingHealthStep satisfies workflow.RingHealthStepExecutor.
// It reads ring and desired_version from step.Config, queries the fleet for stewards
// in that ring, and returns on_version_pct, failed_pct, pending_count as step outputs.
func (e *RingHealthNodeExecutor) ExecuteRingHealthStep(ctx context.Context, step workflow.Step, execution *workflow.WorkflowExecution) (workflow.StepResult, error) {
	startTime := time.Now()

	cfg, err := parseRingHealthConfig(step.Config)
	if err != nil {
		return failedRingHealthResult(startTime, fmt.Errorf("query_ring_health step %q: %w", step.Name, err)), err
	}

	if cfg.Ring == "" {
		err = fmt.Errorf("query_ring_health step %q: ring must not be empty", step.Name)
		return failedRingHealthResult(startTime, err), err
	}
	if cfg.DesiredVersion == "" {
		err = fmt.Errorf("query_ring_health step %q: desired_version must not be empty", step.Name)
		return failedRingHealthResult(startTime, err), err
	}
	if cfg.TenantID == "" {
		err = fmt.Errorf("query_ring_health step %q: tenant_id must not be empty — fleet queries must be tenant-scoped to prevent cross-tenant data leakage", step.Name)
		return failedRingHealthResult(startTime, err), err
	}

	filter := fleet.Filter{
		TenantID:      cfg.TenantID,
		DNAAttributes: map[string]string{"deployment_ring": cfg.Ring},
	}
	stewards, err := e.fleetQuery.Search(ctx, filter)
	if err != nil {
		err = fmt.Errorf("query_ring_health step %q: fleet query failed: %w", step.Name, err)
		return failedRingHealthResult(startTime, err), err
	}

	total := len(stewards)
	if total == 0 {
		return completedRingHealthResult(startTime, 0.0, 0.0, 0), nil
	}

	onVersion := 0
	failed := 0
	pending := 0

	for _, s := range stewards {
		if s.RunningVersion == cfg.DesiredVersion {
			onVersion++
			continue
		}
		if e.upgradeStore == nil {
			pending++
			continue
		}
		upgradeStatus, found, queryErr := e.latestUpgradeStatus(ctx, s.ID, cfg.DesiredVersion)
		if queryErr != nil {
			err = fmt.Errorf("query_ring_health step %q: upgrade query for steward %q failed: %w", step.Name, s.ID, queryErr)
			return failedRingHealthResult(startTime, err), err
		}
		if found && isTerminalFailure(upgradeStatus) {
			failed++
		} else {
			pending++
		}
	}

	onVersionPct := 100.0 * float64(onVersion) / float64(total)
	failedPct := 100.0 * float64(failed) / float64(total)

	result := completedRingHealthResult(startTime, onVersionPct, failedPct, pending)

	// Store outputs in execution variables so downstream steps can access them.
	execution.SetVariable(step.Name+"_on_version_pct", onVersionPct)
	execution.SetVariable(step.Name+"_failed_pct", failedPct)
	execution.SetVariable(step.Name+"_pending_count", pending)

	return result, nil
}

// latestUpgradeStatus returns the status of the most recent upgrade record for
// stewardID targeting desiredVersion. Returns (status, true, nil) when found,
// ("", false, nil) when no matching record exists, or ("", false, err) on error.
func (e *RingHealthNodeExecutor) latestUpgradeStatus(ctx context.Context, stewardID, desiredVersion string) (business.UpgradeStatus, bool, error) {
	records, err := e.upgradeStore.ListUpgradesBySteward(ctx, stewardID)
	if err != nil {
		return "", false, err
	}
	// Records are ordered by CreatedAt descending; find the most recent for desiredVersion.
	for _, r := range records {
		if r.Version == desiredVersion {
			return r.Status, true, nil
		}
	}
	return "", false, nil
}

// isTerminalFailure returns true for upgrade statuses that represent a definitive
// upgrade failure — the steward tried and could not complete the upgrade.
func isTerminalFailure(status business.UpgradeStatus) bool {
	return status == business.UpgradeStatusFailed || status == business.UpgradeStatusRolledBack
}

// parseRingHealthConfig extracts ring health configuration from the raw step config map.
func parseRingHealthConfig(raw map[string]interface{}) (ringHealthConfig, error) {
	var cfg ringHealthConfig
	if raw == nil {
		return cfg, nil
	}
	if v, ok := raw["ring"]; ok {
		if s, ok := v.(string); ok {
			cfg.Ring = s
		}
	}
	if v, ok := raw["desired_version"]; ok {
		if s, ok := v.(string); ok {
			cfg.DesiredVersion = s
		}
	}
	if v, ok := raw["tenant_id"]; ok {
		if s, ok := v.(string); ok {
			cfg.TenantID = s
		}
	}
	return cfg, nil
}

func failedRingHealthResult(startTime time.Time, err error) workflow.StepResult {
	endTime := time.Now()
	return workflow.StepResult{
		Status:    workflow.StatusFailed,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Error:     err.Error(),
	}
}

func completedRingHealthResult(startTime time.Time, onVersionPct, failedPct float64, pendingCount int) workflow.StepResult {
	endTime := time.Now()
	return workflow.StepResult{
		Status:    workflow.StatusCompleted,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Output: map[string]interface{}{
			"on_version_pct": onVersionPct,
			"failed_pct":     failedPct,
			"pending_count":  pendingCount,
		},
	}
}
