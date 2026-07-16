// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"errors"
	"fmt"
	"time"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/workflow"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"gopkg.in/yaml.v3"
)

// SetHARoleNodeExecutor implements workflow.SetHARoleStepExecutor.
// It reads a steward's device-scope config document, finds the named hyperv.vm
// resource, and merges the ha_role block via ConfigurationServiceV2.SetConfiguration.
type SetHARoleNodeExecutor struct {
	store     cfgconfig.ConfigStore
	configSvc *service.ConfigurationServiceV2
}

// NewSetHARoleNodeExecutor constructs a SetHARoleNodeExecutor.
// store is used read-only (GetConfig). configSvc is used for the validated,
// fan-out write path (SetConfiguration) — never raw ConfigStore.StoreConfig.
func NewSetHARoleNodeExecutor(store cfgconfig.ConfigStore, configSvc *service.ConfigurationServiceV2) *SetHARoleNodeExecutor {
	return &SetHARoleNodeExecutor{
		store:     store,
		configSvc: configSvc,
	}
}

// ExecuteSetHARoleStep satisfies workflow.SetHARoleStepExecutor.
// Required variables in execution.Variables: steward_id, tenant_id, vm_name, cluster_name.
// Optional variable: resource_group_name.
// Missing or wrong-type required variables fail the step with StatusFailed.
func (e *SetHARoleNodeExecutor) ExecuteSetHARoleStep(ctx context.Context, step workflow.Step, execution *workflow.WorkflowExecution) (workflow.StepResult, error) {
	startTime := time.Now()

	stewardID, err := requireStringVar(execution, "steward_id")
	if err != nil {
		return failedHARoleResult(startTime, fmt.Errorf("set_ha_role step %q: %w", step.Name, err)), err
	}
	tenantID, err := requireStringVar(execution, "tenant_id")
	if err != nil {
		return failedHARoleResult(startTime, fmt.Errorf("set_ha_role step %q: %w", step.Name, err)), err
	}
	vmName, err := requireStringVar(execution, "vm_name")
	if err != nil {
		return failedHARoleResult(startTime, fmt.Errorf("set_ha_role step %q: %w", step.Name, err)), err
	}
	clusterName, err := requireStringVar(execution, "cluster_name")
	if err != nil {
		return failedHARoleResult(startTime, fmt.Errorf("set_ha_role step %q: %w", step.Name, err)), err
	}

	resourceGroupName, _ := optionalStringVar(execution, "resource_group_name")

	// Read the steward's device-scope config document.
	entry, err := e.store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	})
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			err = fmt.Errorf("set_ha_role step %q: device config for steward %q not found", step.Name, stewardID)
		} else {
			err = fmt.Errorf("set_ha_role step %q: read device config for steward %q: %w", step.Name, stewardID, err)
		}
		return failedHARoleResult(startTime, err), err
	}

	var cfg stewardtypes.StewardConfig
	if unmarshalErr := yaml.Unmarshal(entry.Data, &cfg); unmarshalErr != nil {
		err = fmt.Errorf("set_ha_role step %q: unmarshal steward config for %q: %w", step.Name, stewardID, unmarshalErr)
		return failedHARoleResult(startTime, err), err
	}

	// Find the hyperv.vm resource named vmName.
	resourceIdx := -1
	for i, r := range cfg.Resources {
		if r.Name == vmName && r.Module == "hyperv.vm" {
			resourceIdx = i
			break
		}
	}
	if resourceIdx < 0 {
		err = fmt.Errorf("set_ha_role step %q: hyperv.vm resource %q not found in steward %q device config", step.Name, vmName, stewardID)
		return failedHARoleResult(startTime, err), err
	}

	resource := &cfg.Resources[resourceIdx]

	// Idempotent re-run: if ha_role already matches desired state, no write needed.
	if haRoleAlreadySet(resource.Config, clusterName, resourceGroupName) {
		return completedHARoleResult(startTime), nil
	}

	// Write ha_role — field names match features/modules/hyperv/vm.go:512-517 (AsMap).
	if resource.Config == nil {
		resource.Config = make(map[string]interface{})
	}
	haRole := map[string]interface{}{
		"cluster_name": clusterName,
	}
	if resourceGroupName != "" {
		haRole["resource_group_name"] = resourceGroupName
	}
	resource.Config["ha_role"] = haRole

	if writeErr := e.configSvc.SetConfiguration(ctx, tenantID, stewardID, &cfg); writeErr != nil {
		err = fmt.Errorf("set_ha_role step %q: persist config for steward %q: %w", step.Name, stewardID, writeErr)
		return failedHARoleResult(startTime, err), err
	}

	return completedHARoleResult(startTime), nil
}

// haRoleAlreadySet returns true when ha_role in the resource config already matches
// the desired cluster_name and resource_group_name (idempotent re-run guard).
func haRoleAlreadySet(resourceConfig map[string]interface{}, clusterName, resourceGroupName string) bool {
	v, ok := resourceConfig["ha_role"]
	if !ok || v == nil {
		return false
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	existingCluster, _ := m["cluster_name"].(string)
	existingRG, _ := m["resource_group_name"].(string)
	return existingCluster == clusterName && existingRG == resourceGroupName
}

// requireStringVar extracts a non-empty string from execution.Variables or returns an error.
func requireStringVar(execution *workflow.WorkflowExecution, key string) (string, error) {
	v, ok := execution.GetVariable(key)
	if !ok {
		return "", fmt.Errorf("missing required variable %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("variable %q must be a string, got %T", key, v)
	}
	if s == "" {
		return "", fmt.Errorf("variable %q must not be empty", key)
	}
	return s, nil
}

// optionalStringVar extracts an optional string from execution.Variables.
// Returns ("", false) when absent or not a string.
func optionalStringVar(execution *workflow.WorkflowExecution, key string) (string, bool) {
	v, ok := execution.GetVariable(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func failedHARoleResult(startTime time.Time, err error) workflow.StepResult {
	endTime := time.Now()
	return workflow.StepResult{
		Status:    workflow.StatusFailed,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Error:     err.Error(),
	}
}

func completedHARoleResult(startTime time.Time) workflow.StepResult {
	endTime := time.Now()
	return workflow.StepResult{
		Status:    workflow.StatusCompleted,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
	}
}
