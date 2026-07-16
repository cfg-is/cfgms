// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/workflow"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"gopkg.in/yaml.v3"
)

// MoveResourceToClusterNodeExecutor implements workflow.MoveResourceToClusterStepExecutor.
// It atomically relocates a named hyperv.vm resource from a steward's device-scope config
// (stewards/<stewardID>) to the tenant's cluster-scope config (cluster-policies/<clusterName>),
// preserving Config unchanged.
//
// Write order: cluster-add (raw ConfigStore) before device-remove (ConfigurationServiceV2).
// A crash between the two writes leaves the resource in both docs; re-running the step
// detects this and completes the device-side removal without re-writing the cluster doc.
type MoveResourceToClusterNodeExecutor struct {
	store     cfgconfig.ConfigStore
	configSvc *service.ConfigurationServiceV2
}

// NewMoveResourceToClusterNodeExecutor constructs a MoveResourceToClusterNodeExecutor.
// store handles all reads and the cluster-policies write (no service-layer equivalent for
// that namespace). configSvc handles the device-scope write via its validated + fan-out path.
func NewMoveResourceToClusterNodeExecutor(store cfgconfig.ConfigStore, configSvc *service.ConfigurationServiceV2) *MoveResourceToClusterNodeExecutor {
	return &MoveResourceToClusterNodeExecutor{
		store:     store,
		configSvc: configSvc,
	}
}

// ExecuteMoveResourceToClusterStep satisfies workflow.MoveResourceToClusterStepExecutor.
// Required variables in execution.Variables: steward_id, tenant_id, vm_name, cluster_name.
func (e *MoveResourceToClusterNodeExecutor) ExecuteMoveResourceToClusterStep(ctx context.Context, step workflow.Step, execution *workflow.WorkflowExecution) (workflow.StepResult, error) {
	startTime := time.Now()

	stewardID, err := requireStringVar(execution, "steward_id")
	if err != nil {
		return failedMoveResult(startTime, fmt.Errorf("move_resource_to_cluster step %q: %w", step.Name, err)), err
	}
	tenantID, err := requireStringVar(execution, "tenant_id")
	if err != nil {
		return failedMoveResult(startTime, fmt.Errorf("move_resource_to_cluster step %q: %w", step.Name, err)), err
	}
	vmName, err := requireStringVar(execution, "vm_name")
	if err != nil {
		return failedMoveResult(startTime, fmt.Errorf("move_resource_to_cluster step %q: %w", step.Name, err)), err
	}
	clusterName, err := requireStringVar(execution, "cluster_name")
	if err != nil {
		return failedMoveResult(startTime, fmt.Errorf("move_resource_to_cluster step %q: %w", step.Name, err)), err
	}

	clusterKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "cluster-policies",
		Name:      clusterName,
	}
	deviceKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	// Step 1: Read cluster doc. A missing cluster doc is not an error — treat as empty config.
	var clusterCfg stewardtypes.StewardConfig
	clusterEntry, clusterErr := e.store.GetConfig(ctx, clusterKey)
	if clusterErr != nil {
		if !errors.Is(clusterErr, cfgconfig.ErrConfigNotFound) {
			err = fmt.Errorf("move_resource_to_cluster step %q: read cluster config %q: %w", step.Name, clusterName, clusterErr)
			return failedMoveResult(startTime, err), err
		}
		// No cluster doc yet; clusterCfg stays zero-valued.
	} else {
		if unmarshalErr := yaml.Unmarshal(clusterEntry.Data, &clusterCfg); unmarshalErr != nil {
			err = fmt.Errorf("move_resource_to_cluster step %q: unmarshal cluster config %q: %w", step.Name, clusterName, unmarshalErr)
			return failedMoveResult(startTime, err), err
		}
	}

	// Step 2: Read device doc.
	deviceEntry, deviceErr := e.store.GetConfig(ctx, deviceKey)
	if deviceErr != nil {
		if errors.Is(deviceErr, cfgconfig.ErrConfigNotFound) {
			err = fmt.Errorf("move_resource_to_cluster step %q: device config for steward %q not found", step.Name, stewardID)
		} else {
			err = fmt.Errorf("move_resource_to_cluster step %q: read device config for steward %q: %w", step.Name, stewardID, deviceErr)
		}
		return failedMoveResult(startTime, err), err
	}
	var deviceCfg stewardtypes.StewardConfig
	if unmarshalErr := yaml.Unmarshal(deviceEntry.Data, &deviceCfg); unmarshalErr != nil {
		err = fmt.Errorf("move_resource_to_cluster step %q: unmarshal device config for steward %q: %w", step.Name, stewardID, unmarshalErr)
		return failedMoveResult(startTime, err), err
	}

	deviceIdx := findHypervVMResource(deviceCfg.Resources, vmName)
	clusterIdx := findHypervVMResource(clusterCfg.Resources, vmName)

	devicePresent := deviceIdx >= 0
	clusterPresent := clusterIdx >= 0

	// Step 7: Missing from both — hard error.
	if !devicePresent && !clusterPresent {
		err = fmt.Errorf("move_resource_to_cluster step %q: hyperv.vm resource %q not found in device config for steward %q or cluster-policies %q — nothing to migrate",
			step.Name, vmName, stewardID, clusterName)
		return failedMoveResult(startTime, err), err
	}

	// Step 3: Fully migrated — absent from device, present in cluster. No-op.
	if !devicePresent && clusterPresent {
		return completedMoveResult(startTime), nil
	}

	// Steps 4 / 4a: Present in both docs — check Config equality.
	if clusterPresent {
		deviceConfig := deviceCfg.Resources[deviceIdx].Config
		clusterConfig := clusterCfg.Resources[clusterIdx].Config
		if !reflect.DeepEqual(deviceConfig, clusterConfig) {
			// Step 4a: Conflicting definitions — hard error, no writes.
			err = fmt.Errorf("move_resource_to_cluster step %q: conflicting resource definitions for %q in device (steward %q) and cluster-policies %q — manual reconciliation required",
				step.Name, vmName, stewardID, clusterName)
			return failedMoveResult(startTime, err), err
		}
		// Step 4: Partial-run recovery — identical Config. Skip cluster write; go straight to device removal.
		return e.removeResourceFromDevice(ctx, step.Name, startTime, tenantID, stewardID, &deviceCfg, deviceIdx)
	}

	// Step 5 (normal first run): Upsert resource into cluster doc and write cluster FIRST.
	resource := deviceCfg.Resources[deviceIdx]
	upsertResourceByName(&clusterCfg, resource)

	clusterData, marshalErr := yaml.Marshal(&clusterCfg)
	if marshalErr != nil {
		err = fmt.Errorf("move_resource_to_cluster step %q: marshal cluster config %q: %w", step.Name, clusterName, marshalErr)
		return failedMoveResult(startTime, err), err
	}
	if storeErr := e.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    clusterKey,
		Data:   clusterData,
		Format: cfgconfig.ConfigFormatYAML,
	}); storeErr != nil {
		err = fmt.Errorf("move_resource_to_cluster step %q: store cluster config %q: %w", step.Name, clusterName, storeErr)
		return failedMoveResult(startTime, err), err
	}

	// Step 6: Remove resource from device doc and write device SECOND.
	return e.removeResourceFromDevice(ctx, step.Name, startTime, tenantID, stewardID, &deviceCfg, deviceIdx)
}

// removeResourceFromDevice removes the resource at idx from cfg.Resources and persists
// via ConfigurationServiceV2.SetConfiguration (the validated + fan-out device-scope write path).
// idx < 0 is treated as a no-op (resource already absent).
func (e *MoveResourceToClusterNodeExecutor) removeResourceFromDevice(
	ctx context.Context,
	stepName string,
	startTime time.Time,
	tenantID, stewardID string,
	cfg *stewardtypes.StewardConfig,
	idx int,
) (workflow.StepResult, error) {
	if idx < 0 {
		return completedMoveResult(startTime), nil
	}
	cfg.Resources = append(cfg.Resources[:idx], cfg.Resources[idx+1:]...)
	if writeErr := e.configSvc.SetConfiguration(ctx, tenantID, stewardID, cfg); writeErr != nil {
		err := fmt.Errorf("move_resource_to_cluster step %q: persist device config for steward %q: %w", stepName, stewardID, writeErr)
		return failedMoveResult(startTime, err), err
	}
	return completedMoveResult(startTime), nil
}

// findHypervVMResource returns the index of the first ResourceConfig with the given name
// and Module == "hyperv.vm", or -1 if not found.
func findHypervVMResource(resources []stewardtypes.ResourceConfig, name string) int {
	for i, r := range resources {
		if r.Name == name && r.Module == "hyperv.vm" {
			return i
		}
	}
	return -1
}

// upsertResourceByName adds resource to cfg.Resources, replacing any existing entry with
// the same Name.
func upsertResourceByName(cfg *stewardtypes.StewardConfig, resource stewardtypes.ResourceConfig) {
	for i, r := range cfg.Resources {
		if r.Name == resource.Name {
			cfg.Resources[i] = resource
			return
		}
	}
	cfg.Resources = append(cfg.Resources, resource)
}

func failedMoveResult(startTime time.Time, err error) workflow.StepResult {
	endTime := time.Now()
	return workflow.StepResult{
		Status:    workflow.StatusFailed,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Error:     err.Error(),
	}
}

func completedMoveResult(startTime time.Time) workflow.StepResult {
	endTime := time.Now()
	return workflow.StepResult{
		Status:    workflow.StatusCompleted,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
	}
}
