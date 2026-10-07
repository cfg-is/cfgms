// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"fmt"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// NewStoreWorkflowResolver returns the WorkflowResolver the controller wires
// into the engine (Issue #4638): a workflow referenced by name resolves to the
// latest version stored in the execution tenant's workflow store — the same
// store the workflow API reads and writes for that tenant.
func NewStoreWorkflowResolver(configStore cfgconfig.ConfigStore) WorkflowResolver {
	return func(ctx context.Context, tenantID, name string) (Workflow, error) {
		if tenantID == "" {
			return Workflow{}, fmt.Errorf("workflow '%s' cannot be resolved without a tenant", name)
		}
		vw, err := NewWorkflowStore(configStore, tenantID).GetLatestWorkflow(ctx, name)
		if err != nil {
			return Workflow{}, err
		}
		return vw.Workflow, nil
	}
}

// freeFormKeys are definition fields whose values are author data the engine
// never interprets as a workflow reference (module config, variables, call
// parameters); a key named workflow_path inside them is not a reference.
var freeFormKeys = map[string]bool{"config": true, "variables": true, "parameters": true}

// ContainsFilesystemWorkflowReference reports whether w references a workflow
// by filesystem path (workflow_path) anywhere — nested workflow steps, error
// workflows, composite components, at any depth (Issue #4638). It inspects the
// definition's JSON form, so a step container added later cannot hide a
// reference from it.
func ContainsFilesystemWorkflowReference(w Workflow) (bool, error) {
	data, err := json.Marshal(w)
	if err != nil {
		return false, fmt.Errorf("inspect workflow definition: %w", err)
	}
	var tree interface{}
	if err := json.Unmarshal(data, &tree); err != nil {
		return false, fmt.Errorf("inspect workflow definition: %w", err)
	}
	return containsWorkflowPath(tree), nil
}

func containsWorkflowPath(node interface{}) bool {
	switch v := node.(type) {
	case map[string]interface{}:
		for key, child := range v {
			if key == "workflow_path" {
				if s, ok := child.(string); ok && s != "" {
					return true
				}
			}
			if freeFormKeys[key] {
				continue
			}
			if containsWorkflowPath(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if containsWorkflowPath(child) {
				return true
			}
		}
	}
	return false
}
