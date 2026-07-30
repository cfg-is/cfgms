// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package templates_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/security"
)

func TestPromoteHVRoleTemplateParses(t *testing.T) {
	parser := workflow.NewParser()
	wf, err := parser.ParseFile("promote-hv-role.yaml")
	require.NoError(t, err, "promote-hv-role.yaml must parse without error via Parser.ParseFile")

	assert.Equal(t, "promote-hv-role", wf.Name)
	assert.Equal(t, workflow.ActionStop, wf.OnFailure, "on_failure must be stop so set_ha_role failure halts before cluster-scope write")

	// Variables block declares the four runtime parameters with empty placeholders.
	require.NotNil(t, wf.Variables)
	assert.Contains(t, wf.Variables, "vm_name")
	assert.Contains(t, wf.Variables, "steward_id")
	assert.Contains(t, wf.Variables, "cluster_name")
	assert.Contains(t, wf.Variables, "tenant_id")

	// Step-type sequence: set_ha_role → delay → move_resource_to_cluster.
	require.Len(t, wf.Steps, 3, "template must have exactly three top-level steps")
	assert.Equal(t, workflow.StepTypeSetHARole, wf.Steps[0].Type, "step 1 must be set_ha_role")
	assert.Equal(t, workflow.StepTypeDelay, wf.Steps[1].Type, "step 2 must be delay")
	assert.Equal(t, workflow.StepTypeMoveResourceToCluster, wf.Steps[2].Type, "step 3 must be move_resource_to_cluster")

	// Delay step must carry a positive duration so the engine can execute it.
	require.NotNil(t, wf.Steps[1].Delay, "delay step must have a delay config block")
	assert.Greater(t, wf.Steps[1].Delay.Duration, time.Duration(0), "delay duration must be positive")
}

// TestPromoteHVRoleTemplate_AuthoritativeSource_PassesProductionValidation confirms
// the authoritative template copy (features/workflow/templates/) also satisfies the
// same validateGenericRequest constraints tested via the embedded CLI copy.  Both
// copies are byte-identical after their header comments, but keeping the assertion
// here prevents a future edit to this file from silently reintroducing a description
// that the controller's validation middleware would reject.
func TestPromoteHVRoleTemplate_AuthoritativeSource_PassesProductionValidation(t *testing.T) {
	parser := workflow.NewParser()
	wf, err := parser.ParseFile("promote-hv-role.yaml")
	require.NoError(t, err, "promote-hv-role.yaml must parse")

	validator := security.NewValidator()
	result := &security.ValidationResult{Valid: true}
	validator.ValidateString(result, "body.description", wf.Description, "charset:safe_text", "max_length:1024")

	assert.True(t, result.Valid,
		"description must pass charset:safe_text + max_length:1024 (validateGenericRequest): %v", result.Errors)
	assert.LessOrEqual(t, len(wf.Description), 1024,
		"description must be at most 1024 characters")

	_, err = workflow.ParseSemanticVersion(wf.Version)
	assert.NoError(t, err,
		"version %q must parse as semantic version N.N.N (ParseSemanticVersion)", wf.Version)
}
