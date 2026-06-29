// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package workflow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCIRunnerProvisionWorkflowDescriptor loads the CI-runner provisioning
// descriptor via the workflow engine's loader and asserts its structure.
//
// NOTE: the descriptor uses api/http/while step types with typed api:/http:/loop:
// blocks. These are represented by the rich workflow.Workflow / Step model and
// are loaded by the engine's actual loader (Engine.loadWorkflowFromPath ->
// yaml.Unmarshal into Workflow) — the same path the engine runs at execution
// time and the same flat format as github-app-runner-token.yaml. (The separate
// features/workflow/parser.go Parser models only task/sequential/parallel/
// conditional steps and a `workflow:`-wrapped format; it cannot represent
// api/http/while steps, so it is not the loader for this descriptor.)
func TestCIRunnerProvisionWorkflowDescriptor(t *testing.T) {
	engine := &Engine{} // loadWorkflowFromPath only reads+unmarshals; no engine state needed

	wf, err := engine.loadWorkflowFromPath("examples/cirunner-provision.yaml")
	// (a) YAML parses without error.
	require.NoError(t, err, "descriptor must parse via the workflow engine loader")
	assert.Equal(t, "cirunner-provision", wf.Name)

	// (b) Step sequence is api -> stage(task) -> http -> while.
	require.Len(t, wf.Steps, 4, "expected exactly 4 top-level steps")
	assert.Equal(t, StepTypeAPI, wf.Steps[0].Type, "step 1 must be api")
	assert.Equal(t, StepTypeTask, wf.Steps[1].Type, "step 2 (stage) must be a task")
	assert.Contains(t, strings.ToLower(wf.Steps[1].Name), "stage", "step 2 is the stage step")
	assert.Equal(t, StepTypeHTTP, wf.Steps[2].Type, "step 3 must be http")
	assert.Equal(t, StepTypeWhile, wf.Steps[3].Type, "step 4 must be while")

	// (c) The api step resolves provider: github, service: runners,
	//     operation: registration-token.
	api := wf.Steps[0].API
	require.NotNil(t, api, "api step must carry an api block")
	assert.Equal(t, "github", api.Provider)
	assert.Equal(t, "runners", api.Service)
	assert.Equal(t, "registration-token", api.Operation)

	// (d) The http step targets POST /api/v1/config/push.
	httpStep := wf.Steps[2].HTTP
	require.NotNil(t, httpStep, "http step must carry an http block")
	assert.Equal(t, "POST", httpStep.Method)
	assert.Contains(t, httpStep.URL, "/api/v1/config/push")

	// AC #5: the stage step references the register script by id + version
	// (a named library script), NOT a per-standup generated script.
	stageCfg := wf.Steps[1].Config
	require.NotNil(t, stageCfg, "stage step must have config")
	assert.Equal(t, "stage", stageCfg["action"])
	assert.Contains(t, stageCfg, "script_id", "stage references a library script by id")
	assert.Contains(t, stageCfg, "script_version", "stage references the script by version")

	// The token is bound as a secret-store param, never a literal value.
	bindings, ok := stageCfg["param_bindings"].([]interface{})
	require.True(t, ok, "stage step must declare param_bindings")
	assert.True(t, hasSecretBinding(bindings, "RUNNER_TOKEN"),
		"RUNNER_TOKEN must be bound from the secret store")

	// AC #4: the wait/poll step keys off the github_runner module's reported
	// state (a while condition), NOT a fixed sleep.
	loop := wf.Steps[3].Loop
	require.NotNil(t, loop, "while step must carry a loop block")
	require.NotNil(t, loop.Condition, "the poll loop must have a state condition, not a fixed sleep")
	assert.Contains(t, loop.Condition.Expression, "github_runner",
		"the poll condition must key off the github_runner module's reported state")
	require.Len(t, wf.Steps[3].Steps, 1, "the while body polls the steward DNA")
	pollStep := wf.Steps[3].Steps[0]
	assert.Equal(t, StepTypeHTTP, pollStep.Type)
	require.NotNil(t, pollStep.HTTP)
	assert.Equal(t, "GET", pollStep.HTTP.Method)
	assert.Contains(t, pollStep.HTTP.URL, "/dna", "the poll reads the steward DNA")

	// No fixed-sleep step anywhere in the descriptor.
	assertNoDelaySteps(t, wf.Steps)
}

// hasSecretBinding reports whether a param_bindings list contains a binding for
// name sourced from the secret store (and never a literal token value).
func hasSecretBinding(bindings []interface{}, name string) bool {
	for _, b := range bindings {
		m, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		if m["name"] == name && m["from"] == "secret-store" {
			// A secret binding must not carry an inline literal value.
			if _, hasValue := m["value"]; !hasValue {
				return true
			}
		}
	}
	return false
}

// assertNoDelaySteps fails if any step (recursively) is a fixed-sleep delay step.
func assertNoDelaySteps(t *testing.T, steps []Step) {
	t.Helper()
	for _, s := range steps {
		assert.NotEqualf(t, StepTypeDelay, s.Type,
			"provisioning must be state-driven; step %q is a fixed-sleep delay", s.Name)
		if len(s.Steps) > 0 {
			assertNoDelaySteps(t, s.Steps)
		}
	}
}
