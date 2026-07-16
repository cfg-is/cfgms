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

	// AC #1 + AC #2: the stage step uses the real script module stage schema —
	// nested stage:{id,version} block (ScriptConfig.Stage / scriptConfigFromMap),
	// not flat script_id/script_version which scriptConfigFromMap never reads.
	// id and version are derived from runner_os so they cannot drift from each
	// other (Issue #2336 regression guard).
	stageCfg := wf.Steps[1].Config
	require.NotNil(t, stageCfg, "stage step must have config")
	assert.Equal(t, "stage", stageCfg["action"])

	// Flat keys must be absent; the engine only decodes the nested stage block.
	assert.NotContains(t, stageCfg, "script_id",
		"flat script_id must not be present; use nested stage.id (scriptConfigFromMap schema)")
	assert.NotContains(t, stageCfg, "script_version",
		"flat script_version must not be present; use nested stage.version (scriptConfigFromMap schema)")

	stageBlock, ok := stageCfg["stage"].(map[string]interface{})
	require.True(t, ok, "stage config must carry a nested 'stage' block (ScriptConfig.Stage)")

	stageID, _ := stageBlock["id"].(string)
	assert.Contains(t, stageID, ".runner_os",
		"stage.id must be derived from runner_os via template")

	// AC #2: stage.version template must branch on runner_os, gating both
	// version literals — linux 1.0.0 and windows 1.1.0 (--runasservice).
	stageVersion, _ := stageBlock["version"].(string)
	assert.Contains(t, stageVersion, "1.0.0",
		"stage.version must include the linux version literal (1.0.0)")
	assert.Contains(t, stageVersion, "1.1.0",
		"stage.version must include the windows version literal (1.1.0)")
	assert.Contains(t, stageVersion, "eq .runner_os",
		"stage.version must branch on runner_os (eq .runner_os conditional)")

	// The token is bound as a secret-store param, never a literal value.
	bindings, ok := stageCfg["param_bindings"].([]interface{})
	require.True(t, ok, "stage step must declare param_bindings")
	assert.True(t, hasSecretBinding(bindings, "RUNNER_TOKEN"),
		"RUNNER_TOKEN must be bound from the secret store")

	// AC #3 + AC #4: the wait/poll step keys off the github_runner module's
	// reported state via the real result-binding and DNA-response shape.
	loop := wf.Steps[3].Loop
	require.NotNil(t, loop, "while step must carry a loop block")
	require.NotNil(t, loop.Condition, "the poll loop must have a state condition, not a fixed sleep")
	assert.Contains(t, loop.Condition.Expression, "github_runner",
		"the poll condition must key off the github_runner module's reported state")

	// AC #4: condition must read DNAInfo.Attributes (flat map[string]string keyed
	// by "<resourceID>.<field>", e.g. "github_runner.state") — not a nested
	// modules object which does not exist on the DNA response.
	assert.Contains(t, loop.Condition.Expression, ".attributes",
		"condition must read DNAInfo.Attributes (flat map), not a nested modules object")
	assert.Contains(t, loop.Condition.Expression, `"github_runner.state"`,
		"condition must address the flattened DNA attribute key convention")
	assert.NotContains(t, loop.Condition.Expression, ".modules",
		"condition must not reference the nonexistent .modules field on DNAInfo (regression guard)")

	require.Len(t, wf.Steps[3].Steps, 1, "the while body polls the steward DNA")
	pollStep := wf.Steps[3].Steps[0]
	assert.Equal(t, StepTypeHTTP, pollStep.Type)
	// AC #3: poll step name must be hyphen-free so the engine's result binding
	// (<step_name>_response_json) is accessible via Go text/template dot notation.
	// Hyphens (U+002D) are rejected by the template field lexer.
	assert.NotContains(t, pollStep.Name, "-",
		"poll step name must not contain hyphens (template field lexer rejects U+002D)")
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
