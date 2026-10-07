// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

func inputsWorkflow() Workflow {
	return Workflow{
		Name: "inputs-wf",
		Inputs: []InputSpec{
			{Name: "host", Type: InputTypeString, Required: true},
			{Name: "env", Type: InputTypeEnum, Options: []string{"dev", "prod"}, Default: "dev"},
			{Name: "dry_run", Type: InputTypeBool, Default: true},
		},
	}
}

func TestResolveInputs_AppliesDefaultWhenOptionalOmitted(t *testing.T) {
	got, err := inputsWorkflow().ResolveInputs(map[string]interface{}{"host": "a"})
	require.NoError(t, err)
	assert.Equal(t, "dev", got["env"])
	assert.Equal(t, true, got["dry_run"])
	assert.Equal(t, "a", got["host"])
}

func TestResolveInputs_MissingRequiredNamesField(t *testing.T) {
	_, err := inputsWorkflow().ResolveInputs(nil)
	ie, ok := AsInputsError(err)
	require.True(t, ok)
	require.Len(t, ie.Fields, 1)
	assert.Equal(t, "host", ie.Fields[0].Field)
}

func TestResolveInputs_EnumOutsideOptionsAndWrongTypes(t *testing.T) {
	_, err := inputsWorkflow().ResolveInputs(map[string]interface{}{
		"host": 5, "env": "staging-secret-value", "dry_run": "yes",
	})
	ie, ok := AsInputsError(err)
	require.True(t, ok)
	require.Len(t, ie.Fields, 3)
	for _, f := range ie.Fields {
		assert.NotContains(t, f.Message, "staging-secret-value", "errors must not echo values")
	}
	assert.NotContains(t, err.Error(), "staging-secret-value")
}

func TestResolveInputs_UndeclaredVariablesPassThrough(t *testing.T) {
	got, err := inputsWorkflow().ResolveInputs(map[string]interface{}{"host": "a", "extra": 1})
	require.NoError(t, err)
	assert.Equal(t, 1, got["extra"])
}

func TestValidateInputSpecs(t *testing.T) {
	cases := map[string][]InputSpec{
		"duplicate":        {{Name: "a", Type: InputTypeString}, {Name: "a", Type: InputTypeBool}},
		"unknown type":     {{Name: "a", Type: "int"}},
		"enum no options":  {{Name: "a", Type: InputTypeEnum}},
		"default mismatch": {{Name: "a", Type: InputTypeBool, Default: "x"}},
		"enum default bad": {{Name: "a", Type: InputTypeEnum, Options: []string{"x"}, Default: "y"}},
		"empty name":       {{Type: InputTypeString}},
		"bad name":         {{Name: "a b", Type: InputTypeString}},
		"options on str":   {{Name: "a", Type: InputTypeString, Options: []string{"x"}}},
	}
	for _, reserved := range []string{"tenant_id", "TenantID", "tenant-id", "execution_id", "steps"} {
		cases["reserved "+reserved] = []InputSpec{{Name: reserved, Type: InputTypeString}}
	}
	for name, specs := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, ValidateInputSpecs(specs))
		})
	}
	assert.NoError(t, ValidateInputSpecs(inputsWorkflow().Inputs))
}

func TestParseYAML_KeepsInputs(t *testing.T) {
	data := []byte(`
workflow:
  name: yaml-inputs
  inputs:
    - name: env
      type: enum
      options: [dev, prod]
      default: dev
      description: target env
    - name: host
      type: string
      required: true
  steps:
    - name: s
      type: task
      module: file
      config: {path: /tmp/x}
`)
	wf, err := NewParser().ParseYAML(data)
	require.NoError(t, err)
	require.Len(t, wf.Inputs, 2)
	assert.Equal(t, InputTypeEnum, wf.Inputs[0].Type)
	assert.Equal(t, []string{"dev", "prod"}, wf.Inputs[0].Options)
	assert.Equal(t, "dev", wf.Inputs[0].Default)
	assert.True(t, wf.Inputs[1].Required)
}

func TestWorkflow_InputsYAMLRoundTrip(t *testing.T) {
	out, err := yaml.Marshal(inputsWorkflow())
	require.NoError(t, err)
	var back Workflow
	require.NoError(t, yaml.Unmarshal(out, &back))
	assert.Equal(t, inputsWorkflow().Inputs, back.Inputs)
}

func TestParser_ValidateWorkflow_RejectsBadInputs(t *testing.T) {
	step := Step{Name: "s", Type: StepTypeTask, Module: "file", Config: map[string]interface{}{"a": 1}}
	wf := Workflow{Name: "w", Steps: []Step{step}, Inputs: []InputSpec{{Name: "tenant_id", Type: InputTypeString}}}
	assert.Error(t, NewParser().ValidateWorkflow(wf))
	wf.Inputs = []InputSpec{{Name: "a", Type: InputTypeEnum}}
	assert.Error(t, NewParser().ValidateWorkflow(wf))
	wf.Inputs = []InputSpec{{Name: "a", Type: InputTypeString}, {Name: "a", Type: InputTypeString}}
	assert.Error(t, NewParser().ValidateWorkflow(wf))
}

func TestEngine_ExecuteWorkflow_MissingRequiredInputFailsAndRecords(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	wf := inputsWorkflow()
	wf.Steps = []Step{{Name: "noop", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}}

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-owner")
	execution, err := engine.ExecuteWorkflow(ctx, wf, map[string]interface{}{"tenant_id": "evil"})
	require.Error(t, err)
	_, ok := AsInputsError(err)
	require.True(t, ok)
	require.NotNil(t, execution)
	assert.Equal(t, StatusFailed, execution.GetStatus())
	assert.Contains(t, execution.GetError(), "host")
	assert.Equal(t, "tenant-owner", execution.TenantID)
	assert.Empty(t, execution.StepResults, "no step may run")

	recorded, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, recorded.Status)
}
