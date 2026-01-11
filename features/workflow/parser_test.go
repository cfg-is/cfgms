// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_ParseYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    Workflow
		wantErr bool
	}{
		{
			name: "simple task workflow",
			yaml: `
workflow:
  name: "simple-workflow"
  description: "A simple test workflow"
  version: "1.0.0"
  timeout: "5m"
  steps:
    - name: "create-directory"
      type: "task"
      module: "directory"
      config:
        path: "/opt/test"
        permissions: "755"
`,
			want: Workflow{
				Name:        "simple-workflow",
				Description: "A simple test workflow",
				Version:     "1.0.0",
				Timeout:     5 * time.Minute,
				Steps: []Step{
					{
						Name:   "create-directory",
						Type:   StepTypeTask,
						Module: "directory",
						Config: map[string]interface{}{
							"path":        "/opt/test",
							"permissions": "755",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "sequential workflow",
			yaml: `
workflow:
  name: "sequential-workflow"
  steps:
    - name: "sequential-group"
      type: "sequential"
      steps:
        - name: "step1"
          type: "task"
          module: "file"
          config:
            path: "/tmp/file1"
            content: "hello"
        - name: "step2"
          type: "task"
          module: "file"
          config:
            path: "/tmp/file2"
            content: "world"
`,
			want: Workflow{
				Name: "sequential-workflow",
				Steps: []Step{
					{
						Name: "sequential-group",
						Type: StepTypeSequential,
						Steps: []Step{
							{
								Name:   "step1",
								Type:   StepTypeTask,
								Module: "file",
								Config: map[string]interface{}{
									"path":    "/tmp/file1",
									"content": "hello",
								},
							},
							{
								Name:   "step2",
								Type:   StepTypeTask,
								Module: "file",
								Config: map[string]interface{}{
									"path":    "/tmp/file2",
									"content": "world",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "parallel workflow",
			yaml: `
workflow:
  name: "parallel-workflow"
  steps:
    - name: "parallel-group"
      type: "parallel"
      steps:
        - name: "parallel-step1"
          type: "task"
          module: "package"
          config:
            name: "nginx"
            state: "present"
        - name: "parallel-step2"
          type: "task"
          module: "package"
          config:
            name: "apache2"
            state: "present"
`,
			want: Workflow{
				Name: "parallel-workflow",
				Steps: []Step{
					{
						Name: "parallel-group",
						Type: StepTypeParallel,
						Steps: []Step{
							{
								Name:   "parallel-step1",
								Type:   StepTypeTask,
								Module: "package",
								Config: map[string]interface{}{
									"name":  "nginx",
									"state": "present",
								},
							},
							{
								Name:   "parallel-step2",
								Type:   StepTypeTask,
								Module: "package",
								Config: map[string]interface{}{
									"name":  "apache2",
									"state": "present",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "conditional workflow",
			yaml: `
workflow:
  name: "conditional-workflow"
  variables:
    deploy_env: "production"
  steps:
    - name: "conditional-group"
      type: "conditional"
      condition:
        type: "variable"
        variable: "deploy_env"
        operator: "eq"
        value: "production"
      steps:
        - name: "production-setup"
          type: "task"
          module: "file"
          config:
            path: "/etc/production.conf"
            content: "production=true"
`,
			want: Workflow{
				Name: "conditional-workflow",
				Variables: map[string]interface{}{
					"deploy_env": "production",
				},
				Steps: []Step{
					{
						Name: "conditional-group",
						Type: StepTypeConditional,
						Condition: &Condition{
							Type:     ConditionTypeVariable,
							Variable: "deploy_env",
							Operator: OperatorEqual,
							Value:    "production",
						},
						Steps: []Step{
							{
								Name:   "production-setup",
								Type:   StepTypeTask,
								Module: "file",
								Config: map[string]interface{}{
									"path":    "/etc/production.conf",
									"content": "production=true",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "complex nested workflow",
			yaml: `
workflow:
  name: "complex-workflow"
  description: "A complex nested workflow"
  variables:
    environment: "staging"
  steps:
    - name: "preparation"
      type: "sequential"
      steps:
        - name: "create-dirs"
          type: "parallel"
          steps:
            - name: "create-app-dir"
              type: "task"
              module: "directory"
              config:
                path: "/opt/app"
                permissions: "755"
            - name: "create-log-dir"
              type: "task"
              module: "directory"
              config:
                path: "/var/log/app"
                permissions: "755"
        - name: "install-packages"
          type: "task"
          module: "package"
          config:
            name: "nginx"
            state: "present"
    - name: "deployment"
      type: "conditional"
      condition:
        type: "variable"
        variable: "environment"
        operator: "eq"
        value: "staging"
      steps:
        - name: "deploy-staging"
          type: "task"
          module: "file"
          config:
            path: "/opt/app/config.json"
            content: '{"env": "staging"}'
`,
			want: Workflow{
				Name:        "complex-workflow",
				Description: "A complex nested workflow",
				Variables: map[string]interface{}{
					"environment": "staging",
				},
				Steps: []Step{
					{
						Name: "preparation",
						Type: StepTypeSequential,
						Steps: []Step{
							{
								Name: "create-dirs",
								Type: StepTypeParallel,
								Steps: []Step{
									{
										Name:   "create-app-dir",
										Type:   StepTypeTask,
										Module: "directory",
										Config: map[string]interface{}{
											"path":        "/opt/app",
											"permissions": "755",
										},
									},
									{
										Name:   "create-log-dir",
										Type:   StepTypeTask,
										Module: "directory",
										Config: map[string]interface{}{
											"path":        "/var/log/app",
											"permissions": "755",
										},
									},
								},
							},
							{
								Name:   "install-packages",
								Type:   StepTypeTask,
								Module: "package",
								Config: map[string]interface{}{
									"name":  "nginx",
									"state": "present",
								},
							},
						},
					},
					{
						Name: "deployment",
						Type: StepTypeConditional,
						Condition: &Condition{
							Type:     ConditionTypeVariable,
							Variable: "environment",
							Operator: OperatorEqual,
							Value:    "staging",
						},
						Steps: []Step{
							{
								Name:   "deploy-staging",
								Type:   StepTypeTask,
								Module: "file",
								Config: map[string]interface{}{
									"path":    "/opt/app/config.json",
									"content": `{"env": "staging"}`,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid YAML",
			yaml: `
invalid: yaml: structure
  - missing: proper
    nesting
`,
			wantErr: true,
		},
		{
			name: "missing workflow name",
			yaml: `
workflow:
  steps:
    - name: "test-step"
      type: "task"
      module: "test"
      config: {}
`,
			wantErr: true,
		},
		{
			name: "invalid step type",
			yaml: `
workflow:
  name: "invalid-step-type"
  steps:
    - name: "invalid-step"
      type: "invalid"
      config: {}
`,
			wantErr: true,
		},
		{
			name: "task step missing module",
			yaml: `
workflow:
  name: "missing-module"
  steps:
    - name: "task-without-module"
      type: "task"
      config: {}
`,
			wantErr: true,
		},
		{
			name: "conditional step missing condition",
			yaml: `
workflow:
  name: "missing-condition"
  steps:
    - name: "conditional-without-condition"
      type: "conditional"
      steps:
        - name: "child-step"
          type: "task"
          module: "test"
          config: {}
`,
			wantErr: true,
		},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.ParseYAML([]byte(tt.yaml))

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Description, got.Description)
			assert.Equal(t, tt.want.Version, got.Version)
			assert.Equal(t, tt.want.Timeout, got.Timeout)
			assert.Equal(t, tt.want.Variables, got.Variables)

			// Compare steps recursively
			assertStepsEqual(t, tt.want.Steps, got.Steps)
		})
	}
}

func TestParser_ValidateWorkflow(t *testing.T) {
	tests := []struct {
		name     string
		workflow Workflow
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid workflow",
			workflow: Workflow{
				Name: "valid-workflow",
				Steps: []Step{
					{
						Name:   "test-step",
						Type:   StepTypeTask,
						Module: "test-module",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing workflow name",
			workflow: Workflow{
				Steps: []Step{
					{
						Name:   "test-step",
						Type:   StepTypeTask,
						Module: "test-module",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: true,
			errMsg:  "workflow name is required",
		},
		{
			name: "no steps",
			workflow: Workflow{
				Name:  "empty-workflow",
				Steps: []Step{},
			},
			wantErr: true,
			errMsg:  "workflow must have at least one step",
		},
		{
			name: "duplicate step names",
			workflow: Workflow{
				Name: "duplicate-steps",
				Steps: []Step{
					{
						Name:   "duplicate-step",
						Type:   StepTypeTask,
						Module: "test-module",
						Config: map[string]interface{}{"key": "value1"},
					},
					{
						Name:   "duplicate-step",
						Type:   StepTypeTask,
						Module: "test-module",
						Config: map[string]interface{}{"key": "value2"},
					},
				},
			},
			wantErr: true,
			errMsg:  "duplicate step name",
		},
		{
			name: "invalid step type",
			workflow: Workflow{
				Name: "invalid-step-type",
				Steps: []Step{
					{
						Name: "invalid-step",
						Type: "invalid-type",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid step type",
		},
		{
			name: "task step missing module",
			workflow: Workflow{
				Name: "missing-module",
				Steps: []Step{
					{
						Name:   "task-step",
						Type:   StepTypeTask,
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: true,
			errMsg:  "module is required for task steps",
		},
		{
			name: "task step missing config",
			workflow: Workflow{
				Name: "missing-config",
				Steps: []Step{
					{
						Name:   "task-step",
						Type:   StepTypeTask,
						Module: "test-module",
					},
				},
			},
			wantErr: true,
			errMsg:  "config is required for task steps",
		},
		{
			name: "sequential step without children",
			workflow: Workflow{
				Name: "empty-sequential",
				Steps: []Step{
					{
						Name:  "sequential-step",
						Type:  StepTypeSequential,
						Steps: []Step{},
					},
				},
			},
			wantErr: true,
			errMsg:  "sequential steps must have child steps",
		},
		{
			name: "conditional step missing condition",
			workflow: Workflow{
				Name: "missing-condition",
				Steps: []Step{
					{
						Name: "conditional-step",
						Type: StepTypeConditional,
						Steps: []Step{
							{
								Name:   "child-step",
								Type:   StepTypeTask,
								Module: "test-module",
								Config: map[string]interface{}{"key": "value"},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "condition is required for conditional steps",
		},
		{
			name: "negative timeout",
			workflow: Workflow{
				Name:    "negative-timeout",
				Timeout: -1 * time.Minute,
				Steps: []Step{
					{
						Name:   "test-step",
						Type:   StepTypeTask,
						Module: "test-module",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: true,
			errMsg:  "workflow timeout cannot be negative",
		},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.ValidateWorkflow(tt.workflow)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestValidationHelpers(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func() bool
		expected bool
	}{
		{"valid task step type", func() bool { return isValidStepType(StepTypeTask) }, true},
		{"valid sequential step type", func() bool { return isValidStepType(StepTypeSequential) }, true},
		{"valid parallel step type", func() bool { return isValidStepType(StepTypeParallel) }, true},
		{"valid conditional step type", func() bool { return isValidStepType(StepTypeConditional) }, true},
		{"invalid step type", func() bool { return isValidStepType("invalid") }, false},

		{"valid stop action", func() bool { return isValidFailureAction(ActionStop) }, true},
		{"valid continue action", func() bool { return isValidFailureAction(ActionContinue) }, true},
		{"valid retry action", func() bool { return isValidFailureAction(ActionRetry) }, true},
		{"invalid failure action", func() bool { return isValidFailureAction("invalid") }, false},

		{"valid variable condition", func() bool { return isValidConditionType(ConditionTypeVariable) }, true},
		{"valid expression condition", func() bool { return isValidConditionType(ConditionTypeExpression) }, true},
		{"invalid condition type", func() bool { return isValidConditionType("invalid") }, false},

		{"valid equal operator", func() bool { return isValidComparisonOperator(OperatorEqual) }, true},
		{"valid not equal operator", func() bool { return isValidComparisonOperator(OperatorNotEqual) }, true},
		{"valid exists operator", func() bool { return isValidComparisonOperator(OperatorExists) }, true},
		{"invalid comparison operator", func() bool { return isValidComparisonOperator("invalid") }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to recursively compare steps
func assertStepsEqual(t *testing.T, expected, actual []Step) {
	assert.Len(t, actual, len(expected))

	for i, expectedStep := range expected {
		if i >= len(actual) {
			break
		}

		actualStep := actual[i]
		assert.Equal(t, expectedStep.Name, actualStep.Name)
		assert.Equal(t, expectedStep.Type, actualStep.Type)
		assert.Equal(t, expectedStep.Module, actualStep.Module)
		assert.Equal(t, expectedStep.Config, actualStep.Config)
		assert.Equal(t, expectedStep.Timeout, actualStep.Timeout)
		assert.Equal(t, expectedStep.OnFailure, actualStep.OnFailure)
		assert.Equal(t, expectedStep.Variables, actualStep.Variables)

		if expectedStep.Condition != nil {
			require.NotNil(t, actualStep.Condition)
			assert.Equal(t, *expectedStep.Condition, *actualStep.Condition)
		} else {
			assert.Nil(t, actualStep.Condition)
		}

		if len(expectedStep.Steps) > 0 {
			assertStepsEqual(t, expectedStep.Steps, actualStep.Steps)
		}
	}
}
