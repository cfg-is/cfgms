package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateEngine_ValidateTemplate(t *testing.T) {
	engine := NewTemplateEngine()

	tests := []struct {
		name     string
		template *WorkflowTemplate
		hasError bool
	}{
		{
			name: "valid template",
			template: &WorkflowTemplate{
				ID:   "test-template",
				Name: "Test Template",
				Version: SemanticVersion{1, 0, 0, "", ""},
				Parameters: []TemplateParameter{
					{
						Name:     "param1",
						Type:     ParameterTypeString,
						Required: true,
					},
				},
				Workflow: Workflow{
					Name:  "test-workflow",
					Steps: []Step{},
				},
			},
			hasError: false,
		},
		{
			name: "missing ID",
			template: &WorkflowTemplate{
				Name: "Test Template",
				Version: SemanticVersion{1, 0, 0, "", ""},
				Workflow: Workflow{
					Name:  "test-workflow",
					Steps: []Step{},
				},
			},
			hasError: true,
		},
		{
			name: "missing name",
			template: &WorkflowTemplate{
				ID:      "test-template",
				Version: SemanticVersion{1, 0, 0, "", ""},
				Workflow: Workflow{
					Name:  "test-workflow",
					Steps: []Step{},
				},
			},
			hasError: true,
		},
		{
			name: "duplicate parameter names",
			template: &WorkflowTemplate{
				ID:   "test-template",
				Name: "Test Template",
				Version: SemanticVersion{1, 0, 0, "", ""},
				Parameters: []TemplateParameter{
					{Name: "param1", Type: ParameterTypeString},
					{Name: "param1", Type: ParameterTypeInt},
				},
				Workflow: Workflow{
					Name:  "test-workflow",
					Steps: []Step{},
				},
			},
			hasError: true,
		},
		{
			name: "invalid parameter type",
			template: &WorkflowTemplate{
				ID:   "test-template",
				Name: "Test Template",
				Version: SemanticVersion{1, 0, 0, "", ""},
				Parameters: []TemplateParameter{
					{Name: "param1", Type: ParameterType("invalid")},
				},
				Workflow: Workflow{
					Name:  "test-workflow",
					Steps: []Step{},
				},
			},
			hasError: true,
		},
		{
			name: "missing workflow name",
			template: &WorkflowTemplate{
				ID:      "test-template",
				Name:    "Test Template",
				Version: SemanticVersion{1, 0, 0, "", ""},
				Workflow: Workflow{
					Steps: []Step{},
				},
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidateTemplate(tt.template)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTemplateEngine_RegisterTemplate(t *testing.T) {
	engine := NewTemplateEngine()

	template := &WorkflowTemplate{
		ID:   "test-template",
		Name: "Test Template",
		Version: SemanticVersion{1, 0, 0, "", ""},
		Workflow: Workflow{
			Name:  "test-workflow",
			Steps: []Step{},
		},
	}

	// Register template
	err := engine.RegisterTemplate(template)
	require.NoError(t, err)

	// Retrieve template
	retrieved, err := engine.GetTemplate("test-template")
	require.NoError(t, err)
	assert.Equal(t, template, retrieved)

	// Try to get non-existent template
	_, err = engine.GetTemplate("non-existent")
	assert.Error(t, err)
}

func TestTemplateEngine_ValidateParameters(t *testing.T) {
	engine := NewTemplateEngine()

	template := &WorkflowTemplate{
		Parameters: []TemplateParameter{
			{
				Name:     "required_string",
				Type:     ParameterTypeString,
				Required: true,
			},
			{
				Name:     "optional_int",
				Type:     ParameterTypeInt,
				Required: false,
				Default:  42,
			},
			{
				Name:    "pattern_string",
				Type:    ParameterTypeString,
				Pattern: "^[a-z]+$",
			},
			{
				Name:      "length_string",
				Type:      ParameterTypeString,
				MinLength: 3,
				MaxLength: 10,
			},
			{
				Name:    "enum_param",
				Type:    ParameterTypeEnum,
				Options: []interface{}{"option1", "option2", "option3"},
			},
		},
	}

	tests := []struct {
		name       string
		parameters map[string]interface{}
		hasError   bool
	}{
		{
			name: "valid parameters",
			parameters: map[string]interface{}{
				"required_string": "test",
				"optional_int":    10,
				"pattern_string":  "hello",
				"length_string":   "valid",
				"enum_param":      "option1",
			},
			hasError: false,
		},
		{
			name:       "missing required parameter",
			parameters: map[string]interface{}{},
			hasError:   true,
		},
		{
			name: "wrong type",
			parameters: map[string]interface{}{
				"required_string": "test",
				"optional_int":    "not_an_int",
			},
			hasError: true,
		},
		{
			name: "pattern mismatch",
			parameters: map[string]interface{}{
				"required_string": "test",
				"pattern_string":  "HELLO123",
			},
			hasError: true,
		},
		{
			name: "string too short",
			parameters: map[string]interface{}{
				"required_string": "test",
				"length_string":   "hi",
			},
			hasError: true,
		},
		{
			name: "string too long",
			parameters: map[string]interface{}{
				"required_string": "test",
				"length_string":   "this_is_too_long",
			},
			hasError: true,
		},
		{
			name: "invalid enum value",
			parameters: map[string]interface{}{
				"required_string": "test",
				"enum_param":      "invalid_option",
			},
			hasError: true,
		},
		{
			name: "unknown parameter",
			parameters: map[string]interface{}{
				"required_string":   "test",
				"unknown_parameter": "value",
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidateParameters(template, tt.parameters)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTemplateEngine_MergeWithDefaults(t *testing.T) {
	engine := NewTemplateEngine()

	template := &WorkflowTemplate{
		Defaults: map[string]interface{}{
			"global_default": "global_value",
			"override_me":    "global_value",
		},
		Parameters: []TemplateParameter{
			{
				Name:    "param_with_default",
				Type:    ParameterTypeString,
				Default: "param_default",
			},
			{
				Name:    "override_me",
				Type:    ParameterTypeString,
				Default: "param_default",
			},
		},
	}

	parameters := map[string]interface{}{
		"override_me":    "user_value",
		"user_provided": "user_value",
	}

	result := engine.MergeWithDefaults(template, parameters)

	expected := map[string]interface{}{
		"global_default":     "global_value",
		"param_with_default": "param_default",
		"override_me":        "user_value",
		"user_provided":      "user_value",
	}

	assert.Equal(t, expected, result)
}

func TestTemplateEngine_InstantiateTemplate(t *testing.T) {
	engine := NewTemplateEngine()

	template := &WorkflowTemplate{
		ID:      "test-template",
		Name:    "Test Template",
		Version: SemanticVersion{1, 0, 0, "", ""},
		Parameters: []TemplateParameter{
			{
				Name:     "workflow_name",
				Type:     ParameterTypeString,
				Required: true,
			},
		},
		Workflow: Workflow{
			Name:        "test-workflow",
			Description: "Template workflow",
			Steps:       []Step{},
		},
	}

	err := engine.RegisterTemplate(template)
	require.NoError(t, err)

	t.Run("successful instantiation", func(t *testing.T) {
		parameters := map[string]interface{}{
			"workflow_name": "my-workflow",
		}

		instance, err := engine.InstantiateTemplate(context.Background(), "test-template", parameters)
		require.NoError(t, err)

		assert.NotEmpty(t, instance.ID)
		assert.Equal(t, "test-template", instance.TemplateID)
		assert.Equal(t, "Test Template", instance.TemplateName)
		assert.Equal(t, parameters["workflow_name"], instance.Parameters["workflow_name"])
		assert.NotZero(t, instance.CreatedAt)
	})

	t.Run("template not found", func(t *testing.T) {
		_, err := engine.InstantiateTemplate(context.Background(), "non-existent", map[string]interface{}{})
		assert.Error(t, err)
	})

	t.Run("parameter validation fails", func(t *testing.T) {
		_, err := engine.InstantiateTemplate(context.Background(), "test-template", map[string]interface{}{})
		assert.Error(t, err)
	})
}

func TestTemplateEngine_ResolveInheritance(t *testing.T) {
	engine := NewTemplateEngine()

	// Parent template
	parent := &WorkflowTemplate{
		ID:      "parent-template",
		Name:    "Parent Template",
		Version: SemanticVersion{1, 0, 0, "", ""},
		Parameters: []TemplateParameter{
			{Name: "parent_param", Type: ParameterTypeString},
		},
		Defaults: map[string]interface{}{
			"parent_default": "parent_value",
			"override_me":    "parent_value",
		},
		Workflow: Workflow{
			Name:        "parent-workflow",
			Description: "Parent workflow",
		},
	}

	// Child template
	child := &WorkflowTemplate{
		ID:      "child-template",
		Name:    "Child Template",
		Version: SemanticVersion{1, 0, 0, "", ""},
		Extends: "parent-template",
		Parameters: []TemplateParameter{
			{Name: "child_param", Type: ParameterTypeInt},
		},
		Defaults: map[string]interface{}{
			"child_default": "child_value",
			"override_me":   "child_value",
		},
		Workflow: Workflow{
			Name:        "child-workflow",
			Description: "Child workflow",
		},
	}

	err := engine.RegisterTemplate(parent)
	require.NoError(t, err)

	err = engine.RegisterTemplate(child)
	require.NoError(t, err)

	t.Run("resolve inheritance", func(t *testing.T) {
		resolved, err := engine.ResolveInheritance(child)
		require.NoError(t, err)

		// Check that inheritance was resolved
		assert.Empty(t, resolved.Extends)

		// Check parameter merging
		assert.Len(t, resolved.Parameters, 2)
		paramNames := make([]string, len(resolved.Parameters))
		for i, param := range resolved.Parameters {
			paramNames[i] = param.Name
		}
		assert.Contains(t, paramNames, "parent_param")
		assert.Contains(t, paramNames, "child_param")

		// Check defaults merging (child should override parent)
		assert.Equal(t, "parent_value", resolved.Defaults["parent_default"])
		assert.Equal(t, "child_value", resolved.Defaults["child_default"])
		assert.Equal(t, "child_value", resolved.Defaults["override_me"])

		// Check that child workflow takes precedence
		assert.Equal(t, "child-workflow", resolved.Workflow.Name)
		assert.Equal(t, "Child workflow", resolved.Workflow.Description)
	})

	t.Run("no inheritance", func(t *testing.T) {
		resolved, err := engine.ResolveInheritance(parent)
		require.NoError(t, err)
		assert.Equal(t, parent, resolved)
	})

	t.Run("parent not found", func(t *testing.T) {
		orphan := &WorkflowTemplate{
			ID:      "orphan-template",
			Name:    "Orphan Template",
			Version: SemanticVersion{1, 0, 0, "", ""},
			Extends: "non-existent-parent",
		}

		_, err := engine.ResolveInheritance(orphan)
		assert.Error(t, err)
	})
}

func TestTemplateEngine_AbstractTemplate(t *testing.T) {
	engine := NewTemplateEngine()

	abstract := &WorkflowTemplate{
		ID:       "abstract-template",
		Name:     "Abstract Template",
		Version:  SemanticVersion{1, 0, 0, "", ""},
		Abstract: true,
		Workflow: Workflow{
			Name: "abstract-workflow",
		},
	}

	err := engine.RegisterTemplate(abstract)
	require.NoError(t, err)

	t.Run("cannot instantiate abstract template", func(t *testing.T) {
		_, err := engine.InstantiateTemplate(context.Background(), "abstract-template", map[string]interface{}{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot instantiate abstract template")
	})
}

func TestTemplateEngine_ProcessSubstitutions(t *testing.T) {
	engine := NewTemplateEngine()

	parameters := map[string]interface{}{
		"name":        "test-name",
		"port":        8080,
		"enabled":     true,
		"description": "A test workflow",
	}

	tests := []struct {
		name     string
		input    string
		expected string
		hasError bool
	}{
		{
			name:     "simple substitution",
			input:    "workflow name: ${name}",
			expected: "workflow name: test-name",
			hasError: false,
		},
		{
			name:     "multiple substitutions",
			input:    "name: ${name}, port: ${port}, enabled: ${enabled}",
			expected: "name: test-name, port: 8080, enabled: true",
			hasError: false,
		},
		{
			name:     "no substitutions",
			input:    "static content",
			expected: "static content",
			hasError: false,
		},
		{
			name:     "undefined parameter",
			input:    "name: ${undefined_param}",
			expected: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.processSubstitutions(tt.input, parameters)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestWorkflowTemplate_CreationAndUpdate(t *testing.T) {
	template := &WorkflowTemplate{
		ID:          "test-template",
		Name:        "Test Template",
		Description: "A test template",
		Version:     SemanticVersion{1, 0, 0, "", ""},
		Author:      "test-author",
		Parameters: []TemplateParameter{
			{
				Name:        "name",
				Type:        ParameterTypeString,
				Description: "The name parameter",
				Required:    true,
			},
		},
		Workflow: Workflow{
			Name:        "${name}",
			Description: "Generated from template",
		},
		Tags:     []string{"test", "template"},
		Category: "testing",
	}

	// Simulate creation timestamps
	now := time.Now()
	template.CreatedAt = now
	template.UpdatedAt = now

	assert.Equal(t, "test-template", template.ID)
	assert.Equal(t, "Test Template", template.Name)
	assert.Equal(t, SemanticVersion{1, 0, 0, "", ""}, template.Version)
	assert.Len(t, template.Parameters, 1)
	assert.Equal(t, "name", template.Parameters[0].Name)
	assert.True(t, template.Parameters[0].Required)
	assert.Contains(t, template.Tags, "test")
	assert.Equal(t, "testing", template.Category)
	assert.False(t, template.Abstract)
	assert.Empty(t, template.Extends)
}