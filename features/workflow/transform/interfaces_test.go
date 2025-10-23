// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package transform

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTransform for testing
type MockTransform struct {
	BaseTransform
	executeFunc  func(ctx context.Context, transformCtx TransformContext) (TransformResult, error)
	validateFunc func(config map[string]interface{}) error
}

func NewMockTransform(name string) *MockTransform {
	t := &MockTransform{}
	t.SetMetadata(TransformMetadata{
		Name:        name,
		Version:     "1.0.0",
		Description: "Mock transform for testing",
		Category:    CategoryTest,
		Tags:        []string{"test", "mock"},
		Author:      "Test",
	})
	t.SetSchema(TransformSchema{
		InputSchema: SchemaDefinition{
			Type: "object",
			Properties: map[string]SchemaDefinition{
				"test": {Type: "string", Description: "Test input"},
			},
			Required: []string{"test"},
		},
		OutputSchema: SchemaDefinition{
			Type: "object",
			Properties: map[string]SchemaDefinition{
				"result": {Type: "string", Description: "Test output"},
			},
		},
	})
	return t
}

func (t *MockTransform) Execute(ctx context.Context, transformCtx TransformContext) (TransformResult, error) {
	if t.executeFunc != nil {
		return t.executeFunc(ctx, transformCtx)
	}

	// Default implementation
	input := transformCtx.GetString("test")
	return TransformResult{
		Data: map[string]interface{}{
			"result": "processed_" + input,
		},
		Success:  true,
		Duration: time.Millisecond * 10,
	}, nil
}

func (t *MockTransform) Validate(config map[string]interface{}) error {
	if t.validateFunc != nil {
		return t.validateFunc(config)
	}
	return nil
}

func TestTransformMetadata(t *testing.T) {
	metadata := TransformMetadata{
		Name:        "test_transform",
		Version:     "1.0.0",
		Description: "A test transform",
		Category:    CategoryString,
		Tags:        []string{"test", "string"},
		Author:      "Test Author",
		Examples: []TransformExample{
			{
				Name:        "Basic example",
				Description: "Basic usage",
				Input:       map[string]interface{}{"text": "hello"},
				Config:      map[string]interface{}{},
				Output:      map[string]interface{}{"text": "HELLO"},
			},
		},
		SupportsChaining: true,
	}

	assert.Equal(t, "test_transform", metadata.Name)
	assert.Equal(t, "1.0.0", metadata.Version)
	assert.Equal(t, CategoryString, metadata.Category)
	assert.True(t, metadata.SupportsChaining)
	assert.Len(t, metadata.Examples, 1)
	assert.Equal(t, "Basic example", metadata.Examples[0].Name)
}

func TestTransformSchema(t *testing.T) {
	schema := TransformSchema{
		InputSchema: SchemaDefinition{
			Type: "object",
			Properties: map[string]SchemaDefinition{
				"text": {Type: "string", Description: "Input text"},
			},
			Required: []string{"text"},
		},
		OutputSchema: SchemaDefinition{
			Type: "object",
			Properties: map[string]SchemaDefinition{
				"result": {Type: "string", Description: "Output result"},
			},
		},
		ConfigSchema: SchemaDefinition{
			Type: "object",
			Properties: map[string]SchemaDefinition{
				"uppercase": {Type: "boolean", Description: "Convert to uppercase"},
			},
		},
	}

	assert.Equal(t, "object", schema.InputSchema.Type)
	assert.Contains(t, schema.InputSchema.Required, "text")
	assert.Equal(t, "string", schema.InputSchema.Properties["text"].Type)
	assert.Equal(t, "Input text", schema.InputSchema.Properties["text"].Description)
}

func TestTransformResult(t *testing.T) {
	result := TransformResult{
		Data: map[string]interface{}{
			"output": "test_result",
		},
		Success:  true,
		Duration: time.Millisecond * 50,
		Warnings: []string{"Minor warning"},
		Metadata: map[string]interface{}{"process_id": 123},
		Error:    "",
	}

	assert.True(t, result.Success)
	assert.Equal(t, "test_result", result.Data["output"])
	assert.Equal(t, time.Millisecond*50, result.Duration)
	assert.Len(t, result.Warnings, 1)
	assert.Equal(t, "Minor warning", result.Warnings[0])
	assert.Equal(t, 123, result.Metadata["process_id"])
	assert.Empty(t, result.Error)
}

func TestTransformStep(t *testing.T) {
	step := TransformStep{
		Name: "test_transform",
		Config: map[string]interface{}{
			"param1": "value1",
		},
		InputMapping: map[string]string{
			"input_field": "workflow_var",
		},
		OutputMapping: map[string]string{
			"output_field": "result_var",
		},
		Condition: "workflow.status == 'active'",
		OnError:   ErrorActionContinue,
	}

	assert.Equal(t, "test_transform", step.Name)
	assert.Equal(t, "value1", step.Config["param1"])
	assert.Equal(t, "workflow_var", step.InputMapping["input_field"])
	assert.Equal(t, "result_var", step.OutputMapping["output_field"])
	assert.Equal(t, ErrorActionContinue, step.OnError)
}

func TestBaseTransform(t *testing.T) {
	transform := NewMockTransform("base_test")

	metadata := transform.GetMetadata()
	assert.Equal(t, "base_test", metadata.Name)
	assert.Equal(t, "1.0.0", metadata.Version)
	assert.Equal(t, CategoryTest, metadata.Category)

	schema := transform.GetSchema()
	assert.Equal(t, "object", schema.InputSchema.Type)
	assert.Contains(t, schema.InputSchema.Required, "test")

	err := transform.Validate(nil)
	assert.NoError(t, err)
}

func TestMockTransformExecution(t *testing.T) {
	transform := NewMockTransform("mock_test")

	ctx := context.Background()
	transformCtx := NewDefaultTransformContext(
		map[string]interface{}{"test": "hello"},
		map[string]interface{}{},
		map[string]interface{}{},
	)

	result, err := transform.Execute(ctx, transformCtx)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "processed_hello", result.Data["result"])
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestTransformCategories(t *testing.T) {
	categories := []TransformCategory{
		CategoryString,
		CategoryData,
		CategoryMath,
		CategoryValidation,
		CategoryPath,
		CategoryTemplate,
		CategoryCustom,
		CategoryTest,
	}

	for _, category := range categories {
		assert.NotEmpty(t, string(category))
	}

	assert.Equal(t, "string", string(CategoryString))
	assert.Equal(t, "data", string(CategoryData))
	assert.Equal(t, "math", string(CategoryMath))
	assert.Equal(t, "validation", string(CategoryValidation))
}

func TestTransformErrorActions(t *testing.T) {
	actions := []TransformErrorAction{
		ErrorActionStop,
		ErrorActionContinue,
		ErrorActionRetry,
		ErrorActionSkip,
	}

	for _, action := range actions {
		assert.NotEmpty(t, string(action))
	}

	assert.Equal(t, "stop", string(ErrorActionStop))
	assert.Equal(t, "continue", string(ErrorActionContinue))
	assert.Equal(t, "retry", string(ErrorActionRetry))
	assert.Equal(t, "skip", string(ErrorActionSkip))
}
