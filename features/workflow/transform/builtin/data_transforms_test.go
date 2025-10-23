// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/workflow/transform"
)

func TestDataTransformsCompile(t *testing.T) {
	// Test that all data transforms compile and can be created

	jsonParseTransform := NewJSONParseTransform()
	assert.NotNil(t, jsonParseTransform)
	assert.Equal(t, "json_parse", jsonParseTransform.GetMetadata().Name)

	jsonGenTransform := NewJSONGenerateTransform()
	assert.NotNil(t, jsonGenTransform)
	assert.Equal(t, "json_generate", jsonGenTransform.GetMetadata().Name)

	typeTransform := NewTypeConvertTransform()
	assert.NotNil(t, typeTransform)
	assert.Equal(t, "type_convert", typeTransform.GetMetadata().Name)
}

func TestDataTransformsValidation(t *testing.T) {
	// Test that transforms validate correctly

	jsonParseTransform := NewJSONParseTransform()
	err := jsonParseTransform.Validate(nil)
	assert.NoError(t, err)

	typeTransform := NewTypeConvertTransform()
	err = typeTransform.Validate(map[string]interface{}{
		"target_type": "string",
	})
	assert.NoError(t, err)

	err = typeTransform.Validate(nil)
	assert.Error(t, err) // Should fail validation
}

func TestDataTransformsRegistration(t *testing.T) {
	// Test that transforms can be registered in the global registry
	registry := transform.NewDefaultTransformRegistry()

	transforms := []transform.Transform{
		NewJSONParseTransform(),
		NewJSONGenerateTransform(),
		NewTypeConvertTransform(),
	}

	for _, tr := range transforms {
		err := registry.Register(tr)
		assert.NoError(t, err, "Failed to register transform: %s", tr.GetMetadata().Name)
	}

	// Verify all transforms are registered
	metadata := registry.GetMetadata()
	assert.Len(t, metadata, 3)

	// Test retrieval
	for _, tr := range transforms {
		retrieved, err := registry.Get(tr.GetMetadata().Name)
		assert.NoError(t, err)
		assert.Equal(t, tr.GetMetadata().Name, retrieved.GetMetadata().Name)
	}
}
