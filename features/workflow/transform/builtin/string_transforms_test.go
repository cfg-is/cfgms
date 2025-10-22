package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/workflow/transform"
)

func TestStringTransformsCompile(t *testing.T) {
	// Test that all string transforms compile and can be created

	upperTransform := NewUppercaseTransform()
	assert.NotNil(t, upperTransform)
	assert.Equal(t, "uppercase", upperTransform.GetMetadata().Name)

	lowerTransform := NewLowercaseTransform()
	assert.NotNil(t, lowerTransform)
	assert.Equal(t, "lowercase", lowerTransform.GetMetadata().Name)

	trimTransform := NewTrimTransform()
	assert.NotNil(t, trimTransform)
	assert.Equal(t, "trim", trimTransform.GetMetadata().Name)

	replaceTransform := NewReplaceTransform()
	assert.NotNil(t, replaceTransform)
	assert.Equal(t, "replace", replaceTransform.GetMetadata().Name)

	formatTransform := NewFormatTransform()
	assert.NotNil(t, formatTransform)
	assert.Equal(t, "format", formatTransform.GetMetadata().Name)
}

func TestStringTransformsValidation(t *testing.T) {
	// Test that transforms validate correctly

	upperTransform := NewUppercaseTransform()
	err := upperTransform.Validate(nil)
	assert.NoError(t, err)

	replaceTransform := NewReplaceTransform()
	err = replaceTransform.Validate(map[string]interface{}{
		"new": "replacement",
		"old": "original",
	})
	assert.NoError(t, err)

	err = replaceTransform.Validate(nil)
	assert.Error(t, err) // Should fail validation
}

func TestStringTransformsRegistration(t *testing.T) {
	// Test that transforms can be registered in the global registry
	registry := transform.NewDefaultTransformRegistry()

	transforms := []transform.Transform{
		NewUppercaseTransform(),
		NewLowercaseTransform(),
		NewTrimTransform(),
		NewReplaceTransform(),
		NewFormatTransform(),
	}

	for _, tr := range transforms {
		err := registry.Register(tr)
		assert.NoError(t, err, "Failed to register transform: %s", tr.GetMetadata().Name)
	}

	// Verify all transforms are registered
	metadata := registry.GetMetadata()
	assert.Len(t, metadata, 5)

	// Test retrieval
	for _, tr := range transforms {
		retrieved, err := registry.Get(tr.GetMetadata().Name)
		assert.NoError(t, err)
		assert.Equal(t, tr.GetMetadata().Name, retrieved.GetMetadata().Name)
	}
}
