package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultTransformRegistry(t *testing.T) {
	registry := NewDefaultTransformRegistry()

	assert.NotNil(t, registry)

	metadata := registry.GetMetadata()
	assert.Empty(t, metadata)

	transforms := registry.ListByCategory(CategoryString)
	assert.Empty(t, transforms)
}

func TestTransformRegistry_Register(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	transform := NewMockTransform("test_transform")

	// Test successful registration
	err := registry.Register(transform)
	assert.NoError(t, err)

	// Test duplicate registration
	err = registry.Register(transform)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestTransformRegistry_Get(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	transform := NewMockTransform("test_transform")

	// Test getting non-existent transform
	_, err := registry.Get("non_existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Register and test getting existing transform
	err = registry.Register(transform)
	require.NoError(t, err)

	retrieved, err := registry.Get("test_transform")
	assert.NoError(t, err)
	assert.Equal(t, transform, retrieved)
}

func TestTransformRegistry_List(t *testing.T) {
	registry := NewDefaultTransformRegistry()

	// Test empty registry
	transforms := registry.List()
	assert.Empty(t, transforms)

	// Add transforms
	transform1 := NewMockTransform("transform1")
	transform2 := NewMockTransform("transform2")

	err := registry.Register(transform1)
	require.NoError(t, err)

	err = registry.Register(transform2)
	require.NoError(t, err)

	// Test listing all transforms
	transforms = registry.List()
	assert.Len(t, transforms, 2)

	// Check if both transforms are present
	names := make([]string, len(transforms))
	for i, t := range transforms {
		names[i] = t.GetMetadata().Name
	}
	assert.Contains(t, names, "transform1")
	assert.Contains(t, names, "transform2")
}

func TestTransformRegistry_ListByCategory(t *testing.T) {
	registry := NewDefaultTransformRegistry()

	// Create transforms with different categories
	stringTransform := NewMockTransform("string_transform")
	stringTransform.SetMetadata(TransformMetadata{
		Name:     "string_transform",
		Category: CategoryString,
	})

	dataTransform := NewMockTransform("data_transform")
	dataTransform.SetMetadata(TransformMetadata{
		Name:     "data_transform",
		Category: CategoryData,
	})

	testTransform := NewMockTransform("test_transform")
	testTransform.SetMetadata(TransformMetadata{
		Name:     "test_transform",
		Category: CategoryTest,
	})

	// Register transforms
	err := registry.Register(stringTransform)
	require.NoError(t, err)

	err = registry.Register(dataTransform)
	require.NoError(t, err)

	err = registry.Register(testTransform)
	require.NoError(t, err)

	// Test filtering by category
	stringTransforms := registry.ListByCategory(CategoryString)
	assert.Len(t, stringTransforms, 1)
	assert.Equal(t, "string_transform", stringTransforms[0].GetMetadata().Name)

	dataTransforms := registry.ListByCategory(CategoryData)
	assert.Len(t, dataTransforms, 1)
	assert.Equal(t, "data_transform", dataTransforms[0].GetMetadata().Name)

	testTransforms := registry.ListByCategory(CategoryTest)
	assert.Len(t, testTransforms, 1)
	assert.Equal(t, "test_transform", testTransforms[0].GetMetadata().Name)

	// Test empty category
	mathTransforms := registry.ListByCategory(CategoryMath)
	assert.Empty(t, mathTransforms)
}

func TestTransformRegistry_GetMetadata(t *testing.T) {
	registry := NewDefaultTransformRegistry()

	// Test empty registry
	metadata := registry.GetMetadata()
	assert.Empty(t, metadata)

	// Add transform and test metadata
	transform := NewMockTransform("test_transform")
	err := registry.Register(transform)
	require.NoError(t, err)

	metadata = registry.GetMetadata()
	assert.Len(t, metadata, 1)
	assert.Equal(t, "test_transform", metadata[0].Name)
	assert.Equal(t, CategoryTest, metadata[0].Category)
}

func TestTransformRegistry_Search(t *testing.T) {
	// TODO: Implement Search functionality in registry
	// This test is placeholder for future search implementation
	registry := NewDefaultTransformRegistry()
	assert.NotNil(t, registry)
}

func TestTransformRegistry_Unregister(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	transform := NewMockTransform("test_transform")

	// Test unregistering non-existent transform
	err := registry.Unregister("non_existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Register and unregister transform
	err = registry.Register(transform)
	require.NoError(t, err)

	// Verify it's registered
	_, err = registry.Get("test_transform")
	assert.NoError(t, err)

	// Unregister it
	err = registry.Unregister("test_transform")
	assert.NoError(t, err)

	// Verify it's gone
	_, err = registry.Get("test_transform")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTransformRegistry_ThreadSafety(t *testing.T) {
	registry := NewDefaultTransformRegistry()

	// Test concurrent registration
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			transform := NewMockTransform(string(rune('A' + index)))
			err := registry.Register(transform)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all transforms were registered
	transforms := registry.List()
	assert.Len(t, transforms, 10)
}

func TestGetGlobalRegistry(t *testing.T) {
	// Test that global registry is a singleton
	registry1 := GetGlobalRegistry()
	registry2 := GetGlobalRegistry()

	assert.Same(t, registry1, registry2)

	// Test that we can use the global registry
	transform := NewMockTransform("global_test")
	err := registry1.Register(transform)
	assert.NoError(t, err)

	// Verify it's accessible from the second reference
	retrieved, err := registry2.Get("global_test")
	assert.NoError(t, err)
	assert.Equal(t, transform, retrieved)
}

func TestTransformRegistry_RegisterNilTransform(t *testing.T) {
	registry := NewDefaultTransformRegistry()

	err := registry.Register(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transform cannot be nil")
}

func TestTransformRegistry_EmptyNameTransform(t *testing.T) {
	registry := NewDefaultTransformRegistry()
	transform := NewMockTransform("")

	err := registry.Register(transform)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transform name cannot be empty")
}