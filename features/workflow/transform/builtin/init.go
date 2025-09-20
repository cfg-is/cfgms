package builtin

import (
	"github.com/cfgis/cfgms/features/workflow/transform"
)

// init automatically registers all built-in transforms when the package is imported
//
// This provides automatic discovery and registration of built-in transforms
// without requiring manual registration code. New built-in transforms can be
// added by implementing the Transform interface and adding them to this list.
func init() {
	registerBuiltinTransforms()
}

// registerBuiltinTransforms registers all built-in transforms with the global registry
func registerBuiltinTransforms() {
	registry := transform.GetGlobalRegistry()

	// String transforms
	registerTransform(registry, NewUppercaseTransform(), "uppercase")
	registerTransform(registry, NewLowercaseTransform(), "lowercase")
	registerTransform(registry, NewTrimTransform(), "trim")
	registerTransform(registry, NewReplaceTransform(), "replace")
	registerTransform(registry, NewFormatTransform(), "format")

	// Data transforms
	registerTransform(registry, NewJSONParseTransform(), "json_parse")
	registerTransform(registry, NewJSONGenerateTransform(), "json_generate")
	registerTransform(registry, NewTypeConvertTransform(), "type_convert")
}

// registerTransform safely registers a transform with error handling
func registerTransform(registry transform.TransformRegistry, t transform.Transform, name string) {
	if err := registry.Register(t); err != nil {
		// In production, you might want to use a proper logger here
		// For now, we'll just ignore registration errors to prevent panics
		// The transform will simply not be available if registration fails
		_ = err // Silence unused variable warning
	}
}

// GetAllBuiltinTransforms returns metadata for all built-in transforms
//
// This is useful for documentation generation and runtime inspection
// of available built-in capabilities.
func GetAllBuiltinTransforms() []transform.TransformMetadata {
	registry := transform.GetGlobalRegistry()
	return registry.GetMetadata()
}

// GetBuiltinTransformsByCategory returns built-in transforms filtered by category
func GetBuiltinTransformsByCategory(category transform.TransformCategory) []transform.TransformMetadata {
	registry := transform.GetGlobalRegistry()
	transforms := registry.ListByCategory(category)

	var metadata []transform.TransformMetadata
	for _, t := range transforms {
		metadata = append(metadata, t.GetMetadata())
	}

	return metadata
}

// IsBuiltinTransform checks if a transform name corresponds to a built-in transform
func IsBuiltinTransform(name string) bool {
	registry := transform.GetGlobalRegistry()
	_, err := registry.Get(name)
	return err == nil
}

// CreateBuiltinTransformExecutor creates a fully configured transform executor
// with all built-in transforms registered and ready to use
func CreateBuiltinTransformExecutor(cache transform.TransformCache, logger transform.TransformLogger) transform.TransformExecutor {
	registry := transform.GetGlobalRegistry()

	// If no cache provided, use a default memory cache
	if cache == nil {
		cache = transform.DefaultMemoryTransformCache()
	}

	// If no logger provided, use a no-op logger
	if logger == nil {
		logger = &transform.NoOpTransformLogger{}
	}

	return transform.NewDefaultTransformExecutor(registry, cache, logger)
}

// BuiltinTransformList contains the names of all built-in transforms
var BuiltinTransformList = []string{
	// String transforms
	"uppercase",
	"lowercase",
	"trim",
	"replace",
	"format",

	// Data transforms
	"json_parse",
	"json_generate",
	"type_convert",
}

// BuiltinTransformsByCategory organizes built-in transforms by category
var BuiltinTransformsByCategory = map[transform.TransformCategory][]string{
	transform.CategoryString: {
		"uppercase",
		"lowercase",
		"trim",
		"replace",
		"format",
	},
	transform.CategoryData: {
		"json_parse",
		"json_generate",
		"type_convert",
	},
}

// ExampleWorkflows provides example workflow definitions using built-in transforms
var ExampleWorkflows = map[string]interface{}{
	"simple_text_processing": map[string]interface{}{
		"name":        "Simple Text Processing",
		"description": "Demonstrates basic string transforms",
		"variables": map[string]interface{}{
			"input_text": "  Hello, World!  ",
		},
		"steps": []interface{}{
			map[string]interface{}{
				"name": "trim_text",
				"type": "transform",
				"config": map[string]interface{}{
					"transform": "trim",
					"input_mapping": map[string]string{
						"text": "input_text",
					},
					"output_mapping": map[string]string{
						"text": "trimmed_text",
					},
				},
			},
			map[string]interface{}{
				"name": "uppercase_text",
				"type": "transform",
				"config": map[string]interface{}{
					"transform": "uppercase",
					"input_mapping": map[string]string{
						"text": "trimmed_text",
					},
					"output_mapping": map[string]string{
						"text": "final_text",
					},
				},
			},
		},
	},

	"data_processing_chain": map[string]interface{}{
		"name":        "Data Processing Chain",
		"description": "Demonstrates data transforms and chaining",
		"variables": map[string]interface{}{
			"user_data": `{"name": "alice", "age": "30", "active": "true"}`,
		},
		"steps": []interface{}{
			map[string]interface{}{
				"name": "process_user_data",
				"type": "transform",
				"config": map[string]interface{}{
					"chain": []interface{}{
						map[string]interface{}{
							"name": "json_parse",
							"input_mapping": map[string]string{
								"json": "user_data",
							},
						},
						map[string]interface{}{
							"name": "type_convert",
							"config": map[string]interface{}{
								"target_type": "number",
							},
							"input_mapping": map[string]string{
								"value": "age",
							},
							"output_mapping": map[string]string{
								"value": "age_numeric",
							},
						},
						map[string]interface{}{
							"name": "uppercase",
							"input_mapping": map[string]string{
								"text": "name",
							},
							"output_mapping": map[string]string{
								"text": "name_upper",
							},
						},
					},
					"output_mapping": map[string]string{
						"name_upper":   "processed_name",
						"age_numeric":  "processed_age",
						"active":       "is_active",
					},
				},
			},
		},
	},
}