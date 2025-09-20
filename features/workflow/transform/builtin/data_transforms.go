package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/workflow/transform"
)

// JSONParseTransform parses JSON strings into structured data
type JSONParseTransform struct {
	transform.BaseTransform
}

// NewJSONParseTransform creates a new JSON parse transform
func NewJSONParseTransform() *JSONParseTransform {
	t := &JSONParseTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "json_parse",
		Version:     "1.0.0",
		Description: "Parses JSON strings into structured data objects",
		Category:    transform.CategoryData,
		Tags:        []string{"json", "parse", "data", "deserialize"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Parse JSON object",
				Description: "Parse a JSON string into an object",
				Input:       map[string]interface{}{"json": `{"name": "Alice", "age": 30}`},
				Config:      map[string]interface{}{},
				Output: map[string]interface{}{
					"data": map[string]interface{}{
						"name": "Alice",
						"age":  float64(30),
					},
				},
			},
			{
				Name:        "Parse JSON array",
				Description: "Parse a JSON array",
				Input:       map[string]interface{}{"json": `[1, 2, 3, "test"]`},
				Config:      map[string]interface{}{},
				Output: map[string]interface{}{
					"data": []interface{}{float64(1), float64(2), float64(3), "test"},
				},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"json": {Type: "string", Description: "The JSON string to parse"},
			},
			Required: []string{"json"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"data": {Description: "The parsed JSON data"},
			},
		},
		ConfigSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"strict": {
					Type:        "boolean",
					Description: "Whether to use strict JSON parsing (default: false)",
				},
			},
		},
	})

	return t
}

// Execute performs the JSON parse transformation
func (t *JSONParseTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	jsonStr := transformCtx.GetString("json")
	if jsonStr == "" {
		return transform.TransformResult{
			Success: false,
			Error:   "input 'json' is required and must be a non-empty string",
		}, nil
	}

	var data interface{}
	var err error

	strict := transformCtx.GetConfigBool("strict")
	if strict {
		decoder := json.NewDecoder(strings.NewReader(jsonStr))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&data)
	} else {
		err = json.Unmarshal([]byte(jsonStr), &data)
	}

	if err != nil {
		return transform.TransformResult{
			Success: false,
			Error:   fmt.Sprintf("failed to parse JSON: %v", err),
		}, nil
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"data": data,
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}

// Validate validates the JSON parse transform configuration
func (t *JSONParseTransform) Validate(config map[string]interface{}) error {
	// No special validation needed - strict field is optional boolean
	return nil
}

// JSONGenerateTransform converts structured data to JSON strings
type JSONGenerateTransform struct {
	transform.BaseTransform
}

// NewJSONGenerateTransform creates a new JSON generate transform
func NewJSONGenerateTransform() *JSONGenerateTransform {
	t := &JSONGenerateTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "json_generate",
		Version:     "1.0.0",
		Description: "Converts structured data into JSON strings",
		Category:    transform.CategoryData,
		Tags:        []string{"json", "generate", "serialize", "data"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Generate JSON from object",
				Description: "Convert an object to JSON string",
				Input: map[string]interface{}{
					"data": map[string]interface{}{
						"name": "Alice",
						"age":  30,
					},
				},
				Config: map[string]interface{}{},
				Output: map[string]interface{}{"json": `{"age":30,"name":"Alice"}`},
			},
			{
				Name:        "Pretty print JSON",
				Description: "Generate formatted JSON",
				Input: map[string]interface{}{
					"data": map[string]interface{}{"name": "Alice", "age": 30},
				},
				Config: map[string]interface{}{"pretty": true},
				Output: map[string]interface{}{"json": "{\n  \"age\": 30,\n  \"name\": \"Alice\"\n}"},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"data": {Description: "The data to convert to JSON"},
			},
			Required: []string{"data"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"json": {Type: "string", Description: "The generated JSON string"},
			},
		},
		ConfigSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"pretty": {
					Type:        "boolean",
					Description: "Whether to format the JSON with indentation (default: false)",
				},
				"html_escape": {
					Type:        "boolean",
					Description: "Whether to escape HTML characters (default: true)",
				},
			},
		},
	})

	return t
}

// Execute performs the JSON generate transformation
func (t *JSONGenerateTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	data, exists := transformCtx.GetData()["data"]
	if !exists {
		return transform.TransformResult{
			Success: false,
			Error:   "input 'data' is required",
		}, nil
	}

	pretty := transformCtx.GetConfigBool("pretty")
	htmlEscape := transformCtx.GetConfigBool("html_escape")

	var jsonBytes []byte
	var err error

	if pretty {
		jsonBytes, err = json.MarshalIndent(data, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(data)
	}

	if err != nil {
		return transform.TransformResult{
			Success: false,
			Error:   fmt.Sprintf("failed to generate JSON: %v", err),
		}, nil
	}

	// Handle HTML escaping
	if !htmlEscape {
		// JSON package escapes HTML by default, so we need to unescape if requested
		jsonStr := string(jsonBytes)
		jsonStr = strings.ReplaceAll(jsonStr, "\\u003c", "<")
		jsonStr = strings.ReplaceAll(jsonStr, "\\u003e", ">")
		jsonStr = strings.ReplaceAll(jsonStr, "\\u0026", "&")
		jsonBytes = []byte(jsonStr)
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"json": string(jsonBytes),
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}

// TypeConvertTransform converts data types between different formats
type TypeConvertTransform struct {
	transform.BaseTransform
}

// NewTypeConvertTransform creates a new type conversion transform
func NewTypeConvertTransform() *TypeConvertTransform {
	t := &TypeConvertTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "type_convert",
		Version:     "1.0.0",
		Description: "Converts data between different types (string, number, boolean)",
		Category:    transform.CategoryData,
		Tags:        []string{"convert", "type", "cast", "data"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "String to number",
				Description: "Convert a string to a number",
				Input:       map[string]interface{}{"value": "123.45"},
				Config:      map[string]interface{}{"target_type": "number"},
				Output:      map[string]interface{}{"value": float64(123.45)},
			},
			{
				Name:        "Number to string",
				Description: "Convert a number to a string",
				Input:       map[string]interface{}{"value": 42},
				Config:      map[string]interface{}{"target_type": "string"},
				Output:      map[string]interface{}{"value": "42"},
			},
			{
				Name:        "String to boolean",
				Description: "Convert a string to a boolean",
				Input:       map[string]interface{}{"value": "true"},
				Config:      map[string]interface{}{"target_type": "boolean"},
				Output:      map[string]interface{}{"value": true},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"value": {Description: "The value to convert"},
			},
			Required: []string{"value"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"value": {Description: "The converted value"},
			},
		},
		ConfigSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"target_type": {
					Type:        "string",
					Description: "The target type to convert to",
					Enum:        []interface{}{"string", "number", "boolean", "array", "object"},
				},
				"default_value": {
					Description: "Default value to use if conversion fails",
				},
			},
			Required: []string{"target_type"},
		},
	})

	return t
}

// Execute performs the type conversion transformation
func (t *TypeConvertTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	value, exists := transformCtx.GetData()["value"]
	if !exists {
		return transform.TransformResult{
			Success: false,
			Error:   "input 'value' is required",
		}, nil
	}

	targetType := transformCtx.GetConfigString("target_type")
	if targetType == "" {
		return transform.TransformResult{
			Success: false,
			Error:   "config 'target_type' is required",
		}, nil
	}

	defaultValue, hasDefault := transformCtx.GetConfig()["default_value"]

	convertedValue, err := t.convertValue(value, targetType)
	if err != nil {
		if hasDefault {
			convertedValue = defaultValue
		} else {
			return transform.TransformResult{
				Success: false,
				Error:   fmt.Sprintf("conversion failed: %v", err),
			}, nil
		}
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"value": convertedValue,
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}

// convertValue performs the actual type conversion
func (t *TypeConvertTransform) convertValue(value interface{}, targetType string) (interface{}, error) {
	switch targetType {
	case "string":
		return fmt.Sprintf("%v", value), nil

	case "number":
		switch v := value.(type) {
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f, nil
			}
			return nil, fmt.Errorf("cannot convert string '%s' to number", v)
		case int:
			return float64(v), nil
		case int64:
			return float64(v), nil
		case float32:
			return float64(v), nil
		case float64:
			return v, nil
		case bool:
			if v {
				return float64(1), nil
			}
			return float64(0), nil
		default:
			return nil, fmt.Errorf("cannot convert %T to number", value)
		}

	case "boolean":
		switch v := value.(type) {
		case bool:
			return v, nil
		case string:
			if b, err := strconv.ParseBool(v); err == nil {
				return b, nil
			}
			// Support common string representations
			switch strings.ToLower(v) {
			case "yes", "y", "1", "on", "enabled":
				return true, nil
			case "no", "n", "0", "off", "disabled", "":
				return false, nil
			default:
				return nil, fmt.Errorf("cannot convert string '%s' to boolean", v)
			}
		case int, int64:
			return v != 0, nil
		case float64:
			return v != 0.0, nil
		default:
			return nil, fmt.Errorf("cannot convert %T to boolean", value)
		}

	case "array":
		switch v := value.(type) {
		case []interface{}:
			return v, nil
		case string:
			// Try to parse as JSON array
			var arr []interface{}
			if err := json.Unmarshal([]byte(v), &arr); err == nil {
				return arr, nil
			}
			// Otherwise, return single-element array
			return []interface{}{v}, nil
		default:
			// Convert single value to array
			return []interface{}{value}, nil
		}

	case "object":
		switch v := value.(type) {
		case map[string]interface{}:
			return v, nil
		case string:
			// Try to parse as JSON object
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(v), &obj); err == nil {
				return obj, nil
			} else {
				return nil, fmt.Errorf("cannot convert string to object: %v", err)
			}
		default:
			return nil, fmt.Errorf("cannot convert %T to object", value)
		}

	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}
}

// Validate validates the type conversion transform configuration
func (t *TypeConvertTransform) Validate(config map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("configuration is required")
	}

	targetType, exists := config["target_type"]
	if !exists {
		return fmt.Errorf("'target_type' is required")
	}

	targetTypeStr, ok := targetType.(string)
	if !ok {
		return fmt.Errorf("'target_type' must be a string")
	}

	validTypes := []string{"string", "number", "boolean", "array", "object"}
	for _, validType := range validTypes {
		if targetTypeStr == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid target_type '%s', must be one of: %v", targetTypeStr, validTypes)
}