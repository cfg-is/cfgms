package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultTransformContext(t *testing.T) {
	data := map[string]interface{}{
		"string_val": "hello",
		"int_val":    42,
		"bool_val":   true,
	}
	config := map[string]interface{}{
		"config_key": "config_value",
	}
	variables := map[string]interface{}{
		"var_key": "var_value",
	}

	ctx := NewDefaultTransformContext(data, variables, config)

	assert.NotNil(t, ctx)
	assert.Equal(t, data, ctx.GetData())
	assert.Equal(t, config, ctx.GetConfig())
	assert.Equal(t, variables, ctx.GetVariables())
}

func TestTransformContext_GetString(t *testing.T) {
	data := map[string]interface{}{
		"string_val": "hello",
		"int_val":    42,
		"bool_val":   true,
		"float_val":  3.14,
		"nil_val":    nil,
		"empty_val":  "",
		"slice_val":  []string{"a", "b"},
		"map_val":    map[string]string{"key": "value"},
	}

	ctx := NewDefaultTransformContext(data, nil, nil)

	// Test string value
	assert.Equal(t, "hello", ctx.GetString("string_val"))

	// Test non-string values converted to string
	assert.Equal(t, "42", ctx.GetString("int_val"))
	assert.Equal(t, "true", ctx.GetString("bool_val"))
	assert.Equal(t, "3.14", ctx.GetString("float_val"))

	// Test nil and empty values
	assert.Equal(t, "", ctx.GetString("nil_val"))
	assert.Equal(t, "", ctx.GetString("empty_val"))

	// Test non-existent key
	assert.Equal(t, "", ctx.GetString("non_existent"))

	// Test complex types (should return empty string)
	assert.Equal(t, "", ctx.GetString("slice_val"))
	assert.Equal(t, "", ctx.GetString("map_val"))
}

func TestTransformContext_GetInt(t *testing.T) {
	data := map[string]interface{}{
		"int_val":      42,
		"int64_val":    int64(123),
		"float_val":    3.14,
		"string_int":   "789",
		"string_float": "3.14",
		"string_text":  "hello",
		"bool_true":    true,
		"bool_false":   false,
		"nil_val":      nil,
	}

	ctx := NewDefaultTransformContext(data, nil, nil)

	// Test integer values
	assert.Equal(t, 42, ctx.GetInt("int_val"))
	assert.Equal(t, 123, ctx.GetInt("int64_val"))

	// Test float to int conversion
	assert.Equal(t, 3, ctx.GetInt("float_val"))

	// Test string to int conversion
	assert.Equal(t, 789, ctx.GetInt("string_int"))
	assert.Equal(t, 3, ctx.GetInt("string_float"))

	// Test invalid string
	assert.Equal(t, 0, ctx.GetInt("string_text"))

	// Test boolean values
	assert.Equal(t, 1, ctx.GetInt("bool_true"))
	assert.Equal(t, 0, ctx.GetInt("bool_false"))

	// Test nil and non-existent
	assert.Equal(t, 0, ctx.GetInt("nil_val"))
	assert.Equal(t, 0, ctx.GetInt("non_existent"))
}

func TestTransformContext_GetFloat(t *testing.T) {
	data := map[string]interface{}{
		"float_val":    3.14,
		"int_val":      42,
		"string_float": "3.14159",
		"string_int":   "42",
		"string_text":  "hello",
		"bool_true":    true,
		"bool_false":   false,
		"nil_val":      nil,
	}

	ctx := NewDefaultTransformContext(data, nil, nil)

	// Test float values
	assert.Equal(t, 3.14, ctx.GetFloat("float_val"))

	// Test int to float conversion
	assert.Equal(t, 42.0, ctx.GetFloat("int_val"))

	// Test string to float conversion
	assert.Equal(t, 3.14159, ctx.GetFloat("string_float"))
	assert.Equal(t, 42.0, ctx.GetFloat("string_int"))

	// Test invalid string
	assert.Equal(t, 0.0, ctx.GetFloat("string_text"))

	// Test boolean values
	assert.Equal(t, 1.0, ctx.GetFloat("bool_true"))
	assert.Equal(t, 0.0, ctx.GetFloat("bool_false"))

	// Test nil and non-existent
	assert.Equal(t, 0.0, ctx.GetFloat("nil_val"))
	assert.Equal(t, 0.0, ctx.GetFloat("non_existent"))
}

func TestTransformContext_GetBool(t *testing.T) {
	data := map[string]interface{}{
		"bool_true":    true,
		"bool_false":   false,
		"string_true":  "true",
		"string_false": "false",
		"string_yes":   "yes",
		"string_no":    "no",
		"string_1":     "1",
		"string_0":     "0",
		"string_text":  "hello",
		"int_1":        1,
		"int_0":        0,
		"int_42":       42,
		"float_1":      1.0,
		"float_0":      0.0,
		"nil_val":      nil,
	}

	ctx := NewDefaultTransformContext(data, nil, nil)

	// Test boolean values
	assert.True(t, ctx.GetBool("bool_true"))
	assert.False(t, ctx.GetBool("bool_false"))

	// Test string to bool conversion
	assert.True(t, ctx.GetBool("string_true"))
	assert.False(t, ctx.GetBool("string_false"))
	assert.True(t, ctx.GetBool("string_yes"))
	assert.False(t, ctx.GetBool("string_no"))
	assert.True(t, ctx.GetBool("string_1"))
	assert.False(t, ctx.GetBool("string_0"))

	// Test invalid string (should be false)
	assert.False(t, ctx.GetBool("string_text"))

	// Test numeric values
	assert.True(t, ctx.GetBool("int_1"))
	assert.False(t, ctx.GetBool("int_0"))
	assert.True(t, ctx.GetBool("int_42"))
	assert.True(t, ctx.GetBool("float_1"))
	assert.False(t, ctx.GetBool("float_0"))

	// Test nil and non-existent
	assert.False(t, ctx.GetBool("nil_val"))
	assert.False(t, ctx.GetBool("non_existent"))
}

func TestTransformContext_GetArray(t *testing.T) {
	data := map[string]interface{}{
		"slice_val":    []interface{}{"a", "b", "c"},
		"string_slice": []string{"x", "y", "z"},
		"int_slice":    []int{1, 2, 3},
		"mixed_slice":  []interface{}{1, "hello", true},
		"single_val":   "hello",
		"nil_val":      nil,
		"map_val":      map[string]string{"key": "value"},
	}

	ctx := NewDefaultTransformContext(data, nil, nil)

	// Test slice values
	expected := []interface{}{"a", "b", "c"}
	assert.Equal(t, expected, ctx.GetArray("slice_val"))

	// Test typed slices (should convert to []interface{})
	stringSlice := ctx.GetArray("string_slice")
	assert.Len(t, stringSlice, 3)
	assert.Equal(t, "x", stringSlice[0])

	intSlice := ctx.GetArray("int_slice")
	assert.Len(t, intSlice, 3)
	assert.Equal(t, 1, intSlice[0])

	// Test mixed slice
	mixedSlice := ctx.GetArray("mixed_slice")
	assert.Len(t, mixedSlice, 3)
	assert.Equal(t, 1, mixedSlice[0])
	assert.Equal(t, "hello", mixedSlice[1])
	assert.Equal(t, true, mixedSlice[2])

	// Test non-slice values (should return empty slice)
	assert.Empty(t, ctx.GetArray("single_val"))
	assert.Empty(t, ctx.GetArray("nil_val"))
	assert.Empty(t, ctx.GetArray("map_val"))
	assert.Empty(t, ctx.GetArray("non_existent"))
}

func TestTransformContext_GetMap(t *testing.T) {
	data := map[string]interface{}{
		"map_val": map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
		"string_map": map[string]string{
			"a": "x",
			"b": "y",
		},
		"non_map": "hello",
		"nil_val": nil,
	}

	ctx := NewDefaultTransformContext(data, nil, nil)

	// Test map values
	expected := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}
	assert.Equal(t, expected, ctx.GetMap("map_val"))

	// Test typed map (should convert)
	stringMap := ctx.GetMap("string_map")
	assert.Len(t, stringMap, 2)
	assert.Equal(t, "x", stringMap["a"])
	assert.Equal(t, "y", stringMap["b"])

	// Test non-map values (should return empty map)
	assert.Empty(t, ctx.GetMap("non_map"))
	assert.Empty(t, ctx.GetMap("nil_val"))
	assert.Empty(t, ctx.GetMap("non_existent"))
}

func TestTransformContext_ConfigMethods(t *testing.T) {
	config := map[string]interface{}{
		"string_config": "config_value",
		"int_config":    123,
		"bool_config":   true,
		"float_config":  2.71,
	}

	ctx := NewDefaultTransformContext(nil, nil, config)

	// Test config string
	assert.Equal(t, "config_value", ctx.GetConfigString("string_config"))
	assert.Equal(t, "123", ctx.GetConfigString("int_config"))
	assert.Equal(t, "", ctx.GetConfigString("non_existent"))

	// Test config int
	assert.Equal(t, 123, ctx.GetConfigInt("int_config"))
	assert.Equal(t, 0, ctx.GetConfigInt("string_config"))
	assert.Equal(t, 0, ctx.GetConfigInt("non_existent"))

	// Test config bool
	assert.True(t, ctx.GetConfigBool("bool_config"))
	assert.False(t, ctx.GetConfigBool("string_config"))
	assert.False(t, ctx.GetConfigBool("non_existent"))

	// Test config float
	assert.Equal(t, 2.71, ctx.GetConfigFloat("float_config"))
	assert.Equal(t, 123.0, ctx.GetConfigFloat("int_config"))
	assert.Equal(t, 0.0, ctx.GetConfigFloat("non_existent"))
}

func TestTransformContext_VariableMethods(t *testing.T) {
	variables := map[string]interface{}{
		"string_var": "var_value",
		"int_var":    456,
		"bool_var":   false,
		"float_var":  1.41,
	}

	ctx := NewDefaultTransformContext(nil, variables, nil)

	// Test variable string
	assert.Equal(t, "var_value", ctx.GetVariableString("string_var"))
	assert.Equal(t, "456", ctx.GetVariableString("int_var"))
	assert.Equal(t, "", ctx.GetVariableString("non_existent"))

	// Test variable int
	assert.Equal(t, 456, ctx.GetVariableInt("int_var"))
	assert.Equal(t, 0, ctx.GetVariableInt("string_var"))
	assert.Equal(t, 0, ctx.GetVariableInt("non_existent"))

	// Test variable bool
	assert.False(t, ctx.GetVariableBool("bool_var"))
	assert.False(t, ctx.GetVariableBool("string_var"))
	assert.False(t, ctx.GetVariableBool("non_existent"))

	// Test variable float
	assert.Equal(t, 1.41, ctx.GetVariableFloat("float_var"))
	assert.Equal(t, 456.0, ctx.GetVariableFloat("int_var"))
	assert.Equal(t, 0.0, ctx.GetVariableFloat("non_existent"))
}

func TestTransformContext_EmptyContexts(t *testing.T) {
	ctx := NewDefaultTransformContext(nil, nil, nil)

	// Test that empty contexts return safe defaults
	assert.Equal(t, "", ctx.GetString("key"))
	assert.Equal(t, 0, ctx.GetInt("key"))
	assert.Equal(t, 0.0, ctx.GetFloat("key"))
	assert.False(t, ctx.GetBool("key"))
	assert.Empty(t, ctx.GetArray("key"))
	assert.Empty(t, ctx.GetMap("key"))

	assert.Equal(t, "", ctx.GetConfigString("key"))
	assert.Equal(t, 0, ctx.GetConfigInt("key"))
	assert.Equal(t, 0.0, ctx.GetConfigFloat("key"))
	assert.False(t, ctx.GetConfigBool("key"))

	assert.Equal(t, "", ctx.GetVariableString("key"))
	assert.Equal(t, 0, ctx.GetVariableInt("key"))
	assert.Equal(t, 0.0, ctx.GetVariableFloat("key"))
	assert.False(t, ctx.GetVariableBool("key"))

	assert.Empty(t, ctx.GetData())
	assert.Empty(t, ctx.GetConfig())
	assert.Empty(t, ctx.GetVariables())
}

func TestTransformContext_ComplexTypes(t *testing.T) {
	complexData := map[string]interface{}{
		"nested_map": map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": "deep_value",
			},
		},
		"nested_slice": []interface{}{
			[]interface{}{"a", "b"},
			[]interface{}{"c", "d"},
		},
		"mixed_data": map[string]interface{}{
			"strings": []string{"x", "y", "z"},
			"numbers": []int{1, 2, 3},
			"meta":    map[string]string{"type": "test"},
		},
	}

	ctx := NewDefaultTransformContext(complexData, nil, nil)

	// Test that complex nested structures are accessible
	nestedMap := ctx.GetMap("nested_map")
	assert.NotEmpty(t, nestedMap)
	assert.Contains(t, nestedMap, "level1")

	nestedSlice := ctx.GetArray("nested_slice")
	assert.Len(t, nestedSlice, 2)

	mixedData := ctx.GetMap("mixed_data")
	assert.Contains(t, mixedData, "strings")
	assert.Contains(t, mixedData, "numbers")
	assert.Contains(t, mixedData, "meta")
}
