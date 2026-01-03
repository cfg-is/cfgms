// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package diff

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultEngine_Compare(t *testing.T) {
	tests := []struct {
		name     string
		fromData map[string]interface{}
		toData   map[string]interface{}
		options  DiffOptions
		want     struct {
			entryCount    int
			addedCount    int
			deletedCount  int
			modifiedCount int
		}
	}{
		{
			name: "simple value change",
			fromData: map[string]interface{}{
				"host": "localhost",
				"port": 8080,
			},
			toData: map[string]interface{}{
				"host": "remote.example.com",
				"port": 8080,
			},
			options: DiffOptions{},
			want: struct {
				entryCount    int
				addedCount    int
				deletedCount  int
				modifiedCount int
			}{
				entryCount:    1,
				addedCount:    0,
				deletedCount:  0,
				modifiedCount: 1,
			},
		},
		{
			name: "add and delete items",
			fromData: map[string]interface{}{
				"database": map[string]interface{}{
					"host": "localhost",
					"port": 5432,
				},
			},
			toData: map[string]interface{}{
				"database": map[string]interface{}{
					"host":     "localhost",
					"port":     5432,
					"ssl_mode": "require",
				},
				"cache": map[string]interface{}{
					"type": "redis",
				},
			},
			options: DiffOptions{},
			want: struct {
				entryCount    int
				addedCount    int
				deletedCount  int
				modifiedCount int
			}{
				entryCount:    2,
				addedCount:    2,
				deletedCount:  0,
				modifiedCount: 0,
			},
		},
		{
			name: "nested object changes",
			fromData: map[string]interface{}{
				"server": map[string]interface{}{
					"config": map[string]interface{}{
						"timeout": 30,
						"retries": 3,
					},
				},
			},
			toData: map[string]interface{}{
				"server": map[string]interface{}{
					"config": map[string]interface{}{
						"timeout": 60,
						"retries": 5,
					},
				},
			},
			options: DiffOptions{},
			want: struct {
				entryCount    int
				addedCount    int
				deletedCount  int
				modifiedCount int
			}{
				entryCount:    2,
				addedCount:    0,
				deletedCount:  0,
				modifiedCount: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock engine that uses the test data directly
			engine := &mockEngine{
				fromData: tt.fromData,
				toData:   tt.toData,
			}

			fromRef := ConfigurationReference{
				Repository: "test-repo",
				Branch:     "main",
				Commit:     "abc123def456",
				Path:       "config.json",
				Timestamp:  time.Now(),
				Author:     "test-user",
				Message:    "test commit",
			}

			toRef := ConfigurationReference{
				Repository: "test-repo",
				Branch:     "main",
				Commit:     "def456ghi789",
				Path:       "config.json",
				Timestamp:  time.Now(),
				Author:     "test-user",
				Message:    "updated config",
			}

			result, err := engine.Compare(context.Background(), fromRef, toRef, tt.options)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.want.entryCount, len(result.Entries))
			assert.Equal(t, tt.want.addedCount, result.Summary.AddedItems)
			assert.Equal(t, tt.want.deletedCount, result.Summary.DeletedItems)
			assert.Equal(t, tt.want.modifiedCount, result.Summary.ModifiedItems)
		})
	}
}

func TestDefaultEngine_ThreeWayCompare(t *testing.T) {
	engine := &mockEngine{
		baseData: map[string]interface{}{
			"host": "localhost",
			"port": 8080,
		},
		leftData: map[string]interface{}{
			"host": "left.example.com",
			"port": 8080,
		},
		rightData: map[string]interface{}{
			"host": "right.example.com",
			"port": 9090,
		},
	}

	baseRef := ConfigurationReference{
		Repository: "test-repo",
		Commit:     "base123",
		Path:       "config.json",
		Timestamp:  time.Now(),
	}

	leftRef := ConfigurationReference{
		Repository: "test-repo",
		Commit:     "left456",
		Path:       "config.json",
		Timestamp:  time.Now(),
	}

	rightRef := ConfigurationReference{
		Repository: "test-repo",
		Commit:     "right789",
		Path:       "config.json",
		Timestamp:  time.Now(),
	}

	result, err := engine.ThreeWayCompare(context.Background(), baseRef, leftRef, rightRef, DiffOptions{})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.Summary.LeftChanges)  // host changed on left
	assert.Equal(t, 2, result.Summary.RightChanges) // host and port changed on right
	assert.Equal(t, 1, result.Summary.Conflicts)    // conflict on host field
}

func TestDefaultEngine_DetectConflicts(t *testing.T) {
	engine := NewDefaultEngine(nil, nil, nil)

	leftEntries := []DiffEntry{
		{
			Path:     "host",
			Type:     DiffTypeModify,
			OldValue: "localhost",
			NewValue: "left.example.com",
		},
	}

	rightEntries := []DiffEntry{
		{
			Path:     "host",
			Type:     DiffTypeModify,
			OldValue: "localhost",
			NewValue: "right.example.com",
		},
	}

	conflicts := engine.detectConflicts(leftEntries, rightEntries)
	require.Len(t, conflicts, 1)

	conflict := conflicts[0]
	assert.Equal(t, "host", conflict.Path)
	assert.Equal(t, ConflictTypeModifyModify, conflict.ConflictType)
	assert.Equal(t, ResolutionStrategyManual, conflict.ResolutionStrategy)
}

func TestDefaultEngine_CompareSlicesIgnoreOrder(t *testing.T) {
	engine := NewDefaultEngine(nil, nil, nil)

	fromSlice := []interface{}{"a", "b", "c"}
	toSlice := []interface{}{"c", "a", "d"}

	fromValue := reflect.ValueOf(fromSlice)
	toValue := reflect.ValueOf(toSlice)

	entries := engine.compareSlicesIgnoreOrder("items", fromValue, toValue,
		DiffOptions{IgnoreOrder: true})

	require.Len(t, entries, 2) // "b" deleted, "d" added

	deletedFound := false
	addedFound := false
	for _, entry := range entries {
		if entry.Type == DiffTypeDelete && entry.OldValue == "b" {
			deletedFound = true
		}
		if entry.Type == DiffTypeAdd && entry.NewValue == "d" {
			addedFound = true
		}
	}

	assert.True(t, deletedFound, "Should find deleted item 'b'")
	assert.True(t, addedFound, "Should find added item 'd'")
}

// Mock implementations for testing

type mockEngine struct {
	fromData  map[string]interface{}
	toData    map[string]interface{}
	baseData  map[string]interface{}
	leftData  map[string]interface{}
	rightData map[string]interface{}

	*DefaultEngine
}

func (m *mockEngine) Compare(ctx context.Context, from, to ConfigurationReference, options DiffOptions) (*ComparisonResult, error) {
	// Use DefaultEngine's logic but with mock data loading
	engine := NewDefaultEngine(nil, nil, nil)

	// Simulate the comparison logic
	entries := engine.compareData("", m.fromData, m.toData, options)
	summary := engine.calculateSummary(entries)

	return &ComparisonResult{
		ID:      "mock-comparison",
		FromRef: from,
		ToRef:   to,
		Summary: summary,
		Entries: entries,
		Metadata: ComparisonMetadata{
			CreatedAt: time.Now(),
			Duration:  time.Millisecond,
			Engine:    "MockEngine",
			Version:   "1.0.0",
			Options:   options,
		},
	}, nil
}

func (m *mockEngine) ThreeWayCompare(ctx context.Context, base, left, right ConfigurationReference, options DiffOptions) (*ThreeWayDiffResult, error) {
	engine := NewDefaultEngine(nil, nil, nil)

	// Compare base to left
	baseToLeftEntries := engine.compareData("", m.baseData, m.leftData, options)

	// Compare base to right
	baseToRightEntries := engine.compareData("", m.baseData, m.rightData, options)

	// Detect conflicts
	conflicts := engine.detectConflicts(baseToLeftEntries, baseToRightEntries)

	summary := ThreeWayDiffSummary{
		LeftChanges:      len(baseToLeftEntries),
		RightChanges:     len(baseToRightEntries),
		Conflicts:        len(conflicts),
		AutoResolvable:   engine.countAutoResolvable(conflicts),
		ManualResolution: engine.countManualResolution(conflicts),
	}

	return &ThreeWayDiffResult{
		BaseRef:     base,
		LeftRef:     left,
		RightRef:    right,
		BaseToLeft:  baseToLeftEntries,
		BaseToRight: baseToRightEntries,
		Conflicts:   conflicts,
		Summary:     summary,
		Metadata: ComparisonMetadata{
			CreatedAt: time.Now(),
			Duration:  time.Millisecond,
			Engine:    "MockEngine",
			Version:   "1.0.0",
			Options:   options,
		},
	}, nil
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: "<nil>",
		},
		{
			name:     "simple string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: `"hello world"`,
		},
		{
			name:     "simple array",
			input:    []interface{}{"a", "b"},
			expected: "[a, b]",
		},
		{
			name:     "large array",
			input:    []interface{}{"a", "b", "c", "d", "e"},
			expected: "[a, ... (5 items)]",
		},
		{
			name:     "simple map",
			input:    map[string]interface{}{"key": "value"},
			expected: "{key: value}",
		},
		{
			name:     "large map",
			input:    map[string]interface{}{"k1": "v1", "k2": "v2", "k3": "v3"},
			expected: "{...} (3 keys)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateComparisonID(t *testing.T) {
	from := ConfigurationReference{
		Repository: "repo1",
		Commit:     "abc123",
	}

	to := ConfigurationReference{
		Repository: "repo1",
		Commit:     "def456",
	}

	id1 := generateComparisonID(from, to)
	id2 := generateComparisonID(from, to)

	// Should be deterministic
	assert.Equal(t, id1, id2)
	assert.Len(t, id1, 16) // 8 bytes hex encoded
}

func TestBuildPath(t *testing.T) {
	tests := []struct {
		parent   string
		key      string
		expected string
	}{
		{"", "root", "root"},
		{"parent", "child", "parent.child"},
		{"a.b", "c", "a.b.c"},
	}

	for _, tt := range tests {
		result := buildPath(tt.parent, tt.key)
		assert.Equal(t, tt.expected, result)
	}
}

func TestGetParentPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"root", ""},
		{"parent.child", "parent"},
		{"a.b.c", "a.b"},
	}

	for _, tt := range tests {
		result := getParentPath(tt.path)
		assert.Equal(t, tt.expected, result)
	}
}

// Benchmark tests
func BenchmarkCompareData(b *testing.B) {
	engine := NewDefaultEngine(nil, nil, nil)

	fromData := generateLargeConfig(100)
	toData := generateLargeConfig(100)
	// Make some changes
	toData["modified_field"] = "new_value"
	toData["new_field"] = "added_value"
	delete(toData, "field_0")

	options := DiffOptions{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.compareData("", fromData, toData, options)
	}
}

func generateLargeConfig(size int) map[string]interface{} {
	config := make(map[string]interface{})

	for i := 0; i < size; i++ {
		config[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	// Add some nested structures
	config["nested"] = map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"deep_field": "deep_value",
			},
		},
	}

	// Add an array
	config["array_field"] = []interface{}{"item1", "item2", "item3"}

	return config
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"config.json", "json"},
		{"config.yaml", "yaml"},
		{"config.yml", "yaml"},
		{"config.toml", "json"}, // defaults to json
		{"config", "json"},      // defaults to json
	}

	for _, tt := range tests {
		result := detectFormat(tt.path)
		assert.Equal(t, tt.expected, result)
	}
}

func TestParseConfiguration(t *testing.T) {
	engine := NewDefaultEngine(nil, nil, nil)

	jsonData := `{"host": "localhost", "port": 8080}`
	yamlData := `host: localhost
port: 8080`

	// Test JSON parsing
	jsonResult, err := engine.parseConfiguration([]byte(jsonData), "json")
	require.NoError(t, err)

	jsonMap := jsonResult.(map[string]interface{})
	assert.Equal(t, "localhost", jsonMap["host"])
	assert.Equal(t, float64(8080), jsonMap["port"]) // JSON numbers are float64

	// Test YAML parsing
	yamlResult, err := engine.parseConfiguration([]byte(yamlData), "yaml")
	require.NoError(t, err)

	yamlMap := yamlResult.(map[string]interface{})
	assert.Equal(t, "localhost", yamlMap["host"])
	assert.Equal(t, 8080, yamlMap["port"]) // YAML preserves int type

	// Test invalid format
	_, err = engine.parseConfiguration([]byte(jsonData), "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestCalculateSummary(t *testing.T) {
	engine := NewDefaultEngine(nil, nil, nil)

	entries := []DiffEntry{
		{
			Type: DiffTypeAdd,
			Impact: ChangeImpact{
				Level:          ImpactLevelHigh,
				Category:       ChangeCategorySecurity,
				BreakingChange: false,
			},
		},
		{
			Type: DiffTypeModify,
			Impact: ChangeImpact{
				Level:          ImpactLevelCritical,
				Category:       ChangeCategorySecurity,
				BreakingChange: true,
			},
		},
		{
			Type: DiffTypeDelete,
			Impact: ChangeImpact{
				Level:    ImpactLevelMedium,
				Category: ChangeCategoryValue,
			},
		},
	}

	summary := engine.calculateSummary(entries)

	assert.Equal(t, 3, summary.TotalChanges)
	assert.Equal(t, 1, summary.AddedItems)
	assert.Equal(t, 1, summary.ModifiedItems)
	assert.Equal(t, 1, summary.DeletedItems)
	assert.Equal(t, 0, summary.MovedItems)
	assert.Equal(t, 1, summary.BreakingChanges)
	assert.Equal(t, 2, summary.SecurityChanges)

	// Check impact breakdown
	assert.Equal(t, 1, summary.ImpactBreakdown[ImpactLevelHigh])
	assert.Equal(t, 1, summary.ImpactBreakdown[ImpactLevelCritical])
	assert.Equal(t, 1, summary.ImpactBreakdown[ImpactLevelMedium])

	// Check category breakdown
	assert.Equal(t, 2, summary.CategoryBreakdown[ChangeCategorySecurity])
	assert.Equal(t, 1, summary.CategoryBreakdown[ChangeCategoryValue])
}
