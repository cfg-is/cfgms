// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package diff

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSemanticAnalyzer_AnalyzeStructure(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	tests := []struct {
		name             string
		config           string
		format           string
		expectedSchema   string
		expectedSections int
	}{
		{
			name:   "kubernetes manifest",
			format: "yaml",
			config: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  host: localhost
  port: "8080"`,
			expectedSchema:   "kubernetes",
			expectedSections: 4, // apiVersion, kind, metadata, data
		},
		{
			name:   "docker compose",
			format: "yaml",
			config: `version: '3.8'
services:
  app:
    image: nginx
    ports:
      - "80:80"
  db:
    image: postgres
    environment:
      POSTGRES_DB: myapp`,
			expectedSchema:   "docker-compose",
			expectedSections: 2, // version, services
		},
		{
			name:   "simple json config",
			format: "json",
			config: `{
  "database": {
    "host": "localhost",
    "port": 5432,
    "ssl": true
  },
  "logging": {
    "level": "info",
    "output": "stdout"
  }
}`,
			expectedSchema:   "unknown",
			expectedSections: 2, // database, logging
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := analyzer.AnalyzeStructure(context.Background(), []byte(tt.config), tt.format)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.format, result.Format)
			assert.Equal(t, tt.expectedSchema, result.Schema)
			assert.Len(t, result.Sections, tt.expectedSections)
		})
	}
}

func TestDefaultSemanticAnalyzer_DetectSchema(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	tests := []struct {
		name     string
		data     map[string]interface{}
		expected string
	}{
		{
			name: "kubernetes",
			data: map[string]interface{}{
				"version": "v1",
				"kind":    "ConfigMap",
			},
			expected: "kubernetes",
		},
		{
			name: "docker-compose",
			data: map[string]interface{}{
				"services": map[string]interface{}{
					"app": "nginx",
				},
			},
			expected: "docker-compose",
		},
		{
			name: "package.json",
			data: map[string]interface{}{
				"name": "my-app",
				"main": "index.js",
			},
			expected: "package.json",
		},
		{
			name: "terraform",
			data: map[string]interface{}{
				"resource": map[string]interface{}{
					"aws_instance": "example",
				},
			},
			expected: "terraform",
		},
		{
			name: "unknown",
			data: map[string]interface{}{
				"custom_field": "value",
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.detectSchema(tt.data, "yaml")
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultSemanticAnalyzer_DetectSectionType(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected string
	}{
		{
			name:     "database section",
			key:      "database",
			value:    map[string]interface{}{},
			expected: "database",
		},
		{
			name:     "security section",
			key:      "auth",
			value:    map[string]interface{}{},
			expected: "security",
		},
		{
			name: "connection section",
			key:  "server",
			value: map[string]interface{}{
				"host": "localhost",
				"port": 8080,
			},
			expected: "server",
		},
		{
			name: "feature section",
			key:  "feature_flags",
			value: map[string]interface{}{
				"enabled": true,
			},
			expected: "feature",
		},
		{
			name:     "string value",
			key:      "name",
			value:    "test",
			expected: "string",
		},
		{
			name:     "boolean value",
			key:      "enabled",
			value:    true,
			expected: "boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.detectSectionType(tt.key, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultSemanticAnalyzer_DetectRuntimePatterns(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	data := map[string]interface{}{
		"database": map[string]interface{}{
			"host": "localhost",
			"port": 5432,
		},
		"auth": map[string]interface{}{
			"jwt_secret": "secret123",
			"ssl_cert":   "/path/to/cert",
		},
		"logging": map[string]interface{}{
			"level":  "info",
			"output": "stdout",
		},
		"server": map[string]interface{}{
			"daemon": true,
		},
	}

	patterns := analyzer.detectRuntimePatterns(data, "")

	// Should detect multiple pattern types
	patternTypes := make(map[string]bool)
	for _, pattern := range patterns {
		patternTypes[pattern.Type] = true
	}

	assert.True(t, patternTypes["connection"], "Should detect connection pattern")
	assert.True(t, patternTypes["security"], "Should detect security pattern")
	assert.True(t, patternTypes["logging"], "Should detect logging pattern")
	assert.True(t, patternTypes["service"], "Should detect service pattern")
}

func TestDefaultSemanticAnalyzer_CompareStructures(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	fromStructure := &ConfigStructure{
		Format: "json",
		Sections: []ConfigSection{
			{
				Name: "database",
				Path: "database",
				Type: "database",
			},
			{
				Name: "logging",
				Path: "logging",
				Type: "logging",
			},
		},
		Dependencies: []SectionDependency{
			{
				From: "app",
				To:   "database",
				Type: "connection",
			},
		},
	}

	toStructure := &ConfigStructure{
		Format: "json",
		Sections: []ConfigSection{
			{
				Name: "database",
				Path: "database",
				Type: "connection", // type changed
			},
			{
				Name: "cache",
				Path: "cache",
				Type: "cache", // new section
			},
			// logging section removed
		},
		Dependencies: []SectionDependency{
			{
				From: "app",
				To:   "cache", // new dependency
				Type: "connection",
			},
			// database dependency removed
		},
	}

	changes, err := analyzer.CompareStructures(context.Background(), fromStructure, toStructure)
	require.NoError(t, err)

	// Should detect: section type change, section added, section removed, dependency changes
	assert.GreaterOrEqual(t, len(changes), 4)

	changeTypes := make(map[StructuralChangeType]int)
	for _, change := range changes {
		changeTypes[change.Type]++
	}

	assert.Greater(t, changeTypes[StructuralChangeTypeSectionAdded], 0)
	assert.Greater(t, changeTypes[StructuralChangeTypeSectionRemoved], 0)
	assert.Greater(t, changeTypes[StructuralChangeTypeDependencyAdded], 0)
	assert.Greater(t, changeTypes[StructuralChangeTypeDependencyRemoved], 0)
}

func TestDefaultSemanticAnalyzer_DetectSectionDependencies(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	sectionValue := map[string]interface{}{
		"database_url": "${database.host}:${database.port}",
		"cache_config": "redis.config",
		"normal_field": "value",
	}

	rootData := map[string]interface{}{
		"database": map[string]interface{}{
			"host": "localhost",
		},
		"redis": map[string]interface{}{
			"host": "cache-server",
		},
	}

	dependencies := analyzer.detectSectionDependencies("app", sectionValue, rootData)

	assert.Len(t, dependencies, 2) // variable reference + path reference

	depTypes := make(map[string]bool)
	for _, dep := range dependencies {
		depTypes[dep.Type] = true
	}

	assert.True(t, depTypes["variable_reference"])
	assert.True(t, depTypes["path_reference"])
}

func TestDefaultSemanticAnalyzer_DetectPatterns(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	config := `{
  "database": {
    "host": "localhost",
    "port": 5432
  },
  "auth": {
    "jwt_secret": "secret",
    "ssl_enabled": true
  }
}`

	patterns, err := analyzer.DetectPatterns(context.Background(), []byte(config), "json")
	require.NoError(t, err)

	assert.Greater(t, len(patterns), 0)

	// Should detect connection and security patterns
	patternNames := make(map[string]bool)
	for _, pattern := range patterns {
		patternNames[pattern.Name] = true
	}

	assert.True(t, patternNames["connection_config"] || patternNames["security_config"])
}

func TestDefaultSemanticAnalyzer_InvalidInput(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	// Test invalid JSON
	_, err := analyzer.AnalyzeStructure(context.Background(), []byte("invalid json"), "json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON")

	// Test invalid YAML
	_, err = analyzer.AnalyzeStructure(context.Background(), []byte("invalid: [\n  unclosed"), "yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML")

	// Test unsupported format
	_, err = analyzer.AnalyzeStructure(context.Background(), []byte("data"), "xml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestDefaultSemanticAnalyzer_ExtractProperties(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	value := map[string]interface{}{
		"host":        "localhost",
		"port":        8080,
		"enabled":     true,
		"timeout":     30,
		"other_field": "ignored",
		"version":     "1.0",
	}

	properties := analyzer.extractProperties(value)

	// Should extract only important properties
	expectedProps := []string{"host", "port", "enabled", "timeout", "version"}
	for _, prop := range expectedProps {
		assert.Contains(t, properties, prop, "Should extract property: %s", prop)
	}

	assert.NotContains(t, properties, "other_field", "Should not extract non-important properties")
}

func BenchmarkAnalyzeStructure(b *testing.B) {
	analyzer := NewDefaultSemanticAnalyzer()

	config := `{
  "database": {
    "host": "localhost",
    "port": 5432,
    "connections": {
      "max_pool": 100,
      "timeout": 30
    }
  },
  "auth": {
    "jwt_secret": "secret",
    "providers": ["local", "oauth"],
    "settings": {
      "require_email": true,
      "password_policy": {
        "min_length": 8,
        "require_special": true
      }
    }
  },
  "logging": {
    "level": "info",
    "outputs": ["stdout", "file"],
    "file_config": {
      "path": "/var/log/app.log",
      "rotate": true
    }
  }
}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.AnalyzeStructure(context.Background(), []byte(config), "json")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestDefaultSemanticAnalyzer_ComplexNesting(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	config := `{
  "app": {
    "server": {
      "http": {
        "host": "localhost",
        "port": 8080,
        "ssl": {
          "enabled": true,
          "cert_path": "/etc/ssl/cert.pem"
        }
      }
    },
    "database": {
      "connections": {
        "primary": {
          "host": "db1.example.com",
          "port": 5432
        },
        "replica": {
          "host": "db2.example.com", 
          "port": 5432
        }
      }
    }
  }
}`

	result, err := analyzer.AnalyzeStructure(context.Background(), []byte(config), "json")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should handle deep nesting
	assert.Greater(t, len(result.Sections), 0)

	// Find the app section which should have children
	var appSection *ConfigSection
	for _, section := range result.Sections {
		if section.Name == "app" {
			appSection = &section
			break
		}
	}

	require.NotNil(t, appSection, "Should find app section")
	assert.Greater(t, len(appSection.Children), 0, "App section should have children")
}

func TestDefaultSemanticAnalyzer_EdgeCases(t *testing.T) {
	analyzer := NewDefaultSemanticAnalyzer()

	tests := []struct {
		name   string
		config string
		format string
	}{
		{
			name:   "empty object",
			config: "{}",
			format: "json",
		},
		{
			name:   "empty array root",
			config: "[]",
			format: "json",
		},
		{
			name:   "null values",
			config: `{"field": null}`,
			format: "json",
		},
		{
			name:   "mixed types",
			config: `{"string": "value", "number": 123, "boolean": true, "null": null, "array": [1,2,3]}`,
			format: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := analyzer.AnalyzeStructure(context.Background(), []byte(tt.config), tt.format)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.format, result.Format)
		})
	}
}
