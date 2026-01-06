// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package script

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// getTestShell returns an appropriate shell for the current platform
func getTestShell() ShellType {
	switch runtime.GOOS {
	case "windows":
		return ShellCmd
	default:
		return ShellBash
	}
}

// getTestScript returns a simple test script for the current platform
func getTestScript() string {
	switch runtime.GOOS {
	case "windows":
		return "echo Hello World"
	default:
		return "echo 'Hello World'"
	}
}

func TestScriptModule_New(t *testing.T) {
	module := New()
	if module == nil {
		t.Fatal("New() returned nil")
	}

	// Module is already of type modules.Module, no need to verify
}

func TestScriptConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  ScriptConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   getTestShell(),
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty content",
			config: ScriptConfig{
				Content: "",
				Shell:   getTestShell(),
			},
			wantErr: true,
		},
		{
			name: "empty shell",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   "",
			},
			wantErr: true,
		},
		{
			name: "unsupported shell on platform",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   ShellType("unsupported"),
			},
			wantErr: true,
		},
		{
			name: "negative timeout",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   getTestShell(),
				Timeout: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "required signature missing",
			config: ScriptConfig{
				Content:       getTestScript(),
				Shell:         getTestShell(),
				SigningPolicy: SigningPolicyRequired,
				Signature:     nil,
			},
			wantErr: true,
		},
		{
			name: "invalid signing policy",
			config: ScriptConfig{
				Content:       getTestScript(),
				Shell:         getTestShell(),
				SigningPolicy: SigningPolicy("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ScriptConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScriptConfig_DefaultValues(t *testing.T) {
	config := ScriptConfig{
		Content: getTestScript(),
		Shell:   getTestShell(),
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Check default timeout is set
	if config.Timeout != 5*time.Minute {
		t.Errorf("Expected default timeout of 5 minutes, got %v", config.Timeout)
	}

	// Check default signing policy is set
	if config.SigningPolicy != SigningPolicyNone {
		t.Errorf("Expected default signing policy 'none', got %v", config.SigningPolicy)
	}
}

func TestScriptConfig_AsMap(t *testing.T) {
	config := ScriptConfig{
		Content:     getTestScript(),
		Shell:       getTestShell(),
		Timeout:     30 * time.Second,
		Environment: map[string]string{"TEST": "value"},
		WorkingDir:  "/tmp",
		Description: "Test script",
	}

	asMap := config.AsMap()

	// Check required fields
	if asMap["content"] != config.Content {
		t.Errorf("Expected content %v, got %v", config.Content, asMap["content"])
	}
	if asMap["shell"] != string(config.Shell) {
		t.Errorf("Expected shell %v, got %v", config.Shell, asMap["shell"])
	}
	if asMap["timeout"] != config.Timeout.String() {
		t.Errorf("Expected timeout %v, got %v", config.Timeout.String(), asMap["timeout"])
	}

	// Check optional fields
	if asMap["environment"] == nil {
		t.Error("Expected environment to be present in map")
	}
	if asMap["working_dir"] != config.WorkingDir {
		t.Errorf("Expected working_dir %v, got %v", config.WorkingDir, asMap["working_dir"])
	}
	if asMap["description"] != config.Description {
		t.Errorf("Expected description %v, got %v", config.Description, asMap["description"])
	}
}

func TestScriptConfig_YAMLSerialization(t *testing.T) {
	original := ScriptConfig{
		Content:       getTestScript(),
		Shell:         getTestShell(),
		Timeout:       30 * time.Second,
		Environment:   map[string]string{"TEST": "value"},
		SigningPolicy: SigningPolicyOptional,
		Description:   "Test script",
	}

	// Serialize to YAML
	yamlData, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() failed: %v", err)
	}

	// Deserialize from YAML
	var deserialized ScriptConfig
	err = deserialized.FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML() failed: %v", err)
	}

	// Compare key fields
	if deserialized.Content != original.Content {
		t.Errorf("Content mismatch: got %v, want %v", deserialized.Content, original.Content)
	}
	if deserialized.Shell != original.Shell {
		t.Errorf("Shell mismatch: got %v, want %v", deserialized.Shell, original.Shell)
	}
	if deserialized.Timeout != original.Timeout {
		t.Errorf("Timeout mismatch: got %v, want %v", deserialized.Timeout, original.Timeout)
	}
	if deserialized.SigningPolicy != original.SigningPolicy {
		t.Errorf("SigningPolicy mismatch: got %v, want %v", deserialized.SigningPolicy, original.SigningPolicy)
	}
}

func TestScriptConfig_GetManagedFields(t *testing.T) {
	config := ScriptConfig{
		Content:     getTestScript(),
		Shell:       getTestShell(),
		Environment: map[string]string{"TEST": "value"},
		WorkingDir:  "/tmp",
		Description: "Test script",
	}

	fields := config.GetManagedFields()

	// Check that basic fields are always present
	expectedBasic := []string{"content", "shell", "timeout", "signing_policy"}
	for _, expected := range expectedBasic {
		found := false
		for _, field := range fields {
			if field == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected field %s not found in managed fields", expected)
		}
	}

	// Check that optional fields are present when set
	expectedOptional := []string{"environment", "working_dir", "description"}
	for _, expected := range expectedOptional {
		found := false
		for _, field := range fields {
			if field == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected optional field %s not found in managed fields", expected)
		}
	}
}

func TestScriptModule_GetSet(t *testing.T) {
	module := NewModule()
	ctx := context.Background()
	resourceID := "test-script"

	// Test Get on non-existent resource
	config, err := module.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	// Should return empty config
	scriptConfig, ok := config.(*ScriptConfig)
	if !ok {
		t.Fatalf("Get() returned wrong type: %T", config)
	}
	if scriptConfig.SigningPolicy != SigningPolicyNone {
		t.Errorf("Expected empty config with 'none' signing policy, got %v", scriptConfig.SigningPolicy)
	}

	// Test Set with valid config
	testConfig := &ScriptConfig{
		Content: getTestScript(),
		Shell:   getTestShell(),
		Timeout: 10 * time.Second,
	}

	// Add context timestamp to avoid panic
	ctx = context.WithValue(ctx, timestampKey, time.Now().Unix())

	err = module.Set(ctx, resourceID, testConfig)
	if err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Test Get after Set
	config, err = module.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("Get() after Set() failed: %v", err)
	}

	scriptConfig, ok = config.(*ScriptConfig)
	if !ok {
		t.Fatalf("Get() returned wrong type: %T", config)
	}

	if scriptConfig.Content != testConfig.Content {
		t.Errorf("Content mismatch: got %v, want %v", scriptConfig.Content, testConfig.Content)
	}
	if scriptConfig.Shell != testConfig.Shell {
		t.Errorf("Shell mismatch: got %v, want %v", scriptConfig.Shell, testConfig.Shell)
	}
}

func TestScriptModule_ExecutionState(t *testing.T) {
	module := NewModule()
	resourceID := "test-execution-state"

	// Test non-existent execution state
	state, exists := module.GetExecutionState(resourceID)
	if exists {
		t.Error("Expected non-existent execution state to return false")
	}
	if state != nil {
		t.Error("Expected nil state for non-existent execution")
	}

	// Create a test execution state
	testConfig := &ScriptConfig{
		Content: getTestScript(),
		Shell:   getTestShell(),
	}

	ctx := context.WithValue(context.Background(), timestampKey, time.Now().Unix())

	// This will create an execution state
	err := module.Set(ctx, resourceID, testConfig)
	if err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Test existing execution state
	state, exists = module.GetExecutionState(resourceID)
	if !exists {
		t.Error("Expected existing execution state to return true")
	}
	if state == nil {
		t.Fatal("Expected non-nil state for existing execution")
	}

	if state.Config.Content != testConfig.Content {
		t.Errorf("Execution state content mismatch: got %v, want %v", state.Config.Content, testConfig.Content)
	}

	// Test clear execution
	module.ClearExecution(resourceID)
	_, exists = module.GetExecutionState(resourceID)
	if exists {
		t.Error("Expected cleared execution state to return false")
	}
}

func TestScriptModule_InvalidConfig(t *testing.T) {
	module := NewModule()
	ctx := context.Background()
	resourceID := "test-invalid"

	// Test with invalid script config
	invalidConfig := &ScriptConfig{
		Content: "", // Empty content should fail validation
		Shell:   getTestShell(),
	}

	err := module.Set(ctx, resourceID, invalidConfig)
	if err == nil {
		t.Error("Expected Set() to fail with invalid script config")
	}
}

// Test helper for module discovery integration
// This will be automatically discovered by the discovery_test.go
