// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package file

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// createConfigFromYAML creates a FileConfig from YAML string
func createConfigFromYAML(yamlData string) modules.ConfigState {
	var config FileConfig
	if err := yaml.Unmarshal([]byte(yamlData), &config); err != nil {
		return nil
	}
	return &config
}

// getTestUser returns a test user for the current platform
func getTestUser(t *testing.T) (string, string) {
	switch runtime.GOOS {
	case "linux", "darwin":
		// Try to use the current user for testing
		currentUser, err := user.Current()
		if err != nil {
			t.Fatalf("Failed to get current user: %v", err)
		}
		// Get the primary group name
		group, err := user.LookupGroupId(currentUser.Gid)
		if err != nil {
			t.Logf("Failed to get group name: %v", err)
			return currentUser.Username, ""
		}
		return currentUser.Username, group.Name
	case "windows":
		// Windows uses SIDs, but we'll use the username for testing
		currentUser, err := user.Current()
		if err != nil {
			t.Fatalf("Failed to get current user: %v", err)
		}
		return currentUser.Username, "Users" // Common Windows group
	default:
		t.Skipf("Unsupported platform: %s", runtime.GOOS)
		return "", ""
	}
}

func TestFileModule(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content"

	// Get test user and group
	testUser, testGroup := getTestUser(t)

	tests := []struct {
		name       string
		configData string
		setup      func() error
		cleanup    func() error
		wantErr    bool
	}{
		{
			name: "Create new file",
			configData: `content: "` + testContent + `"
permissions: 420`,
			cleanup: func() error {
				return os.Remove(testFile)
			},
			wantErr: false,
		},
		{
			name: "Create file with ownership",
			configData: `content: "` + testContent + `"
permissions: 420
owner: ` + testUser + `
group: ` + testGroup,
			cleanup: func() error {
				return os.Remove(testFile)
			},
			wantErr: false,
		},
		{
			name: "Invalid content (empty)",
			configData: `content: ""
permissions: 420`,
			wantErr: true,
		},
		{
			name: "Invalid permissions",
			configData: `content: "` + testContent + `"
permissions: 9999`,
			wantErr: true,
		},
		{
			name: "Invalid owner",
			configData: `content: "` + testContent + `"
permissions: 420
owner: nonexistentuser`,
			wantErr: true,
		},
		{
			name: "Invalid group",
			configData: `content: "` + testContent + `"
permissions: 420
group: nonexistentgroup`,
			wantErr: true,
		},
	}

	module := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			if tt.cleanup != nil {
				defer func() {
					if err := tt.cleanup(); err != nil {
						t.Errorf("Cleanup failed: %v", err)
					}
				}()
			}

			// Create ConfigState from YAML
			configState := createConfigFromYAML(tt.configData)
			if configState == nil && !tt.wantErr {
				t.Errorf("Failed to create config from YAML: %s", tt.configData)
				return
			}

			// Test Set
			if configState == nil && !tt.wantErr {
				t.Errorf("configState is nil but test should not expect error")
				return
			}

			err := module.Set(context.Background(), testFile, configState)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Test Get
			if !tt.wantErr {
				config, err := module.Get(context.Background(), testFile)
				if err != nil {
					t.Errorf("Get() error = %v", err)
					return
				}
				if config == nil {
					t.Error("Get() returned nil config")
				}
			}
		})
	}
}

func TestFileModule_EdgeCases(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	module := New()

	// Test with empty resource ID
	configData := `content: "test content"
permissions: 420`
	configState := createConfigFromYAML(configData)

	err := module.Set(context.Background(), "", configState)
	if err == nil {
		t.Error("Set() with empty resource ID should fail")
	}

	// Test Get with non-existent file
	_, err = module.Get(context.Background(), filepath.Join(tempDir, "nonexistent.txt"))
	if err == nil {
		t.Error("Get() with non-existent file should fail")
	}

	// Test file creation and verification
	configData = `content: "test content for verification"
permissions: 493`
	configState = createConfigFromYAML(configData)

	err = module.Set(context.Background(), testFile, configState)
	if err != nil {
		t.Errorf("Set() failed: %v", err)
	}

	// Verify file exists and has correct content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Errorf("Failed to read created file: %v", err)
	}

	if string(content) != "test content for verification" {
		t.Errorf("File content mismatch: got %q, want %q", string(content), "test content for verification")
	}

	// Verify permissions
	info, err := os.Stat(testFile)
	if err != nil {
		t.Errorf("Failed to stat file: %v", err)
	}

	expectedPerms := os.FileMode(0755)
	if info.Mode().Perm() != expectedPerms {
		t.Errorf("File permissions mismatch: got %v, want %v", info.Mode().Perm(), expectedPerms)
	}
}
